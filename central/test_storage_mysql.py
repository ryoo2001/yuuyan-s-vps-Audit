"""Synthetic, task-owned schema tests; no production facts are modified."""
import json
import re
from pathlib import Path
import threading
import time

import pymysql
import region
import storage
from model import TABLES,create_table_sql,upsert_sql
from receive import ingest,prune

DATABASE='audit_opt_test'


def connect():
    return pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user='root',database=DATABASE,
                           charset='utf8mb4',autocommit=True,read_timeout=20)


def verify(db,prefixes=('',)):
    with db.cursor() as c:c.execute('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY')
    try:
        for prefix in prefixes:region.verify_namespace(db,DATABASE,prefix)
        with db.cursor() as c:
            c.execute(storage.totals_select(DATABASE,prefixes))
            actual={tuple(r[:3]):(int(r[3]),int(r[4]),int(r[5])) for r in c.fetchall()}
            parts=[]
            for prefix in prefixes:
                for name,stamp in (('samples','ts'),('traffic_rollup','latest_ts')):
                    parts.append('SELECT '+','.join(storage.normalized(k)+' AS '+storage.identifier(k) for k in storage.KEYS)
                        +',upload_bytes,download_bytes FROM '+storage.table(DATABASE,prefix,name)
                        +' WHERE '+storage.identifier(stamp)+'>='+storage.MONTH_START+' AND '+storage.identifier(stamp)+'<=UNIX_TIMESTAMP()')
            c.execute('SELECT source_ip,node,site,SUM(COALESCE(upload_bytes,0)),SUM(COALESCE(download_bytes,0)),COUNT(*) FROM ('
                      +' UNION ALL '.join(parts)+') facts GROUP BY source_ip,node,site')
            expected={tuple(r[:3]):(int(r[3]),int(r[4]),int(r[5])) for r in c.fetchall()}
            assert actual==expected,(actual,expected)
    finally:db.rollback()


def main():
    admin=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user='root',charset='utf8mb4',autocommit=True)
    with admin.cursor() as c:
        c.execute('SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=%s',(DATABASE,))
        assert not c.fetchone(),'task_fixture_database_already_exists'
    created=False
    checks=[]
    try:
        created=True
        region.create_region(admin,DATABASE,('',),Path(__file__).with_name('views.sql').read_text())
        db=connect();now=time.time()
        with db.cursor() as c:
            c.execute('SET SESSION lock_wait_timeout=4');c.execute('SET SESSION innodb_lock_wait_timeout=4')
        row=['event',now-60,'conn','entry','192.0.2.1','same.test',12,30,'fixture']
        def payload(seq,values):
            return {'version':1,'publisher':'term-a1','epoch':'a'*32,'through':seq,'sent_at':time.time(),
                    'rows':[[seq,'samples',values]],'missing':0}
        ingest(db,payload(1,row));verify(db)
        ingest(db,payload(1,row))
        verify(db);checks.append('duplicate_upsert_idempotent')
        newer=row.copy();newer[6]=20
        ingest(db,payload(3,newer));ingest(db,payload(2,row));verify(db)
        checks.append('old_sequence_does_not_regress_totals')
        moved=newer.copy();moved[4]='192.0.2.2';moved[5]='changed.test';moved[6]=5
        ingest(db,payload(4,moved));verify(db);checks.append('late_attribution_and_counter_decrease')
        wrong=payload(5,row);wrong['epoch']='b'*32
        try:ingest(db,wrong);raise AssertionError('epoch_reset_accepted')
        except ValueError:db.rollback()
        verify(db);checks.append('epoch_rejection_keeps_totals')
        db.autocommit(False)
        with db.cursor() as c:
            c.execute(upsert_sql('samples'),['rollback',now,'conn','entry','192.0.2.1','rollback.test',1000,2000,'fixture',10])
        db.rollback();db.autocommit(True);verify(db);checks.append('trigger_changes_rollback_with_facts')
        with db.cursor() as c:
            for eid,ts,ip,site,up,down in [
                ('future',now+120,'192.0.2.1','future.test',555,666),
                ('zero',now-5,None,'zero.test',0,0),
                ('unknown',now-5,None,None,25,30),
                ('unknown-text',now-5,'未识别','未识别',7,8),
                ('case1',now-5,'192.0.2.1','Case.test',12,13),
                ('case2',now-5,'192.0.2.1','case.test',14,15),
                ('expired',now-8*86400,'192.0.2.1','retained.test',1000000000,4),
                ('previous-month',1761926400,'192.0.2.1','previous.test',9,10)]:
                c.execute(upsert_sql('samples'),[eid,ts,'conn','entry',ip,site,up,down,'fixture',11])
        verify(db);checks.append('future_unknown_case_zero_and_month_boundary')
        with db.cursor() as c:c.execute('SET timestamp=%s',(int(now)+121,))
        verify(db)
        with db.cursor() as c:c.execute('SET timestamp=0')
        checks.append('future_observation_becomes_visible_without_refresh')
        with db.cursor() as c:
            c.execute('SELECT '+storage.NEXT_MONTH);next_month=c.fetchone()[0]
            for eid,stamp in [('month-end',next_month-1),('month-start',next_month+.25)]:
                c.execute(upsert_sql('samples'),[eid,stamp,'conn','entry','192.0.2.1','month.test',20,21,'fixture',12])
            c.execute('SET timestamp=%s',(next_month+1,))
        verify(db)
        with db.cursor() as c:
            c.execute(storage.summary_select(DATABASE,('',)));month_rows=c.fetchall()
            assert len(month_rows)==1 and month_rows[0][3]=='month.test',month_rows
            c.execute('SET timestamp=0')
        checks.append('beijing_month_rollover_preserves_exact_boundary')
        with db.cursor() as c:c.execute(storage.summary_select(DATABASE,('',)));before=c.fetchall()
        prune(db);verify(db)
        with db.cursor() as c:c.execute(storage.summary_select(DATABASE,('',)));after=c.fetchall()
        assert before==after,(before,after)
        prune(db);verify(db);checks.append('legacy_prune_does_not_delete_before_verified_archive')
        # Backfill another namespace while a concurrent writer is changing facts.
        with db.cursor() as c:
            for name in TABLES:
                ddl=re.sub(r',KEY by_(?:source|site)_time \([^)]*\)','',create_table_sql(name))
                c.execute(ddl.replace('`'+name+'`',storage.table(DATABASE,'two_',name),1))
            for name in ('sync_state','traffic_rollup'):
                c.execute('CREATE TABLE '+storage.table(DATABASE,'two_',name)+' LIKE '+storage.table(DATABASE,'',name))
            c.execute('ALTER TABLE '+storage.table(DATABASE,'two_','traffic_rollup')+' DROP INDEX by_latest')
        stop=threading.Event();started=threading.Event();errors=[];commits=[]
        def writer():
            writer_db=connect()
            try:
                i=1
                while not stop.is_set():
                    with writer_db.cursor() as cur:
                        sql=upsert_sql('samples').replace('`samples`',storage.table(DATABASE,'two_','samples'),1)
                        cur.execute(sql,['writer'+str(i%10),now-30,'collision','entry','192.0.2.1','same.test',i,i+1,'fixture',i])
                    commits.append(i);i+=1;started.set();time.sleep(.004)
            except Exception as exc:errors.append(type(exc).__name__+':'+str(exc))
            finally:writer_db.close()
        thread=threading.Thread(target=writer);thread.start();assert started.wait(5)
        try:
            report=region.install_namespace(db,DATABASE,'two_')
            time.sleep(.05)
        finally:stop.set();thread.join(8)
        assert not thread.is_alive() and not errors,errors
        verify(db,('','two_'));checks.append('concurrent_online_seed_and_namespace_isolation')
        assert len(report['indexes_added'])==7,report
        checks.append('online_inplace_indexes_while_writer_is_active')
        # Source collisions remain separate physical facts, then add at display scope.
        with db.cursor() as c:
            for ddl in region.base_view_ddls(DATABASE,('','two_'),Path(__file__).with_name('views.sql').read_text()).values():c.execute(ddl)
            for name in ('审计明细','流量汇总','入口流量汇总','访问记录','同步状态'):
                c.execute('SELECT * FROM '+storage.identifier(name)+' LIMIT 1');c.fetchall()
        checks.append('future_multi_source_region_has_five_working_views')
        repeat=region.install_namespace(db,DATABASE,'two_')
        assert repeat['already_ready'] is True and not repeat['indexes_added']
        checks.append('ready_schema_reuse_is_non_destructive')
        db.close()
        print(json.dumps({'mysql_storage_fixtures_passed':True,'checks':checks,'concurrent_commits':len(commits),
                          'seed_gate_seconds':report['write_gate_seconds'],'production_facts_untouched':True}))
    finally:
        if created:
            with admin.cursor() as c:c.execute('DROP DATABASE '+storage.identifier(DATABASE))
        admin.close()


if __name__=='__main__':main()
