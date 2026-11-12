"""Root-only isolated tier fixture. Never writes production facts."""
from datetime import datetime
import json
from pathlib import Path
import tempfile
import time
import pymysql
import archive
from model import TABLES,upsert_sql
from receive import ingest,prune,PUBLISHER
import region,storage,tiering
DATABASE='audit_tier_test'

def main():
    db=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user='root',charset='utf8mb4',autocommit=True,read_timeout=25)
    made=False;checks=[];now=int(time.time());cold=now-16*86400
    try:
        with db.cursor() as c:
            c.execute('SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=%s',(DATABASE,))
            if c.fetchone():raise ValueError('existing_fixture_database_refused')
        made=True
        region.create_region(db,DATABASE,('','edge_'),Path(__file__).with_name('views.sql').read_text())
        with db.cursor() as c:
            c.execute('USE '+storage.identifier(DATABASE));c.execute('SET SESSION max_statement_time=20');c.execute('SET timestamp=%s',(now,))
            for prefix in ('','edge_'):
                sql=upsert_sql('samples').replace('`samples`',storage.table(DATABASE,prefix,'samples'),1)
                for event,days,seq in [('hot',1,1),('warm',9,2),('cold',16,3),('past-month',45,4)]:
                    c.execute(sql,[event,now-days*86400,'conn-'+event,'entry','192.0.2.1',event+'.test',10,20,'fixture',seq])
            c.execute('INSERT INTO traffic_rollup VALUES(%s,%s,%s,%s,%s,%s,%s)',(int(cold//86400)*86400,'192.0.2.1','entry','historic.test',77,88,cold))
            for event,days,seq in [('hot',1,5),('warm',9,6),('cold',16,7)]:
                c.execute(upsert_sql('visits'),['visit-'+event,now-days*86400,'entry','192.0.2.1',event+'.test',443,'tcp','flow','fixture',seq])
            c.execute('SELECT `目标网站` FROM `访问记录`');assert [r[0] for r in c.fetchall()]==['hot.test']
            c.execute('SELECT COUNT(*) FROM visits WHERE ts<%s AND ts>=%s',(now-7*86400,now-14*86400));assert c.fetchone()[0]==1
            # The summary is the current Beijing calendar month, so which fixture rows are visible depends on today's date.
            label=lambda stamp:datetime.fromtimestamp(stamp,archive.TZ).strftime('%Y-%m')
            expected={event+'.test' for event,days in (('hot',1),('warm',9),('cold',16)) if label(now-days*86400)==label(now)}|({'historic.test'} if label(cold)==label(now) else set())
            c.execute(storage.summary_select(DATABASE,('','edge_')));visible=c.fetchall();assert {r[3] for r in visible}==expected,(visible,expected)
        checks.append('hot_defaults_and_explicit_fourteen_day_warm_access')
        try:
            with db.cursor() as c:c.execute("DELETE FROM samples WHERE event_id='warm'")
            raise AssertionError('unarchived_delete_was_allowed')
        except pymysql.err.OperationalError as error:
            assert error.args[0]==1644,error
            db.rollback()
        checks.append('unarchived_delete_is_blocked')
        region.verify_namespace(db,DATABASE,'');assert prune(db)==0
        with tempfile.TemporaryDirectory(prefix='archive-fixture-') as directory:
            store=archive.Store(directory)
            class Failing:
                def write(self,*args,**kwargs):raise OSError('fixture_disk_full')
            try:archive.archive_batch(db,Failing(),DATABASE,'','samples',now-14*86400)
            except OSError:pass
            else:raise AssertionError('fixture_failure_missing')
            with db.cursor() as c:c.execute("SELECT COUNT(*) FROM samples WHERE event_id='cold'");assert c.fetchone()[0]==1
            checks.append('archive_io_failure_keeps_original_fact')
            class AfterWriteFailure:
                def write(self,*args,**kwargs):
                    store.write(*args,**kwargs);raise OSError('fixture_after_fsync')
            try:archive.archive_batch(db,AfterWriteFailure(),DATABASE,'','samples',now-14*86400)
            except OSError:pass
            with db.cursor() as c:c.execute('SELECT SUM(upload_bytes),SUM(download_bytes) FROM samples');before=tuple(int(n) for n in c.fetchone())
            for prefix in ('','edge_'):
                for logical in [n for n in TABLES if TABLES[n][2]]+['traffic_rollup']:
                    archive.archive_batch(db,store,DATABASE,prefix,logical,now-14*86400)
                region.verify_namespace(db,DATABASE,prefix)
            with db.cursor() as c:
                c.execute('SELECT SUM(upload_bytes),SUM(download_bytes) FROM samples');after=tuple(int(n) for n in c.fetchone())
                c.execute('SELECT COUNT(*) FROM traffic_rollup');assert c.fetchone()[0]==0
            month=datetime.fromtimestamp(cold,archive.TZ).strftime('%Y-%m')
            extra=20 if datetime.fromtimestamp(now-45*86400,archive.TZ).strftime('%Y-%m')==month else 0  # past-month rows share the cold month late in a month
            result=archive.query_month(store,DATABASE,month);assert result['totals']=={'upload_bytes':97+extra,'download_bytes':128+2*extra,'total_bytes':225+3*extra},result
            assert before[0]-after[0]==20 and before[1]-after[1]==40
            checks.append('retry_and_cross_namespace_archives_preserve_exact_totals')
            payload={'version':1,'publisher':PUBLISHER,'epoch':'a'*32,'through':100,'sent_at':time.time(),'missing':0,
                     'rows':[[100,'samples',['late',cold,'late-conn','entry','192.0.2.1','late.test',5,6,'fixture']]]}
            ingest(db,payload);archive.archive_batch(db,store,DATABASE,'','samples',now-14*86400);ingest(db,payload)
            with db.cursor() as c:c.execute("SELECT COUNT(*) FROM samples WHERE event_id='late'");assert c.fetchone()[0]==0
            result=archive.query_month(store,DATABASE,month);assert result['totals']['total_bytes']==236+3*extra,result
            checks.append('late_facts_retained_and_old_sequence_cannot_resurrect_archives')
            old_month=datetime.fromtimestamp(now-45*86400,archive.TZ).strftime('%Y-%m');before_pack=archive.query_month(store,DATABASE,old_month)
            store.pack(DATABASE,old_month);assert archive.query_month(store,DATABASE,old_month)==before_pack
            assert not list(Path(directory).glob('.query-*'))
            checks.append('sealed_month_reads_without_mysql_restore_and_cleans_scratch')
        for prefix in ('','edge_'):
            tiering.install_namespace(db,DATABASE,prefix);region.install_namespace(db,DATABASE,prefix);region.verify_namespace(db,DATABASE,prefix)
        checks.append('new_region_and_repeated_install_keep_policy')
        print(json.dumps({'passed':True,'checks':checks,'production_facts_untouched':True,'fixture_database':DATABASE}))
    finally:
        if made:
            with db.cursor() as c:c.execute('DROP DATABASE '+storage.identifier(DATABASE))
        db.close()

if __name__=='__main__':main()
