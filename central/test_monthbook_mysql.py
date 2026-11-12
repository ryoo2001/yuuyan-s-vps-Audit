"""Root-only calendar fixture; never changes production facts."""
import json
from pathlib import Path
import tempfile
import time
from unittest.mock import patch
import pymysql
import archive,monthbook,region,storage
from model import upsert_sql

DATABASE='audit_month_test'


def main():
    db=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user='root',charset='utf8mb4',autocommit=True,read_timeout=20)
    made=False;checks=[];label,start=monthbook.month();cold=start+3600;now=time.time()
    def put(event,stamp,up,down,seq,site='case.test',prefix=''):
        with db.cursor() as c:c.execute(upsert_sql('samples').replace('`samples`',storage.table(DATABASE,prefix,'samples'),1),[event,stamp,'conn','entry','192.0.2.1',site,up,down,'fixture',seq])
    def total():
        with db.cursor() as c:
            c.execute(storage.totals_select(DATABASE,('','other_')));rows=c.fetchall()
        return sum(int(r[3])+int(r[4])for r in rows)
    try:
        with db.cursor() as c:
            c.execute('SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=%s',(DATABASE,))
            if c.fetchone():raise ValueError('existing_month_fixture_refused')
        made=True;region.create_region(db,DATABASE,('','other_'),Path(__file__).with_name('views.sql').read_text())
        with db.cursor() as c:c.execute('USE '+storage.identifier(DATABASE));c.execute('SET SESSION max_statement_time=10')
        put('old',cold,50,60,3);put('hot',now-10,7,9,10)
        with tempfile.TemporaryDirectory(prefix='month-fixture-') as directory:
            store=archive.Store(directory)
            old=['old',cold,'conn','entry','192.0.2.1','case.test',10,20,'fixture',1]
            store.write(DATABASE,'','samples',[old]);old[6]=50;old[7]=60;old[-1]=3;store.write(DATABASE,'','samples',[old])
            monthbook.bootstrap(db,store,DATABASE,('','other_'));assert total()==126,total()
            checks.append('bootstrap_counts_latest_cold_version_once_even_with_online_overlap')
            archive.archive_batch(db,store,DATABASE,'','samples',cold+1);assert total()==126
            checks.append('archival_transfers_bytes_atomically_without_month_total_drop')
            put('old',cold,20,30,4,site='changed.test');assert total()==126
            archive.archive_batch(db,store,DATABASE,'','samples',cold+1);assert total()==66,total()
            put('old',cold,20,30,4,site='changed.test');archive.archive_batch(db,store,DATABASE,'','samples',cold+1);assert total()==66
            put('old',cold,900,900,2);archive.archive_batch(db,store,DATABASE,'','samples',cold+1);assert total()==66
            checks.append('late_revision_attribution_counter_decrease_replay_and_old_sequence')
            put('new',cold,5,6,11,prefix='other_')
            class FailedCommit:
                def __getattr__(self,name):return getattr(db,name)
                def commit(self):raise OSError('fixture_before_commit')
            try:archive.archive_batch(FailedCommit(),store,DATABASE,'other_','samples',cold+1)
            except OSError:pass
            else:raise AssertionError('commit_failure_missing')
            with db.cursor() as c:c.execute("SELECT COUNT(*) FROM other_samples WHERE event_id='new'");assert c.fetchone()[0]==1
            archive.archive_batch(db,store,DATABASE,'other_','samples',cold+1);assert total()==77,total()
            checks.append('failed_sql_commit_retains_fact_and_retry_does_not_double_count')
            put('new',cold,8,9,12,prefix='other_');index=store.calendar_indexes[DATABASE];real_sync=index.sync;called=[0]
            def fail_after_commit(database):
                called[0]+=1
                if called[0]==2:raise OSError('fixture_after_sql_commit')
                return real_sync(database)
            with patch.object(index,'sync',side_effect=fail_after_commit):
                try:archive.archive_batch(db,store,DATABASE,'other_','samples',cold+1)
                except OSError:pass
                else:raise AssertionError('postcommit_failure_missing')
            real_sync(db);assert total()==83,total()
            put('new',cold,8,9,12,prefix='other_');archive.archive_batch(db,store,DATABASE,'other_','samples',cold+1);assert total()==83
            checks.append('archive_receipts_recover_after_sql_commit_before_file_index_commit')
            with db.cursor() as c:
                c.execute(storage.summary_select(DATABASE,('','other_')));rows=c.fetchall();assert all(r[0].startswith(label.replace('-','/')+'/01–')for r in rows),rows
                c.execute('SELECT calendar_version FROM audit_schema');assert all(r[0]==1 for r in c.fetchall())
            for prefix in ('','other_'):monthbook.install(db,DATABASE,prefix);region.verify_namespace(db,DATABASE,prefix)
            checks.append('month_start_label_five_views_new_region_and_idempotent_install')
            from datetime import datetime,timedelta
            next_start=(datetime.fromtimestamp(start,archive.TZ).replace(day=28)+timedelta(days=4)).replace(day=1).timestamp()
            put('next',next_start+1,3,4,30)
            with db.cursor() as c:c.execute('SET timestamp=%s',(next_start+2,))
            with patch.object(monthbook,'month',return_value=(datetime.fromtimestamp(next_start,archive.TZ).strftime('%Y-%m'),int(next_start))):monthbook.retire(db,store,[DATABASE])
            assert total()==7,total();assert store.catalog(DATABASE)
            checks.append('calendar_rollover_resets_visible_month_and_keeps_cold_archive')
            for index in store.calendar_indexes.values():index.close()
        print(json.dumps({'passed':True,'checks':checks,'production_facts_untouched':True}))
    finally:
        if made:
            with db.cursor() as c:c.execute('DROP DATABASE '+storage.identifier(DATABASE))
        db.close()


if __name__=='__main__':main()
