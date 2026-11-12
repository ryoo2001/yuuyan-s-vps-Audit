"""One reviewed calendar correction, never an initialization or grant script."""
from collections import defaultdict
from datetime import datetime,timezone,timedelta
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import time
import pymysql
import archive,monthbook,region,storage

TARGETS={'region-a':('',),'hk':('tb1_','tb2_','termc_','tb3_')}
EXPECTED={'region-a':'32a50605151a886bb626642bccbe8e747375153a08fef42572f0b02a9b07bd41',
          'hk':'f34e97db35bfaf276c9d8c63cf8ec221401b70f6c945491398fb82707c380304'}


def digest(body):return hashlib.sha256(body).hexdigest()


def oracle(db,store,database,prefixes):
    """Separate raw-table + cold-file oracle, independent of compact tables."""
    expected=defaultdict(lambda:[0,0,0]);stamp=int(time.time());start=monthbook.month(stamp)[1]
    with db.cursor() as c:
        c.execute('SET timestamp=%s',(stamp,));c.execute('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY')
    try:
        for prefix in prefixes:
            region.verify_namespace(db,database,prefix)
            with db.cursor() as c:
                for kind,timekey in (('samples','ts'),('traffic_rollup','latest_ts')):
                    c.execute('SELECT COUNT(*) FROM '+storage.table(database,prefix,kind)+' WHERE '+storage.identifier(timekey)+'>=%s AND '+monthbook.suppressed_sql(database,prefix,kind),(start,))
                    assert c.fetchone()[0]==0,'pending_late_rows_require_archive_before_verification'
                    c.execute('SELECT '+','.join(storage.normalized(k)for k in storage.KEYS)+',SUM(upload_bytes),SUM(download_bytes),COUNT(*) FROM '
                        +storage.table(database,prefix,kind)+' WHERE '+storage.identifier(timekey)+'>=%s AND '+storage.identifier(timekey)+'<=%s GROUP BY '+','.join(storage.normalized(k)for k in storage.KEYS),(start,stamp))
                    for row in c.fetchall():
                        for i,n in enumerate(row[3:]):expected[tuple(row[:3])][i]+=int(n)
        label=monthbook.month(stamp)[0]
        if any(x['month']==label for x in store.catalog(database)):
            with archive.read_month(store,database,label) as cold:
                for kind,body in cold.execute("SELECT kind,body FROM facts WHERE kind IN ('samples','traffic_rollup')"):
                    data=json.loads(body);key,values=monthbook.contribution(data)
                    for i,n in enumerate(values):expected[key][i]+=n
        with db.cursor() as c:
            c.execute(storage.totals_select(database,prefixes));actual={tuple(r[:3]):[int(x)for x in r[3:]]for r in c.fetchall()}
            assert actual==dict(expected),'calendar_oracle_mismatch:'+database
            began=time.monotonic();c.execute(storage.summary_select(database,prefixes));rows=c.fetchall();elapsed=time.monotonic()-began
            assert all(r[0].startswith(label.replace('-','/')+'/01–')for r in rows),'incorrect_month_start'
            assert all(r[0].split('–')[1]<=datetime.fromtimestamp(stamp,archive.TZ).strftime('%Y/%m/%d')for r in rows)
        totals={'upload_bytes':sum(v[0]for v in expected.values()),'download_bytes':sum(v[1]for v in expected.values()),'fact_rows':sum(v[2]for v in expected.values())}
        checksum=digest(json.dumps(sorted((list(k)+v for k,v in expected.items())),ensure_ascii=False).encode())
        return {'as_of':stamp,'groups':len(actual),'totals':totals,'all_groups_exact':True,'groups_sha256':checksum,'full_query_seconds':round(elapsed,4),'date_examples':sorted({r[0]for r in rows})[:2]}
    finally:
        db.rollback()
        with db.cursor() as c:c.execute('SET timestamp=0')


def main():
    stage=Path(__file__).parent;os.umask(0o077);payload=json.loads((stage/'candidates.json').read_text())
    root=Path('/var/lib/traffic-central/archive');report={'started_at':datetime.now(timezone(timedelta(hours=8))).isoformat(),'scope':'calendar_month_summary_only_details_remain_hot7_online14','databases':{}}
    with (root/'.lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        backup={}
        for path,item in payload.items():
            p=Path(path);before=p.read_bytes() if p.exists() else None
            assert (digest(before)if before is not None else None)==item['before_sha256'],'live_file_changed:'+path
            compile(item['content'],path,'exec');backup[path]={'data':base64.b64encode(before).decode()if before is not None else None,'mode':p.stat().st_mode&0o777 if p.exists()else None}
        bp=stage/'before-files.json';assert not bp.exists(),'task_already_started';bp.write_text(json.dumps(backup));bp.chmod(0o600)
        db=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user='root',charset='utf8mb4',autocommit=True,read_timeout=25)
        try:
            old_views={}
            with db.cursor() as c:
                c.execute('SET SESSION max_statement_time=20');c.execute('SET SESSION lock_wait_timeout=4');c.execute('SET SESSION innodb_lock_wait_timeout=4');c.execute('SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED')
                for database in TARGETS:
                    c.execute('USE '+storage.identifier(database));c.execute('SHOW CREATE VIEW `流量汇总`');ddl=c.fetchone()[1];assert digest(ddl.encode())==EXPECTED[database],'monthly_view_changed';old_views[database]=ddl
                    c.execute('SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=%s AND TABLE_NAME IN (%s,%s)',(database,'traffic_calendar','archive_receipts'));assert c.fetchone()[0]==0,'calendar_tables_already_exist'
            (stage/'before-views.json').write_text(json.dumps(old_views,ensure_ascii=False))
            store=archive.Store(root)
            for database,prefixes in TARGETS.items():
                for prefix in prefixes:monthbook.install(db,database,prefix)
                report['databases'][database]={'backfill':monthbook.bootstrap(db,store,database,prefixes)}
            report['archive_cycle']=archive.run(db,store,budget=20)
            for database,prefixes in TARGETS.items():report['databases'][database]['before_switch_oracle']=oracle(db,store,database,prefixes)
            report['files']=[]
            for path,item in payload.items():
                p=Path(path);temporary=p.with_name(p.name+'.month-next');temporary.write_text(item['content']);temporary.chmod(backup[path]['mode']or 0o600);os.replace(temporary,p)
                report['files'].append({'path':path,'before_sha256':item['before_sha256'],'sha256':digest(p.read_bytes())})
            with db.cursor() as c:
                for database,prefixes in TARGETS.items():
                    c.execute('USE '+storage.identifier(database));c.execute(storage.summary_ddl(database,prefixes));c.execute('SHOW CREATE VIEW `流量汇总`');report['databases'][database]['view_sha256']=digest(c.fetchone()[1].encode())
            report['verified_at']=datetime.now(timezone(timedelta(hours=8))).isoformat();(stage/'result.json').write_text(json.dumps(report,ensure_ascii=False,indent=2));print(json.dumps(report,ensure_ascii=False))
        finally:db.close()


if __name__=='__main__':main()
