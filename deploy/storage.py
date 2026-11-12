"""Reviewed existing-region optimization; never initializes or grants access."""
import argparse
from datetime import datetime,timezone,timedelta
import hashlib
import json
from pathlib import Path
import time

import region
import storage


def digest(value):return hashlib.sha256(value.encode()).hexdigest()


def query_plans(db,database,prefixes):
    out=[]
    with db.cursor() as c:
        for prefix in prefixes:
            for name,stamp in [('samples','ts'),('visits','ts'),('connection_state','last_seen')]:
                physical=storage.table(database,prefix,name)
                c.execute('SELECT source_ip,site FROM '+physical+' WHERE source_ip IS NOT NULL AND site IS NOT NULL LIMIT 1')
                row=c.fetchone()
                if not row:continue
                for column,value in zip(('source_ip','site'),row):
                    c.execute('EXPLAIN SELECT 1 FROM '+physical+' WHERE '+storage.identifier(column)+'=%s AND '
                              +storage.identifier(stamp)+' BETWEEN %s AND %s',(value,time.time()-86400,time.time()))
                    plan=dict(zip([x[0] for x in c.description],c.fetchone()))
                    out.append({'table':prefix+name,'filter':column,'index':plan['key'],'rows':int(plan['rows'])})
    return out


def apply(db,database,prefixes,expected):
    storage.validate(database,prefixes)
    with db.cursor() as c:
        c.execute('USE '+storage.identifier(database))
        c.execute('SET SESSION lock_wait_timeout=4')
        c.execute('SET SESSION innodb_lock_wait_timeout=4')
        c.execute('SET SESSION max_statement_time=20')
        c.execute('SET SESSION time_zone=%s',('+00:00',))
        c.execute('SHOW CREATE VIEW `流量汇总`');old=c.fetchone()[1]
        if digest(old)!=expected:raise ValueError('live_view_changed')
    result={'database':database,'namespaces':prefixes,'before_view_sha256':expected,
            'plans_before':query_plans(db,database,prefixes)}
    installed=[]
    for prefix in prefixes:
        installed.append(region.install_namespace(db,database,prefix))
        print(json.dumps({'installed_namespace':database+'/'+prefix,'result':installed[-1]}),flush=True)
    result['installed']=installed
    with db.cursor() as c:
        frozen=int(time.time());c.execute('SET timestamp=%s',(frozen,))
        c.execute('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY')
        result['reconciliation']=[region.verify_namespace(db,database,p) for p in prefixes]
        start=time.monotonic();c.execute('SELECT * FROM `流量汇总`');previous=c.fetchall()
        result['old_view_seconds']=round(time.monotonic()-start,4)
        start=time.monotonic();c.execute(storage.summary_select(database,prefixes));candidate=c.fetchall()
        result['new_view_seconds']=round(time.monotonic()-start,4)
        if previous!=candidate:raise ValueError('display_results_changed')
        result.update(display_identical=True,rows=len(candidate),snapshot_epoch=frozen,
                      display_sha256=digest(json.dumps(candidate,ensure_ascii=True,default=str)))
        c.execute(storage.totals_select(database,prefixes))
        totals=c.fetchall();result['upload_bytes']=sum(int(r[3]) for r in totals);result['download_bytes']=sum(int(r[4]) for r in totals)
        db.rollback();c.execute('SET timestamp=0')
        c.execute('SHOW CREATE VIEW `流量汇总`')
        if digest(c.fetchone()[1])!=expected:raise ValueError('concurrent_view_change')
        backup=Path(__file__).with_name('before-'+database+'.sql');backup.write_text(old,encoding='utf8')
        c.execute(storage.summary_ddl(database,prefixes))
        c.execute('SHOW CREATE VIEW `流量汇总`');result['view_sha256']=digest(c.fetchone()[1])
        start=time.monotonic();c.execute('SELECT * FROM `流量汇总`');rows=c.fetchall()
        result['applied_view_seconds']=round(time.monotonic()-start,4)
        result['applied_rows']=len(rows)
        c.execute('EXPLAIN SELECT * FROM `流量汇总` LIMIT 1')
        result['summary_plan']=[dict(zip([x[0] for x in c.description],r)) for r in c.fetchall()]
    result.update(plans_after=query_plans(db,database,prefixes),schema_version=storage.VERSION,
                  verified_at=datetime.now(timezone(timedelta(hours=8))).isoformat(timespec='seconds'))
    Path(__file__).with_name('result-'+database+'.json').write_text(json.dumps(result,indent=2,default=str),encoding='utf8')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--database',required=True)
    parser.add_argument('--namespace',action='append',default=None);parser.add_argument('--expected',required=True)
    args=parser.parse_args()
    import pymysql
    db=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user='root',charset='utf8mb4',autocommit=True,read_timeout=25)
    try:
        result=apply(db,args.database,tuple('' if p=='default' else p+'_' for p in args.namespace or ['default']),args.expected)
        print(json.dumps({k:v for k,v in result.items() if k not in ('summary_plan','plans_before','plans_after')},default=str))
    finally:db.close()
