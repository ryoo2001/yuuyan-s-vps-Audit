"""Reviewed current-region tier activation. No initializers or grants."""
from datetime import datetime,timezone,timedelta
import hashlib
import json
from pathlib import Path
import time
import pymysql
import archive,region,storage,tiering

TARGETS={'region-a':('',),'hk':('tb1_','tb2_','termc_','tb3_')}
EXPECTED={'region-a':'6e596c5c86195975654d4b05e6c4cbe52e272e50314c993769777e5162fa824f',
          'hk':'29afa4d0c4b6851411798405d1eb8f698234bb0fa0b071e6b5e7d20373da3cf9'}

def checksum(text):return hashlib.sha256(text.encode()).hexdigest()

def reconcile_snapshot(db,database,prefixes):
    with db.cursor() as c:c.execute('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY')
    try:return [region.verify_namespace(db,database,p) for p in prefixes]
    finally:db.rollback()

def old_facts(db,cutoff):
    sources=[]
    with db.cursor() as c:
        for database,prefixes in TARGETS.items():
            for prefix in prefixes:
                out={'database':database,'namespace':prefix,'tables':{},'upload_bytes':0,'download_bytes':0}
                for name in [n for n in archive.TABLES if archive.TABLES[n][2]]+['traffic_rollup']:
                    columns,keys,stamp=archive.specification(name)
                    sql='SELECT COUNT(*)'
                    if name in ('samples','traffic_rollup'):sql+=',COALESCE(SUM(upload_bytes),0),COALESCE(SUM(download_bytes),0)'
                    c.execute(sql+' FROM '+storage.table(database,prefix,name)+' WHERE '+storage.identifier(stamp)+'<%s',(cutoff,));row=c.fetchone();out['tables'][name]=row[0]
                    if len(row)>1:out['upload_bytes']+=int(row[1]);out['download_bytes']+=int(row[2])
                sources.append(out)
    return sources

def main():
    root=Path(__file__).parent;db=pymysql.connect(unix_socket='/run/mysqld/mysqld.sock',user='root',charset='utf8mb4',autocommit=True,read_timeout=25)
    report={'started_at':datetime.now(timezone(timedelta(hours=8))).isoformat(),'policy':archive.metadata(),'databases':{}}
    try:
        with db.cursor() as c:
            c.execute('SET SESSION lock_wait_timeout=4');c.execute('SET SESSION innodb_lock_wait_timeout=4');c.execute('SET SESSION max_statement_time=20')
        candidates={};backup={}
        for database,prefixes in TARGETS.items():
            with db.cursor() as c:
                c.execute('USE '+storage.identifier(database));backup[database]={};candidates[database]={}
                for name in storage.FRIENDLY_VIEWS:
                    c.execute('SHOW CREATE VIEW '+storage.identifier(name));ddl=c.fetchone()[1];backup[database][name]=ddl
                if checksum(backup[database]['流量汇总'])!=EXPECTED[database]:raise ValueError('live_monthly_view_changed:'+database)
                for name,ddl in backup[database].items():
                    if name=='流量汇总':candidate=storage.summary_ddl(database,prefixes)
                    elif name=='同步状态':continue
                    else:candidate=tiering.hot_projection(ddl.replace('CREATE ','CREATE OR REPLACE ',1),database,prefixes,name)
                    c.execute('EXPLAIN '+candidate.split(' AS ',1)[1]);c.fetchall();candidates[database][name]=candidate
            report['databases'][database]={'before_views':{n:checksum(s) for n,s in backup[database].items()},'reconciliation_before':reconcile_snapshot(db,database,prefixes)}
        backup_path=root/'before-views.json'
        if backup_path.exists():raise ValueError('task_view_backup_already_exists')
        backup_path.write_text(json.dumps(backup,ensure_ascii=False));backup_path.chmod(0o600)
        cutoff=int(time.time())-archive.ONLINE_DAYS*86400;report['cutoff']=cutoff;report['before_cold_facts']=old_facts(db,cutoff)
        for database,prefixes in TARGETS.items():
            installed=[tiering.install_namespace(db,database,p) for p in prefixes]
            with db.cursor() as c:
                c.execute('USE '+storage.identifier(database))
                for name,ddl in candidates[database].items():c.execute(ddl)
                hashes={}
                for name in storage.FRIENDLY_VIEWS:
                    c.execute('SHOW CREATE VIEW '+storage.identifier(name));hashes[name]=checksum(c.fetchone()[1])
                c.execute('SELECT namespace,archive_policy_version,hot_days,online_days FROM audit_schema ORDER BY namespace');policy=c.fetchall()
            report['databases'][database].update(installed=installed,after_views=hashes,policy=policy)
        report['verified_at']=datetime.now(timezone(timedelta(hours=8))).isoformat()
        (root/'migration-result.json').write_text(json.dumps(report,ensure_ascii=False,indent=2));print(json.dumps(report,ensure_ascii=False))
    finally:db.close()

if __name__=='__main__':main()
