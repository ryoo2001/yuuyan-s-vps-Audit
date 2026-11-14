#!/usr/bin/env python3
"""One-time central database initialization; credentials never go to stdout."""
import json,os,secrets,time
from pathlib import Path
import pymysql
from model import TABLES,create_table_sql
from region import install_namespace,base_view_ddls
from storage import summary_ddl
from storage import geo_ddl
import tiering
import monthbook
ROOT=Path('/etc/traffic-central')
SOCKET='/var/lib/traffic-central/run/mysqld.sock'
os.umask(0o077)
password=(ROOT/'root-password').read_text().strip()
for attempt in range(90):
    try:
        db=pymysql.connect(unix_socket=SOCKET,user='root',password=password,charset='utf8mb4',connect_timeout=2)
        break
    except Exception:
        time.sleep(2)
else:
    raise RuntimeError('mysql_start_timeout')
with db.cursor() as c:
    c.execute('CREATE DATABASE IF NOT EXISTS `region-a` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin')
    c.execute('USE `region-a`')
    for table in TABLES: c.execute(create_table_sql(table))
    c.execute(geo_ddl('region-a'))
    for statement in Path('/usr/local/libexec/traffic-central/views.sql').read_text().split(';'):
        if statement.strip(): c.execute(statement)
    install_namespace(db, 'region-a', '')
    tiering.install_namespace(db, 'region-a', '')
    monthbook.install(db, 'region-a', '')
    for ddl in base_view_ddls('region-a', ('',), Path('/usr/local/libexec/traffic-central/views.sql').read_text()).values():
        c.execute(ddl)
    for name,filename in [('audit_writer','writer.json'),('audit_ro','reader.json')]:
        path=ROOT/filename
        if path.exists():
            cfg=json.loads(path.read_text())
            if cfg['database'] != 'region-a':
                raise RuntimeError('database_migration_required')
        else:
            cfg={'socket':SOCKET,'user':name,'password':secrets.token_urlsafe(32),'database':'region-a'}
            path.write_text(json.dumps(cfg));path.chmod(0o600)
        # Socket writer and loopback-only reader; no wildcard hosts or global grants.
        for host in (['localhost'] if name=='audit_writer' else ['localhost','127.0.0.1']):
            c.execute('CREATE USER IF NOT EXISTS %s@%s IDENTIFIED BY %s',(name,host,cfg['password']))
            if name=='audit_writer':
                c.execute('GRANT SELECT,INSERT,UPDATE,DELETE ON `region-a`.* TO %s@%s',(name,host))
            else:
                c.execute('ALTER USER %s@%s WITH MAX_USER_CONNECTIONS 3',(name,host))
                for view in ['审计明细','流量汇总','入口流量汇总','访问记录','同步状态']:
                    c.execute('GRANT SELECT ON `region-a`.`'+view+'` TO %s@%s',(name,host))
    c.execute('SELECT VERSION()');version=c.fetchone()[0]
    c.execute("SELECT user,host FROM mysql.user WHERE user='root'")
    roots=c.fetchall()
    if roots != (('root','localhost'),): raise RuntimeError('unexpected_root_host')
    c.execute('SHOW TABLES');tables=[r[0] for r in c.fetchall()]
db.commit();db.close()
print(json.dumps({'initialized':True,'version':version,'tables':tables,'root_local_only':True}))
