"""One-off audited, reversible metadata migration; no dump or copied data."""
import json, os, subprocess, sys
from pathlib import Path
import pymysql
sys.path.insert(0, '/usr/local/libexec/traffic-central')
from model import TABLES

OLD, NEW = 'traffic_audit', 'region-a'
ROOT = Path('/etc/traffic-central')
CODE = Path('/usr/local/libexec/traffic-central')
TABLE_NAMES = sorted([*TABLES, 'sync_state', 'traffic_rollup'])
VIEWS = ['审计明细', '流量汇总', '入口流量汇总', '访问记录', '同步状态']
os.umask(0o077)

def snapshot(c, schema):
    counts = {}
    for table in TABLE_NAMES:
        c.execute(f'SELECT COUNT(*) FROM `{schema}`.`{table}`')
        counts[table] = c.fetchone()[0]
    totals = {}
    for table, up, down in [('samples','upload_bytes','download_bytes'),('wire_samples','up_bytes','down_bytes')]:
        c.execute(f'SELECT COALESCE(SUM({up}),0),COALESCE(SUM({down}),0) FROM `{schema}`.`{table}`')
        totals[table] = [int(v) for v in c.fetchone()]
    c.execute(f'SELECT * FROM `{schema}`.sync_state ORDER BY publisher')
    return {'counts':counts, 'totals':totals, 'sync':c.fetchall()}

def replace_file(path, content):
    temp = path.with_name(path.name+'.rename-tmp')
    try:
        temp.write_bytes(content)
        temp.chmod(0o600)
        temp.replace(path)
    finally:
        if temp.exists(): temp.unlink()

original = {p:p.read_bytes() for p in [ROOT/'writer.json',ROOT/'reader.json',CODE/'receive.py',CODE/'init.py']}
views_sql = (CODE/'views.sql').read_text()
for name in ['writer.json','reader.json']:
    assert json.loads(original[ROOT/name])['database'] == OLD
receiver = original[CODE/'receive.py'].decode()
assert "database='traffic_audit'" in receiver
receiver = receiver.replace("database='traffic_audit'", "database=config['database']")
initializer = original[CODE/'init.py'].decode()
initializer = initializer.replace('EXISTS traffic_audit CHARACTER','EXISTS `region-a` CHARACTER').replace('USE traffic_audit','USE `region-a`').replace("'database':'traffic_audit'","'database':'region-a'").replace('ON traffic_audit.','ON `region-a`.')
initializer = initializer.replace("cfg=json.loads(path.read_text())", "cfg=json.loads(path.read_text())\n            if cfg['database'] != 'region-a':\n                raise RuntimeError('database_migration_required')")
compile(receiver, 'receive.py', 'exec'); compile(initializer, 'init.py', 'exec')
db = pymysql.connect(unix_socket='/var/lib/traffic-central/run/mysqld.sock',user='root',password=(ROOT/'root-password').read_text().strip(),charset='utf8mb4',autocommit=True,connect_timeout=5,read_timeout=20,write_timeout=10)
moved = created = False
subprocess.run(['systemctl','stop','traffic-central-prune.timer','traffic-central-prune.service'],check=True,timeout=25)
try:
    with db.cursor() as c:
        c.execute('SET SESSION lock_wait_timeout=8')
        c.execute("SELECT GET_LOCK('traffic-audit-ingest',5)")
        assert c.fetchone()[0] == 1, 'publisher_not_quiescent'
        c.execute('SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=%s',(NEW,))
        assert c.fetchone()[0] == 0, 'target_database_exists'
        c.execute('SELECT TABLE_NAME,ENGINE FROM information_schema.TABLES WHERE TABLE_SCHEMA=%s AND TABLE_TYPE=%s ORDER BY TABLE_NAME',(OLD,'BASE TABLE'))
        assert c.fetchall() == tuple((t,'InnoDB') for t in TABLE_NAMES), 'unexpected_tables'
        for table, column in [('TRIGGERS','TRIGGER_SCHEMA'),('ROUTINES','ROUTINE_SCHEMA'),('EVENTS','EVENT_SCHEMA')]:
            c.execute(f'SELECT COUNT(*) FROM information_schema.{table} WHERE {column}=%s',(OLD,))
            assert c.fetchone()[0] == 0, 'unexpected_database_objects'
        c.execute('SELECT COUNT(*) FROM information_schema.REFERENTIAL_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=%s OR UNIQUE_CONSTRAINT_SCHEMA=%s',(OLD,OLD))
        assert c.fetchone()[0] == 0, 'foreign_key_dependency'
        c.execute('SELECT COUNT(*) FROM information_schema.VIEW_TABLE_USAGE WHERE TABLE_SCHEMA=%s AND VIEW_SCHEMA<>%s',(OLD,OLD))
        assert c.fetchone()[0] == 0, 'external_view_dependency'
        before = snapshot(c,OLD)
        c.execute(f'CREATE DATABASE `{NEW}` CHARACTER SET utf8mb4 COLLATE utf8mb4_bin')
        created = True
        c.execute('RENAME TABLE '+', '.join(f'`{OLD}`.`{t}` TO `{NEW}`.`{t}`' for t in TABLE_NAMES))
        moved = True
        c.execute(f'USE `{NEW}`')
        for statement in views_sql.split(';'):
            if statement.strip(): c.execute(statement)
        c.execute(f'GRANT SELECT,INSERT,UPDATE,DELETE ON `{NEW}`.* TO %s@%s',('audit_writer','localhost'))
        for host in ['localhost','127.0.0.1']:
            for view in VIEWS:
                c.execute(f'GRANT SELECT ON `{NEW}`.`{view}` TO %s@%s',('audit_ro',host))
        after = snapshot(c,NEW)
        assert before == after, 'migration_data_mismatch'
        for name in ['writer.json','reader.json']:
            cfg = json.loads(original[ROOT/name]); cfg['database'] = NEW
            replace_file(ROOT/name,json.dumps(cfg).encode())
        replace_file(CODE/'receive.py',receiver.encode())
        replace_file(CODE/'init.py',initializer.encode())
        cfg = json.loads((ROOT/'reader.json').read_text())
        ro = pymysql.connect(host='127.0.0.1',port=3306,user=cfg['user'],password=cfg['password'],database=NEW,charset='utf8mb4',connect_timeout=5,read_timeout=10)
        with ro.cursor() as rc:
            for view in VIEWS: rc.execute(f'SELECT * FROM `{view}` LIMIT 1'); rc.fetchall()
            for sql in ['SELECT * FROM samples LIMIT 1','UPDATE samples SET upload_bytes=upload_bytes WHERE 1=0']:
                try:
                    rc.execute(sql)
                except pymysql.err.OperationalError as e:
                    assert e.args[0] == 1142
                else: raise AssertionError('read_only_boundary_failed')
        ro.close()
        print(json.dumps({'renamed_to':NEW,'row_counts':after['counts'],'totals':after['totals'],'all_tables_and_totals_match':True,'five_views_readable':True,'raw_read_and_write_denied':True,'old_schema_has_only_views':True},ensure_ascii=False))
except Exception as exc:
    try:
        with db.cursor() as c:
            if moved:
                c.execute('RENAME TABLE '+', '.join(f'`{NEW}`.`{t}` TO `{OLD}`.`{t}`' for t in TABLE_NAMES))
            for path, content in original.items(): replace_file(path,content)
            if created:
                c.execute('SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA=%s AND TABLE_TYPE=%s',(NEW,'BASE TABLE'))
                assert c.fetchone()[0] == 0
                c.execute(f'DROP DATABASE `{NEW}`')
        print(json.dumps({'migration_failed':type(exc).__name__,'restored_original':True}))
    except Exception as rollback:
        print(json.dumps({'migration_failed':type(exc).__name__,'rollback_failed':type(rollback).__name__}))
    raise SystemExit(1)
finally:
    db.close()
    subprocess.run(['systemctl','start','traffic-central-prune.timer'],check=True,timeout=15)
