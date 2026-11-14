"""Verify the public read-only account against every audit database."""
import json
import re
import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "lib"))
import pymysql

cfg = json.loads((Path(__file__).parent / "connection.json").read_text())
parser = argparse.ArgumentParser()
parser.add_argument("--database", action="append", help="Explicit audit database; regional schema v2 is supported")
parser.add_argument("--require-tiers", action="store_true", help="Require the current central hot/warm/cold policy")
args = parser.parse_args()
for name in args.database or ():
    if not re.fullmatch(r'[a-z][a-z0-9_-]{0,47}',name) or name in ('mysql','sys','information_schema','performance_schema'):
        parser.error('invalid audit database name')
db = pymysql.connect(**cfg, charset="utf8mb4", connect_timeout=10,
                     read_timeout=100, write_timeout=10)
checked = {}
with db.cursor() as c:
    c.execute("SET SESSION max_statement_time=90")
    c.execute("SELECT VERSION(),CURRENT_USER()")
    server = c.fetchone()
    c.execute("SHOW DATABASES")
    databases = [r[0] for r in c.fetchall()]
    for database in (args.database or [name for name in databases if name not in ('mysql','sys','information_schema','performance_schema')]):
        try:
            c.execute("SHOW FULL TABLES FROM `" + database + "`")
        except pymysql.err.OperationalError as exc:
            if args.database or exc.args[0] not in (1044,1142):raise
            continue
        objects = c.fetchall()
        object_map=dict(objects)
        if not args.database and database not in ('region-a','hk') and object_map.get('audit_schema')!='BASE TABLE':continue
        if object_map.get('audit_schema')=='BASE TABLE':
            c.execute('SELECT namespace,version,ready FROM `'+database+'`.audit_schema ORDER BY namespace')
            namespaces=c.fetchall()
            assert namespaces and all(version==2 and ready==1 for _,version,ready in namespaces), 'audit_schema_not_ready'
            c.execute("SHOW COLUMNS FROM `"+database+"`.audit_schema LIKE 'archive_policy_version'")
            has_tiers=bool(c.fetchone())
            if args.require_tiers:
                assert has_tiers, 'audit_tier_policy_missing'
            if has_tiers:
                c.execute('SELECT namespace,archive_policy_version,hot_days,online_days FROM `'+database+'`.audit_schema ORDER BY namespace')
                policies=c.fetchall()
                assert {r[0] for r in policies}=={r[0] for r in namespaces}, 'audit_tier_namespaces_missing'
                assert all(version==1 and 3<=hot<=7 and online==14 for _,version,hot,online in policies), 'audit_tier_policy_not_ready'
            raw_names=('samples','visits','wire_samples','connection_state','connection_rates','entry_routes','peers','sync_state','traffic_rollup','traffic_monthly')
            expected_tables={'audit_schema'}|{prefix+name for prefix,_,_ in namespaces for name in raw_names}
            c.execute("SHOW COLUMNS FROM `"+database+"`.audit_schema LIKE 'calendar_version'")
            if c.fetchone():
                c.execute('SELECT calendar_version FROM `'+database+'`.audit_schema')
                assert all(row[0]==1 for row in c.fetchall()), 'calendar_summary_not_ready'
                expected_tables|={'traffic_calendar','archive_receipts'}
            # A namespace may own one edge relay queue (hk/termb4_ since 2026-11-02).
            # It is transport state, not an audit fact table, so it is optional here.
            actual_tables={name for name,kind in objects if kind=='BASE TABLE'}
            relay_queues={prefix+'edge_queue' for prefix,_,_ in namespaces if prefix}
            derived_tables={'ip_geo'}
            assert expected_tables<=actual_tables and actual_tables-expected_tables<=relay_queues|derived_tables,'audit_objects_missing'
        else:
            assert not args.require_tiers, 'audit_tier_policy_missing'
            assert database in ('hk','region-a') and len(objects)==(41 if database=='hk' else 14), 'audit_objects_missing'
        assert {name for name, kind in objects if kind == "VIEW"} == {
            "审计明细", "流量汇总", "入口流量汇总", "访问记录", "同步状态"
        }, "unexpected_user_views"
        for table, _ in objects:
            started = time.monotonic()
            print(json.dumps({"database": database, "reading": table}, ensure_ascii=True), flush=True)
            c.execute("SELECT * FROM `" + database + "`.`" + table + "` LIMIT 1")
            c.fetchall()
            print(json.dumps({"database": database, "read": table,
                              "seconds": round(time.monotonic() - started, 3)}, ensure_ascii=True), flush=True)
        checked[database] = {"tables": sum(r[1] == "BASE TABLE" for r in objects),
                             "views": sum(r[1] == "VIEW" for r in objects)}
        try:
            table = (namespaces[0][0]+'samples') if object_map.get('audit_schema')=='BASE TABLE' else ("tb1_samples" if database == "hk" else "samples")
            c.execute("UPDATE `" + database + "`.`" + table + "` SET upload_bytes=upload_bytes WHERE 1=0")
            raise AssertionError("reader_unexpected_write_permission")
        except pymysql.err.OperationalError as e:
            assert e.args[0] == 1142
        try:
            c.execute("CREATE TEMPORARY TABLE `" + database + "`.audit_forbidden_probe(id int)")
            raise AssertionError("reader_unexpected_ddl_permission")
        except pymysql.err.OperationalError as e:
            assert e.args[0] in (1044, 1142)
    assert checked, 'no_accessible_audit_database'
    checked_database=next(iter(checked))
    for sql in ("SELECT * FROM mysql.user LIMIT 1",
                "CREATE TABLE `"+checked_database+"`.audit_forbidden_probe(id int)"):
        try:
            c.execute(sql)
            raise AssertionError("reader_unexpected_admin_permission")
        except pymysql.err.OperationalError as e:
            assert e.args[0] in (1044, 1142)
db.close()
wrong = {**cfg, "password": "intentionally-wrong-audit-validation"}
try:
    pymysql.connect(**wrong, connect_timeout=10, read_timeout=10)
    raise AssertionError("wrong_password_accepted")
except pymysql.err.OperationalError as e:
    assert e.args[0] == 1045
print(json.dumps({"local_query": True, "server": server, "databases": databases,
                  "checked": checked, "write_denied": True,
                  "system_credentials_denied": True, "ddl_denied": True,
                  "wrong_password_denied": True}, ensure_ascii=True))
