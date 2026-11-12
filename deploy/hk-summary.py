"""Verify or replace only the HK monthly view; never migrate production facts."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import time

from hk_summary import SOURCES, summary_ddl, summary_select


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def legacy_select(ddl, latest):
    # Old nested aggregate windows can remain CPU-bound after KILL on the
    # installed MariaDB. Evaluate the identical global MAX separately.
    select = re.split(r"\sAS\s(?=select)", ddl, maxsplit=1, flags=re.I)[1]
    select, count = re.subn(r"max\(max\(`s`\.`ts`\)\) over \(\)", str(float(latest)), select, flags=re.I)
    if count != 1:
        raise ValueError("unexpected_legacy_view")
    return select


def latest_sql():
    sql = summary_select()
    return sql.split("CROSS JOIN (", 1)[1].rsplit(") latest ", 1)[0]


def run(db, expected, apply=False):
    result = {}
    with db.cursor() as c:
        c.execute("SET SESSION max_statement_time=8")
        c.execute("SET SESSION lock_wait_timeout=4")
        c.execute("SET SESSION time_zone='+00:00'")
        c.execute("SHOW CREATE VIEW `流量汇总`")
        old = c.fetchone()[1]
        if digest(old) != expected:
            raise ValueError("live_view_changed")
        frozen = int(time.time())
        c.execute("SET timestamp=%s", (frozen,))
        c.execute("START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY")
        c.execute(latest_sql())
        latest = c.fetchone()[0] or frozen
        start = time.monotonic()
        c.execute(legacy_select(old, latest))
        previous = c.fetchall()
        result["legacy_without_window_seconds"] = round(time.monotonic()-start, 4)
        start = time.monotonic()
        c.execute(summary_select())
        current = c.fetchall()
        result["candidate_seconds"] = round(time.monotonic()-start, 4)
        if current != previous:
            raise ValueError("production_display_mismatch")
        result.update(display_rows=len(current), display_identical=True, snapshot_epoch=frozen,
                      display_sha256=digest(json.dumps(current, ensure_ascii=True, default=str)))
        # Independent integer-byte reference: read each narrow physical table
        # without SQL grouping or windows and merge the binary display keys.
        totals = {}
        c.execute("SELECT " + __import__('hk_summary').MONTH_START)
        month_start = c.fetchone()[0]
        for source in SOURCES:
            for table, stamp in (("samples", "ts"), ("traffic_rollup", "latest_ts")):
                c.execute("SELECT source_ip,node,site,upload_bytes,download_bytes FROM `hk`.`"
                          + source + "_" + table + "` WHERE `" + stamp + "` BETWEEN %s AND %s",
                          (month_start, frozen))
                for ip, node, site, up, down in c.fetchall():
                    key = tuple((x or '未识别').rstrip(' ') for x in (ip, node, site))
                    totals[key] = totals.get(key, 0) + (up or 0) + (down or 0)
        raw_sql = summary_select().split(" FROM (", 1)[1]
        raw_sql = "SELECT s.source_ip,s.node,s.site,SUM(s.total_bytes) FROM (" + raw_sql
        c.execute(raw_sql)
        actual = {tuple(x.rstrip(' ') for x in row[:3]): int(row[3]) for row in c.fetchall()}
        if actual != totals:
            raise ValueError("production_bytes_mismatch")
        result.update(integer_groups=len(totals), total_bytes=sum(totals.values()), integer_bytes_identical=True)
        db.rollback()
        # Only temporary tables receive fixture rows.
        fixture_old = old
        fixture_new = summary_select()
        fixture_latest = latest_sql()
        fixture_names = []
        for source in SOURCES:
            for table, stamp in (("samples", "ts"), ("traffic_rollup", "latest_ts")):
                name = 'q_' + source + '_' + table
                physical = '`hk`.`' + source + '_' + table + '`'
                c.execute('CREATE TEMPORARY TABLE `' + name + '` LIKE ' + physical)
                fixture_names.append(name)
                fixture_old = fixture_old.replace(physical, '`' + name + '`')
                fixture_old = fixture_old.replace('`' + source + '_' + table + '`', '`' + name + '`')
                fixture_new = fixture_new.replace(physical, '`' + name + '`')
                fixture_latest = fixture_latest.replace(physical, '`' + name + '`')
                cases = [
                    (month_start-1, '1.2.3.4', 'entry', 'previous', 8, 9),
                    (month_start, '1.2.3.4', 'entry', 'same.site', 123, 456),
                    (frozen-5, '1.2.3.4', 'entry', 'same.site', 12, 34),
                    (frozen-2, '', '', '', 500, 600),
                    (frozen-1, '未识别', '未识别', '未识别', 7, 8),
                    (frozen, '5.6.7.8', 'entry', 'gb.site', 999999999, 1),
                    (frozen-3, '9.8.7.6', 'entry', 'Case.site', 10, 11),
                    (frozen-3, '9.8.7.6', 'entry', 'case.site', 20, 21),
                    (frozen-3, '9.8.7.6', 'entry', '网站.site', 30, 31),
                    (frozen+1, '1.2.3.4', 'entry', 'future', 99, 99)]
                for i, (ts, ip, node, site, up, down) in enumerate(cases):
                    if table == 'samples':
                        c.execute('INSERT INTO `' + name + '` (event_id,connection_id,_seq,ts,source_ip,node,site,upload_bytes,download_bytes) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)',
                                  (str(i), 'collision', i, ts, ip or None, node or None, site or None, up, down))
                    else:
                        c.execute('INSERT INTO `' + name + '` (day_start,latest_ts,source_ip,node,site,upload_bytes,download_bytes) VALUES (%s,%s,%s,%s,%s,%s,%s)',
                                  (i, ts, ip, node, site, up, down))
        c.execute(fixture_latest)
        fixture_max = c.fetchone()[0]
        c.execute(legacy_select(fixture_old, fixture_max))
        fixture_reference = c.fetchall()
        c.execute(fixture_new)
        fixture_candidate = c.fetchall()
        if fixture_candidate != fixture_reference:
            raise ValueError('fixture_display_mismatch:' + repr((len(fixture_reference), len(fixture_candidate), fixture_reference[:2], fixture_candidate[:2])))
        for name in fixture_names:
            c.execute('DELETE FROM `' + name + '`')
        c.execute(fixture_new)
        if c.fetchall():
            raise ValueError('empty_fixture_mismatch')
        for name in fixture_names:
            c.execute('DROP TEMPORARY TABLE `' + name + '`')
        db.rollback()
        result.update(fixture_rows=80, fixture_passed=True, empty_fixture_passed=True)
        c.execute('SET timestamp=0')
        if apply:
            c.execute("SHOW CREATE VIEW `流量汇总`")
            if digest(c.fetchone()[1]) != expected:
                raise ValueError('live_view_changed_before_apply')
            Path(__file__).with_name('previous.sql').write_text(old, encoding='utf8')
            c.execute(summary_ddl())
            c.execute("SHOW CREATE VIEW `流量汇总`")
            applied = c.fetchone()[1]
            result.update(applied=True, view_sha256=digest(applied))
            Path(__file__).with_name('result.json').write_text(json.dumps(result, indent=2), encoding='utf8')
        else:
            result['applied'] = False
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--expected', required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    import pymysql
    db = pymysql.connect(unix_socket='/run/mysqld/mysqld.sock', user='root', database='hk',
                         charset='utf8mb4', autocommit=True, read_timeout=15)
    try:
        print(json.dumps(run(db, args.expected, args.apply), ensure_ascii=True))
    finally:
        db.close()
