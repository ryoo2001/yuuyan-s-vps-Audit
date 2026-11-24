"""Root-only hourly totals fixture in an isolated database; never touches production facts."""
from pathlib import Path
import tempfile
import time
import pymysql
import archive, hourly, region, storage
from model import upsert_sql

DATABASE = 'audit_hourly_test'


def main():
    db = pymysql.connect(unix_socket='/run/mysqld/mysqld.sock', user='root', charset='utf8mb4',
                         autocommit=True, read_timeout=30)
    made = False; checks = []; now = time.time(); hour = int(now // 3600 * 3600)
    def put(kind, event, stamp, seq, up=0, down=0, site='case.test', prefix=''):
        target = storage.table(DATABASE, prefix, kind)
        with db.cursor() as c:
            if kind == 'samples':
                c.execute(upsert_sql('samples').replace('`samples`', target, 1),
                          [event, stamp, 'conn', 'entry', '192.0.2.1', site, up, down, 'fixture', seq])
            else:
                c.execute(upsert_sql('visits').replace('`visits`', target, 1),
                          [event, stamp, 'entry', '192.0.2.1', site, 443, 'tcp', 'flow', 'fixture', seq])
    def row(h, site='case.test', prefix=''):
        with db.cursor() as c:
            c.execute('SELECT upload_bytes,download_bytes,fact_rows,visit_events FROM '
                      + storage.table(DATABASE, prefix, 'traffic_hourly')
                      + ' WHERE hour_start=%s AND source_ip=%s AND node=%s AND site=%s', (h, '192.0.2.1', 'entry', site))
            r = c.fetchone()
        return tuple(int(x) for x in r) if r else None
    try:
        with db.cursor() as c:
            c.execute('SELECT 1 FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=%s', (DATABASE,))
            if c.fetchone(): raise ValueError('existing_hourly_fixture_refused')
        made = True
        region.create_region(db, DATABASE, ('', 'other_'), Path(__file__).with_name('views.sql').read_text())
        with db.cursor() as c: c.execute('USE ' + storage.identifier(DATABASE))
        put('samples', 'pre', hour - 7200 + 5, 1, 100, 200)
        put('visits', 'v-pre', hour - 7200 + 6, 2)
        put('samples', 'old', hour - 3 * 86400 + 5, 3, 4, 4, site='early.test')
        seeded = {p: hourly.install(db, DATABASE, p, chunk=3600) for p in ('', 'other_')}
        assert not any(o['already_installed'] for o in seeded.values()), seeded
        assert seeded['']['chunks'] > 3 and seeded['other_']['groups_seeded'] == 0, seeded
        assert row(hour - 7200) == (100, 200, 1, 1), row(hour - 7200)
        assert row(hour - 3 * 86400, 'early.test') == (4, 4, 1, 0)
        checks.append('chunked_seed_counts_existing_samples_and_visits')
        out = hourly.install(db, DATABASE, '', resume_from=hour - 7200, chunk=3600)
        assert row(hour - 7200) == (100, 200, 1, 1) and row(hour - 3 * 86400, 'early.test') == (4, 4, 1, 0), out
        checks.append('resume_reseeds_only_later_hours')
        assert hourly.install(db, DATABASE, '')['already_installed']
        checks.append('reinstall_is_noop')
        put('samples', 'a', hour + 10, 10, 5, 7); put('samples', 'b', hour + 20, 11, 1, 1)
        assert row(hour) == (6, 8, 2, 0), row(hour)
        checks.append('insert_adds_delta')
        put('samples', 'a', hour + 10, 10, 5, 7); assert row(hour) == (6, 8, 2, 0)
        checks.append('identical_replay_is_noop')
        put('samples', 'a', hour + 10, 12, 50, 70); assert row(hour) == (51, 71, 2, 0), row(hour)
        checks.append('absolute_correction_replaces_old_value')
        put('samples', 'b', hour + 20, 13, 1, 1, site='moved.test')
        assert row(hour) == (50, 70, 1, 0) and row(hour, 'moved.test') == (1, 1, 1, 0)
        checks.append('key_change_moves_bytes_between_groups')
        put('visits', 'v1', hour + 30, 14); put('visits', 'v1', hour + 30, 14)
        assert row(hour)[3] == 1
        checks.append('visit_events_counted_once')
        put('samples', 'x', hour + 40, 15, 9, 9, prefix='other_')
        assert row(hour, prefix='other_') == (9, 9, 1, 0) and row(hour) == (50, 70, 1, 1)
        checks.append('namespaces_isolated')
        with tempfile.TemporaryDirectory(prefix='hourly-fixture-') as directory:
            store = archive.Store(directory)
            out = archive.archive_batch(db, store, DATABASE, '', 'samples', hour - 3600)
            assert out['rows'] == 2, out
            archive.archive_batch(db, store, DATABASE, '', 'visits', hour - 3600)
        assert row(hour - 7200) == (100, 200, 1, 1), row(hour - 7200)
        assert row(hour - 3 * 86400, 'early.test') == (4, 4, 1, 0)
        checks.append('archive_delete_keeps_hourly_totals')
        hourly.verify(db, DATABASE, '', since=hour)
        checks.append('verify_matches_recompute_for_online_hours')
        with db.cursor() as c:
            c.execute('INSERT INTO ' + storage.table(DATABASE, '', 'traffic_hourly')
                      + ' VALUES(%s,%s,%s,%s,1,1,1,0)', (hour - 70 * 86400, '192.0.2.1', 'entry', 'old.test'))
        out = hourly.trim(db, DATABASE, '', now=now)
        assert out['removed'] == 1 and row(hour - 7200) is not None, out
        checks.append('trim_removes_only_expired_hours')
        print({'status': 'ok', 'checks': checks})
    finally:
        if made:
            with db.cursor() as c: c.execute('DROP DATABASE IF EXISTS ' + storage.identifier(DATABASE))
        db.close()


if __name__ == '__main__':
    main()
