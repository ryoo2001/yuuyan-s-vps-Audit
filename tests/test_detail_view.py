"""The detail-view rewrite must return exactly the rows and order of the window definition."""
from pathlib import Path
import random
import re
import sqlite3
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'central'))
import detail_view  # noqa: E402

JP = (ROOT / 'tests/fixtures/jp_detail_view.sql').read_text(encoding='utf-8')
HK = (ROOT / 'tests/fixtures/hk_detail_view.sql').read_text(encoding='utf-8')
# The correlated anti-join text an earlier version stored on a real single-namespace database.
ANTIJOIN = (ROOT / 'tests/fixtures/jp_detail_antijoin.sql').read_text(encoding='utf-8')
NOW = 1794400000
MINUTE = lambda sql: sql.replace(detail_view.BUCKET_5S, detail_view.BUCKET)
STATE = ('connection_id TEXT PRIMARY KEY,start_ts REAL,last_seen REAL,source_peer TEXT,source_port INTEGER,'
         'inbound_port INTEGER,site TEXT,prev_up INTEGER,prev_down INTEGER,flow_id TEXT,source_ip TEXT,node TEXT,'
         'quality TEXT,_seq INTEGER')


def to_sqlite(sql, database, prefixes):
    """Translate the MariaDB text enough for SQLite to execute the same logic."""
    for prefix in prefixes:
        for table in ('connection_state', 'connection_rates', 'entry_routes'):
            sql = sql.replace('`%s`.`%s%s`' % (database, prefix, table), '`%s%s`' % (prefix, table))
    sql = sql.replace('`%s`.`ip_geo`' % database, '`ip_geo`')
    sql = re.sub(r' force index \(`by_detail`\)', '', sql, flags=re.IGNORECASE).replace('lcase(', 'lower(').replace('!exists(', 'not exists(')
    sql = sql.replace('unix_timestamp()', str(NOW))
    sql = re.sub(r"date_format\('1970-01-01 08:00:00' \+ interval floor\(`c`\.`last_seen`\) second,'[^']*'\)",
                 'floor(`c`.`last_seen`)', sql)
    sql = re.sub(r'cast\((round\([^)]*\)) as decimal\(22,2\)\)', r'\1', sql)
    return re.sub(r"concat\(([^()]*)\)", lambda m: '(' + m.group(1).replace(',', '||') + ')', sql)


class DetailViewTests(unittest.TestCase):
    def database(self, prefixes, seed):
        db = sqlite3.connect(':memory:')
        rng = random.Random(seed)
        for prefix in prefixes:
            db.execute('CREATE TABLE `%sconnection_state` (%s)' % (prefix, STATE))
            db.execute('CREATE TABLE `%sconnection_rates` (connection_id TEXT PRIMARY KEY,observed_at REAL,'
                       'interval_seconds REAL,upload_bps REAL,download_bps REAL,_seq INTEGER)' % prefix)
            db.execute('CREATE TABLE `%sentry_routes` (node TEXT,inbound_port INTEGER,tunnel_ip TEXT,_seq INTEGER,'
                       'PRIMARY KEY(node,inbound_port))' % prefix)
            db.execute('INSERT INTO `%sentry_routes` VALUES(?,?,?,1)' % prefix, ('edge-a', 2101, '10.0.0.1'))
            db.execute('INSERT INTO `%sentry_routes` VALUES(?,?,?,1)' % prefix, ('edge-b', 443, None))
            for number in range(900):
                # Dense timestamps on a 0.5 s grid force ties, shared windows and window edges.
                seen = NOW - rng.choice((30, 30, 30, 3600, 600000, 700000)) + rng.randrange(0, 40) / 2
                row = ('c%04d' % rng.randrange(10 ** 6) + str(number), seen - 9, seen,
                       rng.choice(('172.30.3.3', '10.0.0.9')), 4000, rng.choice((2101, 443, None)),
                       rng.choice(('a.test', 'b.test', 'A.test', 'unknown', 'Unknown', '', None)), 1, 2, 'f',
                       rng.choice(('192.0.2.1', '192.0.2.2', '', None)), rng.choice(('edge-a', 'edge-b', 'ghost', '', None)),
                       'q', number)
                db.execute('INSERT INTO `%sconnection_state` VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)' % prefix, row)
                if number % 3:
                    db.execute('INSERT INTO `%sconnection_rates` VALUES(?,?,?,?,?,1)' % prefix,
                               (row[0], seen if number % 2 else seen - 1, rng.choice((5, 3, None)), 1500.0, 2500000.0))
        db.execute('CREATE TABLE ip_geo (source_ip TEXT PRIMARY KEY,location TEXT)')
        return db

    def test_single_namespace_window_over_index_equals_window_definition(self):
        head, route = detail_view.parse_single(JP, 'region-a')
        self.assertEqual(route, detail_view.ROUTE_PLAIN)
        new = detail_view.single_select(head, 'region-a', route)
        self.assertEqual(new.count('force index (`by_detail`)'), 1)
        self.assertNotIn('exists', new)            # no correlated probe: cost does not depend on key skew
        self.assertEqual(new.count(detail_view.HOT), 1)
        self.assertIn(detail_view.BUCKET, new)
        self.assertNotIn(detail_view.BUCKET_5S, new)
        for seed in range(6):
            db = self.database(('',), seed)
            old_rows = db.execute(to_sqlite(MINUTE(JP), 'region-a', ('',))).fetchall()
            new_rows = db.execute(to_sqlite(new, 'region-a', ('',))).fetchall()
            self.assertEqual([row[:5] for row in old_rows], new_rows, seed)
            total = db.execute('SELECT COUNT(*) FROM connection_state WHERE last_seen>=?', (NOW - 172800,)).fetchone()[0]
            self.assertTrue(0 < len(new_rows) < total, 'fixture must exercise both merged and kept rows')

    def test_multi_namespace_rewrite_equals_window_definition(self):
        head, prefixes = detail_view.parse_union(HK, 'hk')
        self.assertEqual(prefixes, ('tb1_', 'tb2_', 'termc_', 'tb3_', 'termb4_'))
        new = detail_view.union_select(head, 'hk', prefixes)
        self.assertNotIn(detail_view.HOT, new)     # visible rows are not narrowed
        for seed in range(3):
            db = self.database(prefixes, seed)
            self.assertEqual([row[:5] for row in db.execute(to_sqlite(MINUTE(HK), 'hk', prefixes)).fetchall()],
                             db.execute(to_sqlite(new, 'hk', prefixes)).fetchall(), seed)

    def test_new_projection_can_be_optimized_without_rate_tables(self):
        projected = detail_view.display_projection(JP)
        head, route = detail_view.parse_single(projected, 'region-a')
        new = detail_view.single_select(head, 'region-a', route)
        self.assertNotIn('connection_rates', new)
        self.assertNotIn('%H:%i:%s', new)
        self.assertIn('%H:%i', new)
        db = self.database(('',), 7)
        db.execute('DROP TABLE connection_rates')
        self.assertEqual(db.execute(to_sqlite(MINUTE(projected), 'region-a', ('',))).fetchall(),
                         db.execute(to_sqlite(new, 'region-a', ('',))).fetchall())

    def test_unreviewed_definitions_are_refused(self):
        for broken in (JP.replace('172800', '86400'), JP.replace("lcase(`c`.`site`) = 'unknown'", '1=0'),
                       JP.replace('`c`.`_session_rank` = 1', '`c`.`_session_rank` <= 2'),
                       JP.replace(' AS `目标网站`', ' AS `网站`'), JP + ' limit 10'):
            with self.assertRaises(ValueError):
                detail_view.parse_single(broken, 'region-a')
        with self.assertRaises(ValueError):
            detail_view.parse_single(HK, 'hk')
        for broken in (HK.replace('from `hk`.`tb3_connection_state`', 'from `hk`.`tb3_connection_state` where 1'),
                       HK.replace("'termb4' AS `source_id` from `hk`.`termb4_entry_routes`", "'termb4' AS `source_id` from `hk`.`tb3_entry_routes`"),
                       HK.replace('partition by `c`.`source_id`,', 'partition by ')):
            with self.assertRaises(ValueError):
                detail_view.parse_union(broken, 'hk')
        with self.assertRaises(ValueError):
            detail_view.parse_union(JP, 'region-a')

    def test_stored_antijoin_is_converted_to_the_window_without_changing_rows(self):
        converted = detail_view.from_antijoin(ANTIJOIN, 'region-a')
        self.assertEqual(converted.count('force index (`by_detail`)'), 1)
        self.assertNotIn('exists', converted)
        # The intermediate version that probed a second index converts the same way.
        intermediate = ANTIJOIN.replace('`d` FORCE INDEX (`by_detail`)', '`d` FORCE INDEX (`by_session`)')
        self.assertNotEqual(intermediate, ANTIJOIN)
        self.assertEqual(detail_view.from_antijoin(intermediate, 'region-a'), converted)
        for seed in range(4):
            db = self.database(('',), seed)
            five = [row[:5] for row in db.execute(to_sqlite(JP, 'region-a', ('',))).fetchall()]
            minute = [row[:5] for row in db.execute(to_sqlite(MINUTE(JP), 'region-a', ('',))).fetchall()]
            self.assertEqual(db.execute(to_sqlite(converted, 'region-a', ('',))).fetchall(), minute, seed)
            # The stored anti-join itself still has the old five-second semantics.
            self.assertEqual(sorted(db.execute(to_sqlite(ANTIJOIN, 'region-a', ('',))).fetchall(), key=repr),
                             sorted(five, key=repr), seed)

    def test_unreviewed_antijoin_is_refused(self):
        for broken in (ANTIJOIN.replace('172800', '86400'), ANTIJOIN.replace(' - 5 ', ' - 6 '),
                       ANTIJOIN.replace(' limit 1)', ' limit 2)'), ANTIJOIN.replace(' AS `目标网站`', ' AS `网站`'),
                       ANTIJOIN + ' limit 10', JP):
            with self.assertRaises(ValueError):
                detail_view.from_antijoin(broken, 'region-a')

    def test_install_rewrites_by_stored_shape_and_leaves_the_window_alone(self):
        class Db:
            def __init__(self, definition):
                self.definition, self.log = definition, []

            def cursor(self):
                return self

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def execute(self, sql, params=None):
                self.log.append(sql)

            def fetchone(self):
                return (self.definition,)

            def fetchall(self):
                return [(name, 'D' if name == 'last_seen' else 'A') for name in detail_view.INDEX_COLUMNS]

        views = lambda db: [sql for sql in db.log if sql.startswith('CREATE OR REPLACE')]
        for stored in (JP, ANTIJOIN):
            db = Db(stored)
            result = detail_view.install(db, 'region-a', ('',))
            self.assertEqual(result, {'indexes_added': [], 'view_rewritten': True})
            self.assertEqual(len(views(db)), 1)
            self.assertIn('row_number()', views(db)[0])
            self.assertEqual(views(db)[0].count('force index (`by_detail`)'), 1)
            again = Db(views(db)[0].split(' AS ', 1)[1])
            self.assertEqual(detail_view.install(again, 'region-a', ('',)),
                             {'indexes_added': [], 'view_rewritten': False})
            self.assertEqual(views(again), [])

    def test_same_key_collapses_to_one_row_per_minute(self):
        head, route = detail_view.parse_single(JP, 'region-a')
        view = to_sqlite(detail_view.single_select(head, 'region-a', route), 'region-a', ('',))
        db = self.database(('',), 1)
        db.execute('DELETE FROM connection_state')
        db.execute("INSERT INTO entry_routes VALUES('edge-a',2101,'10.0.0.1',1) ON CONFLICT DO NOTHING")
        base = (NOW - 3600) // 60 * 60            # start of a minute
        rows = [('m1', base + 1, '192.0.2.1', 'a.test'), ('m2', base + 31, '192.0.2.1', 'a.test'),
                ('m3', base + 59, '192.0.2.1', 'a.test'),     # same minute, 58 s apart: one row
                ('m4', base + 61, '192.0.2.1', 'a.test'),     # next minute: its own row
                ('o1', base + 2, '192.0.2.1', 'b.test'),      # other site: kept
                ('o2', base + 3, '192.0.2.2', 'a.test'),      # other source IP: kept
                ('u1', base + 4, '', 'a.test'), ('u2', base + 5, '', 'a.test')]   # unknown source: never merged
        for cid, seen, ip, site in rows:
            db.execute("INSERT INTO connection_state VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                       (cid, seen - 1, seen, '10.0.0.9', 4000, 2101, site, 1, 2, 'f', ip, 'edge-a', 'q', 1))
        shown = db.execute(view).fetchall()
        self.assertEqual(len(shown), 6)
        same = [row for row in shown if row[1] == '192.0.2.1' and row[4] == 'a.test']
        self.assertEqual(len(same), 2)
        self.assertEqual(db.execute('SELECT COUNT(*) FROM connection_state').fetchone()[0], 8)   # facts untouched

    def test_stored_five_second_view_is_upgraded_to_the_minute_only(self):
        head, route = detail_view.parse_single(JP, 'region-a')
        minute = detail_view.single_select(head, 'region-a', route)
        stored = minute.replace(detail_view.BUCKET, detail_view.BUCKET_5S)
        self.assertEqual(detail_view.upgrade_bucket(stored), minute)
        self.assertIsNone(detail_view.upgrade_bucket(minute))
        head_u, prefixes = detail_view.parse_union(HK, 'hk')
        union_minute = detail_view.union_select(head_u, 'hk', prefixes)
        self.assertEqual(detail_view.upgrade_bucket(union_minute.replace(detail_view.BUCKET, detail_view.BUCKET_5S)),
                         union_minute)
        for broken in (stored + minute,                                    # mixed buckets
                       stored.replace('AS `_session_rank`', 'AS `rank`'),   # a window the upgrade cannot see
                       ANTIJOIN):                                          # no ranking window at all
            with self.assertRaises(ValueError):
                detail_view.upgrade_bucket(broken)

    def test_install_upgrades_an_already_bounded_five_second_view(self):
        class Db:
            def __init__(self, definition):
                self.definition, self.log = definition, []

            def cursor(self):
                return self

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def execute(self, sql, params=None):
                self.log.append(sql)

            def fetchone(self):
                return (self.definition,)

            def fetchall(self):
                return [(name, 'D' if name == 'last_seen' else 'A') for name in detail_view.INDEX_COLUMNS]

        head, route = detail_view.parse_single(JP, 'region-a')
        minute = detail_view.single_select(head, 'region-a', route)
        db = Db(minute.replace(detail_view.BUCKET, detail_view.BUCKET_5S))
        self.assertEqual(detail_view.install(db, 'region-a', ('',)), {'indexes_added': [], 'view_rewritten': True})
        views = [sql for sql in db.log if sql.startswith('CREATE OR REPLACE')]
        self.assertEqual(len(views), 1)
        self.assertTrue(views[0].endswith(minute))
        self.assertEqual(detail_view.upgrade(Db(minute), 'region-a'), {'view_rewritten': False})

    def test_only_the_covering_index_is_created(self):
        class Cursor:
            def __init__(self, log):
                self.log = log

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def execute(self, sql, params=None):
                self.log.append(sql)

            def fetchall(self):
                return []

        class Db:
            def __init__(self):
                self.log = []

            def cursor(self):
                return Cursor(self.log)

        db = Db()
        self.assertTrue(detail_view.ensure_index(db, 'region-a', ''))
        made = [sql for sql in db.log if sql.startswith('ALTER TABLE')]
        self.assertEqual(len(made), 1)
        self.assertIn('ADD INDEX `by_detail`', made[0])
        self.assertNotIn('by_session', made[0])

    def test_view_hot_window_equals_the_raw_retention_policy(self):
        import tier_policy
        self.assertEqual(detail_view.HOT, 'unix_timestamp() - %d' % (tier_policy.RAW_HOT_HOURS * 3600))
        self.assertIn('connection_state', tier_policy.RAW_HOT_TABLES)

    def test_index_matches_display_order_and_identifiers_are_validated(self):
        ddl = detail_view.index_ddl('hk', 'tb3_')
        self.assertIn('`hk`.`tb3_connection_state` ADD INDEX `by_detail` (`last_seen` DESC,`connection_id`,', ddl)
        self.assertIn('ALGORITHM=INPLACE, LOCK=NONE', ddl)
        with self.assertRaises(ValueError):
            detail_view.index_ddl('hk`; DROP', '')
        self.assertTrue(detail_view.view_ddl('hk', 'select 1').startswith(
            'CREATE OR REPLACE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW `hk`.`审计明细` AS '))


if __name__ == '__main__':
    unittest.main()
