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
NOW = 1794400000
STATE = ('connection_id TEXT PRIMARY KEY,start_ts REAL,last_seen REAL,source_peer TEXT,source_port INTEGER,'
         'inbound_port INTEGER,site TEXT,prev_up INTEGER,prev_down INTEGER,flow_id TEXT,source_ip TEXT,node TEXT,'
         'quality TEXT,_seq INTEGER')


def to_sqlite(sql, database, prefixes):
    """Translate the MariaDB text enough for SQLite to execute the same logic."""
    for prefix in prefixes:
        for table in ('connection_state', 'connection_rates', 'entry_routes'):
            sql = sql.replace('`%s`.`%s%s`' % (database, prefix, table), '`%s%s`' % (prefix, table))
    sql = sql.replace(' force index (`by_detail`)', '').replace('lcase(', 'lower(')
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
        return db

    def test_single_namespace_antijoin_equals_window_definition(self):
        head, route = detail_view.parse_single(JP, 'region-a')
        self.assertEqual(route, detail_view.ROUTE_PLAIN)
        new = detail_view.single_select(head, 'region-a', route)
        self.assertNotIn('row_number', new)
        self.assertEqual(new.count('force index (`by_detail`)'), 2)
        for seed in range(6):
            db = self.database(('',), seed)
            old_rows = db.execute(to_sqlite(JP, 'region-a', ('',))).fetchall()
            new_rows = db.execute(to_sqlite(new, 'region-a', ('',))).fetchall()
            self.assertEqual(old_rows, new_rows, seed)
            total = db.execute('SELECT COUNT(*) FROM connection_state WHERE last_seen>=?', (NOW - 604800,)).fetchone()[0]
            self.assertTrue(0 < len(new_rows) < total, 'fixture must exercise both merged and kept rows')

    def test_multi_namespace_rewrite_equals_window_definition(self):
        head, prefixes = detail_view.parse_union(HK, 'hk')
        self.assertEqual(prefixes, ('tb1_', 'tb2_', 'termc_', 'tb3_', 'termb4_'))
        new = detail_view.union_select(head, 'hk', prefixes)
        self.assertNotIn(detail_view.HOT, new)     # visible rows are not narrowed
        for seed in range(3):
            db = self.database(prefixes, seed)
            self.assertEqual(db.execute(to_sqlite(HK, 'hk', prefixes)).fetchall(),
                             db.execute(to_sqlite(new, 'hk', prefixes)).fetchall(), seed)

    def test_unreviewed_definitions_are_refused(self):
        for broken in (JP.replace('604800', '86400'), JP.replace("lcase(`c`.`site`) = 'unknown'", '1=0'),
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
