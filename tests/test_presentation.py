"""Display, sampling semantics and read-only reader regression tests."""
from datetime import datetime, timezone
import importlib.util
import sqlite3
import tempfile
import time
from pathlib import Path
import unittest

from audit import Store
from presentation import COLUMNS, install

spec = importlib.util.spec_from_file_location("presentation_source_query", Path(__file__).resolve().parents[1] / "query.py")
source_query = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source_query)
details, parse_args, QueryError = source_query.details, source_query.parse_args, source_query.QueryError


class PresentationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.cfg = {
            'node': 'terminal', 'mode': 'terminal', 'db': str(Path(self.temp.name) / 'audit.sqlite'),
            'inbound_ports': [31100, 3310, 3320, 3366, 3380, 3390], 'retention_days': 7,
            'peers': {n: {} for n in ['entry-a0', 'entry-a1', 'entry-a3']},
            'entry_routes': [
                {'node': n, 'inbound_port': port, 'tunnel_ip': ip}
                for n, port, ip in [('entry-a0', 31100, '10.77.250.5'),
                    ('entry-a3', 3310, '10.77.251.2'),
                    ('entry-a1', 3366, '10.77.250.2'), ('entry-a1', 3380, None)]
            ],
        }
        self.store = Store(self.cfg)
        self.now = datetime(2026, 10, 3, 16, 1, 2, tzinfo=timezone.utc).timestamp()
        self.store.audit_start = self.now - 60

    def tearDown(self):
        self.store.db.close()
        self.temp.cleanup()

    def conn(self, up=100, down=200, cid='one'):
        return {'id': cid, 'start': datetime.fromtimestamp(self.now-2, timezone.utc).isoformat(),
                'upload': up, 'download': down,
                'metadata': {'type': 'Mieru', 'inboundPort': '31100', 'sourceIP': '10.77.250.1',
                             'sourcePort': '12345', 'host': 'example.com'}}

    def sample(self, up=100, down=200, offset=0, tick=100):
        self.store.sample([self.conn(up, down)], self.now + offset, monotonic_now=tick)

    def row(self):
        cursor = self.store.db.execute('SELECT * FROM "审计明细"')
        self.assertEqual(tuple(c[0] for c in cursor.description), COLUMNS)
        return tuple(cursor.fetchone())

    def test_column_order_timezone_24h_and_no_ports(self):
        self.sample()
        row = self.row()
        self.assertEqual(row, ('2026/10/04 00:01', '未识别', '未识别', '未识别', 'example.com'))
        self.assertEqual(len(row), 5)
        self.assertNotIn('10.77.250.1', str(row))
        self.assertEqual(self.store.db.execute('SELECT source_port FROM connection_state').fetchone()[0], 12345)

    def test_all_tunnel_addresses_use_proven_node_not_peer(self):
        self.sample()
        for route in [r for r in self.cfg['entry_routes'] if r['tunnel_ip'] is not None]:
            self.store.db.execute('UPDATE connection_state SET source_ip=?,node=?,inbound_port=?',
                                 ('198.51.100.27', route['node'], route['inbound_port']))
            row = self.row()
            self.assertEqual(row[1], '198.51.100.27')
            self.assertEqual(row[3], route['tunnel_ip'] + '（' + route['node'] + '）')

    def test_direct_path_does_not_claim_a_tunnel(self):
        self.sample()
        self.store.db.execute("UPDATE connection_state SET source_ip='198.51.100.27',node='entry-a1',inbound_port=3380")
        self.assertEqual(self.row()[3], '直连（entry-a1；未经过隧道）')

    def test_unknown_route_and_unmatched_source(self):
        self.sample()
        self.store.db.execute("UPDATE connection_state SET source_ip='198.51.100.27',node='unexpected'")
        self.assertEqual(self.row()[3], '未核验（unexpected）')
        self.store.db.execute('UPDATE connection_state SET source_ip=NULL')
        self.assertEqual((self.row()[1], self.row()[3]), ('未识别', '未识别'))

    def test_verified_entry_remains_visible_when_source_is_unknown(self):
        self.sample()
        self.store.db.execute("UPDATE connection_state SET source_ip=NULL,node='entry-a0'")
        self.assertEqual((self.row()[1], self.row()[3]), ('未识别', '10.77.250.5（entry-a0）'))

    def identified_start(self, up=0, down=0):
        self.sample(up=up, down=down)
        self.store.db.execute("UPDATE connection_state SET source_ip='198.51.100.27',node='entry-a0'")
        # Start a fresh, known-IP window at the same synthetic clock.
        self.sample(up=up, down=down)

    def test_rates_use_ip_window_delta_not_total(self):
        self.identified_start(up=90000000, down=80000000)
        self.sample(up=90010000, down=90000000, offset=5, tick=105)
        self.assertEqual(tuple(self.store.db.execute('SELECT upload_bps,download_bps FROM connection_rates').fetchone()), (2000.0, 2000000.0))
        values = self.store.db.execute('SELECT interval_seconds,upload_bps,download_bps FROM connection_rates').fetchone()
        self.assertEqual(tuple(values), (5, 2000.0, 2000000.0))

    def test_unit_threshold_and_zero_are_real_measurements(self):
        self.identified_start()
        self.sample(up=4999995, down=5000000, offset=5, tick=105)
        self.assertEqual(tuple(self.store.db.execute('SELECT upload_bps,download_bps FROM connection_rates').fetchone()), (999999.0, 1000000.0))
        self.sample(up=4999995, down=5000000, offset=10, tick=110)
        self.assertEqual(tuple(self.store.db.execute('SELECT upload_bps,download_bps FROM connection_rates').fetchone()), (0.0, 0.0))

    def test_counter_reset_or_gap_is_not_fabricated_zero(self):
        self.identified_start(up=100, down=200)
        self.sample(up=10, down=20, offset=5, tick=105)
        self.assertEqual(tuple(self.store.db.execute('SELECT upload_bps,download_bps FROM connection_rates').fetchone()), (None, None))
        self.sample(up=100, down=200, offset=20, tick=120)
        self.assertEqual(tuple(self.store.db.execute('SELECT upload_bps,download_bps FROM connection_rates').fetchone()), (None, None))

    def test_restart_and_short_window_do_not_fabricate_rates(self):
        self.identified_start()
        self.sample(up=200, down=400, offset=1, tick=101)
        self.assertEqual(tuple(self.store.db.execute('SELECT upload_bps,download_bps FROM connection_rates').fetchone()), (None, None))
        self.store.db.commit()
        self.store.db.close()
        self.store = Store(self.cfg)
        self.sample(up=600, down=900, offset=4, tick=104)
        self.assertEqual(tuple(self.store.db.execute('SELECT upload_bps,download_bps FROM connection_rates').fetchone()), (None, None))

    def test_unknown_ips_are_not_aggregated(self):
        self.sample()
        self.sample(up=90010000, down=90000000, offset=5, tick=105)
        self.assertEqual(tuple(self.store.db.execute('SELECT upload_bps,download_bps FROM connection_rates').fetchone()), (None, None))

    def test_clock_adjustment_does_not_distort_rate(self):
        self.identified_start()
        self.sample(up=10000, down=20000, offset=-60, tick=105)
        self.assertEqual(tuple(self.store.db.execute('SELECT upload_bps,download_bps FROM connection_rates').fetchone()), (2000.0, 4000.0))

    def test_same_source_multiple_connections_share_aggregate(self):
        self.store.sample([self.conn(0, 0, 'one'), self.conn(0, 0, 'two')], self.now, monotonic_now=99)
        self.store.db.execute("UPDATE connection_state SET source_ip='198.51.100.27',node='entry-a0'")
        self.store.sample([self.conn(0, 0, 'one'), self.conn(0, 0, 'two')], self.now, monotonic_now=100)
        self.store.sample([self.conn(10000, 20000, 'one'), self.conn(15000, 30000, 'two')], self.now+5, monotonic_now=105)
        rates = self.store.db.execute('SELECT upload_bps,download_bps FROM connection_rates ORDER BY connection_id').fetchall()
        self.assertEqual([tuple(r) for r in rates], [(5000.0, 10000.0)]*2)
        # Aggregation must not multiply the persisted application payload.
        totals = self.store.db.execute('SELECT SUM(upload_bytes),SUM(download_bytes) FROM samples').fetchone()
        self.assertEqual(tuple(totals), (25000, 50000))

    def test_legacy_rates_invalidated_once_without_deleting_facts(self):
        self.sample()
        self.store.db.execute("DELETE FROM meta WHERE key='rate_basis'")
        self.store.db.execute("UPDATE connection_rates SET interval_seconds=0.5,upload_bps=10,download_bps=20")
        self.store.db.commit(); self.store.db.close()
        self.store = Store(self.cfg)
        row = self.store.db.execute('SELECT interval_seconds,upload_bps,download_bps FROM connection_rates').fetchone()
        self.assertEqual(tuple(row), (None, None, None))
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM connection_state').fetchone()[0], 1)

    def test_upgrade_legacy_records_and_install_idempotence(self):
        self.sample()
        self.store.db.execute('DELETE FROM connection_rates')
        install(self.store.db, self.cfg)
        install(self.store.db, self.cfg)
        self.assertEqual(len(self.row()), 5)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM connection_state').fetchone()[0], 1)

    def test_retention_prunes_rates_with_parent_connection(self):
        self.sample()
        self.store.prune(self.now + 7*86400 + 1)
        self.assertEqual(self.store.db.execute('SELECT count(*) FROM connection_rates').fetchone()[0], 0)

    def test_detail_view_merges_same_source_site_and_entry_within_five_seconds(self):
        first = self.conn(cid='one')
        second = self.conn(cid='two')
        self.store.sample([first, second], self.now, monotonic_now=100)
        self.store.db.execute(
            "UPDATE connection_state SET source_ip='198.51.100.27',node='entry-a0',inbound_port=31100"
        )
        self.store.sample([first, second], self.now + 1, monotonic_now=101)
        raw_count = self.store.db.execute(
            "SELECT COUNT(*) FROM connection_state WHERE source_ip='198.51.100.27'"
        ).fetchone()[0]
        visible = self.store.db.execute('SELECT * FROM "审计明细"').fetchall()
        self.assertEqual(raw_count, 2)
        self.assertEqual(len(visible), 1)
        self.assertEqual(visible[0][1], '198.51.100.27')
        self.assertEqual(visible[0][4], 'example.com')

    def test_month_summary_view_groups_source_site_and_adapts_mb_gb(self):
        stamp = int(time.time()) - 60
        self.store.db.executemany(
            'INSERT INTO samples VALUES(?,?,?,?,?,?,?,?,?)',
            [
                ('summary-a', stamp - 60, 'a', 'entry-a0', '198.51.100.10',
                 'same.example', 600000, 400000, None),
                ('summary-b', stamp, 'b', 'entry-a0', '198.51.100.10',
                 'same.example', 500000, 500000, None),
                ('summary-c', stamp, 'c', 'entry-a0', '198.51.100.11',
                 'large.example', 1500000000, 0, None),
            ],
        )
        self.store.db.execute("INSERT INTO ip_geo VALUES('198.51.100.10','江苏省-南京市 电信','matched',0)")
        rows = self.store.db.execute('SELECT * FROM "流量汇总"').fetchall()
        self.assertEqual(tuple(c[0] for c in self.store.db.execute('SELECT * FROM "流量汇总"').description),
                         ('时间', '源 IP', 'IP归属地', '入口机器', '目标网站', '流量统计'))
        by_site = {row[4]: row for row in rows}
        self.assertEqual(by_site['same.example'][5], '2.00 MB')
        self.assertEqual(by_site['large.example'][5], '1.50 GB')
        self.assertRegex(by_site['same.example'][0], r'^\d{4}/\d{2}/01–\d{4}/\d{2}/\d{2}$')
        self.assertTrue(by_site['same.example'][0].startswith(
            datetime.fromtimestamp(time.time() + 8 * 3600, timezone.utc).strftime('%Y/%m/01–')))
        self.assertEqual(len(rows), 2)
        self.assertEqual(by_site['same.example'][2], '江苏省-南京市 电信')
        self.assertEqual(by_site['large.example'][2], '未查询')

    def test_month_summary_keeps_folded_bytes_after_raw_retention(self):
        # Keep both samples in the current Beijing month, even near month start.
        now = time.time()
        beijing_now = datetime.fromtimestamp(now + 8 * 3600, timezone.utc)
        month_start = beijing_now.replace(day=1, hour=0, minute=0, second=0, microsecond=0).timestamp() - 8 * 3600
        elapsed = now - month_start
        self.store.config['retention_days'] = elapsed / (3 * 86400)
        old = now - elapsed * 2 / 3
        self.store.db.execute(
            'INSERT INTO samples VALUES(?,?,?,?,?,?,?,?,?)',
            ('expired', old, 'expired-connection', 'entry-a0', '198.51.100.10',
             'folded.example', 600000, 400000, 'matched'))
        self.store.db.execute(
            'INSERT INTO samples VALUES(?,?,?,?,?,?,?,?,?)',
            ('live', now - elapsed / 6, 'live-connection', 'entry-a0', '198.51.100.10',
             'folded.example', 500000, 500000, 'matched'))
        self.store.db.commit()
        before = self.store.db.execute(
            'SELECT "流量统计" FROM "流量汇总" WHERE "目标网站"=?', ('folded.example',)
        ).fetchone()[0]
        self.store.prune(now)
        after = self.store.db.execute(
            'SELECT "流量统计" FROM "流量汇总" WHERE "目标网站"=?', ('folded.example',)
        ).fetchone()[0]
        self.assertEqual(before, '2.00 MB')
        self.assertEqual(after, before)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM samples WHERE event_id=?', ('expired',)).fetchone()[0], 0)
        self.assertEqual(self.store.db.execute('SELECT SUM(upload_bytes+download_bytes) FROM traffic_rollup').fetchone()[0], 1000000)
        # Re-running retention must not add the folded row a second time.
        self.store.prune(now + 60)
        self.assertEqual(self.store.db.execute(
            'SELECT "流量统计" FROM "流量汇总" WHERE "目标网站"=?', ('folded.example',)
        ).fetchone()[0], before)

    def test_readonly_query_uses_same_display_and_filters(self):
        self.sample()
        self.store.db.execute("UPDATE connection_state SET source_ip='198.51.100.27',node='entry-a0'")
        self.store.db.commit()
        before = self.store.db.total_changes
        args = parse_args(['details', '--source-ip', '198.51.100.27', '--domain', 'EXAMPLE.COM.'])
        out = details(self.cfg, args, self.now)
        self.assertEqual(list(out['rows'][0].values()), list(self.row()))
        self.assertEqual(out['timezone'], 'Asia/Shanghai')
        self.assertEqual(out['time_basis'], 'last_observed')
        self.assertEqual(out['deduplication']['window_seconds'], 5)
        self.assertEqual(out['deduplication']['basis'], 'source_ip_site_entry_fixed_window')
        self.assertFalse(out['has_more'])
        self.assertEqual(before, self.store.db.total_changes)
        out = details(self.cfg, parse_args(['details', '--source-ip', '198.51.100.99']), self.now)
        self.assertEqual(out['rows'], [])

    def test_query_is_latest_first_and_has_more(self):
        self.sample()
        self.store.sample([self.conn(cid='two')], self.now+1, monotonic_now=101)
        out = details(self.cfg, parse_args(['details', '--limit', '1']), self.now+1)
        self.assertTrue(out['has_more'])
        self.assertEqual(out['rows'][0]['时间'], '2026/10/04 00:01')

    def test_invalid_parameters_and_no_database_creation(self):
        for args in [['--limit', '0'], ['--limit', '101'], ['--limit', '1;DROP'], ['--limit', '1', '--limit', '2'], ['--source-ip', '10.0.0.1:80']]:
            with self.assertRaises(QueryError):
                parse_args(['details'] + args)
        missing = dict(self.cfg, db=str(Path(self.temp.name) / 'missing.sqlite'))
        with self.assertRaises(QueryError):
            details(missing, parse_args(['details']), self.now)
        self.assertFalse(Path(missing['db']).exists())
        with self.assertRaises(QueryError):
            details(dict(self.cfg, mode='edge'), parse_args(['details']), self.now)

    def test_minute_display_keeps_five_second_sessions_without_rate_reads(self):
        self.sample()
        self.store.db.execute("UPDATE connection_state SET source_ip='198.51.100.27',node='entry-a0'")
        self.store.sample([self.conn(cid='two')], self.now+10, monotonic_now=110)
        self.store.db.execute("UPDATE connection_state SET source_ip='198.51.100.27',node='entry-a0'")
        self.store.db.execute('DROP TABLE connection_rates')
        rows = self.store.db.execute('SELECT * FROM "审计明细"').fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual([row[0] for row in rows], ['2026/10/04 00:01'] * 2)

    def test_route_config_validation(self):
        invalid = dict(self.cfg, entry_routes=[{'node':'not-a-peer','inbound_port':31100,'tunnel_ip':'10.0.0.2'}])
        with self.assertRaises(ValueError):
            install(self.store.db, invalid)


if __name__ == '__main__':
    unittest.main()
