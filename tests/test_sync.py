"""Regression coverage for compressed, 60-second central synchronization."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.append(str(ROOT / 'central'))
from audit import Store
import publish
import query as source_query

spec = importlib.util.spec_from_file_location('central_query_for_sync_tests', ROOT / 'central/query.py')
central_query = importlib.util.module_from_spec(spec)
with patch.dict(sys.modules, {'source_query': source_query}):
    spec.loader.exec_module(central_query)


class PublisherCadenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = Store({'node': 'term-a2', 'mode': 'terminal',
                            'db': str(self.root / 'audit.sqlite'), 'inbound_ports': []})
        self.db = self.store.db
        self.epoch = publish.setup(self.db)

    def tearDown(self):
        self.db.close()
        self.temp.cleanup()

    def add_samples(self, count):
        with self.db:
            self.db.executemany('INSERT INTO samples VALUES(?,?,?,?,?,?,?,?,?)',
                                [(f's-{i}', 1000 + i * .5, 'connection', 'edge',
                                  '198.51.100.1', 'example.test', i + 1, 2, 'matched')
                                 for i in range(count)])

    def run_one_cycle(self):
        sent = []
        def ingest(db, payload):
            sent.append(json.dumps(payload, separators=(',', ':')).encode())
        fcntl = types.SimpleNamespace(flock=MagicMock(), LOCK_EX=2, LOCK_NB=4)
        with patch.dict(sys.modules, {'fcntl': fcntl}), \
             patch.object(publish, 'open', create=True) as lock_open, \
             patch.object(publish.sqlite3, 'connect', return_value=self.db), \
             patch.object(publish, 'central_connect', return_value=MagicMock()) as central_connect, \
             patch.object(publish, 'ingest', side_effect=ingest), \
             patch.object(publish, 'prune', return_value=0), \
             patch.object(publish, 'trim_cache', return_value=0), \
             patch.object(publish, 'HEALTH', self.root / 'health.json'), \
             patch.object(publish.time, 'sleep', side_effect=RuntimeError('end-cycle')) as sleep:
            with self.assertRaisesRegex(RuntimeError, 'end-cycle'):
                publish.run()
            self.assertEqual(central_connect.call_count, 1)
            self.assertEqual(lock_open.call_count, 1)
            health = json.loads((self.root / 'health.json').read_text())
            self.assertIsNone(health['last_error'])
            return json.loads(sent[0]), sleep.call_args.args[0], health

    def test_normal_batch_waits_sixty_seconds_without_dropping_samples(self):
        self.add_samples(60)
        payload, pause, health = self.run_one_cycle()
        self.assertEqual(pause, 60)
        self.assertEqual(len(payload['rows']), 60)
        self.assertEqual(sum(row[2][6] for row in payload['rows']), sum(range(1, 61)))
        self.assertEqual(health['queued'], 0)

    def test_empty_batch_keeps_sixty_second_heartbeat(self):
        payload, pause, health = self.run_one_cycle()
        self.assertEqual(payload['rows'], [])
        self.assertEqual(pause, 60)
        self.assertEqual(health['batches'], 1)

    def test_full_batch_drains_without_sixty_second_backlog_delay(self):
        self.add_samples(205)
        payload, pause, health = self.run_one_cycle()
        self.assertEqual(len(payload['rows']), 200)
        self.assertEqual(pause, .05)
        self.assertEqual(health['queued'], 5)
        self.assertEqual(len(publish.batch(self.db, self.epoch)[0]['rows']), 5)

    def test_new_updates_wait_for_next_flush_boundary(self):
        self.add_samples(2)
        boundary = self.db.execute('SELECT MAX(id) FROM central_dirty').fetchone()[0]
        with self.db:
            self.db.execute("UPDATE samples SET upload_bytes=99 WHERE event_id='s-0'")
        payload, encoded = publish.batch(self.db, self.epoch, through=boundary)
        self.assertEqual([row[2][0] for row in payload['rows']], ['s-1'])
        publish.acknowledge(self.db, payload, encoded,
                            {'ok': True, 'through': payload['through'],
                             'digest': hashlib.sha256(encoded).hexdigest()})
        self.assertIsNone(self.db.execute('SELECT 1 FROM central_dirty WHERE id<=?',(boundary,)).fetchone())
        pending, _ = publish.batch(self.db, self.epoch)
        self.assertEqual(pending['rows'][0][2][6],99)

    def test_lost_ack_replays_same_payload_and_preserves_newer_update(self):
        self.add_samples(1)
        sent=[]
        def ingest(db,payload):
            data=json.dumps(payload,separators=(',',':')).encode(); sent.append(data)
            if len(sent)==1:
                with self.db:self.db.execute("UPDATE samples SET upload_bytes=99 WHERE event_id='s-0'")
                raise TimeoutError('fixture')
        def pause(seconds):
            if seconds>=60:raise RuntimeError('done')
        fcntl=types.SimpleNamespace(flock=MagicMock(),LOCK_EX=2,LOCK_NB=4)
        with patch.dict(sys.modules,{'fcntl':fcntl}), \
             patch.object(publish,'open',create=True), \
             patch.object(publish.sqlite3,'connect',return_value=self.db), \
             patch.object(publish,'central_connect',return_value=MagicMock()), \
             patch.object(publish,'ingest',side_effect=ingest), \
             patch.object(publish,'prune',return_value=0), \
             patch.object(publish,'trim_cache',return_value=0), \
             patch.object(publish,'HEALTH',self.root/'health.json'), \
             patch.object(publish.time,'sleep',side_effect=pause):
            with self.assertRaisesRegex(RuntimeError,'done'):publish.run()
        self.assertEqual(sent[0],sent[1])
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM central_dirty').fetchone()[0],1)


class CentralFreshnessTests(unittest.TestCase):
    def health(self, sync_age=31, peer_age=35, count=3, missing=0, retired=False):
        now = 10000
        db = MagicMock()
        cursor = db.cursor.return_value.__enter__.return_value
        cursor.fetchall.side_effect = [
            [('term-a1', now - sync_age, missing)],
            [(node, now - peer_age, '{}') for node in central_query.ACTIVE_EDGE_NODES[:count]]
              + ([('retired-edge', 1, '{}')] if retired else []),
        ]
        with patch.object(central_query, 'connect', return_value=db), \
             patch.object(central_query.time, 'time', return_value=now):
            result = central_query.run(types.SimpleNamespace(command='health'))
        db.rollback.assert_called_once()
        db.close.assert_called_once()
        return result

    def retired_health(self, live_age, retired=('old/gone',)):
        now = 10000
        db = MagicMock()
        cursor = db.cursor.return_value.__enter__.return_value
        cursor.fetchall.side_effect = [
            [('term-a1', now - live_age, 0), ('old/gone', now - 2000000, 0)],
            [(node, now - 5, '{}') for node in central_query.ACTIVE_EDGE_NODES],
        ]
        with patch.object(central_query, 'connect', return_value=db),              patch.object(central_query, 'PUBLISHERS', ('term-a1', 'old/gone')),              patch.object(central_query, 'RETIRED_PUBLISHERS', retired),              patch.object(central_query.time, 'time', return_value=now):
            return central_query.run(types.SimpleNamespace(command='health'))

    def test_retired_publisher_does_not_mask_or_cause_degraded(self):
        out = self.retired_health(30)
        self.assertEqual(out['status'], 'ok')
        self.assertEqual(out['metrics']['retired_publishers'], ['old/gone'])
        self.assertEqual(out['metrics']['sync_age_seconds'], 30)
        self.assertEqual(out['metrics']['sync_age_seconds_by_publisher']['old/gone'], 2000000)
        # an active publisher going stale is still reported
        stale = self.retired_health(91)
        self.assertEqual(stale['status'], 'degraded')
        self.assertIn('central_sync_stale_or_missing', stale['warnings'])
        # without the explicit retired list the old behaviour is unchanged
        self.assertEqual(self.retired_health(30, retired=())['status'], 'degraded')

    def test_normal_batch_delay_is_not_a_false_alarm(self):
        self.assertEqual(self.health()['status'], 'ok')
        self.assertEqual(self.health(sync_age=90, peer_age=90)['status'], 'ok')

    def test_missing_upload_is_still_reported(self):
        out = self.health(sync_age=90.001)
        self.assertEqual(out['status'], 'degraded')
        self.assertIn('central_sync_stale_or_missing', out['warnings'])

    def test_stale_or_absent_probe_is_still_reported(self):
        for kwargs in ({'peer_age': 90.001}, {'count': 2}):
            with self.subTest(**kwargs):
                out = self.health(**kwargs)
                self.assertEqual(out['status'], 'degraded')
                self.assertIn('edge_telemetry_stale_or_missing', out['warnings'])

    def test_missing_rows_remain_an_error(self):
        out = self.health(missing=1)
        self.assertEqual(out['status'], 'degraded')
        self.assertIn('publisher_missing_rows_observed', out['warnings'])

    def test_retired_peer_history_does_not_trigger_active_health_alarm(self):
        out = self.health(retired=True)
        self.assertEqual(out['status'], 'ok')
        self.assertNotIn('retired-edge', out['metrics']['peers'])
        self.assertEqual(self.health(count=2, retired=True)['status'], 'degraded')


class CentralDetailReadTests(unittest.TestCase):
    def row(self, connection_id, last_seen, site='example.test', source='198.51.100.1'):
        return (connection_id, last_seen, '172.30.3.3', 35800, site, source, 'entry-a4',
                'entry-a4', '10.77.250.4', None)

    def test_reader_deduplicates_fixed_window_and_keeps_latest(self):
        cursor = MagicMock()
        cursor.fetchall.return_value = [
            self.row('new', 105.0), self.row('old', 104.0),
            self.row('other', 100.0, site='other.test'),
        ]
        args = types.SimpleNamespace(limit=2, source_ip=None, domain=None)
        rows = central_query._read_details(cursor, args)
        self.assertNotIn('connection_rates', cursor.execute.call_args.args[0])
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][0], '1970/01/01 08:01')
        self.assertEqual(cursor.execute.call_count, 1)

    def test_reader_stops_after_enough_ordered_rows(self):
        cursor = MagicMock()
        cursor.fetchall.return_value = [self.row(str(i), 1000.0 - i * 10) for i in range(60)]
        args = types.SimpleNamespace(limit=50, source_ip=None, domain=None)
        rows = central_query._read_details(cursor, args)
        self.assertEqual(len(rows), 51)
        self.assertEqual(cursor.execute.call_count, 1)


if __name__ == '__main__':
    unittest.main()
