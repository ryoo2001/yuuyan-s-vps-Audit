"""Preserve facts while bounding steady-state audit work."""
from datetime import datetime, timezone
import hashlib
import tempfile
import time
import unittest
import sys
from pathlib import Path
from unittest.mock import patch
import uuid

from audit import Audit, Store
from maintenance import delete_batches
sys.path.append(str(Path(__file__).resolve().parents[1]/'central'))
import publish


class SamplingWorkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store({'mode': 'terminal', 'node': 'term-a2', 'inbound_ports': [35800],
                            'db': str(Path(self.temp.name) / 'audit.sqlite')})
        self.now = time.time() + 1

    def tearDown(self):
        self.store.db.close()
        self.temp.cleanup()

    def connections(self, count=1000, up=0):
        return [{'id': str(i), 'start': datetime.fromtimestamp(self.now, timezone.utc).isoformat(),
                 'upload': up, 'download': up * 2,
                 'metadata': {'type': 'Mieru', 'inboundPort': '35800', 'sourceIP': '10.77.250.4',
                              'sourcePort': str(10000+i), 'host': 'example.test'}} for i in range(count)]

    def test_idle_thousand_connections_do_not_rewrite_every_poll(self):
        connections = self.connections()
        self.store.sample(connections, self.now, monotonic_now=100)
        first = self.store.sample_stats['sampler_state_writes']
        for i in range(1, 20):
            self.store.sample(connections, self.now+i*.5, monotonic_now=100+i*.5)
        self.assertEqual(self.store.sample_stats['sampler_state_writes'], first)
        self.assertEqual(self.store.sample_stats['sampler_rate_writes'], first)
        self.assertLessEqual(self.store.sample_stats['sampler_flow_queries'], 5000)
        self.store.sample(connections, self.now+10, monotonic_now=110)
        self.assertEqual(self.store.sample_stats['sampler_state_writes'], first+1000)

    def test_active_deltas_and_disconnected_cache_remain_correct(self):
        self.store.sample(self.connections(100), self.now, monotonic_now=100)
        for i in range(1, 21):
            self.store.sample(self.connections(100, i*10), self.now+i*.5, monotonic_now=100+i*.5)
        row = self.store.db.execute('SELECT SUM(upload_bytes),SUM(download_bytes) FROM samples').fetchone()
        self.assertEqual(tuple(row), (20000, 40000))
        self.store.sample([], self.now+11, monotonic_now=111)
        self.assertFalse(self.store.state_cache)
        self.assertFalse(self.store.lookup_checks)

    def test_write_failure_does_not_advance_cached_counter_baseline(self):
        self.store.sample(self.connections(1), self.now, monotonic_now=100)
        self.store.db.execute("CREATE TRIGGER reject_sample BEFORE INSERT ON samples BEGIN SELECT RAISE(ABORT,'fixture'); END")
        with self.assertRaises(Exception):
            self.store.sample(self.connections(1, 20), self.now+.5, monotonic_now=100.5)
        self.store.db.execute('DROP TRIGGER reject_sample')
        self.store.sample(self.connections(1, 30), self.now+1, monotonic_now=101)
        row = self.store.db.execute('SELECT SUM(upload_bytes),SUM(download_bytes) FROM samples').fetchone()
        self.assertEqual(tuple(row), (30, 60))

    def test_frozen_hot_key_is_sent_and_concurrent_update_survives_ack(self):
        self.store.sample(self.connections(1), self.now, monotonic_now=100)
        epoch = publish.setup(self.store.db)
        boundary = publish.snapshot_keys(self.store.db)
        self.store.sample(self.connections(1, 20), self.now+.5, monotonic_now=100.5)
        payload, encoded = publish.batch(self.store.db, epoch, through=boundary)
        states = [row for row in payload['rows'] if row[1]=='connection_state']
        self.assertEqual(states[0][2][7], 20)
        publish.acknowledge(self.store.db, payload, encoded,
                            {'ok': True, 'through': payload['through'],
                             'digest': hashlib.sha256(encoded).hexdigest()})
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM temp.flush_keys').fetchone()[0], 0)
        self.assertGreater(self.store.db.execute('SELECT COUNT(*) FROM central_dirty').fetchone()[0], 0)

    def test_maintenance_commits_bounded_fold_before_deletion(self):
        stamp = self.now-8*86400
        with self.store.db:
            self.store.db.executemany('INSERT INTO samples VALUES(?,?,?,?,?,?,?,?,?)',
                [(str(i),stamp,'c','edge','192.0.2.1','example.test',1,2,'test') for i in range(1201)])
        calls = []
        self.store.db.set_trace_callback(calls.append)
        self.assertEqual(delete_batches(self.store.db,'samples','ts<?',(self.now-7*86400,),fold_samples=True),1201)
        self.assertGreaterEqual(sum(sql=='COMMIT' for sql in calls),3)
        row=self.store.db.execute('SELECT SUM(upload_bytes),SUM(download_bytes) FROM traffic_rollup').fetchone()
        self.assertEqual(tuple(row),(1201,2402))
        self.assertEqual(delete_batches(self.store.db,'samples','ts<?',(self.now-7*86400,),fold_samples=True),0)

    def terminal_event(self, port=10000):
        return {'type':'flow_open','transport':'tcp','src_ip':'10.77.250.4','src_port':port,
                'dst_ip':'10.77.250.1','dst_port':35800,'flow_id':'flow-'+str(port),
                'capture_ts':self.now,'coverage':'syn'}

    def test_late_flow_invalidates_only_its_lookup(self):
        self.store.sample(self.connections(1),self.now,monotonic_now=100)
        event=self.terminal_event()
        self.store.ingest('terminal',[{'event_id':str(uuid.uuid4()),'event':event}],self.now,self.now,'terminal')
        self.store.sample(self.connections(1),self.now+.5,monotonic_now=100.5)
        self.assertEqual(self.store.db.execute('SELECT flow_id FROM connection_state').fetchone()[0],'terminal/flow-10000')

    def test_unrelated_flows_do_not_defeat_negative_cache_or_grow_it(self):
        self.store.sample(self.connections(1),self.now,monotonic_now=100)
        events=[{'event_id':str(uuid.uuid4()),'event':self.terminal_event(port)} for port in range(11000,11100)]
        self.store.ingest('terminal',events,self.now,self.now,'terminal')
        self.store.sample(self.connections(1),self.now+.5,monotonic_now=100.5)
        self.assertEqual(self.store.sample_stats['sampler_flow_queries'],1)
        self.assertEqual(len(self.store.flow_versions),1)

    def test_failure_after_fold_leaves_raw_and_rollup_consistent(self):
        with self.store.db:
            self.store.db.execute("INSERT INTO samples VALUES('old',?,'c','edge','192.0.2.1','example.test',10,20,'test')",(self.now-8*86400,))
            self.store.db.execute("CREATE TRIGGER fail_delete BEFORE DELETE ON samples BEGIN SELECT RAISE(ABORT,'fixture'); END")
        with self.assertRaises(Exception):
            delete_batches(self.store.db,'samples','ts<?',(self.now-7*86400,),fold_samples=True)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM samples').fetchone()[0],1)
        self.assertEqual(self.store.db.execute('SELECT COUNT(*) FROM traffic_rollup').fetchone()[0],0)


class ControllerCacheTests(unittest.TestCase):
    def test_unchanged_config_is_cached_and_changes_are_revalidated(self):
        with tempfile.TemporaryDirectory() as root:
            config = Path(root)/'mihomo.yaml'
            config.write_text('test')
            access = ('http://127.0.0.1:9090/connections','fixture')
            with patch('audit.controller_config',return_value=access) as parse:
                a = Audit({'mode':'terminal','node':'test','db':str(Path(root)/'audit.sqlite'),
                           'inbound_ports':[], 'mihomo_config':str(config)})
                try:
                    for _ in range(100):self.assertEqual(a.controller_access(),access)
                    self.assertEqual(parse.call_count,1)
                    config.write_text('changed')
                    a.controller_access()
                    self.assertEqual(parse.call_count,2)
                    config.write_text('invalid-change')
                    parse.side_effect = ValueError('loopback required')
                    with self.assertRaises(ValueError):a.controller_access()
                    self.assertIsNone(a.controller_cache)
                finally:a.store.db.close()


if __name__ == '__main__':
    unittest.main()
