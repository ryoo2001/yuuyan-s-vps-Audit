import unittest,tempfile,time,uuid,sqlite3
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from audit import Store,validate_event

class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.now=time.time()
        self.cfg={'node':'terminal','mode':'terminal','db':str(Path(self.tmp.name)/'audit.sqlite'),'inbound_ports':[3320],'retention_days':7,'max_db_mb':8,'port_aliases':{}}
        self.s=Store(self.cfg)
    def tearDown(self):
        self.s.db.close(); self.tmp.cleanup()
    def event(self,typ='flow_open',source='10.0.0.2',fid='t',**kw):
        return dict(type=typ,transport='tcp',src_ip=source,src_port=1234,dst_ip='10.0.0.1',dst_port=3320,flow_id=fid,capture_ts=self.now,**kw)
    def ingest(self,node,kind,e,eid=None):
        self.s.ingest(node,[{'event_id':eid or str(uuid.uuid4()),'event':e}],self.now,self.now,kind)
    def conn(self,id='one',up=100,down=200):
        from datetime import datetime,timezone
        return {'id':id,'start':datetime.fromtimestamp(self.now+0.1,timezone.utc).isoformat(),'upload':up,'download':down,'metadata':{'type':'Mieru','inboundPort':'3320','sourceIP':'10.0.0.2','sourcePort':'1234','host':'example.com'}}
    def test_pair_late_and_counters_idempotent(self):
        self.ingest('terminal','terminal',self.event(coverage='syn'))
        self.ingest('terminal','terminal',self.event('fingerprint',fingerprint='a'*64))
        self.s.sample([self.conn()],self.now+1)
        self.ingest('edge','edge',self.event('fingerprint',source='198.51.100.1',fid='e',fingerprint='a'*64))
        self.s.sample([self.conn(up=120,down=230)],self.now+2)
        self.s.sample([self.conn(up=120,down=230)],self.now+3)
        r=self.s.db.execute('select sum(upload_bytes),sum(download_bytes),min(source_ip),min(node) from samples').fetchone()
        self.assertEqual(tuple(r),(120,230,'198.51.100.1','edge'))

    def test_existing_tcp_connection_rebinds_only_to_verified_active_midstream(self):
        self.cfg['tcp_stream_recovery'] = True
        self.s.inbound_types[3320] = frozenset(['ShadowSocks'])
        connection = self.conn()
        connection['metadata'].update(type='ShadowSocks', network='tcp')
        self.ingest('terminal', 'terminal', self.event(coverage='syn'))
        self.s.sample([connection], self.now + 1, monotonic_now=1)
        later = self.event(fid='restart', coverage='midstream')
        later['capture_ts'] = self.now + 100
        self.ingest('terminal', 'terminal', later)
        digest = 'd' * 64
        later.update(type='fingerprint', fingerprint=digest)
        self.ingest('terminal', 'terminal', later)
        self.s.sample([connection], self.now + 101, monotonic_now=101)
        self.assertIsNone(self.s.db.execute('SELECT source_ip FROM connection_state').fetchone()[0])
        self.ingest('edge', 'edge', self.event('fingerprint', source='198.51.100.1', fid='edge-current', fingerprint=digest))
        self.s.sample([connection], self.now + 102, monotonic_now=102)
        row = self.s.db.execute('SELECT source_ip,node,flow_id FROM connection_state').fetchone()
        self.assertEqual(tuple(row), ('198.51.100.1', 'edge', 'terminal/restart'))
        self.assertEqual(tuple(self.s.db.execute('SELECT SUM(upload_bytes),SUM(download_bytes) FROM samples').fetchone()), (100, 200))

    def test_midstream_recovery_is_opt_in_and_rejects_ambiguous_candidates(self):
        self.s.inbound_types[3320] = frozenset(['ShadowSocks'])
        connection = self.conn()
        connection['metadata'].update(type='ShadowSocks', network='tcp')
        for i in range(2):
            event = self.event('fingerprint', fid='later' + str(i), fingerprint=str(i) * 64)
            event['capture_ts'] = self.now + 100
            event['type'] = 'flow_open'
            event['coverage'] = 'midstream'
            self.ingest('terminal', 'terminal', event)
            event['type'] = 'fingerprint'
            self.ingest('terminal', 'terminal', event)
            self.ingest('edge', 'edge', self.event('fingerprint', source='198.51.100.' + str(i + 1), fid='edge' + str(i), fingerprint=str(i) * 64))
        self.s.sample([connection], self.now + 101, monotonic_now=101)
        self.assertIsNone(self.s.db.execute('SELECT source_ip FROM connection_state').fetchone()[0])
        self.cfg['tcp_stream_recovery'] = True
        self.s.sample([connection], self.now + 104, monotonic_now=104)
        self.assertIsNone(self.s.db.execute('SELECT source_ip FROM connection_state').fetchone()[0])
    def test_socket_lookup_uses_full_index_without_transport_assumption(self):
        self.ingest('terminal','terminal',self.event(coverage='syn'))
        query = """SELECT * FROM flows WHERE kind='terminal' AND src_ip=? AND src_port=?
          AND dst_port=? AND start_ts<=? AND (end_ts IS NULL OR end_ts>=?)
          ORDER BY start_ts DESC LIMIT 2"""
        args = ('10.0.0.2',1234,3320,self.now+2,self.now)
        plan = ' '.join(row[3] for row in self.s.db.execute('EXPLAIN QUERY PLAN '+query,args))
        self.assertIn('flow_socket',plan)
        self.assertIn('src_port=?',plan)
        self.assertNotIn('TEMP B-TREE',plan)
        self.assertEqual(len(self.s.db.execute(query,args).fetchall()),1)
        plan = ' '.join(row[3] for row in self.s.db.execute(
            "EXPLAIN QUERY PLAN SELECT connection_id FROM connection_state WHERE flow_id=?",('terminal/t',)))
        self.assertIn('connection_flow',plan)
        self.assertNotIn('SCAN connection_state',plan)
        self.s.db.execute("UPDATE flows SET source_ip='198.51.100.1' WHERE flow_id='terminal/t'")
        query = "SELECT COUNT(*) FROM flows WHERE kind='terminal' AND source_ip IS NOT NULL"
        plan = ' '.join(row[3] for row in self.s.db.execute('EXPLAIN QUERY PLAN '+query))
        self.assertIn('COVERING INDEX flow_matches',plan)
        self.assertEqual(self.s.db.execute(query).fetchone()[0],1)
    def test_ambiguous_never_guesses(self):
        self.ingest('terminal','terminal',self.event(coverage='syn'))
        self.ingest('terminal','terminal',self.event('fingerprint',fingerprint='b'*64))
        self.ingest('edge','edge',self.event('fingerprint',source='198.51.100.1',fid='e1',fingerprint='b'*64))
        self.s.sample([self.conn()],self.now+1)
        self.ingest('edge2','edge',self.event('fingerprint',source='198.51.100.2',fid='e2',fingerprint='b'*64))
        r=self.s.db.execute('select source_ip,quality from samples').fetchone()
        self.assertEqual(tuple(r),(None,'ambiguous_fingerprint'))
    def test_duplicate_batch_wire_exactly_once(self):
        e=self.event('wire_delta',source='198.51.100.1',up_bytes=7,down_bytes=13,up_packets=1,down_packets=2)
        id=str(uuid.uuid4())
        self.ingest('edge','edge',e,id);self.ingest('edge','edge',e,id)
        self.assertEqual(tuple(self.s.db.execute('select up_bytes,down_bytes from wire_samples').fetchone()),(7,13))

    def test_reserved_rfc2544_source_stays_unknown(self):
        self.ingest('terminal','terminal',self.event(coverage='syn'))
        self.ingest('terminal','terminal',self.event('fingerprint',fingerprint='c'*64))
        self.ingest('edge','edge',self.event('fingerprint',source='198.19.13.35',fid='e',fingerprint='c'*64))
        flow=self.s.db.execute('select source_ip,source_node,quality from flows where kind="terminal"').fetchone()
        self.assertEqual(tuple(flow),(None,'edge','reserved_source_ip'))

        wire=self.event('wire_delta',source='198.19.13.35',up_bytes=7,down_bytes=13,up_packets=1,down_packets=2)
        self.ingest('edge','edge',wire)
        self.assertEqual(self.s.db.execute('select source_ip from wire_samples').fetchone()[0],'')
    def test_predeploy_bytes_not_counted(self):
        c=self.conn();c['start']='2020-01-01T00:00:00+00:00'
        self.s.sample([c],self.now)
        self.assertEqual(self.s.db.execute('select sum(upload_bytes) from samples').fetchone()[0],0)
    def test_retention_7_days(self):
        self.s.db.execute("insert into samples values('old',?,'c',null,null,'x',1,1,'unknown')",(self.now-7*86400-1,))
        self.s.db.execute("insert into samples values('keep',?,'c',null,null,'x',1,1,'unknown')",(self.now-7*86400+1,));self.s.db.commit()
        self.s.prune(self.now)
        self.assertEqual(self.s.db.execute('select event_id from samples').fetchone()[0],'keep')
    def test_source_tuple_reuse_does_not_match_closed_flow(self):
        self.ingest('terminal','terminal',self.event(coverage='syn'))
        e=self.event('flow_close');e['capture_ts']=self.now
        self.ingest('terminal','terminal',e)
        self.s.sample([self.conn()],self.now+1)
        self.assertIsNone(self.s.db.execute('select flow_id from connection_state').fetchone()[0])
    def test_minute_compaction_preserves_deltas(self):
        self.s.sample([self.conn()],self.now+1)
        self.s.sample([self.conn(up=130,down=280)],self.now+1.1)
        r=self.s.db.execute('select count(*),sum(upload_bytes),sum(download_bytes) from samples').fetchone()
        self.assertEqual(tuple(r),(1,130,280))
    def test_invalid_event(self):
        e=self.event('fingerprint',fingerprint='raw-payload')
        with self.assertRaises(ValueError):validate_event(e)
    def test_log_parses_without_storing_raw(self):
        self.ingest('terminal','terminal',self.event(coverage='syn'))
        self.assertTrue(self.s.visit('[TCP] 10.0.0.2:1234 --> example.com:443 using DIRECT',self.now+1))
        self.assertFalse(self.s.visit('a secret unrelated log',self.now+1))
        self.assertEqual(self.s.db.execute('select site from visits').fetchone()[0],'example.com')

if __name__=='__main__':unittest.main()
