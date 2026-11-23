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
    def test_exact_domain_excluded_from_sampling_and_visits(self):
        self.ingest('terminal', 'terminal', self.event(coverage='syn'))
        sites = ['www.gstatic.com', 'WWW.GSTATIC.COM.', 'fonts.gstatic.com',
                 'sub.www.gstatic.com', 'www.gstatic.com.example']
        connections = []
        for site in sites:
            connection = self.conn(id=site)
            connection['metadata']['host'] = site
            connections.append(connection)
            self.assertEqual(self.s.visit(f'[TCP] 10.0.0.2:1234 --> {site}:443 using DIRECT',
                                          self.now + 1), site in sites[2:])
        counts = self.s.sample(connections, self.now + 1)
        self.assertEqual(counts['active_connections'], 3)
        for table in ('samples', 'visits', 'connection_state'):
            self.assertCountEqual([r[0] for r in self.s.db.execute(f'SELECT site FROM {table}')],
                                  sites[2:])
        self.assertCountEqual([r[0] for r in self.s.db.execute('SELECT connection_id FROM connection_rates')],
                              sites[2:])

    def test_invalid_event(self):
        e=self.event('fingerprint',fingerprint='raw-payload')
        with self.assertRaises(ValueError):validate_event(e)
    def test_log_parses_without_storing_raw(self):
        self.ingest('terminal','terminal',self.event(coverage='syn'))
        self.assertTrue(self.s.visit('[TCP] 10.0.0.2:1234 --> example.com:443 using DIRECT',self.now+1))
        self.assertFalse(self.s.visit('a secret unrelated log',self.now+1))
        self.assertEqual(self.s.db.execute('select site from visits').fetchone()[0],'example.com')

    def test_trusted_controller_source_uses_real_client_and_chain_egress(self):
        self.s.db.close()
        self.cfg.update({
            'inbound_types': {'3320': ['AnyTLS']},
            'controller_source_ip': {'3320': {
                'types': ['AnyTLS'],
                'egress_by_chain': {'DIRECT': 'term-d', 'egress-d-socks5': 'egress-d'},
                'default_egress': 'term-d',
                'trust_unmatched_logs': True,
            }},
        })
        self.s = Store(self.cfg)
        c = self.conn()
        c['metadata'].update(type='AnyTLS', sourceIP='8.8.8.8', chains=['egress-d-socks5'])
        self.s.sample([c], self.now + 1)
        row = self.s.db.execute('SELECT source_ip,node,quality FROM connection_state').fetchone()
        self.assertEqual(tuple(row), ('8.8.8.8', 'egress-d', 'controller_source_ip'))
        self.assertTrue(self.s.visit(
            '[TCP] 8.8.8.8:1234 --> chat.openai.com:443 match Match using egress-d-socks5', self.now + 1))
        row = self.s.db.execute('SELECT source_ip,node,quality FROM visits').fetchone()
        self.assertEqual(tuple(row), ('8.8.8.8', 'egress-d', 'controller_source_ip'))

    def controller_store(self):
        self.s.db.close()
        self.cfg.update({
            'inbound_types': {'3320': ['AnyTLS']},
            'controller_source_ip': {'3320': {
                'types': ['AnyTLS'],
                'egress_by_chain': {'DIRECT': 'term-d', 'egress-d-socks5': 'egress-d'},
                'default_egress': 'term-d',
                'trust_unmatched_logs': True,
            }},
        })
        self.s = Store(self.cfg)

    def test_log_outbound_name_ignores_rule_names(self):
        from audit import log_outbound_name
        self.assertEqual(log_outbound_name('[TCP] 8.8.8.8:1 --> x.com:443 match Match using DIRECT'), 'DIRECT')
        self.assertEqual(log_outbound_name('[TCP] 8.8.8.8:1 --> x.com:443 match DomainSuffix(openai.com) using egress-d-socks5'), 'egress-d-socks5')
        self.assertEqual(log_outbound_name('[TCP] 8.8.8.8:1 --> x.com:443 using egress-d-socks5'), 'egress-d-socks5')
        self.assertIsNone(log_outbound_name('[TCP] 8.8.8.8:1 --> x.com:443 match Match'))

    def test_visit_with_matched_flow_uses_chain_egress_not_flow_node(self):
        self.controller_store()
        self.ingest('terminal', 'terminal', self.event(source='8.8.8.8', coverage='syn'))
        self.assertTrue(self.s.visit(
            '[TCP] 8.8.8.8:1234 --> chat.openai.com:443 match Match using egress-d-socks5', self.now + 1))
        row = self.s.db.execute('SELECT source_ip,node,quality,flow_id FROM visits').fetchone()
        self.assertEqual(tuple(row[:3]), ('8.8.8.8', 'egress-d', 'controller_source_ip'))
        self.assertIsNotNone(row[3])

    def test_unmatched_log_egress_uses_outbound_not_rule_name(self):
        self.controller_store()
        self.assertTrue(self.s.visit(
            '[TCP] 8.8.8.8:1234 --> x.com:443 match DomainSuffix(x.com) using egress-d-socks5', self.now + 1))
        self.assertTrue(self.s.visit(
            '[TCP] 9.9.9.9:1234 --> x.com:443 match Match using DIRECT', self.now + 1))
        rows = dict(tuple(r) for r in self.s.db.execute('SELECT source_ip,node FROM visits').fetchall())
        self.assertEqual(rows, {'8.8.8.8': 'egress-d', '9.9.9.9': 'term-d'})

    def anytls(self, source='8.8.8.8', chains=None, id='one'):
        c = self.conn(id=id)
        c['metadata'].update(type='AnyTLS', sourceIP=source)
        if chains is not None:
            c['chains'] = chains
        return c

    def test_unmapped_chain_is_not_defaulted_and_is_reported(self):
        self.controller_store()
        self.s.sample([self.anytls(chains=['us-new-socks5', 'Proxy'])], self.now + 1)
        row = self.s.db.execute('SELECT source_ip,node,quality FROM connection_state').fetchone()
        self.assertEqual(tuple(row), ('8.8.8.8', None, 'controller_source_ip'))
        self.assertEqual(self.s.unmapped_routes, {'us-new-socks5'})
        self.assertTrue(self.s.visit('[TCP] 9.9.9.9:1 --> x.com:443 match Match using us-new-socks5', self.now + 1))
        self.assertIsNone(self.s.db.execute("SELECT node FROM visits WHERE source_ip='9.9.9.9'").fetchone()[0])

    def test_rejected_connection_has_no_egress_and_no_warning(self):
        self.controller_store()
        self.s.sample([self.anytls(chains=['REJECT'])], self.now + 1)
        self.assertTrue(self.s.visit('[TCP] 9.9.9.9:1 --> x.com:22 match DstPort(22) using REJECT', self.now + 1))
        self.assertIsNone(self.s.db.execute('SELECT node FROM connection_state').fetchone()[0])
        self.assertIsNone(self.s.db.execute('SELECT node FROM visits').fetchone()[0])
        self.assertEqual(self.s.unmapped_routes, set())

    def test_no_reported_route_uses_default_egress_and_group_member_maps(self):
        self.controller_store()
        self.s.sample([self.anytls(chains=[])], self.now + 1)
        self.assertEqual(self.s.db.execute('SELECT node FROM connection_state').fetchone()[0], 'term-d')
        self.assertTrue(self.s.visit('[TCP] 9.9.9.9:1 --> x.com:443 match Match using Proxy[egress-d-socks5]', self.now + 1))
        self.assertEqual(self.s.db.execute('SELECT node FROM visits').fetchone()[0], 'egress-d')
        self.assertEqual(self.s.unmapped_routes, set())

    def test_existing_conflicting_fingerprint_hides_both_sources(self):
        self.controller_store()
        self.ingest('terminal', 'terminal', self.event(source='8.8.8.8', coverage='syn'))
        self.ingest('terminal', 'terminal', self.event('fingerprint', source='8.8.8.8', fingerprint='c' * 64))
        self.ingest('edge', 'edge', self.event('fingerprint', source='1.1.1.1', fid='e', fingerprint='c' * 64))
        c = self.anytls(chains=['DIRECT'])
        for step in (1, 2, 3):
            self.s.sample([c], self.now + step)
        self.assertEqual(tuple(self.s.db.execute('SELECT source_ip,node,quality FROM connection_state').fetchone()),
                         (None, 'term-d', 'source_conflict'))
        self.assertEqual(self.s.source_conflicts, 1)

    def test_private_controller_peer_keeps_fingerprint_evidence(self):
        self.controller_store()
        self.ingest('terminal', 'terminal', self.event(coverage='syn'))
        self.ingest('terminal', 'terminal', self.event('fingerprint', fingerprint='b' * 64))
        self.ingest('edge', 'edge', self.event('fingerprint', source='1.1.1.1', fid='e', fingerprint='b' * 64))
        self.s.sample([self.anytls(source='10.0.0.2', chains=['DIRECT'])], self.now + 1)
        self.assertEqual(tuple(self.s.db.execute('SELECT source_ip,node,quality FROM connection_state').fetchone()),
                         ('1.1.1.1', 'edge', 'ciphertext_fingerprint'))

    def test_late_agreeing_fingerprint_keeps_chain_egress(self):
        self.controller_store()
        self.ingest('terminal', 'terminal', self.event(source='8.8.8.8', coverage='syn'))
        self.ingest('terminal', 'terminal', self.event('fingerprint', source='8.8.8.8', fingerprint='e' * 64))
        self.s.sample([self.anytls(chains=['egress-d-socks5'])], self.now + 1)
        self.s.visit('[TCP] 8.8.8.8:1234 --> x.com:443 match Match using egress-d-socks5', self.now + 1)
        self.ingest('edge', 'edge', self.event('fingerprint', source='8.8.8.8', fid='e', fingerprint='e' * 64))
        for table in ('connection_state', 'visits', 'samples'):
            self.assertEqual(tuple(self.s.db.execute('SELECT source_ip,node,quality FROM ' + table).fetchone()),
                             ('8.8.8.8', 'egress-d', 'controller_source_ip'), table)

    def test_late_disagreeing_fingerprint_marks_conflict(self):
        self.controller_store()
        self.ingest('terminal', 'terminal', self.event(source='8.8.8.8', coverage='syn'))
        self.ingest('terminal', 'terminal', self.event('fingerprint', source='8.8.8.8', fingerprint='f' * 64))
        c = self.anytls(chains=['egress-d-socks5'])
        self.s.sample([c], self.now + 1)
        self.s.visit('[TCP] 8.8.8.8:1234 --> x.com:443 match Match using egress-d-socks5', self.now + 1)
        self.ingest('edge', 'edge', self.event('fingerprint', source='1.1.1.1', fid='e', fingerprint='f' * 64))
        for table in ('connection_state', 'visits', 'samples'):
            self.assertEqual(tuple(self.s.db.execute('SELECT source_ip,node,quality FROM ' + table).fetchone()),
                             (None, 'egress-d', 'source_conflict'), table)
        self.s.sample([c], self.now + 2)
        self.s.sample([c], self.now + 3)
        self.assertEqual(tuple(self.s.db.execute('SELECT source_ip,quality FROM connection_state').fetchone()),
                         (None, 'source_conflict'))
        self.assertEqual(self.s.source_conflicts, 1)

    def test_controller_source_rejects_non_global_addresses(self):
        self.controller_store()
        for peer in ('127.0.0.1', '10.0.0.2', '192.168.1.5', '169.254.1.1', '203.0.113.108', '198.18.0.5'):
            self.assertIsNone(self.s.trusted_controller_source(peer, 3320, 'AnyTLS'), peer)
            self.assertFalse(self.s.visit(
                '[TCP] %s:1234 --> x.com:443 match Match using DIRECT' % peer, self.now + 1), peer)
        self.assertEqual(self.s.trusted_controller_source('8.8.8.8', 3320, 'AnyTLS'), '8.8.8.8')
        self.assertIsNone(self.s.trusted_controller_source('8.8.8.8', 3320, 'Mieru'))

if __name__=='__main__':unittest.main()
