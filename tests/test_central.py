import hashlib,json,sqlite3,sys,tempfile,time,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
sys.path.append(str(Path(__file__).resolve().parents[1]/'central'))
from audit import Store
from model import TABLES,validate_row,upsert_sql
from publish import setup,batch,acknowledge,trim_cache
from receive import validate_batch,connect
from unittest.mock import patch,MagicMock

class CentralTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.store=Store({'node':'term-a2','mode':'terminal','db':str(Path(self.tmp.name)/'test.sqlite'),'inbound_ports':[]})
        self.db=self.store.db
        self.epoch=setup(self.db)
    def tearDown(self):
        self.db.close(); self.tmp.cleanup()
    def insert(self,n=1):
        with self.db:
            self.db.execute("INSERT INTO samples VALUES('s',?,'c','edge','198.51.100.1','example.test',?,2,'matched') ON CONFLICT(event_id) DO UPDATE SET upload_bytes=excluded.upload_bytes",(time.time(),n))
    def ack(self,p,b):
        acknowledge(self.db,p,b,{'ok':True,'through':p['through'],'digest':hashlib.sha256(b).hexdigest()})
    def test_connect_uses_configured_database_name(self):
        cfg=Path(self.tmp.name)/'writer.json'
        cfg.write_text(json.dumps({'socket':'test.sock','user':'test','password':'test','database':'region-a'}))
        mysql=MagicMock()
        with patch.dict(sys.modules, {'pymysql':mysql}):
            connect(cfg)
        self.assertEqual(mysql.connect.call_args.kwargs['database'],'region-a')

    def test_mutating_bucket_coalesces_and_absolute(self):
        self.insert(); self.insert(12)
        p,b=batch(self.db,self.epoch)
        self.assertEqual(len(p['rows']),1)
        self.assertEqual(p['rows'][0][2][6],12)
        validate_batch(p);self.ack(p,b)
        self.assertEqual(batch(self.db,self.epoch)[0]['rows'],[])
    def test_old_ack_never_removes_concurrent_update(self):
        self.insert();p,b=batch(self.db,self.epoch)
        self.insert(29);self.ack(p,b)
        n,_=batch(self.db,self.epoch)
        self.assertEqual(n['rows'][0][2][6],29)
        self.assertGreater(n['through'],p['through'])
    def test_invalid_ack_preserves_queue(self):
        self.insert();p,b=batch(self.db,self.epoch)
        with self.assertRaises(ValueError): acknowledge(self.db,p,b,{'ok':True,'through':p['through'],'digest':'x'})
        self.assertEqual(len(batch(self.db,self.epoch)[0]['rows']),1)
    def test_ignore_and_replace_outer_policies(self):
        with self.db:
            self.db.execute("INSERT OR IGNORE INTO peers VALUES('edge',1,1,'{}')")
            self.db.execute("INSERT OR REPLACE INTO peers VALUES('edge',2,2,'{}')")
            self.db.execute("UPDATE peers SET sender_ts=3 WHERE node='edge'")
        p,_=batch(self.db,self.epoch)
        self.assertEqual(len(p['rows']),1); self.assertEqual(p['rows'][0][2][2],3)
    def test_bootstrap_idempotent_and_epoch_stable(self):
        self.insert();p,_=batch(self.db,self.epoch)
        self.assertEqual(setup(self.db),self.epoch)
        self.assertEqual(batch(self.db,self.epoch)[0]['through'],p['through'])
    def test_wire_composite_keys(self):
        with self.db:
            self.db.execute("INSERT INTO wire_samples VALUES(60,'edge','198.51.100.1',3320,'tcp',1,2,3,4)")
            self.db.execute("UPDATE wire_samples SET down_bytes=99")
        p,_=batch(self.db,self.epoch)
        self.assertEqual(p['rows'][0][2][6],99)
    def test_cache_keeps_unacked_and_unattributed(self):
        self.insert()
        with self.db:
            self.db.execute('UPDATE samples SET ts=?',(time.time()-2*86400,))
        self.assertEqual(trim_cache(self.db),0)
        p,b=batch(self.db,self.epoch);self.ack(p,b)
        self.assertEqual(trim_cache(self.db),1)
        self.assertEqual(self.db.execute('SELECT SUM(upload_bytes+download_bytes) FROM traffic_rollup').fetchone()[0],3)
        self.insert()
        with self.db:
            self.db.execute('UPDATE samples SET ts=?,source_ip=NULL',(time.time()-2*86400,))
        p,b=batch(self.db,self.epoch);self.ack(p,b)
        self.assertEqual(trim_cache(self.db),0)
    def test_bad_contract(self):
        for name,row in [('bad',[]),([],[]),('samples',[]),('peers',['n',float('nan'),1,'{}']),('peers',[None,1,1,'{}'])]:
            with self.assertRaises(ValueError): validate_row(name,row)
        self.insert();p,_=batch(self.db,self.epoch)
        p['epoch']='bad'
        with self.assertRaises(ValueError): validate_batch(p)
    def test_ingest_sends_one_multirow_upsert_per_table_above_watermark(self):
        import importlib
        for module in ('receive','hk_receive'):
            ingest=importlib.import_module(module).ingest
            db=MagicMock();cursor=db.cursor.return_value.__enter__.return_value;cursor.fetchone.return_value=('a'*32,5)
            sample=lambda key:[key,time.time(),'c','edge','198.51.100.1','example.test',1,2,'matched']
            rate=['c',time.time(),5.0,1.0,2.0]
            payload={'version':1,'publisher':'term-a1','epoch':'a'*32,'through':9,'sent_at':time.time(),'missing':0,
                     'rows':[[4,'samples',sample('old')],[6,'samples',sample('s6')],[7,'connection_rates',rate],[9,'samples',sample('s9')]]}
            ingest(db,payload)
            calls=cursor.executemany.call_args_list
            self.assertEqual(len(calls),2,module)
            self.assertIn('samples',calls[0].args[0]);self.assertEqual([r[0] for r in calls[0].args[1]],['s6','s9'])
            self.assertEqual([r[-1] for r in calls[0].args[1]],[6,9]);self.assertEqual(calls[1].args[1],[rate+[7]])
            self.assertIn('ON DUPLICATE KEY UPDATE',calls[0].args[0])
            # only the watermark read and the sync_state write remain single statements
            self.assertEqual(cursor.execute.call_count,2,module);db.commit.assert_called_once()
            cursor.fetchone.return_value=('b'*32,5)
            with self.assertRaisesRegex(ValueError,'publisher_epoch_changed'):ingest(db,payload)
            self.assertEqual(len(cursor.executemany.call_args_list),2,module)
    def test_central_tls_is_opt_in(self):
        import publish
        cfg=Path(self.tmp.name)/'writer.json';base={'host':'192.0.2.1','user':'u','password':'p','database':'hk'}
        for module,call in (('receive',lambda:connect(cfg)),('publish',lambda:publish.central_connect())):
            mysql=MagicMock()
            with patch.dict(sys.modules,{'pymysql':mysql}),patch.object(publish,'CENTRAL_CONFIG',cfg):
                cfg.write_text(json.dumps(base));call();self.assertNotIn('ssl',mysql.connect.call_args.kwargs,module)
                cfg.write_text(json.dumps(dict(base,tls=True)));call();self.assertIn('ssl',mysql.connect.call_args.kwargs,module)
                cfg.write_text(json.dumps(dict(base,tls=True,socket='x.sock')));call();self.assertNotIn('ssl',mysql.connect.call_args.kwargs,module)
    def test_upsert_never_adds_replayed_counters(self):
        for name in TABLES:
            sql=upsert_sql(name)
            self.assertIn('GREATEST',sql);self.assertNotIn(' + ',sql)

if __name__=='__main__': unittest.main()
