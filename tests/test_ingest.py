import json, tempfile, time, unittest, uuid
from pathlib import Path
from unittest.mock import patch
import audit

class IngestTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.cfg={"mode":"terminal","node":"terminal","db":str(Path(self.tmp.name)/"audit.sqlite"),"health":str(Path(self.tmp.name)/"health.json"),"retention_days":7,"max_db_mb":8,"inbound_ports":[3320],"peers":{"edge":{"tcp_ports":[3320],"udp_ports":[]}}}
        self.a=audit.Audit(self.cfg)
    def tearDown(self):
        self.a.store.db.close();self.tmp.cleanup()
    def batch(self,count=1):
        return {"node":"edge","sent_at":time.time(),"metrics":{},"events":[{"event_id":str(uuid.uuid4()),"event":{"type":"wire_delta","transport":"tcp","capture_ts":time.time(),"src_ip":"198.51.100.1","src_port":1234,"dst_ip":"10.0.0.1","dst_port":3320,"flow_id":"flow-"+str(i),"up_bytes":10,"down_bytes":20,"up_packets":1,"down_packets":1}} for i in range(count)]}
    def test_accept_retry_idempotent(self):
        b=self.batch();self.assertEqual(self.a.accept_batch("edge",b),{"accepted":1});self.a.accept_batch("edge",b)
        self.assertEqual(tuple(self.a.store.db.execute("SELECT sum(up_bytes),sum(down_bytes) FROM wire_samples").fetchone()),(10,20))
    def test_terminal_without_controller_is_degraded_not_runtime_error(self):
        self.assertFalse(self.a.controller_available)
        self.a.health()
        payload=json.loads(Path(self.cfg["health"]).read_text())
        self.assertEqual(self.a.errors, {})
        self.assertIn("mihomo_controller_unavailable", payload["warnings"])
    def test_bad_batch_is_all_or_nothing(self):
        b=self.batch(2);b["events"][1]["event"]["dst_port"]=1
        with self.assertRaises(ValueError):self.a.accept_batch("edge",b)
        self.assertEqual(self.a.store.db.execute("SELECT count(*) FROM seen").fetchone()[0],0)
    def test_clock_validation(self):
        for stamp in [True,float("nan"),time.time()-901,time.time()+901]:
            b=self.batch();b["sent_at"]=stamp
            with self.assertRaises(ValueError):self.a.accept_batch("edge",b)
    def test_wrong_node_and_invalid_metrics(self):
        for change in [{"node":"other"},{"metrics":[]},{"events":None}]:
            b=self.batch();b.update(change)
            with self.assertRaises(ValueError):self.a.accept_batch("edge",b)
    def test_udp_packet_batch_preserves_prefix(self):
        from transport import encode
        b=self.batch(256);kept=audit.udp_batch("edge",b"key",b)
        self.assertGreater(len(kept["events"]),0);self.assertLess(len(kept["events"]),256)
        self.assertEqual(kept["events"],b["events"][:len(kept["events"])])
        self.assertEqual(len(b["events"]),256);self.assertLessEqual(len(encode("edge",b"key",kept)),1200)
    def test_udp_oversize_single_event_fails_loudly(self):
        from transport import PacketTooLarge
        b=self.batch();b["metrics"]={"noise":"".join(uuid.uuid4().hex for _ in range(100))}
        with self.assertRaises(PacketTooLarge):audit.udp_batch("edge",b"key",b)
    def run_upload_once(self, fail=False):
        self.a.store.db.close();self.cfg.update(mode="edge",node="edge",upload_transport="udp",endpoint="http://127.0.0.1:19091",auth_file="unused")
        self.a=audit.Audit(self.cfg);b=self.batch(100);self.a.store.enqueue([x["event"] for x in b["events"]])
        class Stop:
            stopped=False
            def is_set(self):return self.stopped
            def wait(self,seconds):self.stopped=True
        sent=[]
        def exchange(address,node,key,data):
            sent.append(data)
            if fail:raise TimeoutError()
            return {"accepted":len(data["events"])}
        with patch.object(audit,"STOP",Stop()),patch.object(audit,"derive_key",return_value=b"key"),patch("transport.exchange",side_effect=exchange):self.a.upload()
        return sent,self.a.store.db.execute("SELECT count(*) FROM spool").fetchone()[0]
    def test_upload_removes_only_confirmed_prefix(self):
        sent,left=self.run_upload_once();self.assertEqual(left,100-len(sent[0]["events"]));self.assertNotIn("upload",self.a.errors)
    def test_upload_timeout_keeps_entire_spool(self):
        sent,left=self.run_upload_once(True);self.assertEqual(left,100);self.assertEqual(self.a.errors["upload"],"TimeoutError")

if __name__=="__main__":unittest.main()
