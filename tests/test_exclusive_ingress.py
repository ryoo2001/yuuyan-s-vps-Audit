import copy
import tempfile
import time
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path

from audit import Store, exclusive_ingress_routes


class ExclusiveIngressTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.now = time.time()
        self.config = {
            "node": "term-b1", "mode": "terminal",
            "db": str(Path(self.temp.name) / "audit.sqlite"),
            "retention_days": 7, "max_db_mb": 8,
            "inbound_ports": [28900, 28901],
            "peers": {"entry-b2": {}, "entry-a1": {}},
            "captures": [{"interface": "et_shdm0", "tcp_ports": [28901], "udp_ports": [28901]}],
            "entry_routes": [
                {"node": "entry-b2", "inbound_port": 28900, "tunnel_ip": "10.77.65.1"},
                {"node": "entry-a1", "inbound_port": 28900, "tunnel_ip": "10.77.63.1"},
                {"node": "entry-a1", "inbound_port": 28901, "tunnel_ip": "10.77.63.1"},
            ],
            "exclusive_ingress": [{
                "node": "entry-a1", "source_peer": "10.77.66.1", "inbound_port": 28901,
                "interface": "et_shdm0", "inbound_names": ["ENTRYA-31500-TCP", "ENTRYA-31500-UDP"],
            }],
        }
        self.store = Store(self.config)

    def tearDown(self):
        self.store.db.close()
        self.temp.cleanup()

    def connection(self, peer="10.77.66.1", port=28901, name="ENTRYA-31500-TCP"):
        return {"id": "one", "start": datetime.fromtimestamp(self.now + .1, timezone.utc).isoformat(),
                "upload": 10, "download": 20,
                "metadata": {"type": "Mieru", "sourceIP": peer, "sourcePort": "12345",
                             "inboundPort": str(port), "inboundName": name, "host": "example.com"}}

    def test_node_without_fingerprint_does_not_invent_customer_ip(self):
        result = self.store.sample([self.connection()], self.now + 1)
        row = self.store.db.execute("select source_ip,node,quality from connection_state").fetchone()
        self.assertEqual(tuple(row), (None, "entry-a1", "exclusive_ingress"))
        self.assertEqual(result["unresolved_connections"], 1)
        row = self.store.db.execute('select "源 IP","隧道内网 IP（入口机器）" from "审计明细"').fetchone()
        self.assertEqual(tuple(row), ("未识别", "10.77.63.1（entry-a1）"))

    def test_udp_listener_also_identifies_only_the_entry(self):
        self.store.sample([self.connection(name="ENTRYA-31500-UDP")], self.now + 1)
        self.assertEqual(tuple(self.store.db.execute("select source_ip,node from connection_state").fetchone()),
                         (None, "entry-a1"))

    def test_other_path_and_wrong_name_stay_unknown(self):
        for peer, port, name in [("10.77.65.1", 28900, "ENTRY-B2-28900-TCP"),
                                 ("10.77.65.1", 28901, "ENTRYA-31500-TCP"),
                                 ("10.77.66.1", 28901, "ENTRY-B2-28900-TCP")]:
            with self.subTest(peer=peer, port=port, name=name):
                self.store.sample([self.connection(peer, port, name)], self.now + 1)
                self.assertIsNone(self.store.db.execute("select node from connection_state").fetchone()[0])

    def test_shared_port_cannot_be_configured_as_exclusive(self):
        config = copy.deepcopy(self.config)
        config["entry_routes"].append({"node": "entry-b2", "inbound_port": 28901, "tunnel_ip": "10.77.65.1"})
        with self.assertRaisesRegex(ValueError, "shared"):
            exclusive_ingress_routes(config)

    def test_fingerprint_from_other_entry_cannot_claim_the_customer(self):
        def event(node, kind, peer, flow):
            payload = {"type": "fingerprint", "transport": "tcp", "src_ip": peer, "src_port": 12345,
                       "dst_ip": "10.77.66.2", "dst_port": 28901, "flow_id": flow,
                       "capture_ts": self.now, "fingerprint": "a" * 64}
            self.store.ingest(node, [{"event_id": str(uuid.uuid4()), "event": payload}], self.now, self.now, kind)
        event("term-b1", "terminal", "10.77.66.1", "terminal-flow")
        event("entry-b2", "edge", "198.51.100.27", "wrong-entry")
        self.store.sample([self.connection()], self.now + 1)
        self.assertEqual(tuple(self.store.db.execute("select source_ip,node from connection_state").fetchone()),
                         (None, "entry-a1"))
        event("entry-a1", "edge", "198.51.100.31", "correct-entry")
        self.store.sample([self.connection()], self.now + 2)
        self.assertEqual(tuple(self.store.db.execute("select source_ip,node,quality from connection_state").fetchone()),
                         ("198.51.100.31", "entry-a1", "ciphertext_fingerprint"))


if __name__ == "__main__":
    unittest.main()
