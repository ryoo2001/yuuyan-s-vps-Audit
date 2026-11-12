"""DNAT port mapping, explicit Shadowsocks sampling and NAT-leg exclusion."""
import copy
import tempfile
import time
import unittest
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import audit
from audit import Store, fingerprint_routes, inbound_types


class L4AttributionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.now = time.time()
        self.config = {
            "mode": "terminal", "node": "terminal", "retention_days": 7, "max_db_mb": 8,
            "db": str(Path(self.tmp.name) / "audit.sqlite"), "inbound_ports": [2101, 3366],
            "inbound_types": {"2101": ["ShadowSocks"]},
            "peers": {"entrya": {"tcp_ports": [2101, 28600], "udp_ports": [2101]},
                      "other": {"tcp_ports": [2101]}},
            "captures": [{"interface": "eth0", "tcp_ports": [2101, 3366], "udp_ports": [2101]}],
            "fingerprint_routes": [
                {"node": "entrya", "inbound_port": 2101, "entry_port": 2101, "transport": "tcp"},
                {"node": "entrya", "inbound_port": 2101, "entry_port": 2101, "transport": "udp"},
                {"node": "entrya", "inbound_port": 3366, "entry_port": 28600, "transport": "tcp"},
            ],
        }
        self.store = Store(self.config)

    def tearDown(self):
        self.store.db.close()
        self.tmp.cleanup()

    def event(self, kind, node, port=2101, transport="tcp", source=None, flow=None):
        e = {"type": "fingerprint", "flow_id": flow or str(uuid.uuid4()), "capture_ts": self.now,
             "transport": transport, "src_ip": source or ("203.0.113.105" if kind == "terminal" else "203.0.113.8"),
             "src_port": 12345, "dst_ip": "192.0.2.1", "dst_port": port, "fingerprint": "a" * 64}
        self.store.ingest(node, [{"event_id": str(uuid.uuid4()), "event": e}], self.now, self.now, kind)

    def connection(self, network="tcp", port=2101, typ="ShadowSocks"):
        return {"id": "client", "start": datetime.fromtimestamp(self.now + .1, timezone.utc).isoformat(),
                "upload": 100, "download": 200,
                "metadata": {"type": typ, "network": network, "sourceIP": "203.0.113.105",
                             "sourcePort": "12345", "inboundPort": str(port), "host": "example.com"}}

    def test_shadowsocks_tcp_and_udp_with_same_tuple_do_not_cross_match(self):
        for transport in ("tcp", "udp"):
            self.event("terminal", "terminal", transport=transport, flow=transport)
            self.event("edge", "entrya", transport=transport, source="203.0.113." + ("8" if transport == "tcp" else "9"))
        for transport, expected in (("tcp", "203.0.113.8"), ("udp", "203.0.113.9")):
            c = self.connection(transport)
            c["id"] = transport
            self.store.sample([c], self.now + 1)
            row = self.store.db.execute("select source_ip,node,quality from connection_state where connection_id=?", (transport,)).fetchone()
            self.assertEqual(tuple(row), (expected, "entrya", "ciphertext_fingerprint"))

    def test_wrong_entry_or_original_port_cannot_claim_shared_digest(self):
        self.event("terminal", "terminal", port=3366)
        self.event("edge", "other")
        self.event("edge", "entrya", port=2101)
        self.store.sample([self.connection(port=3366, typ="Mieru")], self.now + 1)
        self.assertIsNone(self.store.db.execute("select source_ip from connection_state").fetchone()[0])
        self.event("edge", "entrya", port=28600)
        self.store.sample([self.connection(port=3366, typ="Mieru")], self.now + 2)
        self.assertEqual(tuple(self.store.db.execute("select source_ip,node from connection_state").fetchone()),
                         ("203.0.113.8", "entrya"))

    def test_protocol_is_explicit_per_listener_and_unknown_network_is_skipped(self):
        for c in [self.connection(port=3366), self.connection(typ="Mieru"),
                  self.connection(network=None), self.connection(network="invalid")]:
            self.assertEqual(self.store.sample([c], self.now + 1)["active_connections"], 0)

    def test_missing_fingerprint_does_not_publish_relay_as_source(self):
        self.store.sample([self.connection()], self.now + 1)
        self.assertEqual(tuple(self.store.db.execute("select source_ip,node,quality from connection_state").fetchone()),
                         (None, None, "unresolved"))

    def test_mieru_udp_payload_still_matches_tcp_carrier(self):
        self.event("terminal", "terminal", port=3366)
        self.event("edge", "entrya", port=28600)
        self.store.sample([self.connection(network="udp", port=3366, typ="Mieru")], self.now + 1)
        self.assertEqual(self.store.db.execute("select source_ip from connection_state").fetchone()[0], "203.0.113.8")

    def test_anytls_tcp_and_udp_payload_match_mapped_tcp_carrier(self):
        config = copy.deepcopy(self.config)
        config["inbound_types"]["3366"] = ["AnyTLS"]
        self.store.db.close()
        self.store = Store(config)
        self.event("terminal", "terminal", port=3366)
        self.event("edge", "other")
        self.event("edge", "entrya", port=2101)
        self.store.sample([self.connection(port=3366, typ="AnyTLS")], self.now + 1)
        self.assertIsNone(self.store.db.execute("select source_ip from connection_state").fetchone()[0])
        self.event("edge", "entrya", port=28600)
        for network in ("tcp", "udp"):
            connection = self.connection(network=network, port=3366, typ="AnyTLS")
            connection["id"] = network
            self.store.sample([connection], self.now + 2)
            row = self.store.db.execute(
                "select source_ip,node,quality from connection_state where connection_id=?", (network,)).fetchone()
            self.assertEqual(tuple(row), ("203.0.113.8", "entrya", "ciphertext_fingerprint"))

    def test_anytls_requires_explicit_listener_type(self):
        self.assertEqual(self.store.sample([self.connection(typ="AnyTLS")], self.now + 1)["active_connections"], 0)

    def test_route_configuration_fails_closed(self):
        for key, value in [("node", "unknown"), ("entry_port", 999), ("inbound_port", 999), ("transport", "icmp")]:
            config = copy.deepcopy(self.config)
            config["fingerprint_routes"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                fingerprint_routes(config)
        for spec in [{"999": ["ShadowSocks"]}, {"2101": ["Unknown"]}, {"2101": []}]:
            with self.assertRaises(ValueError):
                inbound_types(dict(self.config, inbound_types=spec))

    def test_edge_runtime_uses_client_facing_filter(self):
        instance = audit.Audit.__new__(audit.Audit)
        instance.config = {"mode": "edge"}
        instance.errors = {}
        instance.capture_event = lambda event: None
        with patch("capture.Capture") as capture:
            capture.return_value.tcp_ports = [28960]
            capture.return_value.udp_ports = [28960]
            instance.capture({"interface": "ens3", "front_address": "172.29.17.195",
                              "tcp_ports": [28960], "udp_ports": [28960]})
            self.assertIn("dst host 172.29.17.195", capture.return_value.bpf)
            capture.return_value.run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
