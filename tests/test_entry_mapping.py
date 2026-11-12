"""Exercise the production MySQL entry CASE without changing source identity."""
import re
import json
import sqlite3
import unittest
from pathlib import Path


class EntryMappingTests(unittest.TestCase):
    def setUp(self):
        sql = (Path(__file__).resolve().parents[1] / "central" / "views.sql").read_text(encoding="utf-8")
        match = re.search(r"(CASE WHEN c\.source_peer=.*?END) AS `隧道内网 IP（入口机器）`", sql, re.S)
        self.assertIsNotNone(match)
        self.entry_case = match.group(1)
        self.db = sqlite3.connect(":memory:")
        self.db.create_function("CONCAT", -1, lambda *args: None if None in args else "".join(args))

    def tearDown(self):
        self.db.close()

    def display(self, peer="172.30.3.3", source=None, node=None, route=None, tunnel=None):
        return self.db.execute(
            "SELECT COALESCE(NULLIF(c.source_ip,''),'未识别'), " + self.entry_case +
            " FROM (SELECT ? source_peer,? source_ip,? node) c"
            " CROSS JOIN (SELECT ? node,? tunnel_ip) r",
            (peer, source, node, route, tunnel),
        ).fetchone()

    def test_confirmed_peer_maps_entry_not_source(self):
        self.assertEqual(self.display(), ("未识别", "172.30.3.3（云厂入口：203.0.113.103）"))

    def test_empty_identity_also_maps_entry(self):
        self.assertEqual(self.display(source="", node=""), self.display())

    def test_other_unknown_peers_are_not_mapped(self):
        for peer in ("10.77.250.1", "10.77.251.1", "172.30.3.30", "", None):
            with self.subTest(peer=peer):
                self.assertEqual(self.display(peer=peer), ("未识别", "未识别"))

    def test_public_address_is_not_used_as_peer_evidence(self):
        self.assertEqual(self.display(peer="203.0.113.103"), ("未识别", "未识别"))

    def test_existing_source_identity_is_preserved(self):
        self.assertEqual(self.display(source="198.51.100.27")[0], "198.51.100.27")

    def test_verified_probe_route_takes_precedence(self):
        self.assertEqual(self.display(source="198.51.100.27", node="entry-a1",
                                     route="entry-a1", tunnel="10.77.250.2"),
                         ("198.51.100.27", "10.77.250.2（entry-a1）"))

    def test_unverified_nonempty_node_is_not_reassigned(self):
        self.assertEqual(self.display(source="198.51.100.27", node="another-entry"),
                         ("198.51.100.27", "未核验（another-entry）"))

    def test_existing_direct_entry_is_preserved(self):
        self.assertEqual(self.display(source="198.51.100.27", node="entry-a1", route="entry-a1"),
                         ("198.51.100.27", "直连（entry-a1；未经过隧道）"))

    def hk_routes(self):
        config = json.loads((Path(__file__).resolve().parents[1] / "config" / "term-b1.json").read_text(encoding="utf-8"))
        return {route["node"]: route["tunnel_ip"] for route in config["entry_routes"]}

    def test_entryb2_uses_current_public_entry_without_changing_source(self):
        route = self.hk_routes()["entry-b2"]
        self.assertEqual(route, "203.0.113.111")
        self.assertEqual(self.display(peer="10.77.65.1", source="198.51.100.27",
                                     node="entry-b2", route="entry-b2", tunnel=route),
                         ("198.51.100.27", "203.0.113.111（entry-b2）"))

    def test_entrya_displays_public_entry_and_shared_relay_is_not_identity(self):
        route = self.hk_routes()["entry-a1"]
        self.assertEqual(route, "203.0.113.114")
        self.assertEqual(self.display(peer="10.77.65.1", source="198.51.100.27",
                                     node="entry-a1", route="entry-a1", tunnel=route),
                         ("198.51.100.27", "203.0.113.114（entry-a1）"))
        self.assertEqual(self.display(peer="10.77.65.1"), ("未识别", "未识别"))

    def test_verified_entry_with_unknown_customer_remains_visible(self):
        self.assertEqual(self.display(peer="10.77.66.1", node="entry-a1",
                                     route="entry-a1", tunnel="10.77.63.1"),
                         ("未识别", "10.77.63.1（entry-a1）"))
        self.assertEqual(self.display(peer="10.77.66.1", node="unexpected"),
                         ("未识别", "未识别"))


if __name__ == "__main__":
    unittest.main()
