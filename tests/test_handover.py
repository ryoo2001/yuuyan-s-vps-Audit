"""Offline documentation/contract guard regressions; never use live credentials."""
import ast
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("handover_check", ROOT / "tools/check.py")
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)


class HandoverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="audit-check-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        public_link_targets = (
            "edge_front.py", "config/entry-b2.json", "config/entrya-hk-2101.json", "tests/test_edge_front.py",
            "deploy/traffic-audit-entryb2-edge.service", "deploy/traffic-audit-entryb2-tunnel.service",
            "deploy/entryb2-audit.manifest.json", "deploy/hk2-audit.manifest.json",
            "config/term-b1.json", "deploy/hk-tb1-audit.manifest.json",
            "deploy/hk-route-display.manifest.json", "deploy/entrya-split.manifest.json",
            "docs/patch-2026.10.11.1.md", "deploy/patch-2026.10.11.1.manifest.json",
            "central/rollup_patch.py",
            "deploy/traffic-audit-wbt.service", "deploy/traffic-audit-wbt.conf",
            "central/hk_receive.py", "central/hk_merge.py", "central/hk_query.py", "central/hk_query_core.py",
            "deploy/merge-hk.py", "deploy/hk-merge.manifest.json",
            "deploy/hk-links.manifest.json", "deploy/hk-center-move.manifest.json",
            "deploy/traffic-audit-publish-hk-tb1.service",
            "deploy/datawave-move.manifest.json",
            "central/hk_summary.py", "deploy/hk-summary.py", "deploy/hk-summary.manifest.json",
            "central/storage.py", "central/region.py", "central/test_storage_mysql.py",
            "deploy/storage.py", "deploy/storage.manifest.json", "docs/storage.md",
            "central/tier_policy.py", "central/tiering.py", "central/archive.py", "central/test_archive_mysql.py",
            "central/traffic-central-archive.service", "central/traffic-central-archive.timer",
            "deploy/tiers.py", "deploy/tiers_migrate.py", "deploy/tiers.manifest.json",
            "central/monthbook.py", "central/test_monthbook_mysql.py", "deploy/month_migrate.py", "deploy/month.manifest.json",
            "docs/database-optimization.md", "deploy/hk-l4-24864.manifest.json", "deploy/entrya2.manifest.json",
            "deploy/stream.manifest.json", "deploy/hk-unknown-fix.manifest.json", "deploy/optimize.manifest.json",
            "central/detail_view.py",
        )
        for name in (*check.REQUIRED_FILES, *public_link_targets):
            if not (ROOT / name).is_file():
                continue  # Private deployment records are intentionally absent in public checkouts.
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if name in check.EVIDENCE_FILES:
                target.write_text("{}", encoding="utf8")  # No historical client data copied.
            else:
                shutil.copyfile(ROOT / name, target)
        if (ROOT / "docs/baseline.json").is_file():
            shutil.copyfile(ROOT / "docs/baseline.json", self.root / "docs/baseline.json")

    def edit(self, name, before, after):
        path = self.root / name
        original = path.read_text(encoding="utf8")
        self.assertIn(before, original)
        path.write_text(original.replace(before, after), encoding="utf8")

    def expect_error(self, part, baseline=False):
        report = check.check_project(self.root, baseline)
        self.assertFalse(report["ok"], report)
        self.assertTrue(any(part in error for error in report["errors"]), report)
        self.assertFalse(report["network_used"])
        return report

    def test_current_project_contracts(self):
        report = check.check_project(ROOT)
        self.assertTrue(report["ok"], report)

    def test_shared_audit_entry_port_rejected(self):
        self.edit("config/entry-a4.json", "203.0.113.101:3396", "203.0.113.101:3395")
        self.expect_error("edge endpoint mismatch: entry-a4")

    def test_jp_shadowsocks_sampling_type_required(self):
        path = self.root / "config/term-a1.json"
        config = json.loads(path.read_text(encoding="utf8"))
        config["inbound_types"]["3386"] = ["Mieru"]
        path.write_text(json.dumps(config), encoding="utf8")
        self.expect_error("JP SS2022 protocol drift")

    def test_termb4_edge_cannot_upload_to_retired_terminal(self):
        self.edit("config/entrya-hk-2101.json", "http://127.0.0.1:19091", "http://203.0.113.115:19091")
        self.expect_error("term-b4 edge identity/endpoint drift: entry-a1")

    def test_tb3_peer_and_fingerprint_must_match_new_carrier(self):
        path = self.root / "config/term-b3.json"
        config = json.loads(path.read_text(encoding="utf8"))
        config["peers"]["entry-b2"]["udp_ports"] = [24864]
        config["fingerprint_routes"][0]["entry_port"] = 28900
        path.write_text(json.dumps(config), encoding="utf8")
        self.expect_error("Tb3 edge/terminal port mismatch: entry-b2")
        self.expect_error("Tb3 fingerprint route drift")

    def test_hk_cloud_rejects_old_24865_capture(self):
        path = self.root / "config/entry-b1-tb3.json"
        config = json.loads(path.read_text(encoding="utf8"))
        config["captures"][0]["tcp_ports"] = [24865]
        path.write_text(json.dumps(config), encoding="utf8")
        self.expect_error("Tb3 edge/terminal port mismatch: entry-b1")

    def test_hk_anytls_requires_explicit_type(self):
        path = self.root / "config/term-b1.json"
        config = json.loads(path.read_text(encoding="utf8"))
        del config["inbound_types"]["24443"]
        path.write_text(json.dumps(config), encoding="utf8")
        self.expect_error("HK explicit protocol drift")

    def test_hk_anytls_wrong_carrier_or_route_rejected(self):
        path = self.root / "config/term-b1.json"
        config = json.loads(path.read_text(encoding="utf8"))
        config["captures"][0]["tcp_ports"].remove(24443)
        config["captures"][0]["udp_ports"].append(24443)
        config["fingerprint_routes"][-1]["entry_port"] = 28900
        path.write_text(json.dumps(config), encoding="utf8")
        self.expect_error("HK AnyTLS TCP carrier capture drift")
        self.expect_error("HK AnyTLS fingerprint route drift")

    def test_entrya_cm_listener_not_reused(self):
        path = self.root / "config/term-a1.json"
        config = json.loads(path.read_text(encoding="utf8"))
        for route in config["fingerprint_routes"]:
            if route["node"] == "entry-a1" and route["entry_port"] == 28600:
                route["inbound_port"] = 3366
        path.write_text(json.dumps(config), encoding="utf8")
        self.expect_error("terminal DNAT fingerprint route drift")

    def test_sh1_3990_missing_fingerprint_route_rejected(self):
        path = self.root / "config/term-a1.json"
        config = json.loads(path.read_text(encoding="utf8"))
        config["fingerprint_routes"] = [route for route in config["fingerprint_routes"]
                                        if not (route["node"] == "entry-a4"
                                                and route["entry_port"] == 3990
                                                and route["transport"] == "udp")]
        path.write_text(json.dumps(config), encoding="utf8")
        self.expect_error("terminal DNAT fingerprint route drift")

    def test_runtime_tunnel_signing_identity_rejected(self):
        self.edit("config/entry-a3.json", "/etc/traffic-audit/identity.toml", "/run/easytier-udp3990/config.toml")
        self.expect_error("edge signing identity must survive tunnel retirement: entry-a3")

    def test_checker_read_only(self):
        before = {p.relative_to(self.root).as_posix(): check.sha256(p) for p in self.root.rglob("*") if p.is_file()}
        report = check.check_project(self.root)
        self.assertTrue(report["ok"], report)
        after = {p.relative_to(self.root).as_posix(): check.sha256(p) for p in self.root.rglob("*") if p.is_file()}
        self.assertEqual(before, after)

    def test_missing_required_file(self):
        (self.root / "docs/storage.md").unlink()
        self.expect_error("missing file: docs/storage.md")

    def test_public_checkout_without_private_evidence(self):
        (self.root / "docs/baseline.json").unlink(missing_ok=True)
        self.assertTrue(check.check_project(self.root)["ok"])
        self.expect_error("--baseline requires", baseline=True)

    def test_broken_link(self):
        self.edit("README.md", "(docs/data.md)", "(docs/missing.md)")
        self.expect_error("broken link")

    def test_link_outside_project(self):
        self.edit("README.md", "(docs/data.md)", "(../outside.md)")
        self.expect_error("link escapes project")

    def test_external_links_not_fetched(self):
        path = self.root / "README.md"
        path.write_text(path.read_text(encoding="utf8") + "\n[external](https://does-not-exist.invalid/)\n", encoding="utf8")
        self.assertTrue(check.check_project(self.root)["ok"])

    def test_rate_contract_drift(self):
        self.edit("rates.py", "RATE_WINDOW_SECONDS = 5", "RATE_WINDOW_SECONDS = 10")
        self.expect_error("RATE_WINDOW_SECONDS")

    def test_sync_contract_drift(self):
        self.edit("central/publish.py", "SYNC_INTERVAL_SECONDS = 60", "SYNC_INTERVAL_SECONDS = 30")
        self.expect_error("SYNC_INTERVAL_SECONDS")

    def test_view_column_drift(self):
        self.edit("central/views.sql", "AS `IP归属地`", "AS `归属地原始值`")
        self.expect_error("view column order drift")

    def test_provider_mapping_guard(self):
        self.edit("central/views.sql", " AND (c.node IS NULL OR c.node='')", "")
        self.expect_error("view identity/time/dedup guard missing")

    def test_completed_minute_guard(self):
        self.edit("central/views.sql", "bucket < FLOOR(UNIX_TIMESTAMP()/60)*60", "bucket <= FLOOR(UNIX_TIMESTAMP()/60)*60")
        self.expect_error("incomplete minute not excluded")

    def test_config_transport_mismatch(self):
        path = self.root / "config/entry-a4.json"
        cfg = json.loads(path.read_text(encoding="utf8"))
        cfg["upload_transport"] = "udp"
        path.write_text(json.dumps(cfg), encoding="utf8")
        self.expect_error("edge transport mismatch")

    def test_retired_edge_config_rejected(self):
        (self.root / "config/entry-a0.json").write_text("{}", encoding="utf8")
        self.expect_error("retired edge config must be absent")

    def test_retired_edge_health_membership_rejected(self):
        self.edit("central/query.py", "entry-a1,entry-a3,entry-a4", "entry-a1,entry-a0,entry-a3")
        self.expect_error("central active edge membership drift")

    def test_unused_udp_receiver_rejected(self):
        path = self.root / "config/term-a2.json"
        cfg = json.loads(path.read_text(encoding="utf8"))
        cfg["udp_listen"] = ["10.77.250.1"]
        path.write_text(json.dumps(cfg), encoding="utf8")
        self.expect_error("unused UDP receiver must be disabled")

    def test_mysql_no_public_bind(self):
        self.edit("central/mysql.cnf", "bind-address=127.0.0.1", "bind-address=0.0.0.0")
        self.expect_error("MySQL must bind loopback")

    @unittest.skipUnless((ROOT / "docs/baseline.json").is_file(), "private baseline not published")
    def test_optional_hash_drift(self):
        path = self.root / "rates.py"
        path.write_text(path.read_text(encoding="utf8") + "\n# local-only intentional edit\n", encoding="utf8")
        self.assertTrue(check.check_project(self.root)["ok"])
        self.expect_error("local baseline drift: rates.py", True)

    @unittest.skipUnless((ROOT / "docs/baseline.json").is_file(), "private baseline not published")
    def test_manifest_cannot_request_secret_file(self):
        path = self.root / "docs/baseline.json"
        manifest = json.loads(path.read_text(encoding="utf8"))
        manifest["local_sources"]["client/connection.json"] = "0" * 64
        path.write_text(json.dumps(manifest), encoding="utf8")
        report = self.expect_error("unapproved baseline path (not read): client/connection.json", True)
        self.assertFalse(any("FileNotFoundError" in e for e in report["errors"]))

    @unittest.skipUnless((ROOT / "docs/baseline.json").is_file(), "private baseline not published")
    def test_manifest_cannot_read_outside_project(self):
        path = self.root / "docs/baseline.json"
        manifest = json.loads(path.read_text(encoding="utf8"))
        manifest["local_sources"]["../outside.key"] = "0" * 64
        path.write_text(json.dumps(manifest), encoding="utf8")
        self.expect_error("unapproved baseline path (not read): ../outside.key", True)

    @unittest.skipUnless((ROOT / "docs/baseline.json").is_file(), "private baseline not published")
    def test_manifest_false_remote_match(self):
        path = self.root / "docs/baseline.json"
        manifest = json.loads(path.read_text(encoding="utf8"))
        manifest["remote_files"][0]["sha256"] = "0" * 64
        path.write_text(json.dumps(manifest), encoding="utf8")
        self.expect_error("remote/local record claims false match")

    @unittest.skipUnless((ROOT / "docs/baseline.json").is_file(), "private baseline not published")
    def test_malformed_manifest_reports_error(self):
        (self.root / "docs/baseline.json").write_text("not json", encoding="utf8")
        self.expect_error("JSONDecodeError")

    def test_safe_path_guards(self):
        for path in ("../outside", "/absolute", "C:/windows", "docs\\file", ""):
            with self.subTest(path=path), self.assertRaises(ValueError):
                check.safe_path(self.root, path)

    def test_static_reader_never_executes_script(self):
        path = self.root / "rates.py"
        path.write_text("raise RuntimeError('never execute')\n" + path.read_text(encoding="utf8"), encoding="utf8")
        self.assertTrue(check.check_project(self.root)["ok"])
        with self.assertRaises(ValueError):
            check.static_value(ast.parse("open('private.key').read()", mode="eval").body)

    def test_cli_json(self):
        out = io.StringIO()
        with redirect_stdout(out):
            status = check.main(["--json"])
        self.assertEqual(status, 0)
        self.assertTrue(json.loads(out.getvalue())["ok"])


if __name__ == "__main__":
    unittest.main()
