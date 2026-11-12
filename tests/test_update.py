import importlib.util
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_update", ROOT / "deploy" / "update.py")
update = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(update)


class UpdatePlanTests(unittest.TestCase):
    def test_plan_is_single_host_and_contains_health_gate(self):
        requests, manifest = update.build_request("term-a2")
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]["args"]["hostId"], "term-a2")
        command = requests[0]["args"]["command"]
        self.assertIn("AUDIT_RELEASE_PREFLIGHT", command)
        self.assertIn("AUDIT_RELEASE_HEALTH", command)
        self.assertIn("traffic-audit.service", command)
        self.assertIn("source_ip", command)
        self.assertIn("non-target service state changed during update", command)
        self.assertEqual(manifest["component"], "collector")
        self.assertFalse(manifest["include_config"])

    def test_config_is_opt_in(self):
        requests, manifest = update.build_request("entry-a1", include_config=True)
        paths = {item["remote"] for item in manifest["files"]}
        self.assertIn("/etc/traffic-audit/config.json", paths)
        self.assertIn("/etc/traffic-audit/config.json", requests[0]["args"]["command"])

    def test_manifest_links_changed_scope_to_validation(self):
        _, manifest = update.build_request("term-a2", changed=("presentation.py",))
        self.assertEqual(manifest["validation"]["level"], "L3")
        self.assertIn("test_presentation.py", manifest["validation"]["test_files"])
        self.assertIn("pending", manifest["validation"]["acceptance"])

    def test_unknown_or_unsafe_host_is_rejected(self):
        with self.assertRaises(ValueError):
            update.build_request("../term-a2")
        with self.assertRaises(ValueError):
            update.build_request("client")

    def test_plan_does_not_read_or_embed_private_client_material(self):
        requests, _ = update.build_request("term-a2")
        encoded = json.dumps(requests, ensure_ascii=True)
        self.assertNotIn("client/connection.json", encoded)
        self.assertNotIn("hosts.json", encoded)


if __name__ == "__main__":
    unittest.main()
