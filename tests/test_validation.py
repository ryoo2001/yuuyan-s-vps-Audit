"""Deployment-check routing, evidence, and failure gates; no live configuration."""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("validation", ROOT / "tools/validate.py")
validation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validation)


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="audit-validation-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        for name in (*validation.COLLECTOR, "deploy/traffic-audit.service"):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)

    def accepted_release(self, mode="edge"):
        files = [{"remote": f"/usr/local/libexec/traffic-audit/{name}",
                  "sha256": validation.normalized_hash(self.root / name)} for name in validation.COLLECTOR]
        files.append({"remote": "/etc/systemd/system/traffic-audit.service",
                      "sha256": validation.normalized_hash(self.root / "deploy/traffic-audit.service", mode == "terminal")})
        data = {"component": "collector", "mode": mode, "files": files,
                "verification": {"status": "passed", "verified_at": "2026-10-01T12:00:00+08:00",
                                 "checks": ["edge_telemetry", "collector_runtime", "central_sync", "protected"]}}
        (self.root / "deploy/accepted.manifest.json").write_text(json.dumps(data), encoding="utf8")
        return "deploy/accepted.manifest.json"

    def test_docs_has_no_regression_build_or_remote_work(self):
        plan = validation.build_plan("docs", ["docs/state.md"])
        self.assertEqual(plan["level"], "L0")
        self.assertEqual([t["id"] for t in plan["local_tasks"]], ["handover"])
        self.assertEqual(plan["remote_gates"], [])

    def test_accepted_edge_install_minimum(self):
        plan = validation.build_plan("edge-install", release=self.accepted_release(), root=self.root)
        self.assertEqual(plan["level"], "L1")
        self.assertEqual(plan["test_files"], [])
        self.assertFalse(plan["full_suite"])
        gates = {g["id"] for g in plan["remote_gates"]}
        self.assertTrue({"artifact", "edge_telemetry", "central_sync", "protected"} <= gates)
        self.assertFalse({"view_fixture", "sync_fixture", "retention_fixture"} & gates)

    def test_terminal_mode_unit_matches_generator(self):
        spec = importlib.util.spec_from_file_location("release_update", ROOT / "deploy/update.py")
        update = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(update)
        generated = update.files_for("term-a2", {"mode": "terminal"}, False)
        expected = next(item["sha256"] for item in generated if item["remote"].endswith(".service"))
        self.assertEqual(validation.normalized_hash(self.root / "deploy/traffic-audit.service", True), expected)
        plan = validation.build_plan("terminal-install", release=self.accepted_release("terminal"), root=self.root)
        self.assertEqual(plan["level"], "L1")

    def test_missing_evidence_includes_shared_maintenance_regressions(self):
        plan = validation.build_plan("edge-install", root=self.root)
        self.assertEqual(plan["level"], "L3")
        self.assertIn("test_presentation.py", plan["test_files"])
        self.assertIn("test_central.py", plan["test_files"])
        self.assertIn("test_performance.py", plan["test_files"])
        self.assertFalse(plan["full_suite"])

    def test_one_changed_artifact_runs_only_its_regressions(self):
        release = self.accepted_release()
        with (self.root / "presentation.py").open("a", encoding="utf8") as file:
            file.write("\n# changed\n")
        plan = validation.build_plan("edge-install", release=release, root=self.root)
        self.assertEqual(plan["unverified_artifacts"], ["presentation.py"])
        self.assertEqual(plan["level"], "L3")
        self.assertEqual(plan["test_files"], ["test_presentation.py", "test_query.py"])

    def test_generated_manifest_is_not_acceptance_evidence(self):
        release = self.accepted_release()
        path = self.root / release
        data = json.loads(path.read_text())
        del data["verification"]
        path.write_text(json.dumps(data))
        self.assertTrue(validation.build_plan("edge-install", release=release, root=self.root)["unverified_artifacts"])

    def test_role_mismatch_cannot_downgrade(self):
        plan = validation.build_plan("terminal-install", release=self.accepted_release("edge"), root=self.root)
        self.assertGreater(len(plan["test_files"]), 0)

    def test_future_or_timezone_free_evidence_cannot_downgrade(self):
        for date in ("2026-10-01T12:00:00", "2999-01-01T00:00:00+08:00"):
            release = self.accepted_release()
            path = self.root / release
            data = json.loads(path.read_text())
            data["verification"]["verified_at"] = date
            path.write_text(json.dumps(data))
            self.assertTrue(validation.build_plan("edge-install", release=release, root=self.root)["unverified_artifacts"])

    def test_business_label_cannot_hide_code_risk(self):
        plan = validation.build_plan("docs", ["central/receive.py", "capture.py"])
        self.assertEqual(plan["level"], "L3")
        self.assertIn("test_central.py", plan["test_files"])
        self.assertIn("test_capture.py", plan["test_files"])
        self.assertFalse(plan["full_suite"])

    def test_unknown_code_requires_full_regression(self):
        plan = validation.build_plan("docs", ["new_module.py"])
        self.assertEqual(plan["level"], "L3")
        self.assertTrue(plan["full_suite"])

    def test_private_and_traversal_inputs_are_rejected_before_reading(self):
        for path in ("../outside.py", "client/connection.json", "hosts.json", "deploy/old.json", "C:/private.py"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                validation.build_plan("docs", [path], root=self.root)
        with self.assertRaises(ValueError):
            validation.build_plan("edge-install", release="client/connection.json", root=self.root)

    def test_ops_docs_skip_build_and_audit_scope_is_focused(self):
        docs = validation.build_plan("docs", ops="docs")
        self.assertFalse(any(t["id"].startswith("ops:") for t in docs["local_tasks"]))
        audit = validation.build_plan("docs", ops="audit")
        ops_tasks = [t for t in audit["local_tasks"] if t["id"].startswith("ops:")]
        self.assertEqual([t["id"] for t in ops_tasks], ["ops:typecheck", "ops:test", "ops:build"])
        self.assertIn("tests/audit.test.mjs", ops_tasks[1]["argv"])
        self.assertNotIn("tests/config-write.test.mjs", ops_tasks[1]["argv"])
        self.assertEqual([g["id"] for g in audit["remote_gates"]], ["mcp_live"])

    def test_dataset_requires_isolation(self):
        plan = validation.build_plan("dataset")
        self.assertEqual(plan["level"], "L3")
        self.assertIn("isolation", {g["id"] for g in plan["remote_gates"]})

    def test_fail_fast_does_not_run_later_tasks(self):
        plan = validation.build_plan("deploy")
        calls = []
        def runner(argv, **kwargs):
            calls.append(argv)
            self.assertFalse(kwargs["shell"])
            return subprocess.CompletedProcess(argv, 1, "failed", "")
        result = validation.execute_local(plan, runner=runner)
        self.assertEqual(result["status"], "local_failed")
        self.assertEqual(len(calls), 1)
        self.assertFalse(result["remote_executed"])

    def test_local_pass_preserves_pending_remote_gates(self):
        plan = validation.build_plan("query", ["query.py"])
        def runner(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, "ok", "")
        result = validation.execute_local(plan, runner=runner)
        self.assertEqual(result["status"], "local_pass_remote_pending")
        self.assertFalse(result["remote_executed"])

    def test_missing_selected_test_is_failure_not_zero_test_success(self):
        plan = validation.build_plan("docs", ["tests/test_missing.py"], root=self.root)
        calls = []
        def runner(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, "ok", "")
        result = validation.execute_local(plan, root=self.root, runner=runner)
        self.assertEqual(result["status"], "local_failed")
        self.assertIn("selected test file is missing", result["results"][-1]["output"])
        self.assertEqual(len(calls), 1)

    def test_duplicate_release_paths_are_rejected(self):
        release = self.accepted_release()
        path = self.root / release
        data = json.loads(path.read_text())
        data["files"].append(data["files"][0])
        path.write_text(json.dumps(data))
        with self.assertRaises(ValueError):
            validation.build_plan("edge-install", release=release, root=self.root)


if __name__ == "__main__":
    unittest.main()
