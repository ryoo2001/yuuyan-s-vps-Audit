"""Publication guards use synthetic content; no live credentials."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("publish_check", ROOT / "tools/publish_check.py")
scan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scan)


class PublishTests(unittest.TestCase):
    def test_private_paths_rejected(self):
        for name in ("client/connection.json", "deploy/request.json", "docs/state.md",
                     ".tiers/payload.json", "drafts/design.md", "AGENTS.md",
                     "releases/old/audit.py", "notes.log", "id_ed25519"):
            with self.subTest(name=name):
                self.assertFalse(scan.path_allowed(name))

    def test_source_paths_allowed(self):
        for name in ("audit.py", "config/term-a1.json", "central/backup.sh",
                     ".gitignore", "README.md"):
            self.assertTrue(scan.path_allowed(name), name)

    def test_private_key_rejected(self):
        data = b"-----BEGIN " + b"OPENSSH PRIVATE KEY-----"
        self.assertIn("private-key", scan.scan_blob("audit.py", data))

    def test_token_rejected(self):
        data = b"gh" + b"p_" + b"a" * 30
        self.assertIn("github-token", scan.scan_blob("audit.py", data))

    def test_binary_rejected(self):
        self.assertIn("binary-or-non-utf8-file", scan.scan_blob("audit.py", b"a\x00b"))

    def test_negative_auth_probe_is_narrow_exception(self):
        value = b'password = "' + b'intentionally-wrong-audit-validation' + b'"'
        self.assertEqual(scan.scan_blob("client/verify.py", value), [])
        self.assertIn("credential-assignment", scan.scan_blob("audit.py", value))


if __name__ == "__main__":
    unittest.main()
