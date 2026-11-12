"""Check staged Git blobs, not working-tree copies, before publication.

Reports paths and rule names only; never prints matching secret values.
This is a guardrail, not a substitute for reviewing new configuration.
"""
from pathlib import Path, PurePosixPath
import re
import json
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_SUFFIXES = {".py", ".mjs", ".ps1", ".sql", ".json", ".md",
                    ".service", ".timer", ".conf", ".cnf", ".nft", ".sh"}
PRIVATE_PATHS = {"client/connection.json", "client/status.json",
                 "docs/state.md", "docs/baseline.json", "docs/integration.md"}
PATTERNS = {
    "private-key": rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----",
    "github-token": rb"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})",
    "aws-access-key": rb"(?:AKIA|ASIA)[A-Z0-9]{16}",
    "slack-token": rb"xox[baprs]-[A-Za-z0-9-]{20,}",
    "credential-url": rb"(?:mysql|postgres(?:ql)?|https?|ssh)://[^\s/:]+:[^\s/@]+@",
    "credential-assignment": rb'''(?i)["']?(?:password|passwd|network_secret|api_key|access_token|private_key)["']?\s*[:=]\s*["']([^"'\r\n]{12,})["']''',
}


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def path_allowed(name):
    path = PurePosixPath(name)
    if name in PRIVATE_PATHS or any(part.startswith(".") for part in path.parts):
        return name in {".gitignore", ".gitattributes"}
    if path.name == "AGENTS.md" or path.parts[0] in {"releases", "drafts", "logs", "backups"}:
        return False
    if "__pycache__" in path.parts or name.startswith("client/lib/"):
        return False
    if path.suffix.lower() not in ALLOWED_SUFFIXES:
        return False
    if path.suffix.lower() == ".json" and not name.startswith("config/"):
        return False
    if path.name.startswith("patch-") and path.suffix == ".md":
        return False
    return True


def scan_blob(name, data):
    errors = []
    if not path_allowed(name):
        errors.append("private-or-unapproved-path")
    if b"\x00" in data:
        errors.append("binary-or-non-utf8-file")
    try:
        data.decode("utf-8-sig")
    except UnicodeDecodeError:
        errors.append("non-utf8-file")
    for rule, pattern in PATTERNS.items():
        for match in re.finditer(pattern, data):
            if rule == "credential-assignment":
                value = match.group(1)
                if name == "client/verify.py" and value == b"intentionally-wrong-audit-validation":
                    continue  # Reviewed negative authentication probe, never a valid credential.
                if (value.startswith((b"/etc/", b"/run/", b"/var/", b"<"))
                        or b"Path(" in value or b" + " in value or b"secrets." in value):
                    continue
            errors.append(rule)
            break
    return errors


def main():
    try:
        known_secrets = []
        private_config = ROOT / "client/connection.json"
        if private_config.is_file():
            config = json.loads(private_config.read_text(encoding="utf-8-sig"))
            for key in ("password", "secret", "token", "network_secret"):
                value = config.get(key)
                if isinstance(value, str) and len(value) >= 8:
                    known_secrets.append(value.encode("utf8"))
        entries = git("ls-files", "--stage", "-z").split(b"\x00")
        failures, count = [], 0
        for entry in filter(None, entries):
            meta, raw_name = entry.split(b"\t", 1)
            mode, oid, stage = meta.split()
            name = raw_name.decode("utf8")
            count += 1
            if mode not in (b"100644", b"100755") or stage != b"0":
                failures.append((name, ["unsupported-index-entry"]))
                continue
            data = git("cat-file", "blob", oid.decode("ascii"))
            issues = scan_blob(name, data)
            if any(secret in data for secret in known_secrets):
                issues.append("known-local-credential")
            if issues:
                failures.append((name, issues))
        if not count:
            print("FAIL: no staged/tracked files to inspect")
            return 1
        for name, issues in failures:
            print(f"FAIL: {name}: {', '.join(issues)}")
        print(f"{'FAIL' if failures else 'PASS'}: {count} staged files inspected")
        return int(bool(failures))
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"FAIL: staged scan unavailable ({type(exc).__name__})")
        return 1


if __name__ == "__main__":
    sys.exit(main())
