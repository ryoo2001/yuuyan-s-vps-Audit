#!/usr/bin/env python3
"""Build a reviewed center-only IP geolocation deployment request."""

import base64
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
def normalized(path):
    return (ROOT / path).read_text(encoding="utf8").replace("\r\n", "\n").rstrip("\n") + "\n"


def build_command():
    files = [
        ("central/ipgeo.py", "/usr/local/libexec/traffic-central-storage/ipgeo.py"),
        ("central/storage.py", "/usr/local/libexec/traffic-central-storage/storage.py"),
        ("central/region.py", "/usr/local/libexec/traffic-central-storage/region.py"),
        ("central/detail_view.py", "/usr/local/libexec/traffic-central-storage/detail_view.py"),
        ("central/views.sql", "/usr/local/libexec/traffic-central-storage/views.sql"),
        ("central/views.sql", "/usr/local/libexec/traffic-central/views.sql"),
        ("central/query.py", "/usr/local/libexec/traffic-central/query.py"),
        ("query.py", "/usr/local/libexec/traffic-central/source_query.py"),
        ("presentation.py", "/usr/local/libexec/traffic-central/presentation.py"),
        ("central/traffic-central-geo.service", "/etc/systemd/system/traffic-central-geo.service"),
        ("central/traffic-central-geo.timer", "/etc/systemd/system/traffic-central-geo.timer"),
    ]
    lines = [
        "set -Eeuo pipefail",
        "umask 077",
        "stage=$(mktemp -d /var/tmp/traffic-central-geo-stage.XXXXXX)",
        "backup=$(mktemp -d /var/tmp/traffic-central-geo-backup.XXXXXX)",
        "changed=0",
        "cleanup() { rc=$?; if [ \"$rc\" -ne 0 ] && [ \"$changed\" -eq 1 ]; then for p in "
        + " ".join("'" + remote + "'" for _, remote in files)
        + "; do rel=${p#/}; if [ -f \"$backup/$rel\" ]; then install -m 600 \"$backup/$rel\" \"$p\"; else rm -f -- \"$p\"; fi; done; systemctl daemon-reload; fi; rm -rf -- \"$stage\" \"$backup\"; exit \"$rc\"; }",
        "trap cleanup EXIT",
        "mkdir -p \"$stage/usr/local/libexec/traffic-central-storage\" \"$stage/usr/local/libexec/traffic-central\" \"$stage/etc/systemd/system\" \"$stage/etc/traffic-central\"",
        "mkdir -p /var/lib/traffic-central/geo",
    ]
    for source, remote in files:
        body = normalized(source)
        digest = hashlib.sha256(body.encode("utf8")).hexdigest()
        encoded = base64.b64encode(body.encode("utf8")).decode("ascii")
        relative = remote.lstrip("/")
        lines.extend([
            f"if [ -f '{remote}' ]; then rel='{relative}'; mkdir -p \"$backup/$(dirname \"$rel\")\"; cp -p '{remote}' \"$backup/$rel\"; fi",
            f"printf '%s' '{encoded}' | base64 -d > \"$stage/{relative}\"",
            f"printf '%s  %s\\n' '{digest}' \"$stage/{relative}\" | sha256sum -c -",
        ])
    lines.extend([
        "/usr/bin/python3 - \"$stage\" <<'TRAFFIC_GEO_COMPILE'\nimport sys\nfrom pathlib import Path\nroot=Path(sys.argv[1])\nfor path in root.rglob('*.py'):\n    compile(path.read_text(encoding='utf8'), str(path), 'exec')\nTRAFFIC_GEO_COMPILE",
        "systemd-analyze verify \"$stage/etc/systemd/system/traffic-central-geo.service\" \"$stage/etc/systemd/system/traffic-central-geo.timer\"",
    ])
    for _, remote in files:
        relative = remote.lstrip("/")
        mode = "644" if remote.endswith((".service", ".timer", ".sql")) else "750"
        lines.append(f"install -m {mode} \"$stage/{relative}\" '{remote}'")
    lines.extend([
        "changed=1",
        "systemctl daemon-reload",
        "/usr/bin/python3 /usr/local/libexec/traffic-central-storage/ipgeo.py run",
        "changed=2",
        "systemctl enable --now traffic-central-geo.timer",
        "systemctl is-enabled traffic-central-geo.timer",
        "systemctl is-active traffic-central-geo.timer",
        "find /var/lib/traffic-central/geo -maxdepth 1 -type f -printf '%f %s bytes\\n' | sort",
        "echo traffic-central-geo deployment completed",
    ])
    return "\n".join(lines) + "\n"


def build_request(host="center-host"):
    command = build_command()
    return [{
        "tool": "ops_ssh_exec",
        "args": {"hostId": host, "command": command, "maxChars": 16000, "timeoutMs": 300000},
    }]


if __name__ == "__main__":
    print(json.dumps(build_request(), ensure_ascii=True))
