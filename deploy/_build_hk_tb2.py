import base64
import json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
files = {
    "/usr/local/libexec/traffic-audit/audit.py": root / "audit.py",
    "/usr/local/libexec/traffic-audit/capture.py": root / "capture.py",
    "/usr/local/libexec/traffic-audit/query.py": root / "query.py",
    "/usr/local/libexec/traffic-audit/transport.py": root / "transport.py",
    "/usr/local/libexec/traffic-audit/presentation.py": root / "presentation.py",
    "/usr/local/libexec/traffic-audit/rates.py": root / "rates.py",
    "/usr/local/libexec/traffic-audit/central/publish.py": root / "central" / "publish.py",
    "/usr/local/libexec/traffic-audit/central/model.py": root / "central" / "model.py",
    "/etc/traffic-audit/config.json": root / "config" / "term-b2.json",
    "/etc/systemd/system/traffic-audit.service": root / "deploy" / "traffic-audit.service",
    "/etc/systemd/system/traffic-audit-publish-term-b2.service": root / "deploy" / "traffic-audit-publish-term-b2.service",
}
lines = [
    "set -Eeuo pipefail",
    "umask 077",
    "install -d -m 750 /usr/local/libexec/traffic-audit /usr/local/libexec/traffic-audit/central",
    "install -d -m 700 /etc/traffic-audit /etc/traffic-audit/central-term-b2 /var/lib/traffic-audit",
]
for remote, path in files.items():
    data = path.read_bytes().replace(b"\r\n", b"\n")
    if remote.endswith("traffic-audit.service") and path.name == "traffic-audit.service":
        data = data.replace(
            b"CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN",
            b"CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_DAC_READ_SEARCH",
        )
    encoded = base64.b64encode(data).decode()
    mode = "600" if remote.endswith("config.json") else "750" if remote.endswith(".py") else "644"
    lines.append(f"echo installing {remote}")
    lines.append(f"printf '%s' '{encoded}' | base64 -d > '{remote}'")
    lines.append(f"chmod {mode} '{remote}'")
lines += [
    "if ! grep -q '^external-controller: 127.0.0.1:9090$' /etc/mihomo/config.yaml; then cp -p /etc/mihomo/config.yaml /var/tmp/mihomo-config.audit-term-b2.before; sed -i '1iexternal-controller: 127.0.0.1:9090' /etc/mihomo/config.yaml; fi",
    "python3 - <<'PY2'\nfrom pathlib import Path\nimport secrets\np=Path('/etc/traffic-audit/term-b2-auth.toml')\nif not p.exists():\n p.write_text('[network_identity]\\nnetwork_secret = \\\"'+secrets.token_hex(32)+'\\\"\\n')\n p.chmod(0o600)\nPY2",
    "ssh-keygen -q -t ed25519 -N '' -f /etc/traffic-audit/central-term-b2/id_ed25519 </dev/null || true",
    "printf '%s\\n' '[203.0.113.109]:39238 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEexampleEXAMPLEexampleEXAMPLEexampleEXA' > /etc/traffic-audit/central-term-b2/known_hosts",
    "chmod 600 /etc/traffic-audit/central-term-b2/id_ed25519 /etc/traffic-audit/central-term-b2/id_ed25519.pub /etc/traffic-audit/central-term-b2/known_hosts",
    "python3 - /usr/local/libexec/traffic-audit/audit.py --check",
    "python3 - <<'PY3'\nfrom pathlib import Path\nfor p in Path('/usr/local/libexec/traffic-audit').rglob('*.py'): compile(p.read_text(),str(p),'exec')\nPY3",
    "systemd-analyze verify /etc/systemd/system/traffic-audit.service /etc/systemd/system/traffic-audit-publish-term-b2.service",
    "systemctl daemon-reload",
    "cat /etc/traffic-audit/central-term-b2/id_ed25519.pub",
    "sha256sum /etc/traffic-audit/config.json /etc/systemd/system/traffic-audit.service /etc/systemd/system/traffic-audit-publish-term-b2.service",
]
print(json.dumps("\n".join(lines)))
