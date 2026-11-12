#!/usr/bin/env python3
"""Build a reviewed, one-host-at-a-time collector update request.

This module only builds an ops_mcp request. It never connects to a host or
executes the request. The generated remote transaction stages files, keeps a
small temporary rollback copy, restarts only traffic-audit.service, verifies
capture threads/source-IP coverage, and restores the previous files on failure.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOST_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
COLLECTOR_NAMES = ("audit.py", "capture.py", "query.py", "transport.py", "presentation.py", "rates.py", "maintenance.py")
PROTECTED_SERVICES = (
    "mihomo.service",
    "mihomo-term-a2.service",
    "easytier-net-a.service",
    "easytier-udp3990.service",
    "traffic-audit-publish.service",
    "traffic-audit-hk.service",
    "traffic-audit-hk-publish.service",
    "traffic-audit-hk-edge.service",
)


def load_host(host: str) -> dict:
    if not HOST_RE.fullmatch(host):
        raise ValueError(f"invalid host id: {host!r}")
    path = ROOT / "config" / f"{host}.json"
    if not path.is_file():
        raise ValueError(f"unknown audit host: {host}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("mode") not in {"edge", "terminal"}:
        raise ValueError(f"unsupported audit mode for {host}: {data.get('mode')!r}")
    return data


def file_text(path: Path) -> str:
    text = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    return text.rstrip("\n") + "\n"


def files_for(host: str, config: dict, include_config: bool) -> list[dict]:
    files = []
    for name in COLLECTOR_NAMES:
        files.append({
            "source": ROOT / name,
            "remote": f"/usr/local/libexec/traffic-audit/{name}",
            "mode": "750",
        })
    unit = file_text(ROOT / "deploy" / "traffic-audit.service")
    if config["mode"] == "terminal":
        unit = unit.replace(
            "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN",
            "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_DAC_READ_SEARCH",
        )
    files.append({
        "source": None,
        "remote": "/etc/systemd/system/traffic-audit.service",
        "mode": "644",
        "text": unit,
    })
    if include_config:
        files.append({
            "source": ROOT / "config" / f"{host}.json",
            "remote": "/etc/traffic-audit/config.json",
            "mode": "600",
        })
    for item in files:
        text = item.get("text")
        if text is None:
            text = file_text(item["source"])
            item["text"] = text
        item["sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return files


def release_id(host: str, files: list[dict]) -> str:
    payload = "\n".join(f"{item['remote']} {item['sha256']}" for item in files)
    return hashlib.sha256((host + "\n" + payload).encode("utf-8")).hexdigest()[:16]


def heredoc(path: str, text: str, digest: str) -> list[str]:
    marker = "AUDIT_RELEASE_" + digest[:24]
    if marker in text:
        raise ValueError(f"heredoc marker collision in {path}")
    return [f"cat > \"$stage/{path.lstrip('/')}\" <<'{marker}'", text.rstrip("\n"), marker]


def build_command(host: str, config: dict, files: list[dict], rid: str) -> str:
    remotes = [item["remote"] for item in files]
    protected = " ".join(PROTECTED_SERVICES)
    restore_lines = [
        f"  if [ -f \"$backup/{item['remote'].lstrip('/')}\" ]; then cp -p \"$backup/{item['remote'].lstrip('/')}\" \"{item['remote']}\"; fi"
        for item in files
    ]
    lines = [
        "set -Eeuo pipefail",
        "umask 077",
        f"release_id='{rid}'",
        "target='traffic-audit.service'",
        "stage=$(mktemp -d /var/tmp/traffic-audit-stage.XXXXXX)",
        "backup=$(mktemp -d /var/tmp/traffic-audit-backup.XXXXXX)",
        "changed=0",
        "safe_rm() { case \"$1\" in /var/tmp/traffic-audit-stage.*|/var/tmp/traffic-audit-backup.*) rm -rf -- \"$1\" ;; *) echo 'refusing unsafe cleanup path' >&2; return 1 ;; esac; }",
        "restore() {",
        "  set +e",
        "\n".join(restore_lines),
        "  systemctl daemon-reload",
        "  systemctl restart \"$target\"",
        "}",
        "finish() {",
        "  rc=$?",
        "  if [ \"$rc\" -ne 0 ] && [ \"$changed\" -eq 1 ]; then echo \"release $release_id failed; restoring previous collector\" >&2; restore; fi",
        "  safe_rm \"$stage\"",
        "  safe_rm \"$backup\"",
        "  exit \"$rc\"",
        "}",
        "trap finish EXIT",
        "systemctl is-active --quiet \"$target\"",
        "systemctl show \"$target\" -p MainPID -p ActiveEnterTimestamp -p NRestarts",
        "/usr/bin/python3 - <<'AUDIT_RELEASE_PREFLIGHT'",
        "import json",
        "from pathlib import Path",
        "h = json.loads(Path('/var/lib/traffic-audit/health.json').read_text())",
        "m = h.get('metrics') or {}",
        "errors = {k:v for k,v in (m.get('errors') or {}).items() if k != 'receiver_last_error'}",
        "threads = m.get('threads_alive') or {}",
        "captures = m.get('capture') or {}",
        "bad = [k for k,v in captures.items() if v.get('status') not in ('coverage','health')]",
        "if h.get('status') == 'error' or errors or not threads or not all(threads.values()) or not captures or bad:",
        "    raise SystemExit('preflight health is not safe for update: ' + json.dumps({'status':h.get('status'),'errors':errors,'threads_alive':threads,'bad_captures':bad}, ensure_ascii=True))",
        "print(json.dumps({'status':h.get('status'),'threads_alive':threads,'capture':captures}, ensure_ascii=True))",
        "AUDIT_RELEASE_PREFLIGHT",
        "mkdir -p \"$stage/usr/local/libexec/traffic-audit\" \"$stage/etc/systemd/system\" \"$stage/etc/traffic-audit\"",
        "for remote in " + " ".join(f"'{p}'" for p in remotes) + "; do",
        "  test -f \"$remote\"",
        "  rel=${remote#/}",
        "  mkdir -p \"$backup/$(dirname \"$rel\")\"",
        "  cp -p \"$remote\" \"$backup/$rel\"",
        "done",
        "mkdir -p \"$backup/meta\"",
        "for service in " + protected + "; do",
        "  if systemctl cat \"$service\" >/dev/null 2>&1; then systemctl show \"$service\" -p MainPID -p ActiveEnterTimestamp -p SubState >> \"$backup/meta/protected.before\"; fi",
        "done",
    ]
    for item in files:
        rel = item["remote"].lstrip("/")
        lines.extend(heredoc(rel, item["text"], item["sha256"]))
    lines.extend([
        "for remote in " + " ".join(f"'{p}'" for p in remotes) + "; do test -f \"$stage/${remote#/}\"; done",
        "/usr/bin/python3 - \"$stage\" <<'AUDIT_RELEASE_COMPILE'",
        "import sys",
        "from pathlib import Path",
        "stage = Path(sys.argv[1])",
        "for p in (stage / 'usr/local/libexec/traffic-audit').glob('*.py'):",
        "    compile(p.read_text(), str(p), 'exec')",
        "AUDIT_RELEASE_COMPILE",
    ])
    lines.extend([
        "/usr/bin/python3 - \"$stage/usr/local/libexec/traffic-audit/audit.py\" --check",
        "systemd-analyze verify \"$stage/etc/systemd/system/traffic-audit.service\"",
        "changed=1",
    ])
    for item in files:
        remote = item["remote"]
        rel = remote.lstrip("/")
        lines.append(f"install -m {item['mode']} \"$stage/{rel}\" \"{remote}\"")
        lines.append(f"printf '%s  %s\\n' '{item['sha256']}' '{remote}' | sha256sum -c -")
    lines.extend([
        "systemctl daemon-reload",
        "systemctl restart \"$target\"",
        "ok=0",
        "for attempt in $(seq 1 18); do",
        "  if /usr/bin/python3 - <<'AUDIT_RELEASE_HEALTH'",
        "import json, sqlite3, sys, time",
        "from pathlib import Path",
        "health = Path('/var/lib/traffic-audit/health.json')",
        "if not health.exists(): raise SystemExit('health file missing')",
        "h = json.loads(health.read_text())",
        "m = h.get('metrics') or {}",
        "errors = {k:v for k,v in (m.get('errors') or {}).items() if k != 'receiver_last_error'}",
        "threads = m.get('threads_alive') or {}",
        "captures = m.get('capture') or {}",
        "bad_captures = [k for k,v in captures.items() if v.get('status') not in ('coverage','health')]",
        "if h.get('status') == 'error' or errors or not threads or not all(threads.values()) or not captures or bad_captures:",
        "    print(json.dumps({'status':h.get('status'),'errors':errors,'threads_alive':threads,'bad_captures':bad_captures}, ensure_ascii=True))",
        "    raise SystemExit(1)",
        "if h.get('mode') == 'terminal':",
        "    db = sqlite3.connect('/var/lib/traffic-audit/audit.sqlite')",
        "    now = time.time()",
        "    recent, matched = db.execute(\"SELECT COUNT(*), COALESCE(SUM(source_ip IS NOT NULL AND source_ip<>''),0) FROM samples WHERE ts>=?\", (now-600,)).fetchone()",
        "    db.close()",
        "    if recent and not matched and (m.get('active_connections') or 0) > 0:",
        "        print(json.dumps({'status':h.get('status'),'recent_samples':recent,'matched_source_ip':matched}, ensure_ascii=True))",
        "        raise SystemExit(1)",
        "print(json.dumps({'status':h.get('status'),'threads_alive':threads,'capture':captures,'matched_connections':m.get('matched_connections'),'unresolved_connections':m.get('unresolved_connections')}, ensure_ascii=True))",
        "AUDIT_RELEASE_HEALTH",
        "  then ok=1; break; fi",
        "  sleep 5",
        "done",
        "test \"$ok\" -eq 1",
        "for service in " + protected + "; do",
        "  if systemctl cat \"$service\" >/dev/null 2>&1; then systemctl show \"$service\" -p MainPID -p ActiveEnterTimestamp -p SubState >> \"$backup/meta/protected.after\"; fi",
        "done",
        "if ! diff -u \"$backup/meta/protected.before\" \"$backup/meta/protected.after\"; then echo 'non-target service state changed during update' >&2; exit 1; fi",
        "systemctl is-active --quiet \"$target\"",
        "systemctl show \"$target\" -p MainPID -p ActiveEnterTimestamp -p NRestarts",
        "echo \"release $release_id applied successfully\"",
    ])
    return "\n".join(lines) + "\n"


def build_request(host: str, include_config: bool = False, changed=()) -> tuple[list[dict], dict]:
    config = load_host(host)
    files = files_for(host, config, include_config)
    rid = release_id(host, files)
    spec = importlib.util.spec_from_file_location("audit_validation", ROOT / "tools" / "validate.py")
    validation = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(validation)
    # Pending packaged source must not escape checks merely because --changed was omitted.
    try:
        recorded = json.loads((ROOT / "docs" / "baseline.json").read_text(encoding="utf8"))["local_sources"]
    except (OSError, ValueError, KeyError):
        recorded = {}
    candidates = (*COLLECTOR_NAMES, "deploy/traffic-audit.service")
    drift = tuple(name for name in candidates
                  if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != recorded.get(name))
    scope = tuple(changed) + drift + ((f"config/{host}.json",) if include_config else ())
    plan = validation.build_plan("collector", scope)
    manifest = {
        "release_id": rid,
        "host": host,
        "component": "collector",
        "mode": config["mode"],
        "include_config": include_config,
        "validation": {
            "policy_version": plan["policy_version"], "business": plan["business"], "level": plan["level"],
            "changed": plan["changed"], "test_files": plan["test_files"],
            "remote_gates": plan["remote_gates"],
            "entry": "tools/validate.py",
            "acceptance": "pending; request generation does not execute validation or prove acceptance",
        },
        "files": [{"remote": f["remote"], "sha256": f["sha256"], "mode": f["mode"]} for f in files],
        "protected_services": list(PROTECTED_SERVICES),
        "postflight": ["health status is not error", "all worker threads alive", "all capture interfaces report coverage/health", "recent terminal samples retain a source_ip when samples exist", "protected services unchanged"],
    }
    request = {
        "tool": "ops_ssh_exec",
        "args": {
            "hostId": host,
            "command": build_command(host, config, files, rid),
            "maxChars": 16000,
            "timeoutMs": 180000,
        },
    }
    return [request], manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("host", help="one explicit audit host id, for canary rollout")
    parser.add_argument("--include-config", action="store_true", help="also deploy config/<host>.json; otherwise preserve remote config")
    parser.add_argument("--changed", action="append", default=[], help="actual changed source path for validation scope; repeatable")
    parser.add_argument("--emit", type=Path, help="write a call.mjs-compatible request list")
    parser.add_argument("--manifest", type=Path, help="write the reviewed release manifest")
    args = parser.parse_args(argv)
    requests, manifest = build_request(args.host, args.include_config, args.changed)
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    if args.emit:
        args.emit.parent.mkdir(parents=True, exist_ok=True)
        args.emit.write_text(json.dumps(requests, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"request_file={args.emit}")
    if args.manifest:
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"manifest_file={args.manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
