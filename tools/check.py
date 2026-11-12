"""Read-only, offline handover checks. Never import deployment/runtime scripts.

Default: local documentation, configuration, and frozen interface contracts.
--baseline: additionally compare approved local files with the recorded hashes.
This is not SQL execution, a security scanner, or proof of remote health.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from urllib.parse import unquote, urlsplit

DOC_FILES = (
    "README.md", "design.md", "docs/data.md", "docs/storage.md",
    "docs/operations.md", "docs/validation.md", "docs/database-optimization.md",
    "deploy/README.md", "client/README.md",
)
PROBES = ("entry-a1", "entry-a3", "entry-a4")
BASELINE_FILES = (
    "audit.py", "capture.py", "transport.py", "presentation.py", "query.py", "rates.py", "maintenance.py",
    "central/model.py", "central/publish.py", "central/receive.py", "central/query.py",
    "central/prune.py", "central/views.sql", "central/init.py", "central/mysql.cnf",
    "central/traffic-audit-publish.service", "central/traffic-central-prune.service",
    "central/traffic-central-prune.timer", "central/test_mysql.py", "central/test_views.py",
    "config/term-a1.json", "config/term-a2.json", "config/term-b3.json", "config/entry-b1.json", *(f"config/{node}.json" for node in PROBES),
    "deploy/build.py", "deploy/call.mjs", "deploy/update.py", "deploy/central.py", "deploy/rename_db.py",
    "deploy/traffic-audit.service", "deploy/traffic-audit-hk.service",
    "deploy/traffic-audit-hk-publish.service", "deploy/traffic-audit-hk-edge.service",
    "deploy/traffic-central-hk-prune.service",
    "deploy/traffic-central-hk-prune.timer", "deploy/traffic-central-hk-query.py",
    "tools/check.py", "tools/validate.py", "tests/test_validation.py", "tests/test_update.py", "tests/test_handover.py",
)
EVIDENCE_FILES = (
    "verification.json", "central-verification.json", "sync-verification.json",
    "entry-verification.json", "rate-verification.json", "handover-verification.json",
)
REQUIRED_FILES = (*DOC_FILES, *BASELINE_FILES, ".gitignore", "tools/publish_check.py",
                  "config/entry-b1-tb3.json", "config/entryb2-tb3.json", "config/entrya-hk-2101.json", "config/entrya2-hk-2101.json", "config/term-b4.json",
                  )
VIEWS = {
    "审计明细": ["时间", "源 IP", "隧道内网 IP（入口机器）", "目标网站", "最近上传速率", "最近下载速率"],
    "流量汇总": ["时间", "源 IP", "入口机器", "目标网站", "流量统计"],
    "入口流量汇总": ["时间", "源 IP", "入口机器", "传输协议", "上行线路流量", "下行线路流量", "分钟平均上传速率", "分钟平均下载速率"],
    "访问记录": ["时间", "源 IP", "入口机器", "目标网站", "归属依据"],
    "同步状态": ["采集节点", "最后入库时间", "距上次同步秒", "确认位置", "单批最大缺失数", "统计说明"],
}
CONTRACT = {
    "database": "region-a", "publisher": "term-a1", "archive_node": "center-host",
    "sample_interval_seconds": 0.5, "sync_interval_seconds": 60,
    "sync_stale_seconds": 90, "rate_window_seconds": 5,
    "rate_basis": "source_ip_five_second_sampled_payload_rate",
    "rate_scope": "source_ip", "retention_days": 7, "local_cache_hours": 24,
    "detail_dedup_window_seconds": 5,
    "detail_dedup_basis": "source_ip_site_entry_fixed_window",
    "summary_scope": "current_beijing_calendar_month_to_latest",
    "summary_grouping": "source_ip_node_site",
    "summary_units": "decimal_MB_GB",
    "summary_time_basis": "beijing_month_start_to_latest_sample_date",
    "summary_time_format": "YYYY/MM/01–YYYY/MM/DD",
    "timezone": "Asia/Shanghai", "unit_base": 1000,
    "mysql_target": "203.0.113.113:3306", "ssh_compression": False,
    "provider_mapping": {"peer": "172.30.3.3", "entry": "203.0.113.103", "only_unknown_node": True},
    "views": VIEWS,
}
TABLE_KEYS = {
    "samples": ["event_id"], "visits": ["event_id"],
    "wire_samples": ["bucket", "node", "source_ip", "entry_port", "transport"],
    "connection_state": ["connection_id"], "connection_rates": ["connection_id"],
    "entry_routes": ["node", "inbound_port"], "peers": ["node"],
}
ROUTES = {
    ("entry-a1", 3366): "10.77.250.2", ("entry-a1", 3380): None,
    ("entry-a1", 3390): None,
    ("entry-a3", 3310): "10.77.251.2",
    ("entry-a4", 35800): "10.77.250.4",
}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe_path(root, relative):
    """Reject traversal, platform-dependent paths, and symlinks escaping root."""
    if not isinstance(relative, str) or not relative or "\\" in relative or ":" in relative:
        raise ValueError("invalid relative path")
    parts = PurePosixPath(relative)
    if parts.is_absolute() or ".." in parts.parts:
        raise ValueError("path escapes project")
    target = (root / relative).resolve()
    if not target.is_relative_to(root.resolve()):
        raise ValueError("resolved path escapes project")
    return target


def static_value(node):
    """Tiny AST reader; only literals/containers and literal-string .split()."""
    if isinstance(node, (ast.Tuple, ast.List)):
        values = [static_value(item) for item in node.elts]
        return tuple(values) if isinstance(node, ast.Tuple) else values
    if isinstance(node, ast.Dict):
        return {static_value(k): static_value(v) for k, v in zip(node.keys, node.values)}
    if (isinstance(node, ast.Call) and not node.args and not node.keywords
            and isinstance(node.func, ast.Attribute) and node.func.attr == "split"
            and isinstance(node.func.value, ast.Constant) and isinstance(node.func.value.value, str)):
        return node.func.value.value.split()
    return ast.literal_eval(node)


def constant(path, name):
    for node in ast.parse(path.read_text(encoding="utf8")).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return static_value(node.value)
    raise ValueError(f"missing static constant {name}")


def check_project(root, baseline=False):
    root = Path(root).resolve()
    errors, warnings = [], []
    checks = 0

    def require(ok, message):
        nonlocal checks
        checks += 1
        if not ok:
            errors.append(message)

    def text(name):
        return safe_path(root, name).read_text(encoding="utf8")

    def read_json(name):
        return json.loads(text(name))

    def run(label, fn):
        try:
            fn()
        except (OSError, ValueError, SyntaxError, TypeError, KeyError, AttributeError, IndexError) as exc:
            require(False, f"{label}: {type(exc).__name__}: {exc}")

    for name in REQUIRED_FILES:
        run(name, lambda name=name: require(safe_path(root, name).is_file(), f"missing file: {name}"))

    def check_links(name):
        # Supported contract: inline Markdown links, project-local paths, no title suffix.
        body = re.sub(r"```.*?```", "", text(name), flags=re.S)
        for match in re.finditer(r"\[[^\]\n]+\]\(([^)\n]+)\)", body):
            link = match.group(1).strip().strip("<>")
            uri = urlsplit(link)
            if uri.scheme or uri.netloc or not uri.path:
                continue  # External targets/anchors are never fetched.
            target = (root / name).parent / unquote(uri.path)
            require(target.resolve().is_relative_to(root), f"{name}: link escapes project: {link}")
            if target.resolve().is_relative_to(root):
                require(target.exists(), f"{name}: broken link: {link}")

    for name in DOC_FILES:
        run(f"links {name}", lambda name=name: check_links(name))

    def check_constants():
        expected = (
            ("rates.py", "RATE_WINDOW_SECONDS", 5),
            ("rates.py", "RATE_BASIS", CONTRACT["rate_basis"]),
            ("presentation.py", "COLUMNS", tuple(VIEWS["审计明细"])),
            ("presentation.py", "DETAIL_DEDUP_WINDOW_SECONDS", 5),
            ("presentation.py", "DETAIL_DEDUP_BASIS", CONTRACT["detail_dedup_basis"]),
            ("presentation.py", "SUMMARY_VIEW_COLUMNS", tuple(VIEWS["流量汇总"])),
            ("presentation.py", "SUMMARY_VIEW_SCOPE", CONTRACT["summary_scope"]),
            ("presentation.py", "SUMMARY_VIEW_GROUPING", CONTRACT["summary_grouping"]),
            ("presentation.py", "SUMMARY_VIEW_TIME_BASIS", CONTRACT["summary_time_basis"]),
            ("query.py", "DETAIL_DEDUP_WINDOW_SECONDS", 5),
            ("query.py", "DETAIL_DEDUP_BASIS", CONTRACT["detail_dedup_basis"]),
            ("query.py", "SUMMARY_VIEW_COLUMNS", tuple(VIEWS["流量汇总"])),
            ("query.py", "SUMMARY_VIEW_SCOPE", CONTRACT["summary_scope"]),
            ("query.py", "SUMMARY_VIEW_GROUPING", CONTRACT["summary_grouping"]),
            ("query.py", "SUMMARY_VIEW_TIME_BASIS", CONTRACT["summary_time_basis"]),
            ("central/publish.py", "SYNC_INTERVAL_SECONDS", 60),
            ("central/query.py", "SYNC_STALE_SECONDS", 90),
        )
        for name, key, value in expected:
            require(constant(safe_path(root, name), key) == value, f"contract drift: {name}:{key}")
        tables = constant(safe_path(root, "central/model.py"), "TABLES")
        require({key: item[1] for key, item in tables.items()} == TABLE_KEYS, "sync table primary-key contract drift")
        tree = ast.parse(text("central/publish.py"))
        require(not any(isinstance(n, ast.Constant) and n.value == "-C" for n in ast.walk(tree)), "direct MySQL publisher must not use SSH compression")

    run("constants", check_constants)

    def check_config():
        cfg = read_json("config/term-a1.json")
        legacy_cfg = read_json("config/term-a2.json")
        expected = {"mode": "terminal", "node": "term-a1", "archive_node": "center-host",
                    "sample_interval": 0.5, "retention_days": 7, "local_cache_hours": 24, "max_db_mb": 2048}
        for key, value in expected.items():
            require(cfg.get(key) == value, f"terminal config drift: {key}")
        require(set(cfg["peers"]) == set(PROBES), "probe membership drift")
        expected_routes = {
            ("entry-a1", 3386, "203.0.113.114"), ("entry-a1", 3380, "203.0.113.114"),
            ("entry-a1", 3390, "203.0.113.114"), ("entry-a3", 3310, "203.0.113.102"),
            ("entry-a4", 35800, "203.0.113.100"),
        }
        require({(r["node"], r["inbound_port"], r["tunnel_ip"]) for r in cfg.get("entry_routes", [])}
                == expected_routes, "terminal public entry display drift")
        expected_fingerprints = {
            ("entry-a1", 3386, 28600, "tcp"), ("entry-a1", 3386, 28600, "udp"),
            ("entry-a1", 3380, 3380, "tcp"),
            ("entry-a1", 3390, 3390, "udp"), ("entry-a3", 3310, 3990, "tcp"),
            ("entry-a3", 3310, 3990, "udp"), ("entry-a4", 35800, 35800, "tcp"),
            ("entry-a4", 35800, 35800, "udp"),
            ("entry-a4", 35800, 3990, "tcp"), ("entry-a4", 35800, 3990, "udp"),
        }
        require({(r["node"], r["inbound_port"], r["entry_port"], r["transport"])
                 for r in cfg.get("fingerprint_routes", [])} == expected_fingerprints,
                "terminal DNAT fingerprint route drift")
        hk = read_json("config/term-b1.json")
        require(hk.get("inbound_types") == {"2101": ["ShadowSocks"], "24443": ["AnyTLS"]},
                "HK explicit protocol drift")
        entryb2 = read_json("config/entry-b2.json")
        require(entryb2["captures"][0]["tcp_ports"] == [28900, 443]
                and entryb2["captures"][0]["udp_ports"] == [28900]
                and 24443 in hk["inbound_ports"]
                and 24443 in hk["captures"][0]["tcp_ports"]
                and 24443 not in hk["captures"][0]["udp_ports"]
                and hk["peers"]["entry-b2"]["tcp_ports"] == [28900, 443]
                and hk["peers"]["entry-b2"]["udp_ports"] == [28900],
                "HK AnyTLS TCP carrier capture drift")
        require({"node": "entry-b2", "inbound_port": 24443,
                 "entry_port": 443, "transport": "tcp"} in hk.get("fingerprint_routes", [])
                and {"node": "entry-b2", "inbound_port": 24443,
                     "tunnel_ip": "203.0.113.111"} in hk["entry_routes"],
                "HK AnyTLS fingerprint route drift")
        hk_edge = read_json("config/entrya-hk-2101.json")
        new_hk_edge = read_json("config/entrya2-hk-2101.json")
        tb3 = read_json("config/term-b3.json")
        termb4 = read_json("config/term-b4.json")
        require(tb3.get("node") == "term-b3" and tb3.get("mode") == "terminal"
                and tb3.get("inbound_types") == {"24864": ["AnyTLS"], "24865": ["AnyTLS"], "2101": ["ShadowSocks"]},
                "Tb3 terminal identity/protocol drift")
        require({(r["node"], r["inbound_port"], r["entry_port"], r["transport"])
                 for r in tb3.get("fingerprint_routes", [])} == {
                    ("entry-b1", 24864, 24864, "tcp"), ("entry-b2", 24864, 24864, "tcp")},
                "Tb3 fingerprint route drift")
        for filename, node, endpoint, port, udp in (
                ("entry-b1-tb3", "entry-b1", "http://203.0.113.115:19091", 24864, []),
                ("entryb2-tb3", "entry-b2", "http://203.0.113.115:19091", 24864, [])):
            edge = read_json("config/" + filename + ".json")
            require(edge.get("node") == node and edge.get("endpoint") == endpoint,
                    "Tb3 edge identity/endpoint drift: " + node)
            for protocol, ports in (("tcp_ports", [port]), ("udp_ports", udp)):
                require({p for cap in edge["captures"] for p in cap[protocol]} == set(ports)
                        and tb3["peers"][node][protocol] == ports,
                        "Tb3 edge/terminal port mismatch: " + node)
        require(hk_edge.get("node") == "entry-a1" and hk_edge.get("endpoint") == "http://127.0.0.1:19091",
                "term-b4 edge identity/endpoint drift: entry-a1")
        require(new_hk_edge.get("node") == "entry-a2"
                and new_hk_edge.get("tcp_stream_recovery") is True
                and new_hk_edge.get("endpoint") == "http://127.0.0.1:19091"
                and new_hk_edge.get("captures") == [{"interface": "ens5", "front_address": "172.28.51.221",
                    "tcp_ports": [2101], "udp_ports": [2101]}],
                "term-b4 edge identity/capture drift: entry-a2")
        require(termb4.get("node") == "term-b4" and termb4.get("mode") == "terminal"
                and termb4.get("tcp_stream_recovery") is True
                and termb4.get("inbound_types") == {"2101": ["ShadowSocks"]}
                and termb4.get("peers", {}).get("entry-a1", {}).get("tcp_ports") == [2101]
                and termb4.get("peers", {}).get("entry-a1", {}).get("udp_ports") == [2101]
                and termb4.get("peers", {}).get("entry-a2", {}).get("tcp_ports") == [2101]
                and termb4.get("peers", {}).get("entry-a2", {}).get("udp_ports") == [2101]
                and {(r["node"], r["inbound_port"], r["entry_port"], r["transport"])
                     for r in termb4.get("fingerprint_routes", [])} == {
                        ("entry-a1", 2101, 2101, "tcp"), ("entry-a1", 2101, 2101, "udp"),
                        ("entry-a2", 2101, 2101, "tcp"), ("entry-a2", 2101, 2101, "udp")}
                and {"node": "entry-a1", "inbound_port": 2101, "tunnel_ip": "203.0.113.114"}
                    in termb4.get("entry_routes", []),
                "term-b4 terminal route drift")
        require({"node": "entry-a2", "inbound_port": 2101, "tunnel_ip": "203.0.113.110"}
                in termb4.get("entry_routes", []), "term-b4 new public entry drift")
        require(hk_edge["captures"][0]["udp_ports"] == [2101]
                and 2101 in hk["captures"][0]["udp_ports"]
                and hk["peers"]["entry-a1"]["udp_ports"] == [2101], "HK UDP 2101 capture drift")
        require(set(cfg["inbound_ports"]) == {3309, 3310, 3320, 3366, 3380, 3386, 3390, 3391, 31100, 35800}, "terminal inbound port drift")
        require(cfg.get("inbound_types") == {str(p): ["ShadowSocks"] for p in (3310, 3386, 35800)},
                "JP SS2022 protocol drift")
        require(not cfg.get("udp_listen"), "unused UDP receiver must be disabled")
        require(not legacy_cfg.get("udp_listen"), "unused UDP receiver must be disabled")
        require(not safe_path(root, "config/entry-a0.json").exists(), "retired edge config must be absent")
        tree = ast.parse(text("central/query.py"))
        defaults = [n.args[1].value for n in ast.walk(tree)
                    if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                    and n.func.attr == "get" and len(n.args) == 2
                    and isinstance(n.args[0], ast.Constant)
                    and n.args[0].value == "TRAFFIC_CENTRAL_ACTIVE_EDGE_NODES"
                    and isinstance(n.args[1], ast.Constant)]
        require(defaults == [",".join(PROBES)], "central active edge membership drift")
        for node in PROBES:
            edge = read_json(f"config/{node}.json")
            require(edge["node"] == node and edge["mode"] == "edge", f"edge identity drift: {node}")
            require(edge["spool_hours"] == 24 and edge["max_db_mb"] == 128, f"edge queue drift: {node}")
            peer = cfg["peers"][node]
            for protocol in ("tcp_ports", "udp_ports"):
                ports = {p for cap in edge["captures"] for p in cap[protocol]}
                require(ports == set(peer[protocol]), f"edge/terminal port mismatch: {node} {protocol}")
            require(edge.get("upload_transport", "http") == peer.get("upload_transport", "http"), f"edge transport mismatch: {node}")
            endpoint = urlsplit(edge["endpoint"])
            entry_ports = {"entry-a1": 3395, "entry-a4": 3396, "entry-a3": 3397}
            require(endpoint.hostname == "203.0.113.101" and endpoint.port == entry_ports[node],
                    f"edge endpoint mismatch: {node}")
            require(edge["auth_file"] == "/etc/traffic-audit/identity.toml",
                    f"edge signing identity must survive tunnel retirement: {node}")
        mysql = text("central/mysql.cnf")
        require(bool(re.search(r"(?m)^bind-address\s*=\s*127\.0\.0\.1\s*$", mysql)), "MySQL must bind loopback")
        require(bool(re.search(r"(?mi)^mysqlx\s*=\s*(?:off|0)\s*$", mysql)), "MySQL X plugin must remain disabled")

    run("config", check_config)

    def check_sql():
        views = dict(re.findall(r"CREATE OR REPLACE SQL SECURITY DEFINER VIEW `([^`]+)` AS(.*?);", text("central/views.sql"), re.S))
        require(set(views) == set(VIEWS), "five MySQL views must be present")
        for name, columns in VIEWS.items():
            sql = views[name]
            require(re.findall(r"\bAS `([^`]+)`", sql) == columns, f"view column order drift: {name}")
        detail = views["审计明细"]
        for guard in ("v.interval_seconds<>5", "v.observed_at<>c.last_seen", "c.source_ip IS NULL",
                      "c.source_peer='172.30.3.3' AND (c.node IS NULL OR c.node='')", "203.0.113.103",
                      "ROW_NUMBER() OVER", "_session_rank=1", "c.last_seen + 2.5",
                      "c.site IS NULL OR c.site=''", "LOWER(c.site)='unknown'"):
            require(guard in detail, f"view identity/rate/dedup guard missing: {guard}")
        presentation = text("presentation.py")
        for guard in ("ROW_NUMBER() OVER", "_session_rank=1", "c.last_seen + 2.5",
                      "lower(c.site)='unknown'"):
            require(guard in presentation, f"SQLite detail dedup guard missing: {guard}")
        summary = views["流量汇总"]
        for guard in ("CONCAT(", "'–'",
                      "DATE_FORMAT(TIMESTAMPADD(SECOND,latest.latest_ts",
                      "DATE_FORMAT(DATE_ADD(UTC_TIMESTAMP(), INTERVAL 8 HOUR),'%Y-%m')",
                      "ts >=", "ts <=", "MAX(ts)", "traffic_rollup",
                      "UNION ALL", "COALESCE(NULLIF(s.source_ip,''),'未识别')", "1000000000"):
            require(guard in summary, f"monthly source-IP summary guard missing: {guard}")
        for unit in (" MB'", " GB'"):
            require(unit in summary, f"monthly adaptive unit missing: {unit}")
        presentation = text("presentation.py")
        for guard in ("CREATE VIEW \"流量汇总\"", "current_beijing_calendar_month_to_latest",
                      "1000000000.0", "strftime('%Y/%m/01','now','+8 hours') || '–' ||",
                      "MAX(ts)", "traffic_rollup", "UNION ALL",
                      "strftime('%Y-%m-01 00:00:00','now','+8 hours')"):
            require(guard in presentation, f"SQLite monthly summary guard missing: {guard}")
        for name, column in (("入口流量汇总", "bucket"),):
            sql = views[name]
            require(f"{column} < FLOOR(UNIX_TIMESTAMP()/60)*60" in sql, f"incomplete minute not excluded: {name}")
            for unit in (" KB'", " MB'", " KB/s'", " MB/s'"):
                require(unit in sql, f"adaptive units missing: {name} {unit}")
            require("/60" in sql, f"minute average divisor missing: {name}")

    run("SQL contracts (static, not a SQL engine)", check_sql)

    def check_manifest():
        manifest = read_json("docs/baseline.json")
        require(manifest.get("schema_version") == 1, "baseline schema version drift")
        require(manifest.get("contract") == CONTRACT, "baseline frozen contract drift")
        files = manifest["local_sources"]
        require(set(files) == set(BASELINE_FILES), "baseline local source list is incomplete or contains unapproved paths")
        for name, digest in files.items():
            if name not in BASELINE_FILES:
                require(False, f"unapproved baseline path (not read): {name}")
                continue
            require(isinstance(digest, str) and bool(re.fullmatch(r"[0-9a-f]{64}", digest)), f"invalid SHA-256: {name}")
            if baseline:
                require(sha256(safe_path(root, name)) == digest, f"local baseline drift: {name}")
        for record in manifest["remote_files"]:
            name = record["local_path"]
            require(name in files, f"unapproved remote source mapping: {name}")
            require(record["host_id"] in ("term-a1", "center-host", "term-a2", "legacy-center", "term-b3", "entry-b1"), "unverified remote host in baseline")
            require(record["status"] in ("matched", "known_bootstrap_difference", "compatible_columns_only_difference",
             "local_change_pending_remote"), "unknown remote comparison status")
            digest = record["sha256"]
            require(bool(re.fullmatch(r"[0-9a-f]{64}", digest)), f"invalid remote SHA-256: {name}")
            if record["status"] == "matched":
                require(digest == files.get(name), f"remote/local record claims false match: {name}")
        warnings.append("Remote state is a recorded snapshot; this tool never connects to servers.")
        if not baseline:
            warnings.append("Local source hashes not compared; use --baseline for read-only drift detection.")

    if safe_path(root, "docs/baseline.json").is_file():
        run("baseline manifest", check_manifest)
    elif baseline:
        require(False, "--baseline requires the private docs/baseline.json; no baseline was checked")
    else:
        warnings.append("Public checkout: private deployment evidence is not included; remote health is not checked.")
    return {"ok": not errors, "checks": checks, "errors": errors, "warnings": warnings,
            "baseline_checked": baseline, "network_used": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", action="store_true", help="compare approved local SHA-256 hashes; no network")
    parser.add_argument("--json", action="store_true", help="print machine-readable results")
    args = parser.parse_args(argv)
    report = check_project(Path(__file__).resolve().parents[1], args.baseline)
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(f"{'PASS' if report['ok'] else 'FAIL'}: {report['checks']} offline handover checks")
        for message in report["errors"]:
            print(f"ERROR: {message}")
        for message in report["warnings"]:
            print(f"NOTE: {message}")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
