#!/usr/bin/env python3
"""Plan risk-based deployment checks; --run executes local checks only."""
from __future__ import annotations

import argparse
import ast
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
POLICY_VERSION = 1
PWSH = r"C:\Program Files\PowerShell\7\pwsh.exe"
COLLECTOR = ("audit.py", "capture.py", "query.py", "transport.py", "presentation.py", "rates.py", "maintenance.py")
GROUPS = {
    "runtime": ("test_audit.py", "test_audit_runtime.py", "test_entry_mapping.py", "test_receiver.py", "test_performance.py"),
    "capture": ("test_capture.py",),
    "transport": ("test_transport.py", "test_ingest.py"),
    "query": ("test_query.py",),
    "views": ("test_presentation.py", "test_query.py"),
    "rates": ("test_rates.py", "test_audit.py", "test_presentation.py"),
    "sync": ("test_central.py", "test_sync.py", "test_ingest.py", "test_prune.py"),
    "retention": ("test_central.py", "test_sync.py", "test_audit.py", "test_presentation.py"),
    "deploy": ("test_update.py", "test_validation.py"),
    "handover": ("test_handover.py",),
}
# Level is a safety classification, not a command to run every test.
BUSINESSES = {
    "docs": (0, (), ()),
    "edge-install": (1, (), ("edge_telemetry", "central_sync", "attribution")),
    "terminal-install": (1, (), ("collector_runtime", "central_sync", "attribution", "reader")),
    "config": (1, (), ("collector_runtime", "edge_telemetry", "central_sync", "attribution")),
    "collector": (2, ("runtime", "capture", "transport"), ("collector_runtime", "central_sync", "attribution")),
    "query": (2, ("query",), ("reader",)),
    "views": (3, ("views",), ("reader", "view_fixture", "fixed_window")),
    "sync": (3, ("sync",), ("central_sync", "sync_fixture", "fixed_window")),
    "retention": (3, ("retention",), ("central_sync", "retention_fixture", "fixed_window")),
    "dataset": (3, ("runtime", "capture", "transport", "sync", "views"),
                ("collector_runtime", "edge_telemetry", "central_sync", "attribution", "reader", "isolation", "sync_fixture")),
    "access": (3, ("query", "transport"), ("reader", "access")),
    "deploy": (2, ("deploy", "handover"), ("collector_runtime", "central_sync")),
    "full": (3, ("full",), ("collector_runtime", "central_sync", "reader", "fixed_window")),
}
RULES = {
    "client/verify.py": (3, ("handover",), ("reader", "access")),
    "audit.py": (2, ("runtime",), ("collector_runtime", "attribution", "central_sync")),
    "capture.py": (2, ("capture", "runtime"), ("collector_runtime", "attribution")),
    "edge_front.py": (2, ("capture", "test_edge_front.py"), ("edge_telemetry", "attribution")),
    "transport.py": (2, ("transport",), ("edge_telemetry",)),
    "query.py": (2, ("query",), ("reader",)),
    "presentation.py": (3, ("views",), ("reader", "view_fixture", "fixed_window")),
    "rates.py": (3, ("rates",), ("reader", "fixed_window")),
    "central/model.py": (3, ("sync",), ("sync_fixture", "central_sync", "fixed_window")),
    "central/publish.py": (3, ("sync",), ("sync_fixture", "central_sync", "fixed_window")),
    "maintenance.py": (3, ("runtime", "retention", "sync"), ("retention_fixture", "collector_runtime", "central_sync")),
    "central/rollup_patch.py": (3, ("sync", "retention"), ("retention_fixture", "fixed_window", "central_sync")),
    "central/receive.py": (3, ("sync",), ("sync_fixture", "central_sync", "fixed_window")),
    "central/query.py": (2, ("query", "sync"), ("reader",)),
    "central/detail_view.py": (3, ("views", "test_detail_view.py"), ("view_fixture", "reader", "fixed_window")),
    "central/ipgeo.py": (3, ("views", "test_ipgeo.py"), ("view_fixture", "reader", "protected")),
    "central/test_views.py": (3, ("views",), ("view_fixture", "reader", "fixed_window")),
    "central/views.sql": (3, ("views",), ("view_fixture", "reader", "fixed_window")),
    "central/prune.py": (3, ("retention",), ("retention_fixture", "central_sync", "fixed_window")),
    "central/hk_merge.py": (3, ("views", "test_hk_merge.py"), ("view_fixture", "reader", "fixed_window", "isolation")),
    "central/hk_summary.py": (3, ("views", "test_hk_summary.py"), ("view_fixture", "reader", "fixed_window", "protected")),
    "central/storage.py": (3, ("sync", "views", "test_storage.py"), ("sync_fixture", "retention_fixture", "view_fixture", "fixed_window", "central_sync", "protected")),
    "central/tier_policy.py": (3, ("sync", "views", "test_archive.py"), ("retention_fixture", "central_sync", "fixed_window")),
    "central/archive.py": (3, ("sync", "test_archive.py"), ("retention_fixture", "central_sync", "fixed_window", "protected")),
    "central/monthbook.py": (3, ("sync", "views", "test_monthbook.py", "test_archive.py"), ("retention_fixture", "view_fixture", "fixed_window", "protected")),
    "central/test_monthbook_mysql.py": (3, ("test_monthbook.py",), ("retention_fixture", "view_fixture")),
    "deploy/month_migrate.py": (3, ("sync", "views", "test_monthbook.py"), ("retention_fixture", "view_fixture", "fixed_window", "protected")),
    "central/tiering.py": (3, ("sync", "views", "test_archive.py"), ("retention_fixture", "view_fixture", "central_sync")),
    "central/test_archive_mysql.py": (3, ("test_archive.py",), ("retention_fixture", "view_fixture")),
    "central/traffic-central-archive.service": (3, ("deploy", "test_archive.py"), ("retention_fixture", "protected")),
    "central/traffic-central-archive.timer": (3, ("deploy", "test_archive.py"), ("retention_fixture", "protected")),
    "deploy/tiers.py": (3, ("sync", "views", "test_archive.py"), ("retention_fixture", "central_sync", "protected")),
    "deploy/tiers_migrate.py": (3, ("sync", "views", "test_archive.py"), ("retention_fixture", "central_sync", "protected")),
    "central/hk_query_core.py": (3, ("query", "sync", "test_hk_merge.py"), ("reader", "fixed_window")),
    "central/region.py": (3, ("sync", "views", "test_storage.py"), ("sync_fixture", "retention_fixture", "view_fixture", "fixed_window", "central_sync", "protected")),
    "central/test_storage_mysql.py": (3, ("test_storage.py",), ("sync_fixture", "retention_fixture", "view_fixture")),
    "central/init.py": (3, ("sync", "views", "test_storage.py"), ("sync_fixture", "view_fixture", "isolation")),
    "deploy/central.py": (3, ("deploy", "test_storage.py"), ("static",)),
    "central/hk_receive.py": (3, ("sync", "test_hk_merge.py"), ("sync_fixture", "central_sync", "isolation")),
    "central/hk_query.py": (2, ("query", "test_hk_merge.py"), ("reader",)),
    "central/edge_queue.py": (3, ("transport", "test_edge_queue.py"),
                              ("edge_telemetry", "central_sync", "fixed_window", "isolation")),
    "deploy/update.py": (2, ("deploy",), ("collector_runtime", "central_sync")),
    "deploy/hk-summary.py": (3, ("views", "test_hk_summary.py"), ("view_fixture", "reader", "fixed_window", "protected")),
    "deploy/storage.py": (3, ("sync", "views", "test_storage.py"), ("sync_fixture", "retention_fixture", "view_fixture", "fixed_window", "central_sync", "protected")),
    "tools/validate.py": (2, ("deploy", "handover"), ()),
    "tools/check.py": (2, ("handover",), ()),
}
GATES = {
    "scope": "精确 HostId、角色、数据集、文件/服务清单及本次授权；实探相关状态并记录原有告警",
    "artifact": "候选文件哈希与已验收版本证据一致；新装路径为空，覆盖已有组件转为更新事务",
    "static": "目标机暂存编译、依赖、配置与 systemd 语法检查；激活前通过",
    "boundary": "只检查涉及的监听/权限边界；MySQL/controller 保持回环，审计接收保持获批内网",
    "collector_runtime": "health 新鲜、worker/capture 全部存活且 coverage/health；没有新增运行错误",
    "edge_telemetry": "目标接口/端口正确，入口新遥测抵达既有终止端，队列无持续积压、无新增丢弃",
    "central_sync": "同一数据集 ACK/last_received 在实际同步周期内前进，missing_rows 不新增，publisher 无新增错误",
    "attribution": "一条有界新连接核验源/入口/网站归属；未知源保持未识别，不能以中转 peer 代替",
    "reader": "真实只读账号读取受影响视图/reader，列序、单位、basis 一致；未改授权不重测所有拒绝路径",
    "view_fixture": "仅对改动视图执行独立会话临时表夹具；生产事实未被写入或改写",
    "sync_fixture": "独立临时夹具验证受影响的幂等、旧序号、epoch、提交后 ACK 和中断补传",
    "retention_fixture": "中心夹具验证先落盘校验后删除、磁盘失败保留原事实及重试不重复计量；源缓存另验旧折叠协议，实际归档后固定截止点对账",
    "fixed_window": "固定已结束时间窗/截止点对账，不以持续写入差异判丢失",
    "isolation": "独立数据库/publisher/epoch/锁/强制命令，正确账号可读且原始表/写入被拒，旧数据集继续可读",
    "access": "仅对受影响认证链验证最终配置凭据一致、正确凭据成功、错误凭据/原始表/写入被拒；有锁定风险时按目标契约处理",
    "mcp_live": "仅改 MCP 代码才 build/重连；实际调用受影响 schema；主机登记热加载不需要重建代码",
    "protected": "仅激活目标组件；相关代理、EasyTier、publisher、MySQL 的 PID/启动时间与前置记录一致",
    "cleanup": "清理本轮精确临时路径及已结束恢复窗口的临时备份；保留唯一归档和旧任务材料",
}


def safe_path(root: Path, relative: str) -> Path:
    if not relative or "\\" in relative or ":" in relative:
        raise ValueError("use a project-relative path with forward slashes")
    parts = PurePosixPath(relative)
    if parts.is_absolute() or ".." in parts.parts:
        raise ValueError("path escapes project")
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError("resolved path escapes project")
    return path


def classify(name: str) -> tuple[int, tuple, tuple]:
    if name in RULES:
        return RULES[name]
    if name.endswith(".md") and ("/" not in name or name.startswith(("docs/", "deploy/", "client/"))):
        return 0, (), ()
    if re.fullmatch(r"config/[a-z0-9]+(?:-[a-z0-9]+)*\.json", name):
        return BUSINESSES["config"]
    if name.startswith("tests/") and name.rsplit("/", 1)[-1].startswith("test_") and name.endswith(".py"):
        return 2, (name.rsplit("/", 1)[-1],), ()
    if name.endswith((".service", ".timer")) and name.startswith(("deploy/", "central/")):
        return 2, ("deploy",), ("static", "collector_runtime")
    if name.endswith((".py", ".sql", ".cnf")) and ("/" not in name or name.startswith(("central/", "deploy/", "tools/"))):
        return 3, ("full",), ("sync_fixture", "fixed_window")
    raise ValueError(f"unsupported or private change path (not read): {name}")


def normalized_hash(path: Path, terminal_unit=False) -> str:
    body = path.read_text(encoding="utf8").replace("\r\n", "\n").rstrip("\n") + "\n"
    if terminal_unit:
        body = body.replace("CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN\n",
                            "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_DAC_READ_SEARCH\n")
    return hashlib.sha256(body.encode("utf8")).hexdigest()


def unverified_artifacts(root: Path, business: str, release: str | None) -> list[str]:
    names = (*COLLECTOR, "deploy/traffic-audit.service")
    if release is None:
        return list(names)
    if not re.fullmatch(r"deploy/[a-zA-Z0-9_.-]+\.manifest\.json", release):
        raise ValueError("--release requires deploy/<name>.manifest.json; private files are not read")
    data = json.loads(safe_path(root, release).read_text(encoding="utf8"))
    if not isinstance(data, dict):
        raise ValueError("release manifest must be an object")
    evidence = data.get("verification") or {}
    if not isinstance(evidence, dict):
        return list(names)
    expected_mode = "edge" if business == "edge-install" else "terminal"
    try:
        date = datetime.fromisoformat(evidence.get("verified_at", ""))
        verified = (date.utcoffset() is not None and date <= datetime.now(date.tzinfo)
                    and evidence.get("status") == "passed")
    except (ValueError, TypeError, AttributeError):
        verified = False
    required = {"central_sync", "protected"} | ({"edge_telemetry"} if expected_mode == "edge" else {"collector_runtime"})
    evidence_checks = evidence.get("checks", [])
    if not isinstance(evidence_checks, list) or any(not isinstance(item, str) for item in evidence_checks):
        return list(names)
    if (not verified or data.get("component") != "collector" or data.get("mode") != expected_mode
            or not required.issubset(evidence_checks)):
        return list(names)
    records = data.get("files", [])
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        raise ValueError("invalid release file list")
    remote_hashes = {item.get("remote"): item.get("sha256") for item in records}
    if len(remote_hashes) != len(records):
        raise ValueError("duplicate release file path")
    missing = []
    for name in names:
        unit = name.startswith("deploy/")
        remote = "/etc/systemd/system/traffic-audit.service" if unit else f"/usr/local/libexec/traffic-audit/{name}"
        digest = normalized_hash(safe_path(root, name), unit and expected_mode == "terminal")
        if remote_hashes.get(remote) != digest:
            missing.append(name)
    return missing


def build_plan(business: str, changed=(), *, release=None, ops="none", vps_docs=False, root=ROOT) -> dict:
    root = Path(root).resolve()
    if business not in BUSINESSES or ops not in {"none", "docs", "audit", "runtime", "config"}:
        raise ValueError("unknown business or ops scope")
    install = business in {"edge-install", "terminal-install"}
    if release and not install:
        raise ValueError("--release applies only to reuse installations")
    level, groups, gates = BUSINESSES[business]
    groups, gates = set(groups), set(gates)
    paths = sorted(set(changed))
    for name in paths:
        safe_path(root, name)
        risk, tests, checks = classify(name)
        level, groups, gates = max(level, risk), groups | set(tests), gates | set(checks)
    unverified = unverified_artifacts(root, business, release) if install else []
    for name in unverified:
        risk, tests, checks = classify(name)
        level, groups, gates = max(level, 2, risk), groups | set(tests), gates | set(checks)
    test_files = sorted({name for group in groups if group != "full"
                         for name in GROUPS.get(group, (group,))})
    full = "full" in groups
    audit_remote = business != "docs" or bool(gates)
    tasks = [{"id": "handover", "cwd": str(root), "argv": [sys.executable, "tools/check.py"]}]
    syntax = sorted({name for name in paths + (list(COLLECTOR) if install else []) if name.endswith(".py")})
    if syntax:
        tasks.append({"id": "syntax", "paths": syntax})
    for name in (["test*.py"] if full else test_files):
        tasks.append({"id": f"test:{name}", "cwd": str(root), "argv":
                      [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", name, "-v"]})
    ops_root = root.parent / "ops_mcp"
    if ops in {"audit", "runtime", "config"}:
        level = max(level, 3 if ops in {"runtime", "config"} else 2)
        # Config fixtures do not read hosts.json. Registry syntax uses the existing validator separately.
        selected = ([path.relative_to(ops_root).as_posix() for path in sorted((ops_root / "tests").glob("*.test.mjs"))]
                    if ops == "runtime" else [{"audit": "tests/audit.test.mjs", "config": "tests/config-write.test.mjs"}[ops]])
        if not selected:
            raise ValueError("ops_mcp fixture tests are missing")
        tasks.extend({"id": task_id, "cwd": str(ops_root), "argv": argv} for task_id, argv in (
            ("ops:typecheck", ["node", "node_modules/typescript/bin/tsc", "--noEmit", "-p", "tsconfig.json"]),
            ("ops:test", ["node", "--import", "tsx", "--test", *selected]),
            ("ops:build", ["node", "node_modules/typescript/bin/tsc", "-p", "tsconfig.json"]),
        ))
        gates.add("mcp_live")
    if vps_docs:
        vps_root = root.parent / "vps"
        tasks.append({"id": "vps:docs", "cwd": str(vps_root), "argv":
                      [PWSH, "-NoProfile", "-File", "tools/docs/Test-Documentation.ps1"]})
    if audit_remote:
        gates |= {"scope", "static", "boundary", "protected", "cleanup"}
    if install:
        gates.add("artifact")
    pending = [{"id": name, "check": GATES[name]} for name in GATES if name in gates]
    return {
        "policy_version": POLICY_VERSION, "business": business, "level": f"L{level}",
        "changed": paths, "ops_scope": ops, "unverified_artifacts": unverified,
        "full_suite": full, "test_files": test_files if not full else ["tests/*.py"],
        "local_tasks": tasks, "remote_gates": pending,
        "observation": "受影响采集/关联至少一个完整 5 秒窗口；涉及同步至少一次 30 秒 ACK 前进，最长 90 秒后停止等待并诊断。无流量归属标为未验证。" if gates & {"collector_runtime", "edge_telemetry", "central_sync", "attribution"} else None,
        "skipped": ["全套 Python 回归"] if not full else [],
        "remote_executed": False,
    }


def execute_local(plan: dict, *, root=ROOT, runner=subprocess.run) -> dict:
    root = Path(root).resolve()
    results = []
    for task in plan["local_tasks"]:
        if task["id"] == "syntax":
            try:
                for name in task["paths"]:
                    path = safe_path(root, name)
                    if path.is_file():  # Deleted files have no candidate syntax to check.
                        ast.parse(path.read_text(encoding="utf8"), filename=name)
                result = {"id": "syntax", "returncode": 0}
            except (OSError, SyntaxError, ValueError) as exc:
                result = {"id": "syntax", "returncode": 1, "output": str(exc)}
        else:
            try:
                if task["id"].startswith("test:"):
                    pattern = task["argv"][-2]
                    if not any((root / "tests").glob(pattern)):
                        raise ValueError(f"selected test file is missing: {pattern}")
                env = dict(os.environ, PYTHONUTF8="1", PYTHONIOENCODING="utf-8")
                done = runner(task["argv"], cwd=task["cwd"], env=env, shell=False,
                              capture_output=True, text=True, encoding="utf8", errors="replace")
                result = {"id": task["id"], "returncode": done.returncode,
                          "output": (done.stdout + done.stderr).strip()}
            except (OSError, ValueError) as exc:
                result = {"id": task["id"], "returncode": 1, "output": str(exc)}
        results.append(result)
        if result["returncode"]:
            return {"status": "local_failed", "results": results, "remote_executed": False}
    return {"status": "local_pass_remote_pending" if plan["remote_gates"] else "local_pass",
            "results": results, "remote_executed": False}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--business", required=True, choices=BUSINESSES)
    parser.add_argument("--changed", action="append", default=[], help="actual changed project-relative file; repeatable")
    parser.add_argument("--release", help="reviewed deploy/<name>.manifest.json with previous acceptance evidence")
    parser.add_argument("--ops", choices=("none", "docs", "audit", "runtime", "config"), default="none")
    parser.add_argument("--vps-docs", action="store_true")
    parser.add_argument("--run", action="store_true", help="execute local checks only; never contact hosts")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    try:
        plan = build_plan(args.business, args.changed, release=args.release, ops=args.ops, vps_docs=args.vps_docs)
    except (OSError, ValueError, TypeError) as exc:
        parser.error(str(exc))
    execution = execute_local(plan) if args.run else {"status": "planned", "remote_executed": False}
    if args.json:
        print(json.dumps({"plan": plan, "execution": execution}, ensure_ascii=False, indent=2))
    else:
        print(f"{plan['level']} {plan['business']} — {execution['status']}")
        if plan["unverified_artifacts"]:
            print("缺少匹配的已验收产物证据，按相关代码/单元升级检查：" + ", ".join(plan["unverified_artifacts"]))
        for task in plan["local_tasks"]:
            print("LOCAL " + task["id"] + ": " + (subprocess.list2cmdline(task["argv"]) if "argv" in task else ", ".join(task["paths"])))
        for gate in plan["remote_gates"]:
            print("PENDING " + gate["id"] + ": " + gate["check"])
        if plan["observation"]:
            print(plan["observation"])
        for result in execution.get("results", []):
            print(f"{'PASS' if result['returncode'] == 0 else 'FAIL'} {result['id']}")
            if result["returncode"]:
                print(result.get("output", ""))
        print("本工具没有连接服务器；本地通过不代表线上验收完成。")
    return 1 if execution["status"] == "local_failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
