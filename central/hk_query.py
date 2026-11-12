#!/usr/bin/env python3
"""Unified HK reader; preserve the shared query contract and collector rate scope."""
import json
import os
import runpy
import sys
import time

ROOT = "/usr/local/libexec/traffic-central"
os.environ.setdefault("TRAFFIC_CENTRAL_ROOT", "/etc/traffic-central-hk")
os.environ.setdefault("TRAFFIC_CENTRAL_CONFIG", "/etc/traffic-central-hk/reader.json")
os.environ.setdefault("TRAFFIC_CENTRAL_PUBLISHERS", "tb1/term-b1,tb2/term-b2,termc/term-c,tb3/term-b3,termb4/term-b4")
os.environ.setdefault("TRAFFIC_CENTRAL_NODE", "center-host")
# tb1 (host deregistered) and tb2 (audit units removed 2026-10-26) no longer publish.
os.environ.setdefault("TRAFFIC_CENTRAL_RETIRED_PUBLISHERS", "tb1/term-b1,tb2/term-b2")
os.environ.setdefault("TRAFFIC_CENTRAL_ACTIVE_EDGE_NODES", "termc/entry-b2,tb3/entry-b1,tb3/entry-b2,termb4/entry-a1,termb4/entry-a2")


def main():
    sys.path.insert(0, ROOT)
    reader = runpy.run_path("/usr/local/libexec/traffic-central-hk-store/query.py")
    try:
        result = reader["run"](reader["parse_args"](sys.argv[1:]))
        if sys.argv[1:2] == ["details"]:
            result["rate_terminal_scope"] = "per_collector"
            result["warnings"] = [s.replace("速率为同一真实源 IP", "速率为同一采集终止端内同一真实源 IP") for s in result["warnings"]]
    except Exception as exc:
        result = {"schema_version": 1, "mode": "central", "node": "center-host", "storage": "mysql",
                  "status": "error", "now": time.time(), "retention_days": 14, "metrics": {},
                  "warnings": ["central_query_failed:" + type(exc).__name__]}
    print(json.dumps(result, ensure_ascii=True, allow_nan=False, separators=(",", ":")))
    raise SystemExit(1 if result.get("status") == "error" else 0)


if __name__ == "__main__":
    main()
