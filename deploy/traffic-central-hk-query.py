#!/usr/bin/env python3
"""Read-only HK dataset entrypoint at the unified center-host center."""
import os
import runpy
import sys

ROOT = "/usr/local/libexec/traffic-central"
os.environ.setdefault("TRAFFIC_CENTRAL_ROOT", "/etc/traffic-central-hk")
os.environ.setdefault("TRAFFIC_CENTRAL_CONFIG", "/etc/traffic-central-hk/reader.json")
os.environ.setdefault("TRAFFIC_CENTRAL_PUBLISHERS", "term-b1")
os.environ.setdefault("TRAFFIC_CENTRAL_NODE", "center-host")
os.environ.setdefault("TRAFFIC_CENTRAL_ACTIVE_EDGE_NODES", "entry-b1,entry-b2,entry-a1")
sys.path.insert(0, ROOT)
runpy.run_path(ROOT + "/query.py", run_name="__main__")
