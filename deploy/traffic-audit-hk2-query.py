#!/usr/bin/env python3
"""Fixed read-only health entrypoint for the HK2 edge probe."""
import os
import runpy
os.environ['TRAFFIC_AUDIT_CONFIG'] = '/etc/traffic-audit/entry-b1x.json'
runpy.run_path('/usr/local/libexec/traffic-audit/query_impl.py', run_name='__main__')
