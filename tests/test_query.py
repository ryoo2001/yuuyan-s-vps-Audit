"""Local-only tests: python -B -m unittest discover -s tests -p test_query.py -v."""

import contextlib
from datetime import datetime, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "query.py"
SPEC = importlib.util.spec_from_file_location("traffic_audit_query", SCRIPT)
query = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(query)
START = datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()
NOW = START + 1000
CREATE_SAMPLES = """
CREATE TABLE samples (
    event_id TEXT PRIMARY KEY, ts REAL, connection_id TEXT, node TEXT,
    source_ip TEXT, site TEXT, upload_bytes INTEGER, download_bytes INTEGER, quality TEXT
)
"""
CREATE_VISITS = """
CREATE TABLE visits (
    event_id TEXT PRIMARY KEY, ts REAL, node TEXT, source_ip TEXT, site TEXT,
    destination_port INTEGER, network TEXT, flow_id TEXT, quality TEXT
)
"""


class QueryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="audit-query-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = self.root / "audit.sqlite"
        self.health_path = self.root / "health.json"
        self.config_path = self.root / "config.json"
        self.config = {
            "mode": "terminal", "node": "collector-a", "db": str(self.db),
            "health": str(self.health_path), "retention_days": 7,
        }
        self.write_config()
        env = mock.patch.dict(os.environ, {"TRAFFIC_AUDIT_CONFIG": str(self.config_path)})
        env.start()
        self.addCleanup(env.stop)

    def write_config(self):
        self.config_path.write_text(json.dumps(self.config), encoding="utf-8")

    def create_db(self, rows=None, visits=None, ddl=CREATE_SAMPLES):
        connection = sqlite3.connect(self.db)
        try:
            connection.execute(ddl)
            if rows is not None:
                connection.executemany("INSERT INTO samples VALUES (?,?,?,?,?,?,?,?,?)", rows)
            if visits is not None:
                connection.execute(CREATE_VISITS)
                connection.executemany("INSERT INTO visits VALUES (?,?,?,?,?,?,?,?,?)", visits)
            connection.commit()
        finally:
            connection.close()

    def fixture_rows(self):
        def row(event, offset, connection, node, ip, site, up, down):
            return event, START + offset, connection, node, ip, site, up, down, "sampled"
        return [
            row("before", -0.001, "excluded-before", "node-a", "192.0.2.1", "alpha.example", 999, 999),
            row("a1", 0, "c1", "node-a", "192.0.2.1", "alpha.example", 10, 20),
            row("a2", 1, "c1", "node-a", "192.0.2.1", "alpha.example", 5, 5),
            row("b1", 2, "c2", "node-b", "192.0.2.2", "beta.example", 20, 30),
            row("b2", 3, "c1", "node-b", "192.0.2.1", "beta.example", 7, 3),
            row("u1", 4, "c3", None, None, None, 0, 8),
            row("u2", 5, "c3", "unknown", "", "", 2, 0),
            row("a3", 6, "c4", "node-a", "192.0.2.2", "alpha.example", 5, 5),
            row("at-end", 60, "excluded-end", "node-a", "192.0.2.1", "alpha.example", 999, 999),
        ]

    @staticmethod
    def visit(event, offset=0, node="node-a", ip="192.0.2.1", site="alpha.example", flow="c1"):
        return event, START + offset, node, ip, site, 443, "tcp", flow, "log_observed"

    def fixture_visits(self):
        return [
            self.visit("v-before", -0.001),
            self.visit("v1"),
            self.visit("v2", 1),
            self.visit("v3", 2, node="node-b", ip="192.0.2.2", site="beta.example", flow="c2"),
            self.visit("log-only", 3, node="node-c", ip="192.0.2.3", site="short.example", flow="short"),
            self.visit("v-null", 4, node=None, ip=None, site=None, flow=None),
            self.visit("v-empty", 5, node="unknown", ip="", site="", flow=None),
            self.visit("v-end", 60),
        ]

    def summary_args(self, group="source_ip", limit="100", start="2026-01-01T00:00:00Z", end="2026-01-01T00:01:00Z"):
        return ["summary", "--from", start, "--to", end, "--group-by", group, "--limit", limit]

    def invoke(self, args):
        output = io.StringIO()
        with mock.patch.object(query.time, "time", return_value=NOW), contextlib.redirect_stdout(output):
            code = query.main(args)
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), 1, "CLI must emit exactly one JSON document")
        return code, json.loads(lines[0])

    def subprocess_cli(self, args):
        return subprocess.run(
            [sys.executable, "-B", str(SCRIPT)] + args, cwd=self.root,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True, text=True, encoding="utf-8", timeout=15,
        )

    def write_health(self, age=0, **updates):
        document = {"node": "collector-a", "mode": "terminal", "status": "ok", "metrics": {}, "warnings": []}
        document.update(updates)
        self.health_path.write_text(json.dumps(document), encoding="utf-8")
        os.utime(self.health_path, (NOW - age, NOW - age))

    def assert_error(self, args, expected=None):
        code, payload = self.invoke(args)
        self.assertNotEqual(code, 0)
        self.assertEqual(payload["schema_version"], 1)
        self.assertEqual(payload["status"], "error")
        self.assertIsInstance(payload["error"]["message"], str)
        if expected:
            self.assertEqual(payload["error"]["code"], expected)
        return payload

    @staticmethod
    def counts(connections, up, down, events=0, measurement="sampled_lower_bound", key=None):
        result = dict(connections=connections, upload_bytes=up, download_bytes=down,
                      total_bytes=up + down, request_events=events, measurement=measurement)
        if key is not None:
            result["key"] = key
        return result

    def test_half_open_boundary_and_source_groups(self):
        self.create_db(self.fixture_rows())
        code, payload = self.invoke(self.summary_args())
        self.assertEqual(code, 0)
        self.assertEqual(payload["rows"], [
            self.counts(2, 25, 35, key="192.0.2.2"),
            self.counts(1, 22, 28, key="192.0.2.1"),
            self.counts(1, 2, 8, key="unknown"),
        ])
        self.assertEqual(payload["totals"], self.counts(4, 49, 71))
        self.assertEqual(payload["groups_total"], 3)
        self.assertFalse(payload["truncated"])
        self.assertEqual(payload["byte_basis"], "mihomo_sampled_payload_lower_bound")
        self.assertEqual(payload["window"], {"from": "2026-01-01T00:00:00Z", "to": "2026-01-01T00:01:00Z"})
        warnings = " ".join(payload["warnings"])
        for phrase in ("短连接", "尾量", "不能用于计费", "unknown", "不等于无访问", "不是线上加密报文", "不得视为实际零", "订阅可能丢失"):
            self.assertIn(phrase, warnings)

    def test_site_and_node_connections_deduplicate_independently(self):
        self.create_db(self.fixture_rows(), self.fixture_visits())
        for group, keys in (("site", ["beta.example", "alpha.example", "unknown", "short.example"]),
                            ("node", ["node-b", "node-a", "unknown", "node-c"])):
            with self.subTest(group=group):
                code, payload = self.invoke(self.summary_args(group=group))
                self.assertEqual(code, 0)
                self.assertEqual([row["key"] for row in payload["rows"]], keys)
                self.assertEqual([row["connections"] for row in payload["rows"]], [2, 2, 1, 0])
                self.assertEqual([row["request_events"] for row in payload["rows"]], [1, 2, 2, 1])
                self.assertEqual(payload["totals"]["connections"], 4)
                self.assertEqual(sum(row["connections"] for row in payload["rows"]), 5)
                self.assertEqual(payload["totals"]["request_events"], 6)

    def test_independent_aggregation_avoids_join_multiplication(self):
        self.create_db(self.fixture_rows(), self.fixture_visits())
        code, payload = self.invoke(self.summary_args())
        self.assertEqual(code, 0)
        self.assertEqual(payload["rows"], [
            self.counts(2, 25, 35, events=1, key="192.0.2.2"),
            self.counts(1, 22, 28, events=2, key="192.0.2.1"),
            self.counts(1, 2, 8, events=2, key="unknown"),
            self.counts(0, 0, 0, events=1, measurement="not_observed", key="192.0.2.3"),
        ])
        self.assertEqual(payload["totals"], self.counts(4, 49, 71, events=6))
        self.assertEqual(payload["groups_total"], 4)

    def test_logs_only_site_appears_and_does_not_invent_connections_or_bytes(self):
        self.create_db([], [self.visit("v1", site="short.example"), self.visit("v2", site="short.example")])
        code, payload = self.invoke(self.summary_args(group="site"))
        self.assertEqual(code, 0)
        self.assertEqual(payload["rows"], [self.counts(0, 0, 0, events=2, measurement="not_observed", key="short.example")])
        self.assertEqual(payload["totals"], self.counts(0, 0, 0, events=2, measurement="not_observed"))
        self.assertEqual(payload["groups_total"], 1)
        self.assertIn("不得视为实际零", " ".join(payload["warnings"]))

    def test_measurement_uses_sample_presence_not_bytes_or_connection_count(self):
        self.create_db([("zero", START, None, "node-a", "192.0.2.1", "alpha.example", 0, 0, None)], [self.visit("v1")])
        _, payload = self.invoke(self.summary_args())
        self.assertEqual(payload["rows"][0]["measurement"], "sampled_lower_bound")
        self.assertEqual(payload["totals"], self.counts(0, 0, 0, events=1))

    def test_limit_does_not_change_totals_or_combined_group_count(self):
        self.create_db(self.fixture_rows(), self.fixture_visits())
        code, payload = self.invoke(self.summary_args(limit="1"))
        self.assertEqual(code, 0)
        self.assertEqual(len(payload["rows"]), 1)
        self.assertEqual(payload["groups_total"], 4)
        self.assertTrue(payload["truncated"])
        self.assertEqual(payload["totals"], self.counts(4, 49, 71, events=6))
        _, exact = self.invoke(self.summary_args(limit="4"))
        self.assertFalse(exact["truncated"])

    def test_ties_sort_by_key_ascending_including_logs_only_groups(self):
        self.create_db([
            ("b", START, "c", "n", "192.0.2.2", "b.example", 10, 0, None),
            ("a", START, "c", "n", "192.0.2.1", "a.example", 0, 10, None),
        ], [self.visit("z", site="z.example"), self.visit("y", site="y.example")])
        _, payload = self.invoke(self.summary_args(group="site"))
        self.assertEqual([row["key"] for row in payload["rows"]], ["a.example", "b.example", "y.example", "z.example"])
        self.assertEqual(payload["totals"]["connections"], 1)

    def test_empty_window_is_unobserved_with_caveats(self):
        self.create_db([], [])
        code, payload = self.invoke(self.summary_args())
        self.assertEqual(code, 0)
        self.assertEqual(payload["rows"], [])
        self.assertEqual(payload["groups_total"], 0)
        self.assertFalse(payload["truncated"])
        self.assertEqual(payload["totals"], self.counts(0, 0, 0, measurement="not_observed"))
        self.assertTrue(payload["warnings"])

    def test_null_connection_id_follows_sql_count_distinct(self):
        self.create_db([("n", START, None, None, None, None, 1, 2, None)])
        _, payload = self.invoke(self.summary_args())
        self.assertEqual(payload["rows"][0]["key"], "unknown")
        self.assertEqual(payload["rows"][0]["connections"], 0)
        self.assertEqual(payload["totals"], self.counts(0, 1, 2))

    def test_filters_are_exact_and_intersect_for_both_tables(self):
        self.create_db(self.fixture_rows(), self.fixture_visits())
        _, payload = self.invoke(self.summary_args() + ["--source-ip", "192.0.2.1", "--domain", "ALPHA.EXAMPLE."])
        self.assertEqual(payload["totals"], self.counts(1, 15, 25, events=2))
        _, payload = self.invoke(self.summary_args() + ["--source-ip", "192.0.2.3", "--domain", "SHORT.EXAMPLE."])
        self.assertEqual(payload["totals"], self.counts(0, 0, 0, events=1, measurement="not_observed"))
        _, payload = self.invoke(self.summary_args() + ["--domain", "example"])
        self.assertEqual(payload["groups_total"], 0)
        self.assertEqual(payload["totals"]["request_events"], 0)

    def test_idna_and_ipv6_normalization(self):
        self.create_db([("idn", START, "idn", "n", "2001:db8::1", "xn--bcher-kva.example", 4, 6, "sampled")],
                       [self.visit("idn", ip="2001:db8::1", site="xn--bcher-kva.example")])
        code, payload = self.invoke(self.summary_args() + [
            "--source-ip", "2001:0DB8:0000:0000:0000:0000:0000:0001", "--domain", "BÜCHER。EXAMPLE。",
        ])
        self.assertEqual(code, 0)
        self.assertEqual(payload["totals"], self.counts(1, 4, 6, events=1))
        self.assertEqual(query.normalize_domain("XN--BCHER-KVA.EXAMPLE."), "xn--bcher-kva.example")

    def test_offsets_and_fractional_boundaries_in_both_tables(self):
        self.create_db([
            ("before", START + 0.124999, "before", "n", "192.0.2.1", "s", 99, 0, None),
            ("start", START + 0.125, "start", "n", "192.0.2.1", "s", 1, 2, None),
            ("end", START + 0.5, "end", "n", "192.0.2.1", "s", 99, 0, None),
        ], [self.visit("before", 0.124999), self.visit("start", 0.125), self.visit("end", 0.5)])
        code, payload = self.invoke(self.summary_args(start="2026-01-01T08:00:00.125+08:00", end="2025-12-31T19:00:00.5-05:00"))
        self.assertEqual(code, 0)
        self.assertEqual(payload["totals"], self.counts(1, 1, 2, events=1))
        self.assertEqual(payload["window"], {"from": "2026-01-01T00:00:00.125000Z", "to": "2026-01-01T00:00:00.500000Z"})

    def test_window_maximum_and_invalid_order(self):
        self.create_db([])
        code, _ = self.invoke(self.summary_args(end="2026-02-01T00:00:00Z"))
        self.assertEqual(code, 0)
        for end in ("2026-02-01T00:00:00.000001Z", "2026-01-01T00:00:00Z", "2025-12-31T23:59:59Z"):
            with self.subTest(end=end):
                self.assert_error(self.summary_args(end=end), "invalid_arguments")

    def test_rejects_invalid_or_naive_iso(self):
        for value in ("2026-01-01", "2026-01-01T00:00:00", "2026-01-01 00:00:00Z",
                      "2026-01-01T00:00:00+00:99", "2026-01-01T00:00:00+24:00",
                      "2026-02-30T00:00:00Z", "2026-01-01T00:00:60Z",
                      "2026-01-01T00:00:00.1234567Z", "2026-01-01T00:00:00Z' OR 1=1--"):
            with self.subTest(value=value):
                self.assert_error(self.summary_args(start=value), "invalid_arguments")

    def test_strict_limit_and_group_allowlist(self):
        for limit in ("0", "101", "-1", "1.0", "01", "+1", "1e2", " 1", "1;DROP TABLE samples", "9" * 5000):
            with self.subTest(limit=limit[:30]):
                self.assert_error(self.summary_args(limit=limit), "invalid_arguments")
        for group in ("quality", "SOURCE_IP", "site; DROP TABLE samples;--", "node) UNION SELECT 1--"):
            with self.subTest(group=group):
                self.assert_error(self.summary_args(group=group), "invalid_arguments")

    def test_rejects_bad_ips_and_injection(self):
        for ip in ("192.0.2.999", "192.000.2.1", "192.0.2.1/24", "localhost", "unknown", "",
                   "192.0.2.1:80", " 192.0.2.1", "[2001:db8::1]", "fe80::1%eth0", "' OR 1=1 --"):
            with self.subTest(ip=ip):
                self.assert_error(self.summary_args() + ["--source-ip", ip], "invalid_arguments")

    def test_rejects_invalid_domains_wildcards_and_injection(self):
        for domain in ("", ".", "example..", "a..example", ".example", "-a.example", "a-.example",
                       "_service.example", "a_b.example", "*.example", "?.example", "exa%mple.com",
                       "https://example.com", "example.com:443", "a/b", "a@b", "a b", " a.example",
                       "example.com\n", "x' OR 1=1--", "a" * 64 + ".com", ".".join(["a" * 63] * 4),
                       "xn--.example", "xn--a.example", "😀.example", "xn--e28h.example"):
            with self.subTest(domain=domain):
                self.assert_error(self.summary_args() + ["--domain", domain], "invalid_arguments")

    def test_no_free_sql_paths_abbreviations_or_duplicate_options(self):
        for extra in (["--sql", "SELECT 1"], ["--db", str(self.db)], ["--config", str(self.config_path)],
                      ["--path", str(self.db)], ["--dom", "example.com"], ["--limit", "2"],
                      ["--domain", "a.example", "--domain", "b.example"]):
            with self.subTest(extra=extra):
                self.assert_error(self.summary_args() + extra, "invalid_arguments")
        for args in ([], ["sql"], ["summary"], ["health", "--db", str(self.db)]):
            with self.subTest(args=args):
                self.assert_error(args, "invalid_arguments")

    def test_missing_db_and_parents_are_never_created(self):
        for path in (self.db, self.root / "missing" / "nested" / "audit.sqlite"):
            with self.subTest(path=path):
                self.config["db"] = str(path)
                self.write_config()
                before = set(self.root.rglob("*"))
                payload = self.assert_error(self.summary_args(), "db_missing")
                self.assertNotIn("totals", payload)
                self.assertEqual(set(self.root.rglob("*")), before)
                self.assertFalse(path.exists())

    def test_schema_missing_table_and_view_are_errors(self):
        for ddl in ("CREATE TABLE unrelated(x)", "CREATE TABLE samples(event_id TEXT PRIMARY KEY)",
                    "CREATE VIEW samples AS SELECT 'x' AS event_id"):
            with self.subTest(ddl=ddl):
                self.create_db(ddl=ddl)
                self.assert_error(self.summary_args(), "invalid_schema")
                self.db.unlink()

    def test_schema_wrong_types_and_primary_key_are_errors(self):
        for ddl in (CREATE_SAMPLES.replace("ts REAL", "ts TEXT"),
                    CREATE_SAMPLES.replace("upload_bytes INTEGER", "upload_bytes REAL"),
                    CREATE_SAMPLES.replace("event_id TEXT PRIMARY KEY", "event_id TEXT"),
                    CREATE_SAMPLES.replace("event_id TEXT PRIMARY KEY", "event_id TEXT").replace("quality TEXT", "quality TEXT, PRIMARY KEY(event_id, connection_id)")):
            with self.subTest(ddl=ddl):
                self.create_db(ddl=ddl)
                self.assert_error(self.summary_args(), "invalid_schema")
                self.db.unlink()

    def test_missing_visits_is_backward_compatible_but_explicit(self):
        self.create_db(self.fixture_rows())
        code, payload = self.invoke(self.summary_args())
        self.assertEqual(code, 0)
        self.assertEqual(payload["totals"], self.counts(4, 49, 71))
        self.assertIn("visits 表不存在", " ".join(payload["warnings"]))
        self.assertIn("不代表没有访问", " ".join(payload["warnings"]))

    def test_present_but_invalid_visits_schema_is_error(self):
        for ddl in ("CREATE TABLE visits(event_id TEXT PRIMARY KEY)",
                    CREATE_VISITS.replace("ts REAL", "ts TEXT"),
                    CREATE_VISITS.replace("event_id TEXT PRIMARY KEY", "event_id TEXT"),
                    "CREATE VIEW visits AS SELECT 'x' AS event_id"):
            with self.subTest(ddl=ddl):
                self.create_db([])
                connection = sqlite3.connect(self.db)
                try:
                    connection.execute(ddl)
                    connection.commit()
                finally:
                    connection.close()
                self.assert_error(self.summary_args(), "invalid_schema")
                self.db.unlink()

    def test_empty_visits_table_is_not_reported_missing(self):
        self.create_db([], [])
        _, payload = self.invoke(self.summary_args())
        self.assertNotIn("visits 表不存在", " ".join(payload["warnings"]))

    def test_corrupt_db_is_json_error_and_unchanged(self):
        self.db.write_bytes(b"not a sqlite database")
        self.assert_error(self.summary_args(), "database_error")
        self.assertEqual(self.db.read_bytes(), b"not a sqlite database")

    def test_invalid_counters_fail_instead_of_silently_summing(self):
        for upload in (None, -1, 1.5, "not-a-number"):
            with self.subTest(upload=upload):
                self.create_db([("x", START, "c", "n", None, None, upload, 0, None)])
                self.assert_error(self.summary_args(), "invalid_data")
                self.db.unlink()

    def test_integer_sum_overflow_is_json_error(self):
        self.create_db([
            ("a", START, "a", "n", None, None, 2 ** 63 - 1, 0, None),
            ("b", START, "b", "n", None, None, 1, 0, None),
        ])
        self.assert_error(self.summary_args(), "database_error")

    def test_total_bytes_keeps_full_integer_precision(self):
        self.create_db([("a", START, "c", "n", None, None, 2 ** 63 - 1, 2 ** 63 - 1, None)])
        code, payload = self.invoke(self.summary_args())
        self.assertEqual(code, 0)
        self.assertEqual(payload["totals"]["total_bytes"], 2 ** 64 - 2)
        self.assertEqual(payload["rows"][0]["total_bytes"], 2 ** 64 - 2)

    def test_wire_samples_not_required_or_used(self):
        self.create_db(self.fixture_rows())
        connection = sqlite3.connect(self.db)
        try:
            connection.execute("CREATE TABLE wire_samples(bytes INTEGER)")
            connection.execute("INSERT INTO wire_samples VALUES (9999999)")
            connection.commit()
        finally:
            connection.close()
        _, payload = self.invoke(self.summary_args())
        self.assertEqual(payload["totals"]["total_bytes"], 120)

    def test_summary_read_only_uri_query_only_and_no_db_changes(self):
        self.create_db(self.fixture_rows(), self.fixture_visits())
        before = self.db.read_bytes()
        before_files = set(self.root.iterdir())
        original_connect = sqlite3.connect
        calls, traces = [], []

        def connect(database, **kwargs):
            calls.append((database, kwargs))
            connection = original_connect(database, **kwargs)
            connection.set_trace_callback(traces.append)
            return connection

        with mock.patch.object(query.sqlite3, "connect", side_effect=connect):
            code, _ = self.invoke(self.summary_args())
        self.assertEqual(code, 0)
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][0].endswith("?mode=ro"))
        self.assertTrue(calls[0][1]["uri"])
        self.assertIn("PRAGMA query_only = ON", traces)
        self.assertIn("BEGIN", traces)
        self.assertEqual(self.db.read_bytes(), before)
        self.assertEqual(set(self.root.iterdir()), before_files)
        self.assertFalse(self.health_path.exists())

    def test_wal_data_is_visible_and_aggregates_share_one_snapshot(self):
        self.create_db(self.fixture_rows(), [])
        original_connect = sqlite3.connect
        writer = original_connect(self.db)
        try:
            self.assertEqual(writer.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
            writer.execute("INSERT INTO visits VALUES (?,?,?,?,?,?,?,?,?)", self.visit("before-query"))
            writer.commit()
            writes = []

            def trace(sql):
                if sql.startswith("SELECT COUNT(*), COUNT(DISTINCT") and not writes:
                    writes.append(sql)
                    writer.execute("INSERT INTO visits VALUES (?,?,?,?,?,?,?,?,?)", self.visit("during-query"))
                    writer.execute("INSERT INTO samples VALUES (?,?,?,?,?,?,?,?,?)",
                                   ("during", START, "new", "node-a", "192.0.2.1", "alpha.example", 100, 0, None))
                    writer.commit()

            def connect(database, **kwargs):
                connection = original_connect(database, **kwargs)
                connection.set_trace_callback(trace)
                return connection

            with mock.patch.object(query.sqlite3, "connect", side_effect=connect):
                code, payload = self.invoke(self.summary_args())
            self.assertEqual(code, 0)
            self.assertEqual(len(writes), 1)
            self.assertEqual(payload["totals"], self.counts(4, 49, 71, events=1))
            self.assertEqual(sum(row["total_bytes"] for row in payload["rows"]), 120)
            _, next_payload = self.invoke(self.summary_args())
            self.assertEqual(next_payload["totals"], self.counts(5, 149, 71, events=2))
        finally:
            writer.close()

    def test_configured_filename_is_uri_escaped(self):
        self.db = self.root / "audit #mode=rw.sqlite"
        self.config["db"] = str(self.db)
        self.write_config()
        self.create_db(self.fixture_rows())
        code, payload = self.invoke(self.summary_args())
        self.assertEqual(code, 0)
        self.assertEqual(payload["totals"]["total_bytes"], 120)

    def test_edge_summary_fails_before_touching_database(self):
        self.config["mode"] = "edge"
        self.write_config()
        with mock.patch.object(query.sqlite3, "connect", side_effect=AssertionError("must not connect")):
            self.assert_error(self.summary_args(), "summary_unsupported")
        self.assertFalse(self.db.exists())

    def test_health_contract_and_no_database_access(self):
        self.write_health(metrics={"samples": 12})
        before = set(self.root.iterdir())
        with mock.patch.object(query.sqlite3, "connect", side_effect=AssertionError("health must not open DB")):
            code, payload = self.invoke(["health"])
        self.assertEqual(code, 0)
        self.assertEqual(payload, {
            "schema_version": 1, "mode": "terminal", "node": "collector-a", "status": "ok",
            "now": NOW, "retention_days": 7, "metrics": {"samples": 12}, "warnings": [],
        })
        self.assertFalse(self.db.exists())
        self.assertEqual(set(self.root.iterdir()), before)

    def test_health_age_exact_boundary_and_stale(self):
        self.write_health(age=30)
        self.assertEqual(self.invoke(["health"])[0], 0)
        self.write_health(age=30.001, metrics={"last_samples": 2})
        payload = self.assert_error(["health"], "health_stale")
        self.assertEqual(payload["metrics"], {"last_samples": 2})
        self.assertIn("does not mean no traffic", " ".join(payload["warnings"]))

    def test_health_missing_and_nested_parent_not_created(self):
        self.config["health"] = str(self.root / "missing" / "health.json")
        self.write_config()
        before = set(self.root.rglob("*"))
        payload = self.assert_error(["health"], "health_missing")
        self.assertEqual(payload["metrics"], {})
        self.assertEqual(set(self.root.rglob("*")), before)
        self.assertFalse(self.db.exists())

    def test_health_uses_file_mtime_not_document_time(self):
        self.write_health(age=31, now=NOW, timestamp=NOW)
        self.assert_error(["health"], "health_stale")
        self.write_health(age=0, now=0, timestamp=0)
        self.assertEqual(self.invoke(["health"])[0], 0)

    def test_future_health_mtime_is_error(self):
        self.write_health(age=-1)
        self.assert_error(["health"], "health_future")

    def test_health_node_and_mode_must_match(self):
        for updates in ({"node": "different"}, {"mode": "edge"}, {"node": None}, {"mode": None}):
            with self.subTest(updates=updates):
                self.write_health(**updates)
                self.assert_error(["health"], "health_identity_mismatch")

    def test_health_preserves_degraded_and_error(self):
        for status, expected_code in (("degraded", 0), ("error", 1)):
            with self.subTest(status=status):
                self.write_health(status=status, warnings=["collector cannot reach mihomo"], metrics={"failures": 2})
                code, payload = self.invoke(["health"])
                self.assertEqual(code, expected_code)
                self.assertEqual(payload["status"], status)
                self.assertEqual(payload["warnings"], ["collector cannot reach mihomo"])
                self.assertEqual(payload["metrics"], {"failures": 2})

    def test_edge_health_is_supported(self):
        self.config["mode"] = "edge"
        self.write_config()
        self.write_health(mode="edge")
        code, payload = self.invoke(["health"])
        self.assertEqual(code, 0)
        self.assertEqual(payload["mode"], "edge")

    def test_minimal_health_defaults(self):
        self.health_path.write_text(json.dumps({"mode": "terminal", "node": "collector-a"}), encoding="utf-8")
        os.utime(self.health_path, (NOW, NOW))
        code, payload = self.invoke(["health"])
        self.assertEqual(code, 0)
        self.assertEqual(payload["metrics"], {})
        self.assertEqual(payload["warnings"], [])

    def test_malformed_health_is_json_error(self):
        for content in ("{", "null", "[]", '{"mode":"terminal","node":"collector-a","node":"other"}',
                        '{"mode":"terminal","node":"collector-a","metrics":{"x":NaN}}',
                        '{"mode":"terminal","node":"collector-a","metrics":{"x":1e9999}}'):
            with self.subTest(content=content):
                self.health_path.write_text(content, encoding="utf-8")
                os.utime(self.health_path, (NOW, NOW))
                self.assert_error(["health"], "health_invalid")
        for updates in ({"metrics": []}, {"status": "healthy"}, {"warnings": "oops"}, {"warnings": [1]}):
            with self.subTest(updates=updates):
                self.write_health(**updates)
                self.assert_error(["health"], "health_invalid")

    def test_config_failures_do_not_create_anything(self):
        self.config_path.unlink()
        before = set(self.root.iterdir())
        self.assert_error(["health"], "config_unavailable")
        self.assertEqual(set(self.root.iterdir()), before)
        self.config_path.write_text("{}", encoding="utf-8")
        self.assert_error(["health"], "invalid_config")
        for updates in ({"mode": "other"}, {"node": None}, {"retention_days": 8},
                        {"retention_days": True}, {"db": "relative.sqlite"}, {"health": "file:///tmp/health"}):
            with self.subTest(updates=updates):
                original = dict(self.config)
                self.config.update(updates)
                self.write_config()
                self.assert_error(["health"], "invalid_config")
                self.config = original
        self.assertFalse(self.db.exists())

    def test_fixed_production_paths_without_override(self):
        with mock.patch.dict(os.environ, clear=True), mock.patch("builtins.open", side_effect=FileNotFoundError) as opened:
            self.assert_error(["health"], "config_unavailable")
        opened.assert_called_once_with("/etc/traffic-audit/config.json", "r", encoding="utf-8")
        self.assertEqual(query.DB_PATH, "/var/lib/traffic-audit/audit.sqlite")
        self.assertEqual(query.HEALTH_PATH, "/var/lib/traffic-audit/health.json")
        with mock.patch.dict(os.environ, clear=True), mock.patch("builtins.open", mock.mock_open(read_data=json.dumps(self.config))):
            self.assert_error(["health"], "invalid_config")

    def test_real_cli_success_and_error_json_exit_codes(self):
        self.create_db(self.fixture_rows(), self.fixture_visits())
        result = self.subprocess_cli(self.summary_args())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        self.assertEqual(json.loads(result.stdout)["totals"]["connections"], 4)
        self.assertEqual(json.loads(result.stdout)["totals"]["request_events"], 6)
        for args in (self.summary_args(group="site;DROP TABLE samples"), ["health"], []):
            with self.subTest(args=args):
                result = self.subprocess_cli(args)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stderr, "")
                self.assertEqual(json.loads(result.stdout)["status"], "error")
        connection = sqlite3.connect(self.db)
        try:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM samples").fetchone()[0], 9)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM visits").fetchone()[0], 8)
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
