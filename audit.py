#!/usr/bin/env python3
"""Passive, fail-open audit: ciphertext correlation, never a traffic proxy."""
import argparse
import hashlib
import hmac
import http.server
import ipaddress
import json
import math
import os
from pathlib import Path
import queue
import re
import signal
import socket
import sqlite3
import threading
import time
import tomllib
import urllib.request
import urllib.parse
import uuid
from datetime import datetime

from presentation import install as install_presentation
from rates import SourceRates, RATE_BASIS
from maintenance import delete_batches

VERSION = 1
PATCH_VERSION = "2026.10.11.1"
DAY = 86400
STATE_HEARTBEAT_SECONDS = 10
FLOW_RETRY_SECONDS = 2
STOP = threading.Event()
RFC2544_FAKE_NET = ipaddress.ip_network("198.18.0.0/15")


def compact(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True)


def derive_key(path, node):
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    secret = data["network_identity"]["network_secret"]
    if not isinstance(secret, str) or not secret:
        raise ValueError("network authentication is unavailable")
    return hmac.new(secret.encode(), ("traffic-audit/v1/" + node).encode(), hashlib.sha256).digest()


def is_fake_source_ip(value):
    """Return whether an observed source is RFC2544's reserved test range."""
    try:
        return ipaddress.ip_address(value) in RFC2544_FAKE_NET
    except ValueError:
        return False


def exclusive_ingress_routes(config):
    """Validate explicitly isolated entry paths; never infer a client address."""
    result = {}
    for route in config.get("exclusive_ingress", []):
        node = route.get("node")
        port = route.get("inbound_port")
        names = route.get("inbound_names")
        peer = str(ipaddress.IPv4Address(route.get("source_peer")))
        if config.get("mode") != "terminal" or node not in config.get("peers", {}):
            raise ValueError("unverified exclusive ingress node")
        if type(port) is not int or port not in config.get("inbound_ports", []):
            raise ValueError("unverified exclusive ingress port")
        if not isinstance(names, list) or not names or any(not isinstance(n, str) or not n for n in names):
            raise ValueError("unverified exclusive ingress listener")
        nodes = {r["node"] for r in config.get("entry_routes", []) if r["inbound_port"] == port}
        if nodes != {node} or (peer, port) in result:
            raise ValueError("exclusive ingress port is shared")
        captures = [c for c in config.get("captures", []) if c.get("interface") == route.get("interface")]
        if len(captures) != 1 or any(port not in captures[0].get(p + "_ports", []) for p in ("tcp", "udp")):
            raise ValueError("exclusive ingress capture is missing")
        result[(peer, port)] = (node, frozenset(names))
    return result


def inbound_types(config):
    """Opt in each listener to supported controller metadata types."""
    result = {port: frozenset(("Mieru",)) for port in config.get("inbound_ports", [])}
    for port, names in config.get("inbound_types", {}).items():
        if str(int(port)) != port or int(port) not in result:
            raise ValueError("unverified inbound type port")
        if not isinstance(names, list) or not names or any(n not in ("Mieru", "ShadowSocks", "AnyTLS") for n in names):
            raise ValueError("unsupported inbound type")
        result[int(port)] = frozenset(names)
    return result


def fingerprint_routes(config):
    """Bind signed edge ports to captured terminal ports across DNAT/SNAT."""
    result = {}
    for route in config.get("fingerprint_routes", []):
        node, port, edge_port = route["node"], route["inbound_port"], route["entry_port"]
        transport = route["transport"]
        if (transport not in ("tcp", "udp") or type(port) is not int or type(edge_port) is not int
                or port not in config.get("inbound_ports", [])
                or edge_port not in config.get("peers", {}).get(node, {}).get(transport + "_ports", [])
                or not any(port in c.get(transport + "_ports", []) for c in config.get("captures", []))):
            raise ValueError("unverified fingerprint route")
        result.setdefault((port, transport), set()).add((node, edge_port))
    return result


def controller_config(path):
    # Keep secrets in memory; no configuration or response body is logged.
    import yaml
    data = yaml.safe_load(Path(path).read_text())
    address = data.get('external-controller', '')
    if address not in ('127.0.0.1:9090', 'localhost:9090'):
        raise ValueError('controller must remain loopback-only')
    return "http://127.0.0.1:9090/connections", str(data.get('secret', ''))



def epoch(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def validate_event(event):
    if not isinstance(event, dict):
        raise ValueError("invalid event")
    if event.get("type") not in ("flow_open", "flow_close", "fingerprint", "wire_delta", "capture_stats", "health"):
        raise ValueError("unsupported event")
    stamp = event.get("capture_ts")
    if not isinstance(stamp, (int, float)) or not math.isfinite(stamp):
        raise ValueError("invalid timestamp")
    if len(compact(event)) > 8192:
        raise ValueError("event too large")
    if event["type"] in ("health", "capture_stats"):
        return
    for key in ("src_ip", "dst_ip"):
        ipaddress.IPv4Address(event[key])
    for key in ("src_port", "dst_port"):
        if type(event[key]) is not int or not 1 <= event[key] <= 65535:
            raise ValueError("invalid port")
    if event.get("transport") not in ("tcp", "udp"):
        raise ValueError("invalid transport")
    if not isinstance(event.get("flow_id"), str) or not 1 <= len(event["flow_id"]) <= 160:
        raise ValueError("invalid flow identifier")
    if event["type"] == "fingerprint" and not re.fullmatch(r"[0-9a-f]{64}", event.get("fingerprint", "")):
        raise ValueError("invalid fingerprint")
    if event["type"] == "wire_delta":
        for key in ("up_bytes", "down_bytes", "up_packets", "down_packets"):
            if type(event.get(key)) is not int or not 0 <= event[key] <= 2**53:
                raise ValueError("invalid counter")


def udp_batch(node, key, data):
    """Reduce only the acknowledged event prefix; never silently discard an event."""
    from transport import encode, PacketTooLarge
    data = dict(data, events=list(data["events"]))
    while True:
        try:
            encode(node, key, data)
            return data
        except PacketTooLarge:
            if len(data["events"]) <= 1:
                raise
            data["events"] = data["events"][:max(1, len(data["events"]) // 2)]


class Store:
    def __init__(self, config):
        self.config = config
        self.node = config["node"]
        self.mode = config["mode"]
        self.ingress_routes = exclusive_ingress_routes(config)
        self.inbound_types = inbound_types(config)
        self.fingerprint_routes = fingerprint_routes(config)
        self.lock = threading.RLock()
        self.source_rates = SourceRates()
        self.state_cache = {}
        self.rate_cache = {}
        self.flow_clients = {}
        self.lookup_checks = {}
        self.flow_versions = {}
        self.sample_stats = {"sampler_polls": 0, "sampler_state_writes": 0,
                             "sampler_rate_writes": 0, "sampler_flow_queries": 0}
        path = Path(config["db"])
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False, timeout=5)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA auto_vacuum=INCREMENTAL")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.execute("PRAGMA max_page_count=" + str(config.get("max_db_mb", 2048) * 256))
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS spool(id INTEGER PRIMARY KEY AUTOINCREMENT,event_id TEXT UNIQUE,ts REAL,body TEXT);
        CREATE TABLE IF NOT EXISTS seen(event_id TEXT PRIMARY KEY,ts REAL);
        CREATE INDEX IF NOT EXISTS seen_time ON seen(ts);
        CREATE TABLE IF NOT EXISTS flows(flow_id TEXT PRIMARY KEY,node TEXT,kind TEXT,transport TEXT,
          src_ip TEXT,src_port INTEGER,dst_ip TEXT,dst_port INTEGER,start_ts REAL,end_ts REAL,
          coverage TEXT,source_ip TEXT,source_node TEXT,quality TEXT);
        CREATE INDEX IF NOT EXISTS flow_tuple ON flows(kind,transport,src_ip,src_port,dst_port,start_ts);
        CREATE INDEX IF NOT EXISTS flow_socket ON flows(kind,src_ip,src_port,dst_port,start_ts);
        CREATE INDEX IF NOT EXISTS flow_matches ON flows(kind,source_ip) WHERE source_ip IS NOT NULL;
        CREATE INDEX IF NOT EXISTS flow_log_tuple ON flows(kind,src_ip,src_port,start_ts);
        CREATE INDEX IF NOT EXISTS flow_expiry ON flows(COALESCE(end_ts,start_ts));
        CREATE TABLE IF NOT EXISTS fingerprints(event_id TEXT PRIMARY KEY,ts REAL,node TEXT,kind TEXT,
          transport TEXT,flow_id TEXT,fingerprint TEXT,src_ip TEXT,src_port INTEGER,dst_port INTEGER);
        CREATE INDEX IF NOT EXISTS fingerprint_key ON fingerprints(fingerprint,transport);
        CREATE INDEX IF NOT EXISTS fingerprint_time ON fingerprints(ts);
        CREATE TABLE IF NOT EXISTS connection_state(connection_id TEXT PRIMARY KEY,start_ts REAL,last_seen REAL,
          source_peer TEXT,source_port INTEGER,inbound_port INTEGER,site TEXT,prev_up INTEGER,prev_down INTEGER,
          flow_id TEXT,source_ip TEXT,node TEXT,quality TEXT);
        CREATE INDEX IF NOT EXISTS connection_flow ON connection_state(flow_id);
        CREATE TABLE IF NOT EXISTS samples(event_id TEXT PRIMARY KEY,ts REAL,connection_id TEXT,node TEXT,
          source_ip TEXT,site TEXT,upload_bytes INTEGER,download_bytes INTEGER,quality TEXT);
        CREATE INDEX IF NOT EXISTS samples_time ON samples(ts);
        CREATE INDEX IF NOT EXISTS samples_connection ON samples(connection_id);
        -- Durable daily totals let the human-readable summary survive raw-row retention.
        -- Keys use empty strings for unknown values so SQLite can enforce uniqueness.
        CREATE TABLE IF NOT EXISTS traffic_rollup(
          day_start INTEGER NOT NULL, source_ip TEXT NOT NULL, node TEXT NOT NULL, site TEXT NOT NULL,
          upload_bytes INTEGER NOT NULL, download_bytes INTEGER NOT NULL, latest_ts REAL NOT NULL,
          PRIMARY KEY(day_start,source_ip,node,site));
        CREATE INDEX IF NOT EXISTS traffic_rollup_day ON traffic_rollup(day_start);
        CREATE TABLE IF NOT EXISTS wire_samples(bucket INTEGER,node TEXT,source_ip TEXT,entry_port INTEGER,
          transport TEXT,up_bytes INTEGER,down_bytes INTEGER,up_packets INTEGER,down_packets INTEGER,
          PRIMARY KEY(bucket,node,source_ip,entry_port,transport));
        CREATE INDEX IF NOT EXISTS wire_time ON wire_samples(bucket);
        CREATE TABLE IF NOT EXISTS visits(event_id TEXT PRIMARY KEY,ts REAL,node TEXT,source_ip TEXT,
          site TEXT,destination_port INTEGER,network TEXT,flow_id TEXT,quality TEXT);
        CREATE INDEX IF NOT EXISTS visits_time ON visits(ts);
        CREATE INDEX IF NOT EXISTS visits_flow ON visits(flow_id);
        CREATE TABLE IF NOT EXISTS peers(node TEXT PRIMARY KEY,last_received REAL,sender_ts REAL,metrics TEXT);
        """)
        self.db.execute("INSERT OR IGNORE INTO meta VALUES('audit_start',?)", (str(time.time()),))
        self.audit_start = float(self.db.execute("SELECT value FROM meta WHERE key='audit_start'").fetchone()[0])
        self.sanitize_reserved_sources()
        # Capture continuity cannot be assumed across daemon restarts. Never reuse stale tuples.
        self.db.execute("UPDATE flows SET end_ts=? WHERE kind='terminal' AND end_ts IS NULL", (time.time(),))
        if self.mode == "terminal":
            install_presentation(self.db, config)
            rate_basis = self.db.execute("SELECT value FROM meta WHERE key='rate_basis'").fetchone()
            if not rate_basis or rate_basis[0] != RATE_BASIS:
                self.db.execute("UPDATE connection_rates SET interval_seconds=NULL,upload_bps=NULL,download_bps=NULL")
                self.db.execute("INSERT OR REPLACE INTO meta VALUES('rate_basis',?)", (RATE_BASIS,))
        self.db.commit()
        self.cache_revision = self.db.total_changes

    def sanitize_reserved_sources(self):
        """Drop RFC2544 fake-IP values from derived source identities.

        Keep the raw packet tuple in ``src_ip``/fingerprints, but never leave
        the reserved address in a field that feeds user-facing source views.
        This startup migration is idempotent and also repairs rows written by
        older collectors.
        """
        for table in ("flows", "connection_state", "samples", "visits"):
            rows = self.db.execute(
                f"SELECT rowid,source_ip FROM {table} "
                "WHERE source_ip IS NOT NULL AND source_ip<>''"
            ).fetchall()
            for row in rows:
                if is_fake_source_ip(row["source_ip"]):
                    self.db.execute(
                        f"UPDATE {table} SET source_ip=NULL,quality=? WHERE rowid=?",
                        ("reserved_source_ip", row["rowid"]),
                    )
        # wire_samples uses source_ip as part of its primary key, so merge
        # reserved rows into the empty-source bucket before deleting them.
        rows = self.db.execute(
            "SELECT bucket,node,source_ip,entry_port,transport,up_bytes,down_bytes,"
            "up_packets,down_packets FROM wire_samples WHERE source_ip<>''"
        ).fetchall()
        for row in rows:
            if not is_fake_source_ip(row["source_ip"]):
                continue
            self.db.execute(
                "INSERT INTO wire_samples VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(bucket,node,source_ip,entry_port,transport) DO UPDATE SET "
                "up_bytes=up_bytes+excluded.up_bytes,down_bytes=down_bytes+excluded.down_bytes,"
                "up_packets=up_packets+excluded.up_packets,down_packets=down_packets+excluded.down_packets",
                (row["bucket"], row["node"], "", row["entry_port"], row["transport"],
                 row["up_bytes"], row["down_bytes"], row["up_packets"], row["down_packets"]),
            )
            self.db.execute(
                "DELETE FROM wire_samples WHERE bucket=? AND node=? AND source_ip=? "
                "AND entry_port=? AND transport=?",
                (row["bucket"], row["node"], row["source_ip"], row["entry_port"], row["transport"]),
            )
        rows = self.db.execute(
            "SELECT day_start,source_ip,node,site,upload_bytes,download_bytes,latest_ts "
            "FROM traffic_rollup WHERE source_ip<>''"
        ).fetchall()
        for row in rows:
            if not is_fake_source_ip(row["source_ip"]):
                continue
            self.db.execute(
                "INSERT INTO traffic_rollup VALUES(?,?,?,?,?,?,?) "
                "ON CONFLICT(day_start,source_ip,node,site) DO UPDATE SET "
                "upload_bytes=upload_bytes+excluded.upload_bytes,"
                "download_bytes=download_bytes+excluded.download_bytes,"
                "latest_ts=MAX(latest_ts,excluded.latest_ts)",
                (row["day_start"], "", row["node"], row["site"], row["upload_bytes"],
                 row["download_bytes"], row["latest_ts"]),
            )
            self.db.execute(
                "DELETE FROM traffic_rollup WHERE day_start=? AND source_ip=? AND node=? AND site=?",
                (row["day_start"], row["source_ip"], row["node"], row["site"]),
            )

    def enqueue(self, events):
        with self.lock, self.db:
            self.db.executemany("INSERT INTO spool(event_id,ts,body) VALUES(?,?,?)", [
                (str(uuid.uuid4()), time.time(), compact(e)) for e in events])
        self.cache_revision = self.db.total_changes

    def ingest(self, node, events, sent_at, received_at, kind):
        with self.lock, self.db:
            for wrapped in events:
                event_id, e = wrapped["event_id"], wrapped["event"]
                if not self.db.execute("INSERT OR IGNORE INTO seen VALUES(?,?)", (event_id, received_at)).rowcount:
                    continue
                # Edge clocks are not synchronized. Correlation uses receiver-normalized age.
                stamp = e["capture_ts"] if kind == "terminal" else received_at - max(0, sent_at - e["capture_ts"])
                typ = e["type"]
                if typ in ("health", "capture_stats"):
                    continue
                fid = node + "/" + e["flow_id"]
                dest_port = e["dst_port"]
                if kind == "terminal":
                    dest_port = self.config.get("port_aliases", {}).get(str(dest_port), dest_port)
                    key = (e["src_ip"], e["src_port"], dest_port)
                    if typ in ("flow_open", "flow_close", "fingerprint") and key in self.flow_versions:
                        self.flow_versions[key] += 1
                values = (fid, node, kind, e["transport"], e["src_ip"], e["src_port"], e["dst_ip"], dest_port)
                if typ == "flow_open":
                    self.db.execute("INSERT OR IGNORE INTO flows VALUES(?,?,?,?,?,?,?,?,?,NULL,?,NULL,NULL,'unresolved')",
                                    values + (stamp, e.get("coverage", "unknown")))
                elif typ == "flow_close":
                    self.db.execute("UPDATE flows SET end_ts=? WHERE flow_id=? AND end_ts IS NULL", (stamp, fid))
                elif typ == "fingerprint":
                    self.db.execute("INSERT OR IGNORE INTO flows VALUES(?,?,?,?,?,?,?,?,?,NULL,?,NULL,NULL,'unresolved')",
                                    values + (stamp, "fingerprint"))
                    self.db.execute("INSERT INTO fingerprints VALUES(?,?,?,?,?,?,?,?,?,?)", (
                        event_id, stamp, node, kind, e["transport"], fid, e["fingerprint"], e["src_ip"], e["src_port"], dest_port))
                    self.correlate(e["fingerprint"], e["transport"])
                elif typ == "wire_delta" and kind == "edge":
                    # RFC2544 addresses are client-side fake-IP values, not
                    # public source identities. Keep wire bytes, but put them
                    # in the unknown bucket instead of publishing a fake IP.
                    wire_source = "" if is_fake_source_ip(e["src_ip"]) else e["src_ip"]
                    self.db.execute("""INSERT INTO wire_samples VALUES(?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(bucket,node,source_ip,entry_port,transport) DO UPDATE SET
                    up_bytes=up_bytes+excluded.up_bytes,down_bytes=down_bytes+excluded.down_bytes,
                    up_packets=up_packets+excluded.up_packets,down_packets=down_packets+excluded.down_packets""", (
                        int(stamp // 60) * 60, node, wire_source, e["dst_port"], e["transport"],
                        e["up_bytes"], e["down_bytes"], e["up_packets"], e["down_packets"]))
        self.cache_revision = self.db.total_changes

    def ingress_node(self, peer, port, name=None):
        route = self.ingress_routes.get((peer, port))
        if route and (name is None or name in route[1]):
            return route[0]
        return None

    def correlate(self, digest, transport):
        terminals = self.db.execute("SELECT * FROM fingerprints WHERE kind='terminal' AND fingerprint=? AND transport=?", (digest, transport)).fetchall()
        for term in terminals:
            edges = self.db.execute("""SELECT DISTINCT node,src_ip,src_port,flow_id,dst_port FROM fingerprints
              WHERE kind='edge' AND fingerprint=? AND transport=? AND ABS(ts-?)<=300""", (digest, transport, term["ts"])).fetchall()
            routes = self.fingerprint_routes.get((term["dst_port"], transport))
            if routes:
                edges = [e for e in edges if (e["node"], e["dst_port"]) in routes]
            ingress = self.ingress_node(term["src_ip"], term["dst_port"])
            if ingress:
                edges = [e for e in edges if e["node"] == ingress]
            public_edges = [e for e in edges if not is_fake_source_ip(e["src_ip"])]
            if len(public_edges) == 1:
                e = public_edges[0]
                source_ip, node, quality = e["src_ip"], e["node"], "ciphertext_fingerprint"
            elif len(public_edges) > 1:
                source_ip, node, quality = None, None, "ambiguous_fingerprint"
            elif edges:
                reserved_nodes = {e["node"] for e in edges}
                source_ip = None
                node = next(iter(reserved_nodes)) if len(reserved_nodes) == 1 else None
                quality = "reserved_source_ip" if node is not None else "ambiguous_fingerprint"
            else:
                continue
            existing = self.db.execute("SELECT source_ip,source_node,quality FROM flows WHERE flow_id=?", (term["flow_id"],)).fetchone()
            # Multiple UDP fingerprints must agree; conflicting evidence never silently wins.
            if existing and existing["quality"] == "ambiguous_fingerprint":
                source_ip, node, quality = None, None, "ambiguous_fingerprint"
            elif existing and existing["source_ip"] and (existing["source_ip"], existing["source_node"]) != (source_ip, node):
                source_ip, node, quality = None, None, "ambiguous_fingerprint"
            if existing and tuple(existing) == (source_ip, node, quality):
                continue
            self.db.execute("UPDATE flows SET source_ip=?,source_node=?,quality=? WHERE flow_id=?", (source_ip, node, quality, term["flow_id"]))
            socket_key = (term["src_ip"], term["src_port"], term["dst_port"])
            self.flow_versions[socket_key] = self.flow_versions.get(socket_key, 0) + 1
            self.db.execute("UPDATE connection_state SET source_ip=?,node=?,quality=? WHERE flow_id=?", (source_ip, node, quality, term["flow_id"]))
            self.db.execute("UPDATE visits SET source_ip=?,node=?,quality=? WHERE flow_id=?", (source_ip, node, quality, term["flow_id"]))
            self.db.execute("""UPDATE samples SET source_ip=?,node=?,quality=? WHERE connection_id IN
              (SELECT connection_id FROM connection_state WHERE flow_id=?)""", (source_ip, node, quality, term["flow_id"]))
            for cid in self.flow_clients.get(term["flow_id"], ()):
                self.state_cache.pop(cid, None)
                self.rate_cache.pop(cid, None)

    def visit(self, payload, now):
        match = re.fullmatch(r"\[(TCP|UDP)\] (\d+\.\d+\.\d+\.\d+):(\d+) --> ([^ ]+):(\d+) (?:using|match) .*", payload)
        if not match:
            return False
        network, peer, port, site, destination_port = match.groups()
        with self.lock, self.db:
            flows = self.db.execute("""SELECT * FROM flows WHERE kind='terminal' AND src_ip=? AND src_port=?
              AND start_ts<=? AND (end_ts IS NULL OR end_ts>=?) ORDER BY start_ts DESC LIMIT 2""",
              (peer, int(port), now+2, now-2)).fetchall()
            if len(flows) == 1:
                f = flows[0]
                fid, source, node, quality = f['flow_id'], f['source_ip'], f['source_node'], f['quality']
                ingress = self.ingress_node(f["src_ip"], f["dst_port"])
                if ingress and node != ingress:
                    source, node, quality = None, ingress, "exclusive_ingress"
            else:
                return False
            self.db.execute('INSERT INTO visits VALUES(?,?,?,?,?,?,?,?,?)', (
                str(uuid.uuid4()), now, node, source, site.lower().rstrip('.')[:253], int(destination_port), network.lower(), fid, quality))
        self.cache_revision = self.db.total_changes
        return True

    def sample(self, connections, now, monotonic_now=None):
        tick = time.monotonic() if monotonic_now is None else monotonic_now
        rate_rows = []
        counts = {"active_connections": 0, "matched_connections": 0, "unresolved_connections": 0}
        allowed = set(self.config["inbound_ports"])
        columns = ("connection_id", "start_ts", "last_seen", "source_peer", "source_port",
                   "inbound_port", "site", "prev_up", "prev_down", "flow_id",
                   "source_ip", "node", "quality")
        pending, next_states, next_rates, next_checks = [], {}, {}, {}
        state_writes = rate_writes = 0
        with self.lock:
            if self.db.total_changes != self.cache_revision:
                # Also honor explicit corrections made on this Store's connection.
                self.state_cache.clear()
                self.rate_cache.clear()
                self.lookup_checks.clear()
                self.flow_versions.clear()
                self.flow_clients.clear()
            try:
                with self.db:
                    for c in connections:
                        m = c.get("metadata", {})
                        port = int(m.get("inboundPort") or 0)
                        if port not in allowed or m.get("type") not in self.inbound_types[port]:
                            continue
                        transport = m.get("network") if m.get("type") == "ShadowSocks" else None
                        if m.get("type") == "ShadowSocks" and transport not in ("tcp", "udp"):
                            continue
                        cid = c["id"]
                        up, down = max(0, int(c.get("upload", 0))), max(0, int(c.get("download", 0)))
                        started = epoch(c["start"])
                        peer, source_port = m.get("sourceIP", ""), int(m.get("sourcePort") or 0)
                        site = (m.get("host") or m.get("destinationIP") or "unknown").lower().rstrip(".")[:253]
                        cached = cid in self.state_cache
                        old = self.state_cache.get(cid)
                        if not cached:
                            row = self.db.execute("SELECT * FROM connection_state WHERE connection_id=?", (cid,)).fetchone()
                            old = dict(row) if row else None
                        if old:
                            du, dd = max(0, up-old["prev_up"]), max(0, down-old["prev_down"])
                            fid, source_ip, node, quality = old["flow_id"], old["source_ip"], old["node"], old["quality"]
                            if (old["source_peer"], old["source_port"], old["inbound_port"], old["start_ts"]) != (peer, source_port, port, started):
                                fid, source_ip, node, quality = None, None, None, "unresolved"
                        else:
                            du, dd = (up, down) if started >= self.audit_start else (0, 0)
                            fid, source_ip, node, quality = None, None, None, "unresolved"
                        lookup = self.lookup_checks.get(cid)
                        identity = (peer, source_port, port, started)
                        version = self.flow_versions.get(identity[:3], 0)
                        recover_stream = (self.config.get("tcp_stream_recovery", False)
                                          and transport == "tcp" and not source_ip
                                          and quality != "ambiguous_fingerprint")
                        if (not fid or recover_stream) and (not lookup or lookup[0] != version
                                        or lookup[2] != identity or tick-lookup[1] >= FLOW_RETRY_SECONDS):
                            self.sample_stats["sampler_flow_queries"] += 1
                            # Mieru and AnyTLS may carry UDP over TCP. Shadowsocks
                            # has distinct TCP/UDP sockets, even for the same tuple.
                            candidates = self.db.execute("""SELECT * FROM flows WHERE kind='terminal' AND src_ip=? AND src_port=?
                              AND dst_port=? AND start_ts<=? AND (end_ts IS NULL OR end_ts>=?)
                              AND (? IS NULL OR transport=?)
                              ORDER BY start_ts DESC LIMIT 2""",
                              (peer, source_port, port, started+2, started, transport, transport)).fetchall()
                            lookup = (version, tick, identity)
                            if len(candidates) == 1:
                                f = candidates[0]
                                fid, source_ip, node, quality = f["flow_id"], f["source_ip"], f["source_node"], f["quality"]
                            if recover_stream and quality != "ambiguous_fingerprint":
                                recovered = self.db.execute("""SELECT * FROM flows
                                  WHERE kind='terminal' AND src_ip=? AND src_port=? AND dst_port=?
                                  AND transport='tcp' AND coverage='midstream' AND end_ts IS NULL
                                  AND start_ts>=? AND start_ts<=? AND source_ip IS NOT NULL
                                  AND quality='ciphertext_fingerprint'
                                  ORDER BY start_ts DESC LIMIT 2""",
                                  (peer, source_port, port, started, now+2)).fetchall()
                                if len(recovered) == 1:
                                    f = recovered[0]
                                    fid, source_ip, node, quality = f["flow_id"], f["source_ip"], f["source_node"], f["quality"]
                        elif fid and old and not cached:
                            f = self.db.execute("SELECT * FROM flows WHERE flow_id=?", (fid,)).fetchone()
                            if f:
                                source_ip, node, quality = f["source_ip"], f["source_node"], f["quality"]
                        if lookup:
                            next_checks[cid] = lookup
                        ingress = self.ingress_node(peer, port, m.get("inboundName", ""))
                        if ingress and node != ingress:
                            source_ip, node, quality = None, ingress, "exclusive_ingress"
                        elif not ingress and quality == "exclusive_ingress":
                            source_ip, node, quality = None, None, "unresolved"
                        values = (cid, started, now, peer, source_port, port, site, up, down,
                                  fid, source_ip, node, quality)
                        rate_rows.append((cid, source_ip, up, down, started))
                        pending.append((cid, old, values))
                        if du or dd or not old:
                            bucket = int(now // 60) * 60
                            self.db.execute("""INSERT INTO samples VALUES(?,?,?,?,?,?,?,?,?)
                              ON CONFLICT(event_id) DO UPDATE SET
                              upload_bytes=upload_bytes+excluded.upload_bytes,
                              download_bytes=download_bytes+excluded.download_bytes,
                              node=excluded.node,source_ip=excluded.source_ip,quality=excluded.quality""",
                              (cid + ":" + str(bucket), bucket, cid, node, source_ip, site, du, dd, quality))
                        if source_ip and old and not old["source_ip"]:
                            self.db.execute("UPDATE samples SET source_ip=?,node=?,quality=? WHERE connection_id=?",
                                            (source_ip, node, quality, cid))
                        counts["active_connections"] += 1
                        counts["matched_connections" if source_ip else "unresolved_connections"] += 1
                    rates = self.source_rates.update(rate_rows, tick, now)
                    for cid, old, values in pending:
                        old_rate = self.rate_cache.get(cid)
                        if cid not in self.rate_cache:
                            row = self.db.execute("SELECT observed_at,interval_seconds,upload_bps,download_bps FROM connection_rates WHERE connection_id=?",
                                                  (cid,)).fetchone()
                            old_rate = tuple(row) if row else None
                        row = dict(zip(columns, values))
                        changed = not old or any(row[k] != old[k] for k in columns if k != "last_seen")
                        heartbeat = not old or now < old["last_seen"] or now-old["last_seen"] >= STATE_HEARTBEAT_SECONDS
                        rate_changed = not old_rate or tuple(rates[cid]) != old_rate[1:]
                        rate_unpaired = old and old_rate and old_rate[0] != old["last_seen"]
                        if changed or heartbeat or rate_changed or rate_unpaired:
                            self.db.execute("""INSERT INTO connection_state VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                              ON CONFLICT(connection_id) DO UPDATE SET
                              start_ts=excluded.start_ts,last_seen=excluded.last_seen,
                              source_peer=excluded.source_peer,source_port=excluded.source_port,
                              inbound_port=excluded.inbound_port,site=excluded.site,
                              prev_up=excluded.prev_up,prev_down=excluded.prev_down,
                              flow_id=excluded.flow_id,source_ip=excluded.source_ip,
                              node=excluded.node,quality=excluded.quality""", values)
                            self.db.execute("""INSERT INTO connection_rates VALUES(?,?,?,?,?)
                              ON CONFLICT(connection_id) DO UPDATE SET observed_at=excluded.observed_at,
                              interval_seconds=excluded.interval_seconds,upload_bps=excluded.upload_bps,
                              download_bps=excluded.download_bps""", (cid, now, *rates[cid]))
                            next_states[cid] = row
                            next_rates[cid] = (now, *rates[cid])
                            state_writes += 1
                            rate_writes += 1
                        else:
                            next_states[cid] = old
                            next_rates[cid] = old_rate
                # Publish cache baselines only after a successful database commit.
                self.state_cache, self.rate_cache, self.lookup_checks = next_states, next_rates, next_checks
                self.flow_versions = {lookup[2][:3]: self.flow_versions.get(lookup[2][:3], 0)
                                      for lookup in next_checks.values()}
                self.cache_revision = self.db.total_changes
                self.flow_clients = {}
                for cid, row in next_states.items():
                    if row["flow_id"]:
                        self.flow_clients.setdefault(row["flow_id"], set()).add(cid)
                self.sample_stats["sampler_polls"] += 1
                self.sample_stats["sampler_state_writes"] += state_writes
                self.sample_stats["sampler_rate_writes"] += rate_writes
            except Exception:
                self.state_cache.clear()
                self.rate_cache.clear()
                self.lookup_checks.clear()
                self.flow_versions.clear()
                self.flow_clients.clear()
                self.source_rates = SourceRates()
                raise
        return counts

    def prune(self, now):
        cutoff = now - self.config.get("retention_days", 7) * DAY
        for table, col in (("samples", "ts"), ("visits", "ts"), ("fingerprints", "ts"),
                           ("seen", "ts"), ("wire_samples", "bucket"), ("connection_state", "last_seen")):
            delete_batches(self.db, table, col+"<?", (cutoff,), lock=self.lock,
                           fold_samples=table == "samples")
        if self.mode == "terminal":
            delete_batches(self.db, "connection_rates",
                           "connection_id NOT IN (SELECT connection_id FROM connection_state)", lock=self.lock)
        delete_batches(self.db, "flows",
                       "COALESCE(end_ts,start_ts)<? AND flow_id NOT IN "
                       "(SELECT flow_id FROM connection_state WHERE flow_id IS NOT NULL)",
                       (cutoff,), lock=self.lock)
        expired = delete_batches(self.db, "spool", "ts<?",
                                 (now-self.config.get("spool_hours", 24)*3600,), lock=self.lock)
        with self.lock:
            self.state_cache.clear()
            self.rate_cache.clear()
            self.cache_revision = self.db.total_changes
        return expired


class Audit:
    def __init__(self, config):
        self.config = config
        self.store = Store(config)
        self.events = queue.Queue(maxsize=20000)
        self.metrics = {"queue_dropped": 0, "spool_expired_events": 0, "capture": {}}
        self.errors = {}
        self.wire = {}
        self.started = time.time()
        self.http_servers = []
        self.threads = []
        self.proxyless = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self.controller_available = bool(config.get("mihomo_config"))
        self.controller_lock = threading.Lock()
        self.controller_cache = None
        self.last_database_stats = 0
        if self.controller_available:
            try:
                self.controller_access()
            except Exception:
                # Capture remains available if the controller is unavailable.
                self.controller_available = False
        self.metrics["mihomo_controller_available"] = self.controller_available

    def controller_access(self):
        path = Path(self.config["mihomo_config"])
        stamp = path.stat()
        identity = (stamp.st_ino, stamp.st_size, stamp.st_mtime_ns, stamp.st_ctime_ns)
        with self.controller_lock:
            if self.controller_cache is None or self.controller_cache[0] != identity:
                self.controller_cache = None
                access = controller_config(path)
                self.controller_cache = (identity, access)
            return self.controller_cache[1]

    def capture_event(self, event):
        typ = event.get("type")
        if typ in ("capture_stats", "health"):
            self.metrics["capture"].setdefault(event.get("interface", "unknown"), {}).update(event)
            return
        if self.config["mode"] == "terminal" and typ == "wire_delta":
            return
        try:
            self.events.put_nowait(event)
        except queue.Full:
            self.metrics["queue_dropped"] += 1

    def spawn(self, name, target, restart=False):
        def guarded():
            failures = 0
            while not STOP.is_set():
                try:
                    target()
                    if STOP.is_set():
                        break
                    if not restart:
                        self.errors[name] = "stopped_unexpectedly"
                        break
                    failures += 1
                    self.errors[name] = "stopped_unexpectedly"
                except Exception as exc:
                    self.errors[name] = str(exc) if type(exc).__name__ == "CaptureError" else type(exc).__name__
                    if not restart:
                        break
                    failures += 1
                if restart and not STOP.is_set():
                    self.metrics["capture_restarts"] = self.metrics.get("capture_restarts", 0) + 1
                    delay = self.config.get("capture_restart_backoff_seconds", 1)
                    STOP.wait(min(30, delay * (2 ** min(failures - 1, 5))))
            if restart and STOP.is_set():
                self.errors.pop(name, None)
        thread = threading.Thread(target=guarded, name=name, daemon=True)
        thread.start()
        self.threads.append(thread)

    def capture(self, spec):
        from capture import Capture
        name = "capture:" + spec["interface"]
        self.errors.pop(name, None)
        collector = Capture(spec["interface"], spec.get("tcp_ports", []), spec.get("udp_ports", []),
                            lambda event: self.capture_event(dict(event, interface=spec["interface"])),
                            tcp_stream_fingerprints=self.config.get("tcp_stream_recovery", False))
        if self.config["mode"] == "edge" and spec.get("front_address"):
            from edge_front import front_bpf
            collector.bpf = front_bpf(spec["front_address"], collector.tcp_ports, collector.udp_ports)
        collector.run(STOP)
        if not STOP.is_set():
            self.errors[name] = "stopped_unexpectedly"

    def upload(self):
        udp = self.config.get("upload_transport") == "udp"
        self.metrics["upload_transport"] = "signed_udp" if udp else "http"
        while not STOP.is_set():
            rows = []
            delivered = False
            try:
                with self.store.lock:
                    rows = self.store.db.execute("SELECT * FROM spool ORDER BY id LIMIT 256").fetchall()
                capture_metrics = self.metrics["capture"]
                if udp:
                    # Keep loss diagnostics in every datagram; detailed coverage remains on the edge.
                    capture_metrics = {iface: {k: stat.get(k) for k in (
                        "status", "capture_ts", "snaplen", "packets_received", "packets_dropped", "packets_if_dropped"
                    )} for iface, stat in capture_metrics.items()}
                data = {"node": self.config["node"], "sent_at": time.time(), "events": [
                    {"event_id": r["event_id"], "event": json.loads(r["body"])} for r in rows],
                    "metrics": {"queue_dropped": self.metrics["queue_dropped"],
                                "spool_expired_events": self.metrics["spool_expired_events"],
                                "upload_transport": "signed_udp" if udp else "http", "capture": capture_metrics}}
                key = derive_key(self.config["auth_file"], self.config["node"])
                if udp:
                    from transport import exchange
                    data = udp_batch(self.config["node"], key, data)
                    rows = rows[:len(data["events"])]
                    endpoint = urllib.parse.urlsplit(self.config["endpoint"])
                    result = exchange((endpoint.hostname, endpoint.port or 19091), self.config["node"], key, data)
                else:
                    body = compact(data).encode()
                    req = urllib.request.Request(self.config["endpoint"] + "/ingest", data=body, method="POST", headers={
                        "Content-Type": "application/json", "X-Audit-Node": self.config["node"],
                        "X-Audit-Signature": hmac.new(key, body, hashlib.sha256).hexdigest()})
                    # The HK edge relay persists the batch through the public
                    # MySQL/TCP 3306 queue before acknowledging it.  Under
                    # normal load that write can take several seconds.  A
                    # five-second client deadline makes the relay finish the
                    # insert after the edge has already timed out, so the
                    # batch is retried and the spool grows while the terminal
                    # sees unresolved connections.  Keep the batch intact and
                    # allow the authenticated relay enough time to ACK it.
                    with self.proxyless.open(req, timeout=30) as response:
                        result = json.load(response)
                if type(result.get("accepted")) is not int or result["accepted"] != len(rows):
                    raise ValueError("incomplete acknowledgement")
                if rows:
                    with self.store.lock, self.store.db:
                        self.store.db.executemany("DELETE FROM spool WHERE id=?", [(r["id"],) for r in rows])
                self.metrics["last_upload"] = time.time()
                self.metrics["last_ack_events"] = len(rows)
                self.errors.pop("upload", None)
                delivered = True
            except Exception as exc:
                self.errors["upload"] = type(exc).__name__
            STOP.wait(0.05 if udp and delivered and rows else 1 if len(rows) == 256 else 3)

    def accept_batch(self, node, data):
        peer = self.config["peers"][node]
        if not isinstance(data, dict) or data.get("node") != node or not isinstance(data.get("events"), list) or len(data["events"]) > 256:
            raise ValueError("invalid batch")
        sent_at = data["sent_at"]
        if type(sent_at) not in (int, float) or not math.isfinite(sent_at) or abs(sent_at-time.time()) > 900:
            raise ValueError("invalid clock")
        if not isinstance(data.get("metrics", {}), dict):
            raise ValueError("invalid metrics")
        for item in data["events"]:
            if not isinstance(item, dict) or not re.fullmatch(r"[a-f0-9-]{36}", item.get("event_id", "")):
                raise ValueError("invalid event id")
            validate_event(item["event"])
            e = item["event"]
            if e["type"] not in ("health", "capture_stats") and e["dst_port"] not in peer.get(e["transport"]+"_ports", []):
                raise ValueError("out of scope port")
        received = time.time()
        self.store.ingest(node, data["events"], sent_at, received, "edge")
        with self.store.lock, self.store.db:
            self.store.db.execute("INSERT OR REPLACE INTO peers VALUES(?,?,?,?)", (node, received, sent_at, compact(data.get("metrics", {}))))
        return {"accepted": len(data["events"])}

    def udp_receiver(self, address):
        from transport import decode, encode
        def key_lookup(node):
            peer = self.config["peers"].get(node)
            if not peer or peer.get("upload_transport") != "udp":
                raise ValueError("unsupported UDP peer")
            return derive_key(peer["auth_file"], node)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((address, 19091))
            sock.settimeout(1)
            while not STOP.is_set():
                try:
                    packet, remote = sock.recvfrom(1201)
                except socket.timeout:
                    continue
                try:
                    node, data = decode(packet, key_lookup)
                except (ValueError, KeyError, TypeError):
                    self.metrics["udp_rejected_packets"] = self.metrics.get("udp_rejected_packets", 0) + 1
                    continue
                try:
                    result = self.accept_batch(node, data)
                    result["ack"] = hashlib.sha256(packet).hexdigest()
                    sock.sendto(encode(node, key_lookup(node), result), remote)
                    self.metrics["udp_accepted_batches"] = self.metrics.get("udp_accepted_batches", 0) + 1
                    self.errors.pop("udp_ingest", None)
                except Exception as exc:
                    self.errors["udp_ingest"] = type(exc).__name__

    def receiver(self, address):
        audit = self
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"
            def log_message(self, *args):
                pass
            def do_POST(self):
                self.connection.settimeout(5)
                try:
                    if self.path != "/ingest":
                        self.send_error(404)
                        return
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= 524288:
                        self.send_error(413)
                        return
                    node = self.headers.get("X-Audit-Node", "")
                    peer = audit.config["peers"].get(node)
                    if not peer:
                        self.send_error(403)
                        return
                    body = self.rfile.read(length)
                    if len(body) != length:
                        raise ValueError("incomplete request")
                    key = derive_key(peer["auth_file"], node)
                    signature = self.headers.get("X-Audit-Signature", "")
                    if not hmac.compare_digest(signature, hmac.new(key, body, hashlib.sha256).hexdigest()):
                        self.send_error(403)
                        return
                    payload = compact(audit.accept_batch(node, json.loads(body))).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    audit.errors.pop("receiver_last_error", None)
                except Exception as exc:
                    audit.errors["receiver_last_error"] = str(exc) if type(exc) is ValueError else type(exc).__name__
                    audit.metrics["receiver_failed_requests"] = audit.metrics.get("receiver_failed_requests", 0) + 1
                    try:
                        self.send_error(400 if isinstance(exc, ValueError) else 503)
                    except (BrokenPipeError, ConnectionResetError, TimeoutError):
                        pass
        # The ingestion payload is bounded; a single-threaded server also bounds RAM and sockets.
        class Server(http.server.HTTPServer):
            def get_request(self):
                sock, remote = super().get_request()
                # Header reads happen before do_POST; bound idle/partial-header clients too.
                sock.settimeout(5)
                return sock, remote
        server = Server((address, 19091), Handler)
        server.timeout = 1
        self.http_servers.append(server)
        while not STOP.is_set():
            server.handle_request()
        server.server_close()

    def stream_logs(self):
        while not STOP.is_set():
            try:
                _, secret = self.controller_access()
                req = urllib.request.Request('http://127.0.0.1:9090/logs?level=info', headers={'Authorization': 'Bearer '+secret})
                with self.proxyless.open(req, timeout=15) as response:
                    self.metrics['log_stream_connected'] = time.time()
                    self.errors.pop('logs', None)
                    while not STOP.is_set():
                        line = response.readline(16385)
                        if not line:
                            raise ConnectionError('stream closed')
                        if len(line) > 16384:
                            raise ValueError('log record too large')
                        obj = json.loads(line)
                        if self.store.visit(obj.get('payload', ''), time.time()):
                            self.metrics['last_visit_event'] = time.time()
                            self.metrics['visit_events'] = self.metrics.get('visit_events', 0)+1
            except TimeoutError:
                # Idle HTTP log streams have no heartbeat; reconnect and expose gaps.
                self.metrics['log_reconnects'] = self.metrics.get('log_reconnects', 0)+1
            except Exception as exc:
                self.errors['logs'] = type(exc).__name__
                self.metrics['log_reconnects'] = self.metrics.get('log_reconnects', 0)+1
            STOP.wait(0.5)

    def poll_mihomo(self):
        while not STOP.is_set():
            started = time.monotonic()
            try:
                url, secret = self.controller_access()
                req = urllib.request.Request(url, headers={"Authorization": "Bearer " + secret})
                with self.proxyless.open(req, timeout=3) as response:
                    data = json.load(response)
                if not isinstance(data, dict) or "connections" not in data or not isinstance(data["connections"], (list, type(None))):
                    raise ValueError("invalid controller snapshot")
                self.metrics.update(self.store.sample(data.get("connections") or [], time.time()))
                self.metrics["last_mihomo_poll"] = time.time()
                self.metrics["mihomo_upload_total"] = data.get("uploadTotal")
                self.metrics["mihomo_download_total"] = data.get("downloadTotal")
                self.errors.pop("mihomo", None)
            except Exception as exc:
                self.errors["mihomo"] = type(exc).__name__
            elapsed = time.monotonic() - started
            self.metrics["last_sample_duration_ms"] = round(elapsed * 1000, 3)
            STOP.wait(max(0.01, self.config.get("sample_interval", 0.5)-elapsed))

    def health(self):
        now = time.time()
        warnings = []
        with self.store.lock:
            self.metrics["spool_events"] = self.store.db.execute("SELECT COUNT(*) FROM spool").fetchone()[0]
            self.metrics["database_bytes"] = self.store.db.execute("PRAGMA page_count").fetchone()[0] * 4096
            if self.metrics["database_bytes"] > self.config.get("max_db_mb", 2048)*1048576*0.8:
                warnings.append("database_capacity_above_80_percent")
            if self.config["mode"] == "terminal":
                if now-self.last_database_stats >= 60 or now < self.last_database_stats:
                    self.metrics['retention_oldest_sample'] = self.store.db.execute('SELECT MIN(ts) FROM samples').fetchone()[0]
                    self.metrics['sample_rows'] = self.store.db.execute('SELECT COUNT(*) FROM samples').fetchone()[0]
                    self.metrics['visit_rows'] = self.store.db.execute('SELECT COUNT(*) FROM visits').fetchone()[0]
                    self.metrics['fingerprint_matches'] = self.store.db.execute("SELECT COUNT(*) FROM flows WHERE kind='terminal' AND source_ip IS NOT NULL").fetchone()[0]
                    self.last_database_stats = now
                self.metrics['database_stats_at'] = self.last_database_stats
                self.metrics.update(self.store.sample_stats)
                self.metrics['state_heartbeat_seconds'] = STATE_HEARTBEAT_SECONDS
                peers = {r["node"]: dict(r) for r in self.store.db.execute("SELECT * FROM peers")}
                for peer in peers.values():
                    peer["metrics"] = json.loads(peer["metrics"])
                    peer["clock_offset_seconds"] = peer["last_received"] - peer["sender_ts"]
                self.metrics["peers"] = peers
                for node in self.config["peers"]:
                    if now - peers.get(node, {}).get("last_received", 0) > 30:
                        warnings.append("edge_stale:" + node)
                if self.metrics.get("unresolved_connections", 0):
                    warnings.append("Some sources are unresolved, pre-capture, or outside the four-edge scope; never inferred from relay IP.")
                warnings.append("Website bytes are sampled payload lower bounds: short-lived connections and final bytes can be missed. Not billing data.")
                if not self.controller_available:
                    warnings.append("mihomo_controller_unavailable")
                elif now - self.metrics.get("last_mihomo_poll", 0) > 10:
                    warnings.append("mihomo_snapshot_stale")
            elif now - self.metrics.get("last_upload", 0) > 30:
                warnings.append("upload_stale")
        if self.metrics["queue_dropped"] or self.metrics["spool_expired_events"]:
            warnings.append("audit_data_loss_recorded")
        for interface, stats in self.metrics["capture"].items():
            if stats.get("packets_dropped", 0) or stats.get("packets_if_dropped", 0) or stats.get("ps_drop", 0):
                warnings.append("capture_drops:" + interface)
        for thread in self.threads:
            if not thread.is_alive() and not STOP.is_set():
                warnings.append("thread_not_running:" + thread.name)
        runtime_errors = {k: v for k, v in self.errors.items() if k != "receiver_last_error"}
        status = "error" if runtime_errors else "degraded" if len(warnings) > (1 if self.config["mode"] == "terminal" else 0) else "ok"
        self.metrics["threads_alive"] = {t.name: t.is_alive() for t in self.threads}
        result = {"schema_version": VERSION, "patch_version": PATCH_VERSION, "mode": self.config["mode"], "node": self.config["node"],
                  "status": status, "now": now, "retention_days": 7, "metrics": dict(self.metrics, errors=dict(self.errors)), "warnings": warnings}
        dest = Path(self.config["health"])
        tmp = dest.with_suffix(".tmp")
        tmp.write_text(compact(result))
        os.chmod(tmp, 0o600)
        tmp.replace(dest)

    def run(self):
        for spec in self.config["captures"]:
            self.spawn("capture:"+spec["interface"], lambda spec=spec: self.capture(spec), restart=True)
        if self.config["mode"] == "terminal":
            for addr in self.config["listen"]:
                self.spawn("receiver:"+addr, lambda addr=addr: self.receiver(addr))
            for addr in self.config.get("udp_listen", []):
                self.spawn("udp_receiver:"+addr, lambda addr=addr: self.udp_receiver(addr))
            if self.controller_available:
                self.spawn("mihomo", self.poll_mihomo)
                self.spawn("logs", self.stream_logs)
        else:
            self.spawn("upload", self.upload)
        last_health = last_prune = last_wire = 0
        while not STOP.is_set():
            pending = []
            try:
                pending.append(self.events.get(timeout=0.5))
            except queue.Empty:
                pass
            while len(pending) < 1000:
                try:
                    pending.append(self.events.get_nowait())
                except queue.Empty:
                    break
            events = []
            for e in pending:
                if e["type"] == "wire_delta":
                    k = (e["transport"], e["src_ip"], e["dst_port"])
                    if k not in self.wire:
                        self.wire[k] = dict(e)
                    else:
                        for f in ("up_bytes", "down_bytes", "up_packets", "down_packets"):
                            self.wire[k][f] += e[f]
                        self.wire[k]["capture_ts"] = e["capture_ts"]
                else:
                    events.append(e)
            now = time.time()
            if now-last_wire >= 10:
                events.extend(self.wire.values())
                self.wire.clear()
                last_wire = now
            if events:
                try:
                    if self.config["mode"] == "edge":
                        self.store.enqueue(events)
                    else:
                        self.store.ingest(self.config["node"], [{"event_id": str(uuid.uuid4()), "event": e} for e in events], now, now, "terminal")
                    self.errors.pop("storage", None)
                except Exception as exc:
                    self.errors["storage"] = type(exc).__name__
                    self.metrics["queue_dropped"] += len(events)
            if now-last_prune >= 300:
                try:
                    self.metrics["spool_expired_events"] += self.store.prune(now)
                    last_prune = now
                    self.errors.pop("retention", None)
                except Exception as exc:
                    self.errors["retention"] = type(exc).__name__
            if now-last_health >= 5:
                self.health()
                last_health = now
        # Capture tails stay in the durable queue on normal edge shutdown.
        for thread in self.threads:
            thread.join(timeout=2)
        tail = list(self.wire.values())
        while not self.events.empty():
            tail.append(self.events.get_nowait())
        if tail and self.config["mode"] == "edge":
            self.store.enqueue(tail)
        self.health()
        self.store.db.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/etc/traffic-audit/config.json")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text())
    if config["mode"] not in ("edge", "terminal") or config.get("retention_days") != 7:
        raise ValueError("invalid audit configuration")
    if type(config.get("tcp_stream_recovery", False)) is not bool:
        raise ValueError("invalid tcp_stream_recovery")
    exclusive_ingress_routes(config)
    inbound_types(config)
    fingerprint_routes(config)
    if args.check:
        print(compact({"ok": True, "node": config["node"], "mode": config["mode"]}))
        return
    os.umask(0o077)
    signal.signal(signal.SIGTERM, lambda *_: STOP.set())
    signal.signal(signal.SIGINT, lambda *_: STOP.set())
    Audit(config).run()


if __name__ == "__main__":
    main()
