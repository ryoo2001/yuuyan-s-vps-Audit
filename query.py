#!/usr/bin/env python3
"""Read-only traffic audit CLI; Python 3.8+, standard library only.

Production paths are fixed; TRAFFIC_AUDIT_CONFIG enables local fixture paths.
Domain filters are exact DNS hostnames, normalized using the standard-library
IDNA codec (not wildcard patterns, URLs, or underscore-bearing service labels).
A missing visits table is supported for older databases, with an explicit warning.
"""

import argparse
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import sys
import time
import unicodedata

from presentation import COLUMNS as DETAIL_COLUMNS


CONFIG_PATH = "/etc/traffic-audit/config.json"
DB_PATH = "/var/lib/traffic-audit/audit.sqlite"
HEALTH_PATH = "/var/lib/traffic-audit/health.json"
RETENTION_DAYS = 7
HEALTH_MAX_AGE = 30
BYTE_BASIS = "mihomo_sampled_payload_lower_bound"
DETAIL_DEDUP_WINDOW_SECONDS = 5
DETAIL_DEDUP_BASIS = "source_ip_site_entry_fixed_window"
SUMMARY_VIEW_COLUMNS = ("时间", "源 IP", "IP归属地", "入口机器", "目标网站", "流量统计")
SUMMARY_VIEW_SCOPE = "current_beijing_calendar_month_to_latest"
SUMMARY_VIEW_GROUPING = "source_ip_node_site"
SUMMARY_VIEW_TIME_BASIS = "beijing_month_start_to_latest_sample_date"
SUMMARY_WARNINGS = (
    "载荷增量按连接聚合为一分钟桶；非整分钟查询的起止边界精度为一分钟。",
    "采样可能遗漏短连接及连接结束时的尾量；统计值仅为已采样的载荷下界。",
    "该统计不能用于计费。",
    "unknown 表示归属信息未知，不等于无访问；空结果也不能证明没有流量。",
    "流量口径是 mihomo 采样载荷，不是线上加密报文的字节数。",
    "没有快照时 upload_bytes/download_bytes/total_bytes=0 只是已观测下界，不得视为实际零流量。",
    "request_events 是访问日志观测事件数，不是 HTTP 请求总数；日志订阅可能丢失事件，不能保证访问记录完整。",
)
GROUP_COLUMNS = {"source_ip": "source_ip", "site": "site", "node": "node"}
SAMPLE_COLUMNS = {
    "event_id": "TEXT", "ts": "REAL", "connection_id": "TEXT", "node": "TEXT",
    "source_ip": "TEXT", "site": "TEXT", "upload_bytes": "INTEGER",
    "download_bytes": "INTEGER", "quality": "TEXT",
}
VISIT_COLUMNS = {
    "event_id": "TEXT", "ts": "REAL", "node": "TEXT", "source_ip": "TEXT",
    "site": "TEXT", "destination_port": "INTEGER", "network": "TEXT",
    "flow_id": "TEXT", "quality": "TEXT",
}
ISO_PATTERN = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-][0-9]{2}:[0-9]{2})\Z"
)
HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


class QueryError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


class JsonArgumentParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs["allow_abbrev"] = False
        super().__init__(*args, **kwargs)

    def error(self, message):
        raise QueryError("invalid_arguments", message)


class StoreOnce(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if getattr(namespace, self.dest, None) is not None:
            parser.error("duplicate option: " + option_string)
        setattr(namespace, self.dest, values)


def parse_iso(value):
    if not ISO_PATTERN.fullmatch(value):
        raise QueryError("invalid_arguments", "timestamps require YYYY-MM-DDTHH:MM:SS[.ffffff] and Z or ±HH:MM")
    if value[-1] != "Z" and (int(value[-5:-3]) > 23 or int(value[-2:]) > 59):
        raise QueryError("invalid_arguments", "invalid timezone offset")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise QueryError("invalid_arguments", "invalid ISO timestamp") from exc


def normalize_source_ip(value):
    if "%" in value:
        raise QueryError("invalid_arguments", "source IP must not contain a zone ID")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise QueryError("invalid_arguments", "source IP must be a single IPv4 or IPv6 address") from exc


def normalize_domain(value):
    value = value.translate(str.maketrans({"\u3002": ".", "\uff0e": ".", "\uff61": "."}))
    if value.endswith("."):
        value = value[:-1]
    if not value or any(
        char not in ".-" and unicodedata.category(char)[0] not in "LMN" for char in value
    ):
        raise QueryError("invalid_arguments", "domain must be an exact hostname, not a URL or pattern")
    try:
        domain = value.lower().encode("idna").decode("ascii").lower()
        if len(domain) > 253:
            raise ValueError("hostname too long")
        for label in domain.split("."):
            if not HOST_LABEL.fullmatch(label):
                raise ValueError("invalid hostname label")
            if label.startswith("xn--"):
                # The codec's ASCII fast path does not itself validate A-labels.
                decoded = label.encode("ascii").decode("idna")
                if decoded.encode("idna").decode("ascii") != label:
                    raise ValueError("noncanonical IDNA label")
                if any(char != "-" and unicodedata.category(char)[0] not in "LMN" for char in decoded):
                    raise ValueError("IDNA label is not a hostname")
    except (UnicodeError, ValueError) as exc:
        raise QueryError("invalid_arguments", "invalid DNS/IDNA hostname") from exc
    return domain


def parse_args(argv):
    parser = JsonArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("health", help="read and validate the health file only")
    details_parser = commands.add_parser("details", help="read the human-readable audit view")
    details_parser.add_argument("--limit", action=StoreOnce)
    details_parser.add_argument("--source-ip", action=StoreOnce)
    details_parser.add_argument("--domain", action=StoreOnce)
    summary_parser = commands.add_parser("summary", help="query samples and observed visits read-only")
    for flag in ("--from", "--to", "--group-by", "--limit"):
        summary_parser.add_argument(flag, required=True, action=StoreOnce)
    summary_parser.add_argument("--source-ip", action=StoreOnce)
    summary_parser.add_argument("--domain", action=StoreOnce)
    args = parser.parse_args(argv)
    if args.command == "summary":
        if args.group_by not in GROUP_COLUMNS:
            parser.error("group-by must be source_ip, site, or node")
        if not re.fullmatch(r"[1-9][0-9]{0,2}", args.limit) or int(args.limit) > 100:
            parser.error("limit must be an integer from 1 to 100")
        args.limit = int(args.limit)
        args.start = parse_iso(getattr(args, "from"))
        args.end = parse_iso(args.to)
        if not timedelta(0) < args.end - args.start <= timedelta(days=31):
            parser.error("window must be positive and no longer than 31 days")
        if args.source_ip is not None:
            args.source_ip = normalize_source_ip(args.source_ip)
        if args.domain is not None:
            args.domain = normalize_domain(args.domain)
    if args.command == "details":
        value = args.limit if args.limit is not None else "50"
        if not re.fullmatch(r"[1-9][0-9]{0,2}", value) or int(value) > 100:
            parser.error("limit must be an integer from 1 to 100")
        args.limit = int(value)
        if args.source_ip is not None:
            args.source_ip = normalize_source_ip(args.source_ip)
        if args.domain is not None:
            args.domain = normalize_domain(args.domain)
    return args


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("non-finite JSON number: " + value)


def read_json(stream):
    return json.load(stream, object_pairs_hook=_unique_object, parse_constant=_reject_constant)


def load_config():
    override = os.environ.get("TRAFFIC_AUDIT_CONFIG")
    try:
        with open(override if override is not None else CONFIG_PATH, "r", encoding="utf-8") as stream:
            config = read_json(stream)
    except (OSError, ValueError, RecursionError) as exc:
        raise QueryError("config_unavailable", "configuration is missing, unreadable, or invalid JSON") from exc
    if not isinstance(config, dict):
        raise QueryError("invalid_config", "configuration must be a JSON object")
    if config.get("mode") not in ("terminal", "edge"):
        raise QueryError("invalid_config", "config mode must be terminal or edge")
    node = config.get("node")
    if (not isinstance(node, str) or not node or node.strip() != node
            or any(unicodedata.category(char).startswith("C") for char in node)):
        raise QueryError("invalid_config", "config node must be a nonempty, printable identifier")
    # Fail rather than silently misreporting a conflicting retention setting.
    if type(config.get("retention_days")) is not int or config["retention_days"] != RETENTION_DAYS:
        raise QueryError("invalid_config", "schema version 1 requires retention_days=7")
    for key, fixed_path in (("db", DB_PATH), ("health", HEALTH_PATH)):
        value = config.get(key)
        if not isinstance(value, str) or not value or "\x00" in value or not Path(value).is_absolute():
            raise QueryError("invalid_config", "config " + key + " must be an absolute filesystem path")
        if override is None and value != fixed_path:
            raise QueryError("invalid_config", "production " + key + " path must be " + fixed_path)
    return config


def base_payload(config, now):
    payload = {
        "schema_version": 1,
        "mode": config["mode"] if config else None,
        "node": config["node"] if config else None,
        "status": "ok", "now": now, "retention_days": RETENTION_DAYS, "warnings": [],
    }

    if config and config.get("archive_node"):
        payload.update(archive_node=config["archive_node"], local_cache_hours=config.get("local_cache_hours"))
    return payload


def mark_error(payload, code, message):
    payload["status"] = "error"
    payload["error"] = {"code": code, "message": message}
    payload["warnings"].append(message)
    return payload


def health(config, now):
    payload = base_payload(config, now)
    payload["metrics"] = {}
    try:
        # Use the opened file's metadata, avoiding a separate path/stat race.
        with open(config["health"], "r", encoding="utf-8") as stream:
            document = read_json(stream)
            mtime = os.fstat(stream.fileno()).st_mtime
    except FileNotFoundError:
        return mark_error(payload, "health_missing", "health file is missing; this does not mean no traffic")
    except (OSError, ValueError, RecursionError):
        return mark_error(payload, "health_invalid", "health file is unreadable or invalid JSON")
    if not isinstance(document, dict):
        return mark_error(payload, "health_invalid", "health file must contain a JSON object")
    if document.get("node") != config["node"] or document.get("mode") != config["mode"]:
        return mark_error(payload, "health_identity_mismatch", "health node/mode do not match configuration")
    status, metrics, warnings = document.get("status", "ok"), document.get("metrics", {}), document.get("warnings", [])
    if (status not in ("ok", "degraded", "error") or not isinstance(metrics, dict)
            or not isinstance(warnings, list) or not all(isinstance(item, str) for item in warnings)):
        return mark_error(payload, "health_invalid", "invalid health status, metrics, or warnings")
    try:
        json.dumps(metrics, allow_nan=False)
    except (ValueError, RecursionError):
        return mark_error(payload, "health_invalid", "health metrics must contain finite JSON values")
    payload.update(status=status, metrics=metrics, warnings=list(warnings))
    if now < mtime:
        return mark_error(payload, "health_future", "health mtime is in the future; check clock synchronization")
    if now - mtime > HEALTH_MAX_AGE:
        return mark_error(payload, "health_stale", "health file is older than 30 seconds; this does not mean no traffic")
    return payload


def check_table(connection, table, expected, optional=False):
    # table and expected are internal constants, never CLI-provided identifiers.
    kind = connection.execute("SELECT type FROM sqlite_master WHERE name = ?", (table,)).fetchone()
    if kind is None and optional:
        return False
    if kind is None or kind[0] != "table":
        raise QueryError("invalid_schema", "database must contain a real " + table + " table")
    columns = connection.execute("PRAGMA table_info(" + table + ")").fetchall()
    actual = {column[1]: column[2].upper().strip() for column in columns}
    primary_key = {column[1]: column[5] for column in columns if column[5]}
    if any(actual.get(name) != kind for name, kind in expected.items()) or primary_key != {"event_id": 1}:
        raise QueryError("invalid_schema", table + " columns/types or event_id primary key do not match schema version 1")
    return True


def empty_counts():
    return {
        "connections": 0, "request_events": 0, "upload_bytes": 0,
        "download_bytes": 0, "total_bytes": 0, "measurement": "not_observed",
    }


def sample_counts(record):
    samples, connections, upload, download = record
    if any(type(value) is not int or value < 0 for value in record):
        raise QueryError("invalid_data", "sample aggregates must be nonnegative integers")
    return {
        "connections": connections, "request_events": 0,
        "upload_bytes": upload, "download_bytes": download, "total_bytes": upload + download,
        "measurement": "sampled_lower_bound" if samples else "not_observed",
    }


def summarize_tables(connection, args, visits_available):
    where = "ts >= ? AND ts < ?"
    parameters = [args.start.timestamp(), args.end.timestamp()]
    if args.source_ip is not None:
        where += " AND source_ip = ? COLLATE BINARY"
        parameters.append(args.source_ip)
    if args.domain is not None:
        where += " AND site = ? COLLATE BINARY"
        parameters.append(args.domain)
    column = GROUP_COLUMNS[args.group_by]
    key_sql = "COALESCE(NULLIF(" + column + ", ''), 'unknown') COLLATE BINARY"
    # SQLite accepts text in INTEGER columns; fail instead of silently turning
    # corrupt counters into plausible zero-byte results. Check the selected scope.
    invalid = connection.execute(
        "SELECT 1 FROM samples WHERE " + where + " AND ("
        "typeof(upload_bytes) != 'integer' OR upload_bytes < 0 OR "
        "typeof(download_bytes) != 'integer' OR download_bytes < 0 OR "
        "(connection_id IS NOT NULL AND typeof(connection_id) != 'text')) LIMIT 1",
        parameters,
    ).fetchone()
    if invalid is not None:
        raise QueryError("invalid_data", "selected samples contain invalid counters or connection identifiers")
    aggregates = (
        "COUNT(*), COUNT(DISTINCT connection_id COLLATE BINARY), "
        "COALESCE(SUM(upload_bytes), 0), COALESCE(SUM(download_bytes), 0)"
    )
    # Total connection cardinality must be computed over the whole selection;
    # summing group cardinalities double-counts connections that span groups.
    totals = sample_counts(connection.execute(
        "SELECT " + aggregates + " FROM samples WHERE " + where, parameters
    ).fetchone())
    groups = {}
    for record in connection.execute(
        "SELECT " + key_sql + ", " + aggregates + " FROM samples WHERE " + where + " GROUP BY 1",
        parameters,
    ):
        key = record[0]
        if not isinstance(key, str):
            raise QueryError("invalid_data", "sample group keys must be text or NULL")
        groups[key] = {"key": key, **sample_counts(record[1:])}
    if visits_available:
        # Aggregate each table independently. Joining raw events would multiply
        # both byte counters and visit counts. Only grouped records are merged.
        for key, events in connection.execute(
            "SELECT " + key_sql + ", COUNT(*) FROM visits WHERE " + where + " GROUP BY 1", parameters
        ):
            if not isinstance(key, str):
                raise QueryError("invalid_data", "visit group keys must be text or NULL")
            row = groups.setdefault(key, {"key": key, **empty_counts()})
            row["request_events"] = events
            totals["request_events"] += events
    # Sorting aggregated groups in Python also avoids SQLite's integer-to-float
    # promotion when upload + download exceeds the signed 64-bit integer range.
    rows = sorted(groups.values(), key=lambda row: (-row["total_bytes"], row["key"]))
    return rows[:args.limit], totals, len(groups)


def summary(config, args, now):
    if config["mode"] == "edge":
        raise QueryError("summary_unsupported", "summary is not supported in edge mode")
    if config.get("archive_node"):
        raise QueryError("central_archive_required", "Use legacy-center for authoritative seven-day summaries; this collector has a partial local cache")
    db = Path(config["db"])
    if not db.is_file():
        raise QueryError("db_missing", "audit database is missing or is not a regular file")
    # as_uri() escapes filename characters such as ? and #; they cannot inject
    # URI options. Never fall back to a writable connection or use immutable=1,
    # which could hide a live collector's WAL records.
    uri = db.as_uri() + "?mode=ro"
    connection = None
    try:
        connection = sqlite3.connect(uri, uri=True, timeout=2.0, isolation_level=None)
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA temp_store = MEMORY")
        connection.execute("BEGIN")  # Both tables and all counts share one snapshot.
        check_table(connection, "samples", SAMPLE_COLUMNS)
        visits_available = check_table(connection, "visits", VISIT_COLUMNS, optional=True)
        rows, totals, groups_total = summarize_tables(connection, args, visits_available)
    except sqlite3.Error as exc:
        raise QueryError("database_error", "unable to read audit database or aggregate its events") from exc
    finally:
        if connection is not None:
            connection.close()
    warnings = list(SUMMARY_WARNINGS)
    if not visits_available:
        warnings.append("visits 表不存在，仅返回采样统计；request_events=0 表示未提供日志观测数据，不代表没有访问。")
    payload = base_payload(config, now)
    payload.update(
        window={"from": args.start.isoformat().replace("+00:00", "Z"), "to": args.end.isoformat().replace("+00:00", "Z")},
        group_by=args.group_by, byte_basis=BYTE_BASIS, rows=rows, totals=totals,
        groups_total=groups_total, truncated=groups_total > args.limit, warnings=warnings,
        summary_view={"name": "流量汇总", "columns": list(SUMMARY_VIEW_COLUMNS),
                      "scope": SUMMARY_VIEW_SCOPE, "grouping": SUMMARY_VIEW_GROUPING,
                      "units": "decimal_MB_GB", "time_basis": SUMMARY_VIEW_TIME_BASIS,
                      "time_format": "YYYY/MM/01–YYYY/MM/DD"},
    )
    return payload



def details(config, args, now):
    if config["mode"] != "terminal":
        raise QueryError("unsupported_mode", "audit details are stored on the termination server only")
    connection = None
    try:
        uri = Path(config["db"]).resolve().as_uri() + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=2.0, isolation_level=None)
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        kind = connection.execute("SELECT type FROM sqlite_master WHERE name=?", ("审计明细",)).fetchone()
        if kind != ("view",):
            raise QueryError("invalid_schema", "human-readable audit view is unavailable; update the terminal collector")
        where, parameters = [], []
        if args.source_ip is not None:
            where.append('"源 IP"=? COLLATE BINARY')
            parameters.append(args.source_ip)
        if args.domain is not None:
            where.append('"目标网站"=? COLLATE BINARY')
            parameters.append(args.domain)
        sql = 'SELECT * FROM "审计明细"'
        if where:
            sql += " WHERE " + " AND ".join(where)
        cursor = connection.execute(sql + " LIMIT ?", parameters + [args.limit + 1])
        columns = [item[0] for item in cursor.description]
        if columns != list(DETAIL_COLUMNS):
            raise QueryError("invalid_schema", "audit detail columns do not match the presentation contract")
        records = cursor.fetchall()
    except sqlite3.Error as exc:
        raise QueryError("database_error", "unable to read audit details") from exc
    finally:
        if connection is not None:
            connection.close()
    payload = base_payload(config, now)
    payload.update(
        columns=list(DETAIL_COLUMNS), rows=[dict(zip(DETAIL_COLUMNS, row)) for row in records[:args.limit]],
        has_more=len(records) > args.limit, timezone="Asia/Shanghai", byte_basis=BYTE_BASIS,
        time_basis="last_observed", time_precision="minute",
        deduplication={
            "enabled": True,
            "window_seconds": DETAIL_DEDUP_WINDOW_SECONDS,
            "basis": DETAIL_DEDUP_BASIS,
            "key": ["source_ip", "node", "inbound_port", "site"],
            "representative": "latest_last_seen",
            "unknown_policy": "unknown source/site/entry rows are not merged",
        },
        warnings=[
            "时间为北京时间的最近观测时间，显示到分钟。",
            "源 IP 未关联时显示未识别，绝不替换成 source_peer；隧道地址由已核验的入口机器/路径映射。",
            "短连接和最后尾量仍可能遗漏，不能用于计费。",
        ],
    )
    if payload["has_more"]:
        payload["warnings"].append("本次仅显示最新的指定条数；has_more=true 表示还有记录，不是完整归档导出。")
    return payload


def main(argv=None):
    now, config, args = time.time(), None, None
    try:
        args = parse_args(argv)
        config = load_config()
        if args.command == "health":
            payload = health(config, now)
        elif args.command == "details":
            payload = details(config, args, now)
        else:
            payload = summary(config, args, now)
    except QueryError as exc:
        payload = mark_error(base_payload(config, now), exc.code, exc.message)
        if args is not None and args.command == "health":
            payload["metrics"] = {}
    except (OSError, ValueError, OverflowError):
        payload = mark_error(base_payload(config, now), "read_error", "unable to read or represent audit data")
        if args is not None and args.command == "health":
            payload["metrics"] = {}
    # Escaped Unicode remains portable on Windows and UTF-8 Linux terminals.
    print(json.dumps(payload, ensure_ascii=True, allow_nan=False, separators=(",", ":")))
    return 1 if payload["status"] == "error" else 0


if __name__ == "__main__":
    sys.exit(main())
