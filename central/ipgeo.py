#!/usr/bin/env python3
"""Center-only IP geolocation cache built from public DB-IP Lite MMDB data."""

from __future__ import annotations

import argparse
import ctypes
import gzip
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import time
from datetime import datetime, timezone
from urllib.error import URLError
from urllib.request import Request, urlopen

import storage


GEO_TABLE = "ip_geo"
DEFAULT_DATABASES = ("region-a", "hk")
DATA_ROOT = Path(os.environ.get("TRAFFIC_CENTRAL_GEO_ROOT", "/var/lib/traffic-central/geo"))
DBIP_CITY_URL = os.environ.get(
    "TRAFFIC_CENTRAL_GEO_CITY_URL",
    "https://download.db-ip.com/free/dbip-city-lite-{month}.mmdb.gz",
)
DBIP_ASN_URL = os.environ.get(
    "TRAFFIC_CENTRAL_GEO_ASN_URL",
    "https://download.db-ip.com/free/dbip-asn-lite-{month}.mmdb.gz",
)
DOWNLOAD_INTERVAL = 30 * 24 * 60 * 60
MAX_DATABASE_BYTES = 256 * 1024 * 1024
DEFAULT_BATCH_SIZE = 500
MUNICIPALITIES = {"北京", "北京市", "上海", "上海市", "天津", "天津市", "重庆", "重庆市"}
EMPTY_FIELD = {"", "0", "未知", "unknown", "内网IP", "内网 IP"}


class _MMDBEntry(ctypes.Structure):
    _fields_ = [("mmdb", ctypes.c_void_p), ("offset", ctypes.c_uint32)]


class _MMDBResult(ctypes.Structure):
    _fields_ = [("found_entry", ctypes.c_bool), ("entry", _MMDBEntry), ("netmask", ctypes.c_uint16)]


class _MMDBValue(ctypes.Union):
    _fields_ = [
        ("pointer", ctypes.c_uint32), ("utf8_string", ctypes.c_char_p),
        ("double_value", ctypes.c_double), ("bytes", ctypes.POINTER(ctypes.c_uint8)),
        ("uint16", ctypes.c_uint16), ("uint32", ctypes.c_uint32),
        ("int32", ctypes.c_int32), ("uint64", ctypes.c_uint64),
        # GCC's unsigned __int128 has 16-byte alignment on the center host.
        # c_longdouble gives ctypes the same alignment and size.
        ("uint128", ctypes.c_longdouble),
        ("boolean", ctypes.c_bool), ("float_value", ctypes.c_float),
    ]


class _MMDBData(ctypes.Structure):
    _fields_ = [
        ("has_data", ctypes.c_bool), ("value", _MMDBValue),
        ("offset", ctypes.c_uint32), ("offset_to_next", ctypes.c_uint32),
        ("data_size", ctypes.c_uint32), ("type", ctypes.c_uint32),
    ]


class MmdbReader:
    """Small ctypes wrapper around the center host's libmaxminddb."""

    def __init__(self, path):
        self.path = Path(path)
        self._handle = ctypes.create_string_buffer(512)
        try:
            self._lib = ctypes.CDLL("libmaxminddb.so.0")
        except OSError as exc:
            raise RuntimeError("libmaxminddb_unavailable") from exc
        if ctypes.alignment(_MMDBValue) != 16 or ctypes.sizeof(_MMDBData) != 48:
            raise RuntimeError("libmaxminddb_layout_unsupported")
        self._lib.MMDB_open.argtypes = [ctypes.c_char_p, ctypes.c_uint32, ctypes.c_void_p]
        self._lib.MMDB_open.restype = ctypes.c_int
        self._lib.MMDB_close.argtypes = [ctypes.c_void_p]
        self._lib.MMDB_lookup_string.argtypes = [
            ctypes.c_void_p, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int), ctypes.POINTER(ctypes.c_int)
        ]
        self._lib.MMDB_lookup_string.restype = _MMDBResult
        self._lib.MMDB_aget_value.argtypes = [
            ctypes.POINTER(_MMDBEntry), ctypes.POINTER(_MMDBData), ctypes.POINTER(ctypes.c_char_p)
        ]
        self._lib.MMDB_aget_value.restype = ctypes.c_int
        status = self._lib.MMDB_open(os.fsencode(self.path), 1, ctypes.byref(self._handle))
        if status != 0:
            raise ValueError("dbip_mmdb_open_failed:%d" % status)
        self.version = hashlib.sha256(self.path.read_bytes()).hexdigest()[:24]

    def close(self):
        if self._handle is not None:
            self._lib.MMDB_close(ctypes.byref(self._handle))
            self._handle = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def lookup(self, address, *path):
        gai_error = ctypes.c_int()
        mmdb_error = ctypes.c_int()
        result = self._lib.MMDB_lookup_string(
            ctypes.byref(self._handle), str(address).encode("ascii"),
            ctypes.byref(gai_error), ctypes.byref(mmdb_error)
        )
        if gai_error.value or mmdb_error.value or not result.found_entry:
            return ""
        path_array = (ctypes.c_char_p * (len(path) + 1))(
            *(item.encode("utf8") for item in path), None
        )
        data = _MMDBData()
        status = self._lib.MMDB_aget_value(ctypes.byref(result.entry), ctypes.byref(data), path_array)
        if status != 0 or not data.has_data or data.type != 2 or not data.value.utf8_string:
            return ""
        return ctypes.string_at(data.value.utf8_string, data.data_size).decode("utf8", "replace")


def format_location(region):
    """Format country/province/city/ISP data for the detail-view contract."""
    fields = [part.strip() for part in (region or "").split("|")]
    if len(fields) < 4:
        return ""
    country, province, city, isp = fields[:4]
    country = "" if country in EMPTY_FIELD else country
    province = "" if province in EMPTY_FIELD else province
    city = "" if city in EMPTY_FIELD else city
    isp = "" if isp in EMPTY_FIELD else isp
    if not province and not city and not isp:
        return "" if country in {"中国", "China", "CN"} else country

    if province in MUNICIPALITIES or city in MUNICIPALITIES and country in {"中国", "China", "CN"}:
        place = next((value for value in (province, city) if value), "")
        if place in {"北京", "上海", "天津", "重庆"}:
            place += "市"
    elif province and city and city != province:
        place = province + "-" + city
    else:
        place = province or city or country
    if not place:
        return isp
    return (place + " " + isp).strip()


def lookup(readers, value):
    location, status, _ = lookup_region(readers, value)
    return location, status


def lookup_region(readers, value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return "未识别", "invalid_ip", ""
    normalized = str(address)
    if not address.is_global:
        return "未识别", "non_global", ""
    city = readers.get("city")
    asn = readers.get("asn")
    if city is None:
        return "未识别", "database_unavailable", ""
    province = city_value(city, normalized, ("subdivisions", "0", "names", "zh-CN"),
                          ("subdivisions", "0", "names", "zh"),
                          ("subdivisions", "0", "names", "en"))
    city_name = city_value(city, normalized, ("city", "names", "zh-CN"),
                           ("city", "names", "zh"), ("city", "names", "en"))
    operator = ""
    if asn is not None:
        operator = city_value(asn, normalized, ("autonomous_system_organization",),
                              ("traits", "autonomous_system_organization"),
                              ("traits", "isp"))
    location = format_dbip_location(province, city_name, operator)
    return location or "未识别", "matched" if location else "not_found", "%s|%s|%s" % (province, city_name, operator)


def city_value(reader, address, *paths):
    for path in paths:
        value = reader.lookup(address, *path)
        if value and value.strip() not in EMPTY_FIELD:
            return value.strip()
    return ""


def format_dbip_location(province, city_name, operator):
    province = "" if province in EMPTY_FIELD else province
    city_name = "" if city_name in EMPTY_FIELD else city_name
    operator = "" if operator in EMPTY_FIELD else operator
    if province in MUNICIPALITIES or city_name in MUNICIPALITIES:
        place = next((value for value in (province, city_name) if value), "")
        if place in {"北京", "上海", "天津", "重庆"}:
            place += "市"
    elif province and city_name and province != city_name:
        place = province + "-" + city_name
    else:
        place = province or city_name
    return (place + " " + operator).strip()


def _database_names(value):
    names = tuple(item for item in value.split(",") if item)
    if not names:
        raise ValueError("geo_database_list_empty")
    for name in names:
        storage.identifier(name)
    return names


def _download(path, url, now=None):
    now = time.time() if now is None else now
    if path.is_file() and now - path.stat().st_mtime < DOWNLOAD_INTERVAL:
        MmdbReader(path).close()
        return "cached"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name("." + path.name + ".download")
    request = Request(url, headers={"User-Agent": "traffic-audit-ipgeo/1"})
    try:
        with urlopen(request, timeout=45) as response, gzip.GzipFile(fileobj=response) as source, temporary.open("wb") as output:
            length = response.headers.get("Content-Length")
            if length is not None and int(length) > MAX_DATABASE_BYTES:
                raise ValueError("dbip_mmdb_download_too_large")
            total = 0
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_DATABASE_BYTES:
                    raise ValueError("dbip_mmdb_download_too_large")
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        MmdbReader(temporary).close()
        os.replace(temporary, path)
    except (OSError, URLError, ValueError):
        if temporary.exists():
            temporary.unlink()
        if path.is_file():
            MmdbReader(path).close()
            return "stale"
        raise
    return "updated"


def connect_root():
    import pymysql

    socket = os.environ.get("TRAFFIC_CENTRAL_MYSQL_SOCKET", "/run/mysqld/mysqld.sock")
    password_path = Path(os.environ.get("TRAFFIC_CENTRAL_ROOT_PASSWORD", "/etc/traffic-central/root-password"))
    kwargs = {
        "unix_socket": socket,
        "user": "root",
        "charset": "utf8mb4",
        "autocommit": False,
        "connect_timeout": 5,
        "read_timeout": 30,
        "write_timeout": 30,
    }
    if password_path.is_file():
        kwargs["password"] = password_path.read_text(encoding="utf8").strip()
    return pymysql.connect(**kwargs)


def _prefixes(cursor, database):
    cursor.execute(
        "SELECT TABLE_NAME FROM information_schema.TABLES "
        "WHERE TABLE_SCHEMA=%s AND TABLE_NAME LIKE %s ORDER BY TABLE_NAME",
        (database, "%connection_state"),
    )
    prefixes = []
    suffix = "connection_state"
    for (name,) in cursor.fetchall():
        prefix = name[: -len(suffix)]
        storage.validate(database, (prefix,))
        prefixes.append(prefix)
    if not prefixes:
        raise ValueError("geo_connection_state_missing:" + database)
    return tuple(prefixes)


def install_detail_view(db, database):
    """Add the cache column around the existing optimized detail view once."""
    with db.cursor() as cursor:
        cursor.execute("SHOW CREATE VIEW " + storage.identifier(database) + ".`审计明细`")
        row = cursor.fetchone()
        if not row:
            raise ValueError("geo_detail_view_missing:" + database)
        definition = row[1]
        wrapped = re.search(
            r"\sFROM\s+\(\s*\(?\s*(select\s[\s\S]+)\)\s+`?d`?\s+LEFT\s+JOIN\s+"
            + re.escape(storage.table(database, "", GEO_TABLE)),
            definition,
            re.IGNORECASE,
        )
        if wrapped:
            inner = wrapped.group(1).strip().rstrip(";")
        elif "`IP归属地`" in definition:
            return {"database": database, "view_updated": False}
        else:
            match = re.search(r"\sAS\s+(select\s[\s\S]+)\Z", definition, re.IGNORECASE)
            if not match:
                raise ValueError("geo_detail_view_shape:" + database)
            inner = match.group(1).strip().rstrip(";")
        marker = " AS `源 IP`,"
        if marker not in inner:
            raise ValueError("geo_detail_view_source_column:" + database)
        row_alias = "`u`" if re.match(r"select\s+`u`\.", inner, re.IGNORECASE) else "`c`"
        source_expr = row_alias + ".`源 IP`" if row_alias == "`u`" else row_alias + ".`source_ip`"
        location = (
            "CASE WHEN " + source_expr + " IS NULL OR " + source_expr + "='' OR " + source_expr + "='未识别' THEN '未识别' "
            "ELSE COALESCE(NULLIF((SELECT `g`.`location` FROM "
            + storage.table(database, "", GEO_TABLE)
            + " `g` WHERE `g`.`source_ip`=" + source_expr + " LIMIT 1),''),'未查询') END AS `IP归属地`,"
        )
        position = inner.index(marker) + len(marker)
        inner = inner[:position] + location + inner[position:]
        cursor.execute(
            "CREATE OR REPLACE ALGORITHM=UNDEFINED DEFINER=`root`@`localhost` SQL SECURITY DEFINER VIEW "
            + storage.identifier(database)
            + ".`审计明细` AS "
            + inner
        )
    return {"database": database, "view_updated": True}


def _region_fields(region):
    fields = [part.strip() for part in (region or "").split("|")]
    values = (fields + [""] * 5)[:5]
    return values[0], values[1], values[2], values[3]


def enrich_database(db, database, readers, cutoff=None, batch_size=DEFAULT_BATCH_SIZE):
    cutoff = time.time() - 14 * 86400 if cutoff is None else cutoff
    rows = {}
    with db.cursor() as cursor:
        cursor.execute(storage.geo_ddl(database))
        version = ":".join(sorted(reader.version for reader in readers.values())) or "none"
        for prefix in _prefixes(cursor, database):
            state = storage.table(database, prefix, "connection_state")
            cache = storage.table(database, "", GEO_TABLE)
            cursor.execute(
                "SELECT DISTINCT c.source_ip FROM "
                + state
                + " c LEFT JOIN "
                + cache
                + " g ON g.source_ip=c.source_ip WHERE c.last_seen >= %s "
                "AND c.source_ip IS NOT NULL AND c.source_ip<>'' "
                "AND (g.source_ip IS NULL OR g.db_version<>%s) LIMIT %s",
                (cutoff, version, batch_size),
            )
            for (source_ip,) in cursor.fetchall():
                rows[source_ip] = None
            # Month totals may outlive connection_state after raw data goes cold.
            # Read compact aggregates only, never historical samples or archives.
            monthly = storage.table(database, prefix, 'traffic_monthly')
            calendar = storage.table(database, '', 'traffic_calendar')
            cursor.execute(
                'SELECT DISTINCT c.source_ip FROM (SELECT source_ip FROM ' + monthly
                + ' WHERE month_start=' + storage.MONTH_START.replace('%', '%%')
                + ' UNION SELECT source_ip FROM ' + calendar
                + ' WHERE month_start=' + storage.MONTH_START.replace('%', '%%') + ' AND namespace=%s) c LEFT JOIN '
                + cache + " g ON g.source_ip=c.source_ip WHERE c.source_ip<>'' AND c.source_ip<>'未识别' "
                + 'AND (g.source_ip IS NULL OR g.db_version<>%s) LIMIT %s',
                (prefix, version, batch_size),
            )
            for (source_ip,) in cursor.fetchall():
                rows[source_ip] = None
    values = []
    for source_ip in rows:
        location, status, region = lookup_region(readers, source_ip)
        country, province, city, isp = _region_fields(region)
        values.append((source_ip, location, country, province, city, isp, status, version, time.time()))
    if values:
        with db.cursor() as cursor:
            cursor.executemany(
                "INSERT INTO "
                + storage.table(database, "", GEO_TABLE)
                + " (source_ip,location,country,province,city,isp,lookup_status,db_version,updated_at) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE "
                "location=VALUES(location),country=VALUES(country),province=VALUES(province),"
                "city=VALUES(city),isp=VALUES(isp),lookup_status=VALUES(lookup_status),"
                "db_version=VALUES(db_version),updated_at=VALUES(updated_at)",
                values,
            )
    return {"database": database, "candidates": len(rows), "updated": len(values)}


def run_once(databases=None, data_root=DATA_ROOT, download=True, connector=connect_root):
    databases = tuple(databases or DEFAULT_DATABASES)
    data_root = Path(data_root)
    statuses = {}
    month = datetime.now(timezone.utc).strftime("%Y-%m")
    paths = {"city": data_root / "dbip-city-lite.mmdb", "asn": data_root / "dbip-asn-lite.mmdb"}
    urls = {"city": DBIP_CITY_URL.format(month=month), "asn": DBIP_ASN_URL.format(month=month)}
    for kind in ("city", "asn"):
        if download:
            statuses[kind] = _download(paths[kind], urls[kind])
        elif not paths[kind].is_file():
            raise FileNotFoundError(str(paths[kind]))
    readers = {kind: MmdbReader(paths[kind]) for kind in paths}
    db = connector()
    try:
        result = {"downloads": statuses, "databases": []}
        for database in databases:
            result["databases"].append(enrich_database(db, database, readers))
        db.commit()
        for item, database in zip(result["databases"], databases):
            item.update(install_detail_view(db, database))
        return result
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
        for reader in readers.values():
            reader.close()


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("run", "schema", "lookup"))
    parser.add_argument("--database", default=",".join(DEFAULT_DATABASES))
    parser.add_argument("--data-root", default=str(DATA_ROOT))
    parser.add_argument("--no-download", action="store_true")
    parser.add_argument("--ip")
    args = parser.parse_args(argv)
    databases = _database_names(args.database)
    if args.action == "lookup":
        if not args.ip:
            parser.error("--ip is required for lookup")
        root = Path(args.data_root)
        readers = {kind: MmdbReader(root / ("dbip-%s-lite.mmdb" % kind))
                   for kind in ("city", "asn") if (root / ("dbip-%s-lite.mmdb" % kind)).is_file()}
        print(json.dumps({"ip": args.ip, "location": lookup(readers, args.ip)[0]}, ensure_ascii=False))
        return
    if args.action == "schema":
        db = connect_root()
        try:
            with db.cursor() as cursor:
                for database in databases:
                    cursor.execute(storage.geo_ddl(database))
            db.commit()
        finally:
            db.close()
        return
    print(json.dumps(run_once(databases, Path(args.data_root), not args.no_download), ensure_ascii=False))


if __name__ == "__main__":
    main()
