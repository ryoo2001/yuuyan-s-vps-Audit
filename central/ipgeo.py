#!/usr/bin/env python3
"""Center-only IP geolocation cache built from the public ip2region xdb data."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import time
from urllib.error import URLError
from urllib.request import Request, urlopen

import storage


GEO_TABLE = "ip_geo"
DEFAULT_DATABASES = ("region-a", "hk")
DATA_ROOT = Path(os.environ.get("TRAFFIC_CENTRAL_GEO_ROOT", "/var/lib/traffic-central/geo"))
V4_URL = os.environ.get(
    "TRAFFIC_CENTRAL_GEO_V4_URL",
    "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v4.xdb",
)
V6_URL = os.environ.get(
    "TRAFFIC_CENTRAL_GEO_V6_URL",
    "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/data/ip2region_v6.xdb",
)
DOWNLOAD_INTERVAL = 24 * 60 * 60
MAX_DATABASE_BYTES = 256 * 1024 * 1024
DEFAULT_BATCH_SIZE = 500
DETAIL_COLUMNS = ('时间', '源 IP', 'IP归属地', '隧道内网 IP（入口机器）', '目标网站', '最近上传速率', '最近下载速率')
MUNICIPALITIES = {"北京", "北京市", "上海", "上海市", "天津", "天津市", "重庆", "重庆市"}
EMPTY_FIELD = {"", "0", "未知", "unknown", "内网IP", "内网 IP"}


def _le_uint16(value, offset):
    return value[offset] | value[offset + 1] << 8


def _le_uint32(value, offset):
    return (
        value[offset]
        | value[offset + 1] << 8
        | value[offset + 2] << 16
        | value[offset + 3] << 24
    )


class XdbReader:
    """Small read-only xdb reader using the upstream file format."""

    def __init__(self, path, ip_version):
        self.path = Path(path)
        self.content = self.path.read_bytes()
        if len(self.content) < 256 + 524288:
            raise ValueError("geo_xdb_too_small")
        structure = _le_uint16(self.content, 0)
        if structure not in (2, 3):
            raise ValueError("geo_xdb_structure_unsupported")
        header_ip_version = 4 if structure == 2 else _le_uint16(self.content, 16)
        if header_ip_version != ip_version:
            raise ValueError("geo_xdb_ip_version_mismatch")
        self.ip_version = ip_version
        self.index_size = 14 if ip_version == 4 else 38
        self.start_index = _le_uint32(self.content, 8)
        self.end_index = _le_uint32(self.content, 12)
        if not 256 + 524288 <= self.start_index <= self.end_index <= len(self.content):
            raise ValueError("geo_xdb_index_bounds_invalid")
        self.vector_index = self.content[256 : 256 + 524288]
        self.version = "%d-%d-%d" % (
            structure,
            _le_uint32(self.content, 4),
            int(hashlib.sha256(self.content).hexdigest()[:16], 16),
        )

    def search(self, value):
        address = ipaddress.ip_address(value)
        if address.version != self.ip_version:
            return ""
        packed = address.packed
        index = packed[0] * 256 * 8 + packed[1] * 8
        start = _le_uint32(self.vector_index, index)
        end = _le_uint32(self.vector_index, index + 4)
        if not start or not end:
            return ""
        low = 0
        high = (end - start) // self.index_size
        while low <= high:
            middle = (low + high) >> 1
            pointer = start + middle * self.index_size
            record = self.content[pointer : pointer + self.index_size]
            if len(record) != self.index_size:
                raise ValueError("geo_xdb_index_truncated")
            if self.ip_version == 4:
                lower = record[3::-1]
                upper = record[7:3:-1]
            else:
                lower = record[:16]
                upper = record[16:32]
            if packed < lower:
                high = middle - 1
            elif packed > upper:
                low = middle + 1
            else:
                offset = 8 if self.ip_version == 4 else 32
                length = _le_uint16(record, offset)
                data_pointer = _le_uint32(record, offset + 2)
                data = self.content[data_pointer : data_pointer + length]
                if len(data) != length:
                    raise ValueError("geo_xdb_region_truncated")
                return data.decode("utf-8")
        return ""


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
    reader = readers.get(address.version)
    if reader is None:
        return "未识别", "database_unavailable", ""
    region = reader.search(normalized)
    location = format_location(region)
    return location or "未识别", "matched" if location else "not_found", region


def _database_names(value):
    names = tuple(item for item in value.split(",") if item)
    if not names:
        raise ValueError("geo_database_list_empty")
    for name in names:
        storage.identifier(name)
    return names


def _download(path, url, ip_version, now=None):
    now = time.time() if now is None else now
    if path.is_file() and now - path.stat().st_mtime < DOWNLOAD_INTERVAL:
        XdbReader(path, ip_version)
        return "cached"
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name("." + path.name + ".download")
    request = Request(url, headers={"User-Agent": "traffic-audit-ipgeo/1"})
    try:
        with urlopen(request, timeout=45) as response, temporary.open("wb") as output:
            length = response.headers.get("Content-Length")
            if length is not None and int(length) > MAX_DATABASE_BYTES:
                raise ValueError("geo_xdb_download_too_large")
            total = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_DATABASE_BYTES:
                    raise ValueError("geo_xdb_download_too_large")
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        XdbReader(temporary, ip_version)
        os.replace(temporary, path)
    except (OSError, URLError, ValueError):
        if temporary.exists():
            temporary.unlink()
        if path.is_file():
            XdbReader(path, ip_version)
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
    paths = {4: data_root / "ip2region_v4.xdb", 6: data_root / "ip2region_v6.xdb"}
    urls = {4: V4_URL, 6: V6_URL}
    for version in (4, 6):
        if download:
            statuses[str(version)] = _download(paths[version], urls[version], version)
        elif not paths[version].is_file():
            raise FileNotFoundError(str(paths[version]))
    readers = {version: XdbReader(paths[version], version) for version in (4, 6) if paths[version].is_file()}
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
        readers = {}
        root = Path(args.data_root)
        for version in (4, 6):
            path = root / ("ip2region_v%d.xdb" % version)
            if path.is_file():
                readers[version] = XdbReader(path, version)
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
