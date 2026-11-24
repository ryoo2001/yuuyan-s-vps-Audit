#!/usr/bin/env python3
"""Detail rows older than the 48 h raw tier, read from cold day chunks through a local cache.

The archive writes one gzip JSONL chunk per Beijing day, table and namespace and
records it in `archive_chunks` in the same transaction that deletes the rows.
A reader that sees a chunk listed in its MySQL snapshot can therefore read the
rows from that chunk instead, and never sees a row twice.

The cache grows by chunk: a day file keeps the chunks already loaded and a
later read only fetches the digests it has not seen. Chunks are immutable and
named by the SHA-256 of their content, so a cached chunk never goes stale; rows
are only read for digests listed in the caller's snapshot. Remote reads run in
a child process with a deadline, so a hung NFS mount fails the history part of
one request and nothing else. Cache files are root-only local copies; LRU
eviction never touches the remote chunks.
"""
try:
    import fcntl
except ImportError:  # local tests on Windows; production is Linux
    fcntl = None
import gzip
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time

ARCHIVE_ROOT = os.environ.get('TRAFFIC_CENTRAL_ARCHIVE', '/var/lib/traffic-central/archive')
CACHE_ROOT = os.environ.get('TRAFFIC_CENTRAL_HISTORY_CACHE', '/var/lib/traffic-central/history-cache')
CACHE_LIMIT_BYTES = 300 * 1024 * 1024
CACHE_IDLE_SECONDS = 7 * 86400
FETCH_SECONDS = 30
MAX_WINDOW_SECONDS = 7 * 86400
COLUMNS = ('connection_id', 'last_seen', 'source_peer', 'inbound_port', 'site', 'source_ip', 'node', '_seq')
SCHEMA = ('CREATE TABLE IF NOT EXISTS chunks(digest TEXT PRIMARY KEY,namespace TEXT NOT NULL,rows INTEGER NOT NULL,loaded_at REAL NOT NULL);'
          'CREATE TABLE IF NOT EXISTS facts(digest TEXT NOT NULL,namespace TEXT NOT NULL,connection_id TEXT NOT NULL,'
          'last_seen REAL,source_peer TEXT,inbound_port INTEGER,site TEXT,source_ip TEXT,node TEXT,seq INTEGER,'
          'PRIMARY KEY(digest,namespace,connection_id)) WITHOUT ROWID;'
          'CREATE INDEX IF NOT EXISTS by_time ON facts(last_seen DESC,namespace,connection_id);')


class HistoryError(Exception):
    """The history part of a request could not be read; the hot part is unaffected."""


def split_window(argv, parse_iso, error):
    """Take --from/--to off a details command so the shared parser stays unchanged."""
    if argv[:1] != ['details']:
        return argv, None
    rest, values = [], {}
    items = iter(argv)
    for item in items:
        name, _, inline = item.partition('=')
        if name in ('--from', '--to'):
            if name in values:
                raise error('invalid_arguments', 'duplicate option: ' + name)
            value = inline if inline else next(items, None)
            if value is None:
                raise error('invalid_arguments', name + ' requires a timestamp')
            values[name] = value
        else:
            rest.append(item)
    if not values:
        return rest, None
    if '--from' not in values:
        raise error('invalid_arguments', '--to requires --from')
    start = parse_iso(values['--from']).timestamp()
    end = parse_iso(values['--to']).timestamp() if '--to' in values else time.time()
    if not 0 < end - start <= MAX_WINDOW_SECONDS:
        raise error('invalid_arguments', 'details window must be positive and no longer than 7 days')
    return rest, (start, end)


def beijing_day(ts):
    return time.strftime('%Y-%m-%d', time.gmtime(ts + 8 * 3600))


def snapshot(cursor, start, end):
    """Chunks listed in the caller's MySQL snapshot whose Beijing day overlaps [start, end)."""
    try:
        cursor.execute("SELECT digest,namespace,day,filename,row_count FROM archive_chunks "
                       "WHERE logical_table='connection_state' AND day BETWEEN %s AND %s ORDER BY day,digest",
                       (beijing_day(start), beijing_day(max(start, end - 0.001))))
        chunks = [(r[0], r[1], str(r[2]), r[3], int(r[4])) for r in cursor.fetchall()]
        cursor.execute("SELECT MIN(day) FROM archive_chunks WHERE logical_table='connection_state'")
        first = cursor.fetchone()[0]
    except Exception as exc:
        if (exc.args[0] if exc.args else None) == 1146:  # no chunk index yet
            return [], None
        raise
    return chunks, (str(first) if first is not None else None)


def _verify(blob, database, digest, namespace, expected):
    raw = gzip.decompress(blob)
    if hashlib.sha256(raw).hexdigest() != digest:
        raise HistoryError('history_chunk_checksum_mismatch')
    lines = raw.splitlines()
    header = json.loads(lines[0])
    if (header.get('format') != 'audit-cold-v1' or header.get('database') != database
            or header.get('namespace') != namespace or header.get('logical_table') != 'connection_state'
            or header.get('rows') != expected or len(lines) - 1 != expected
            or any(c not in header.get('columns', ()) for c in COLUMNS)):
        raise HistoryError('history_chunk_contract_mismatch')
    index = [header['columns'].index(c) for c in COLUMNS]
    result = []
    for line in lines[1:]:
        row = json.loads(line)
        result.append([row[i] for i in index])
    return result


def _fetch(database, items, deadline):
    """Copy chunk files to a local scratch directory in a child process with a deadline."""
    scratch = Path(tempfile.mkdtemp(prefix='.fetch-', dir=CACHE_ROOT))
    spec = [str(scratch), ARCHIVE_ROOT, database] + [day[:7] + '/' + name for _, _, day, name, _ in items]
    child = subprocess.Popen([sys.executable, '-I', os.path.abspath(__file__), 'copy'] + spec,
                             stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        _, err = child.communicate(timeout=max(1.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        # A process blocked on a hard NFS mount may not die; do not wait for it.
        child.kill()
        raise HistoryError('remote_unavailable:fetch_timeout')
    if child.returncode != 0:
        raise HistoryError('remote_unavailable:' + (err.decode(errors='replace').strip().splitlines() or ['copy_failed'])[-1][:80])
    return scratch


def _copy(scratch, root, database, members):
    """Child process: plain month-folder parts first, sealed month tars otherwise."""
    tars = {}
    try:
        for member in members:
            month, name = member.split('/', 1)
            if '/' in name or not name.endswith('.jsonl.gz'):
                raise ValueError('invalid_member')
            loose = Path(root, database, month, name)
            if loose.is_file() and not loose.is_symlink():
                data = loose.read_bytes()
            else:
                if month not in tars:
                    tars[month] = tarfile.open(Path(root, database, month + '.tar'), 'r:')
                data = tars[month].extractfile(tars[month].getmember(name)).read()
            Path(scratch, name).write_bytes(data)
    finally:
        for handle in tars.values():
            handle.close()


def _day_path(database, day):
    if not database.replace('-', '').replace('_', '').isalnum() or len(day) != 10:
        raise HistoryError('history_invalid_day')
    folder = Path(CACHE_ROOT, database)
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    return folder / (day + '.sqlite')


class _DayLock:
    def __init__(self, path, exclusive=True, wait=True):
        self.handle = open(str(path) + '.lock', 'a')
        if fcntl is None:
            return
        flags = (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | (0 if wait else fcntl.LOCK_NB)
        try:
            fcntl.flock(self.handle, flags)
        except OSError:
            self.handle.close(); raise

    def close(self):
        self.handle.close()


def load(database, chunks, budget=FETCH_SECONDS):
    """Bring every listed chunk into its day file; only digests not yet cached are fetched."""
    os.umask(0o077)
    Path(CACHE_ROOT).mkdir(parents=True, exist_ok=True, mode=0o700)
    started, deadline = time.monotonic(), time.monotonic() + budget
    by_day = {}
    for chunk in chunks:
        by_day.setdefault(chunk[2], []).append(chunk)
    locks, missing = [], {}
    try:
        for day, items in sorted(by_day.items()):
            path = _day_path(database, day)
            locks.append(_DayLock(path))
            db = sqlite3.connect(str(path))
            try:
                db.executescript(SCHEMA)
                have = {r[0] for r in db.execute('SELECT digest FROM chunks')}
            finally:
                db.close()
            todo = [c for c in items if c[0] not in have]
            if todo:
                missing[day] = todo
        fetched = sum(len(v) for v in missing.values())
        size = 0
        if fetched:
            scratch = _fetch(database, [c for v in missing.values() for c in v], deadline)
            try:
                for day, items in missing.items():
                    db = sqlite3.connect(str(_day_path(database, day)))
                    try:
                        for digest, namespace, _, name, count in items:
                            blob = Path(scratch, name).read_bytes(); size += len(blob)
                            rows = _verify(blob, database, digest, namespace, count)
                            db.executemany('INSERT OR REPLACE INTO facts VALUES(?,?,?,?,?,?,?,?,?,?)',
                                           [(digest, namespace, *row) for row in rows])
                            db.execute('INSERT OR REPLACE INTO chunks VALUES(?,?,?,?)', (digest, namespace, count, time.time()))
                        db.commit()
                    finally:
                        db.close()
            finally:
                for path in scratch.iterdir():
                    path.unlink()
                scratch.rmdir()
        now = time.time()
        for day in by_day:
            os.utime(_day_path(database, day), (now, now))
    finally:
        for lock in locks:
            lock.close()
    return {'days': sorted(by_day), 'chunks': len(chunks), 'fetched_chunks': fetched,
            'fetched_bytes': size, 'fetch_seconds': round(time.monotonic() - started, 3),
            'source_tier': 'remote' if fetched else 'cache'}


def rows(database, chunks, start, end, source_ip=None, site=None):
    """Yield (source_id, connection_id, last_seen, source_peer, inbound_port, site, source_ip, node), newest first."""
    by_day = {}
    for digest, namespace, day, _, _ in chunks:
        by_day.setdefault(day, []).append(digest)
    for day in sorted(by_day, reverse=True):
        digests = by_day[day]
        where = 'digest IN (' + ','.join('?' * len(digests)) + ') AND last_seen>=? AND last_seen<?'
        params = digests + [start, end]
        for column, value in (('source_ip', source_ip), ('site', site)):
            if value is not None:
                where += ' AND ' + column + '=?'; params.append(value)
        db = sqlite3.connect('file:' + str(_day_path(database, day)) + '?mode=ro', uri=True)
        try:
            for ns, cid, seen, peer, port, host, ip, node in db.execute(
                    'SELECT namespace,connection_id,last_seen,source_peer,inbound_port,site,source_ip,node FROM facts WHERE '
                    + where + ' ORDER BY last_seen DESC,namespace,connection_id', params):
                source = ns[:-1]
                yield (source, source + '/' + cid if source else cid, seen, peer, port, host, ip, node)
        finally:
            db.close()


def evict(limit=CACHE_LIMIT_BYTES, idle=CACHE_IDLE_SECONDS, now=None):
    """Drop idle day files, then the least recently read ones until the cache fits."""
    now = time.time() if now is None else now
    root = Path(CACHE_ROOT)
    if not root.is_dir():
        return []
    for scratch in root.glob('.fetch-*'):
        if now - scratch.stat().st_mtime > 3600:
            for path in scratch.iterdir(): path.unlink()
            scratch.rmdir()
    files = sorted(root.glob('*/*.sqlite'), key=lambda p: p.stat().st_mtime)
    total, removed = sum(p.stat().st_size for p in files), []
    for path in files:
        if now - path.stat().st_mtime <= idle and total <= limit:
            break
        try:
            lock = _DayLock(path, wait=False)
        except OSError:
            continue
        try:
            size = path.stat().st_size; path.unlink(); total -= size; removed.append(path.name)
        finally:
            lock.close()
    return removed


def status():
    root = Path(CACHE_ROOT)
    files = list(root.glob('*/*.sqlite')) if root.is_dir() else []
    return {'cache_root': str(root), 'files': len(files), 'bytes': sum(p.stat().st_size for p in files),
            'limit_bytes': CACHE_LIMIT_BYTES, 'days': sorted(p.parent.name + '/' + p.stem for p in files)}


if __name__ == '__main__':
    if sys.argv[1:2] == ['copy']:
        _copy(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:])
    elif sys.argv[1:2] == ['status']:
        print(json.dumps(status(), ensure_ascii=False))
    else:
        sys.exit('usage: history_cache.py status')
