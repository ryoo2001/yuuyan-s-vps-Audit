#!/usr/bin/env python3
"""LINKA committed-row publisher. Durable dirty keys and direct MySQL 3306 ingest."""
import hashlib
import json
import os
from pathlib import Path
import select
import sqlite3
import time
import uuid
from model import TABLES, validate_row
from receive import ingest, prune
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from maintenance import delete_batches

ROOT = Path(os.environ.get('TRAFFIC_AUDIT_CENTRAL_ROOT', '/etc/traffic-audit/central'))
CENTRAL_CONFIG = Path(os.environ.get('TRAFFIC_AUDIT_CENTRAL_CONFIG', str(ROOT / 'writer.json')))
DB = os.environ.get('TRAFFIC_AUDIT_DB', '/var/lib/traffic-audit/audit.sqlite')
HEALTH = Path(os.environ.get('TRAFFIC_AUDIT_HEALTH', '/var/lib/traffic-audit/central-health.json'))
PUBLISHER = os.environ.get('TRAFFIC_AUDIT_PUBLISHER', 'term-a1')
LOCK_PATH = Path(os.environ.get('TRAFFIC_AUDIT_LOCK', '/run/traffic-audit-publish/lock'))
SYNC_INTERVAL_SECONDS = 60
PATCH_VERSION = "2026.10.11.1"
MAX_FLUSH_KEYS = 50000

ROLLUP_DDL = '''CREATE TABLE IF NOT EXISTS traffic_rollup(
  day_start INTEGER NOT NULL, source_ip TEXT NOT NULL, node TEXT NOT NULL, site TEXT NOT NULL,
  upload_bytes INTEGER NOT NULL, download_bytes INTEGER NOT NULL, latest_ts REAL NOT NULL,
  PRIMARY KEY(day_start,source_ip,node,site))'''


def setup(db):
    db.execute('PRAGMA busy_timeout=5000')
    db.execute('PRAGMA synchronous=NORMAL')
    db.execute(ROLLUP_DDL)
    db.execute('CREATE INDEX IF NOT EXISTS traffic_rollup_day ON traffic_rollup(day_start)')
    db.execute('CREATE TABLE IF NOT EXISTS central_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS central_dirty (id INTEGER PRIMARY KEY AUTOINCREMENT, table_name TEXT NOT NULL, row_key TEXT NOT NULL, UNIQUE(table_name,row_key))')
    with db:
        db.execute("INSERT OR IGNORE INTO central_meta VALUES('epoch',?)", (uuid.uuid4().hex,))
        for table, (columns, keys, _) in TABLES.items():
            actual = {row[1] for row in db.execute(f'PRAGMA table_info({table})')}
            if not set(columns) <= actual:
                raise ValueError('source_schema_mismatch:' + table)
            expression = 'json_array(' + ','.join('NEW.' + key for key in keys) + ')'
            for operation in ('INSERT', 'UPDATE'):
                db.execute(f'''CREATE TRIGGER IF NOT EXISTS central_{table}_{operation.lower()}
                AFTER {operation} ON {table} BEGIN
                DELETE FROM central_dirty WHERE table_name='{table}' AND row_key={expression};
                INSERT INTO central_dirty(table_name,row_key) VALUES('{table}',{expression}); END''')
        if not db.execute("SELECT value FROM central_meta WHERE key='seeded'").fetchone():
            for table, (_, keys, _) in TABLES.items():
                expression = 'json_array(' + ','.join(keys) + ')'
                db.execute(f"INSERT OR REPLACE INTO central_dirty(table_name,row_key) SELECT ?,{expression} FROM {table}", (table,))
            db.execute("INSERT INTO central_meta VALUES('seeded','1')")
    return db.execute("SELECT value FROM central_meta WHERE key='epoch'").fetchone()[0]


def batch(db, epoch, limit=200, through=None):
    db.execute('BEGIN')
    try:
        if through is not None and db.execute("SELECT 1 FROM sqlite_temp_master WHERE name='flush_keys'").fetchone():
            dirty = db.execute('SELECT id,table_name,row_key FROM temp.flush_keys WHERE id<=? ORDER BY id LIMIT ?', (through, limit)).fetchall()
        elif through is None:
            dirty = db.execute('SELECT id,table_name,row_key FROM central_dirty ORDER BY id LIMIT ?', (limit,)).fetchall()
        else:
            dirty = db.execute('SELECT id,table_name,row_key FROM central_dirty WHERE id<=? ORDER BY id LIMIT ?', (through, limit)).fetchall()
        rows, missing = [], 0
        for seq, table, key in dirty:
            columns, keys, _ = TABLES[table]
            row = db.execute('SELECT ' + ','.join(columns) + f' FROM {table} WHERE ' + ' AND '.join(k + '=?' for k in keys), json.loads(key)).fetchone()
            if row is None:
                missing += 1
            else:
                rows.append([seq, table, validate_row(table, list(row))])
        db.commit()
    except Exception:
        db.rollback()
        raise
    payload = {'version': 1, 'publisher': PUBLISHER, 'epoch': epoch, 'through': dirty[-1][0] if dirty else 0,
               'sent_at': time.time(), 'rows': rows, 'missing': missing}
    encoded = json.dumps(payload, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode()
    if len(encoded) > 950000:
        if limit <= 1:
            raise ValueError('oversized_row')
        return batch(db, epoch, max(1, limit // 2), through=through)
    return payload, encoded


def snapshot_keys(db):
    """Freeze bounded keys, not counters; hot updates cannot starve a flush."""
    db.execute('PRAGMA temp_store=MEMORY')
    db.execute('CREATE TEMP TABLE IF NOT EXISTS flush_keys(id INTEGER PRIMARY KEY,table_name TEXT,row_key TEXT)')
    with db:
        db.execute('DELETE FROM temp.flush_keys')
        db.execute('INSERT INTO temp.flush_keys SELECT id,table_name,row_key FROM central_dirty ORDER BY id LIMIT ?',
                   (MAX_FLUSH_KEYS,))
    return db.execute('SELECT COALESCE(MAX(id),0) FROM temp.flush_keys').fetchone()[0]


def acknowledge(db, payload, encoded, response):
    expected = hashlib.sha256(encoded).hexdigest()
    if response.get('ok') is not True or response.get('digest') != expected or response.get('through') != payload['through']:
        raise ValueError('invalid_ack')
    with db:
        # Updates occurring during upload have a new id and must survive an old ACK.
        db.execute('DELETE FROM central_dirty WHERE id<=?', (payload['through'],))
        if db.execute("SELECT 1 FROM sqlite_temp_master WHERE name='flush_keys'").fetchone():
            db.execute('DELETE FROM temp.flush_keys WHERE id<=?', (payload['through'],))
        db.execute("INSERT OR REPLACE INTO central_meta VALUES('last_ack',?)", (str(time.time()),))


def trim_cache(db, now=None):
    """Trim only ACKed attributed rows, using bounded atomic folding batches."""
    cutoff = (time.time() if now is None else now) - 24 * 3600
    deleted = 0
    for table in ('samples', 'visits', 'wire_samples'):
        _, keys, stamp = TABLES[table]
        expression = 'json_array(' + ','.join(table + '.' + k for k in keys) + ')'
        where = (f"{stamp}<? AND source_ip IS NOT NULL AND source_ip<>'' "
                 f"AND NOT EXISTS (SELECT 1 FROM central_dirty d WHERE d.table_name=? AND d.row_key={expression})")
        deleted += delete_batches(db, table, where, (cutoff, table), fold_samples=table == 'samples')
    with db:
        db.execute("INSERT OR REPLACE INTO central_meta VALUES('cache_hours','24')")
    return deleted


def write_payload(stream, data, timeout=35):
    fd = stream.fileno()
    os.set_blocking(fd, False)
    deadline = time.monotonic() + timeout
    view = memoryview(data)
    while view:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([], [fd], [], remaining)[1]:
            raise TimeoutError('send_timeout')
        try:
            written = os.write(fd, view)
        except BlockingIOError:
            continue
        if not written:
            raise BrokenPipeError('partial_write')
        view = view[written:]


def read_ack(stream, timeout=35):
    deadline = time.monotonic() + timeout
    data = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([stream], [], [], remaining)[0]:
            raise TimeoutError('ack_timeout')
        chunk = os.read(stream.fileno(), 4097 - len(data))
        if not chunk:
            raise ValueError('missing_ack')
        data.extend(chunk)
        if len(data) > 4096:
            raise ValueError('oversized_ack')
        if b'\n' in data:
            if not data.endswith(b'\n') or data.count(b'\n') != 1:
                raise ValueError('invalid_ack_line')
            return json.loads(data)


def central_connect():
    import pymysql
    config = json.loads(CENTRAL_CONFIG.read_text())
    kwargs = dict(user=config['user'], password=config['password'], database=config['database'],
                  charset='utf8mb4', connect_timeout=5, read_timeout=35, write_timeout=35,
                  autocommit=False)
    if config.get('socket'):
        kwargs['unix_socket'] = config['socket']
    else:
        kwargs['host'] = config['host']
        kwargs['port'] = int(config.get('port', 3306))
        if config.get('tls') is True:
            # Opt-in transport encryption. The server certificate is not
            # verified, so this stops passive capture, not an active proxy.
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            kwargs['ssl'] = context
    return pymysql.connect(**kwargs)


def run():
    import fcntl
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    lock = open(LOCK_PATH, 'w')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    db = sqlite3.connect(DB, timeout=5)
    epoch = setup(db)
    session = None
    last_trim = 0
    flush_through = None
    pending = None
    last_queue_count = 0
    health = {'last_ack': None, 'last_error': None, 'missing_rows': 0, 'batches': 0, 'rows_sent': 0,
              'patch_version': PATCH_VERSION, 'sync_interval_seconds': SYNC_INTERVAL_SECONDS,
              'transport': 'mysql_tcp_3306'}
    if HEALTH.exists():
        try:
            previous = json.loads(HEALTH.read_text())
            for key in ('last_ack', 'missing_rows', 'batches', 'rows_sent'):
                value = previous.get(key)
                if (key == 'last_ack' and (value is None or type(value) in (int, float))) or (key != 'last_ack' and type(value) is int and value >= 0):
                    health[key] = value
        except (OSError, ValueError):
            pass
    while True:
        try:
            if session is None:
                session = central_connect()
            if flush_through is None:
                flush_through = snapshot_keys(db)
                health['last_flush_started'] = time.time()
            if pending is None:
                pending = batch(db, epoch, through=flush_through)
            payload, encoded = pending
            if time.time()-payload['sent_at'] > 300:
                payload = dict(payload, sent_at=time.time())
                encoded = json.dumps(payload, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode()
                pending = (payload, encoded)
            ingest(session, payload)
            acknowledge(db, payload, encoded, {'ok': True, 'through': payload['through'], 'digest': hashlib.sha256(encoded).hexdigest()})
            pending = None
            health.update(last_ack=time.time(), last_error=None, batches=health['batches'] + 1,
                          rows_sent=health['rows_sent'] + len(payload['rows']), missing_rows=health['missing_rows'] + payload['missing'])
            remaining = db.execute('SELECT 1 FROM temp.flush_keys LIMIT 1').fetchone()
            if remaining:
                pause = 0.05
            else:
                flush_through = None
                health['last_flush_completed'] = time.time()
                if time.time() - last_trim >= 300:
                    try:
                        prune(session)
                        trim_cache(db)
                        health.pop('maintenance_error', None)
                    except Exception as exc:
                        db.rollback()
                        health['maintenance_error'] = type(exc).__name__
                    last_trim = time.time()
                pause = SYNC_INTERVAL_SECONDS
        except Exception as exc:
            health['last_error'] = type(exc).__name__
            health['last_error_at'] = time.time()
            if session:
                try: session.close()
                except Exception: pass
                session = None
            pause = 5
        stamp = time.time()
        if stamp-last_queue_count >= 5 or pause >= SYNC_INTERVAL_SECONDS:
            health['queued'] = db.execute('SELECT COUNT(*) FROM central_dirty').fetchone()[0]
            health['queue_observed_at'] = stamp
            last_queue_count = stamp
        health.update(now=stamp, flush_through=flush_through)
        temp = HEALTH.with_suffix('.tmp')
        temp.write_text(json.dumps(health))
        os.chmod(temp, 0o600)
        temp.replace(HEALTH)
        time.sleep(pause)



if __name__ == '__main__':
    run()
