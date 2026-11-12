#!/usr/bin/env python3
"""Forced SSH command: validate fixed rows; commit in MySQL before acknowledging."""
import hashlib
import json
import os
from pathlib import Path
import sys
import time
from tier_policy import ONLINE_DAYS
from model import TABLES, validate_row, upsert_sql

CENTRAL_ROOT = Path(os.environ.get('TRAFFIC_CENTRAL_ROOT', '/etc/traffic-central'))
CONFIG = Path(os.environ.get('TRAFFIC_CENTRAL_CONFIG', str(CENTRAL_ROOT / 'writer.json')))
HEALTH = Path(os.environ.get('TRAFFIC_CENTRAL_HEALTH', '/var/lib/traffic-central/health.json'))
PUBLISHER = os.environ.get('TRAFFIC_CENTRAL_PUBLISHER', 'term-a1')
NODE = os.environ.get('TRAFFIC_CENTRAL_NODE', 'legacy-center')
LOCK_NAME = os.environ.get('TRAFFIC_CENTRAL_LOCK', 'traffic-audit-ingest')
MAX_LINE = 1000000
PATCH_VERSION = "2026.10.11.1"

ROLLUP_DDL = '''CREATE TABLE IF NOT EXISTS traffic_rollup (
  day_start BIGINT UNSIGNED NOT NULL,
  source_ip VARCHAR(45) COLLATE utf8mb4_bin NOT NULL DEFAULT '',
  node VARCHAR(64) COLLATE utf8mb4_bin NOT NULL DEFAULT '',
  site VARCHAR(253) COLLATE utf8mb4_bin NOT NULL DEFAULT '',
  upload_bytes BIGINT UNSIGNED NOT NULL,
  download_bytes BIGINT UNSIGNED NOT NULL,
  latest_ts DOUBLE NOT NULL,
  PRIMARY KEY (day_start,source_ip,node,site),
  KEY by_day (day_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin'''


def connect(path=CONFIG):
    import pymysql
    config = json.loads(path.read_text())
    kwargs = dict(user=config['user'], password=config['password'], database=config['database'],
                  charset='utf8mb4', connect_timeout=5, read_timeout=20, write_timeout=20,
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


def validate_batch(payload):
    if not isinstance(payload, dict) or payload.get('version') != 1 or payload.get('publisher') != PUBLISHER:
        raise ValueError('invalid_publisher')
    epoch = payload.get('epoch')
    if not isinstance(epoch, str) or len(epoch) != 32 or any(c not in '0123456789abcdef' for c in epoch):
        raise ValueError('invalid_epoch')
    through = payload.get('through')
    if type(through) is not int or not 0 <= through <= 9223372036854775807:
        raise ValueError('invalid_sequence')
    sent = payload.get('sent_at')
    if type(sent) not in (int, float) or not abs(time.time() - sent) < 900:
        raise ValueError('invalid_clock')
    rows = payload.get('rows')
    if not isinstance(rows, list) or len(rows) > 200:
        raise ValueError('invalid_batch')
    previous = 0
    for item in rows:
        if not isinstance(item, list) or len(item) != 3:
            raise ValueError('invalid_row')
        seq, table, values = item
        if type(seq) is not int or not previous < seq <= through:
            raise ValueError('nonmonotonic_batch')
        previous = seq
        validate_row(table, values)
    missing = payload.get('missing')
    if type(missing) is not int or not 0 <= missing <= 200:
        raise ValueError('invalid_missing_count')
    return payload


def ingest(db, payload):
    validate_batch(payload)
    with db.cursor() as c:
        c.execute('SELECT epoch,last_seq FROM sync_state WHERE publisher=%s FOR UPDATE', (PUBLISHER,))
        state = c.fetchone()
        if state and state[0] != payload['epoch']:
            raise ValueError('publisher_epoch_changed')
        pending = {}
        for seq, table, values in payload['rows']:
            if state and seq <= state[1]:
                continue
            pending.setdefault(table, []).append(values + [seq])
        # One multi-row upsert per table instead of one statement per row. The
        # absolute-value/_seq guard is unchanged; only round trips and bytes drop.
        for table, rows in pending.items():
            c.executemany(upsert_sql(table), rows)
        c.execute('''INSERT INTO sync_state(publisher,epoch,last_seq,last_received,sent_at,missing_rows)
                     VALUES(%s,%s,%s,%s,%s,%s) ON DUPLICATE KEY UPDATE
                     last_seq=GREATEST(last_seq,VALUES(last_seq)),last_received=VALUES(last_received),
                     sent_at=VALUES(sent_at),missing_rows=GREATEST(missing_rows,VALUES(missing_rows))''',
                  (PUBLISHER, payload['epoch'], payload['through'], time.time(), payload['sent_at'], payload['missing']))
    db.commit()


def prune(db):
    """Archive worker owns expiry; publishers must never delete first."""
    return 0


def run():
    os.umask(0o077)
    db = connect()
    with db.cursor() as c:
        c.execute('SELECT GET_LOCK(%s,0)', (LOCK_NAME,))
        if c.fetchone()[0] != 1:
            raise RuntimeError('receiver_busy')
    last_prune = 0
    try:
        while True:
            line = sys.stdin.buffer.readline(MAX_LINE + 1)
            if not line:
                break
            if len(line) > MAX_LINE or not line.endswith(b'\n'):
                raise ValueError('oversized_or_partial_message')
            raw = line[:-1]
            payload = validate_batch(json.loads(raw))
            ingest(db, payload)
            if time.time() - last_prune >= 300:
                prune(db)
                last_prune = time.time()
            health = {'schema_version': 1, 'patch_version': PATCH_VERSION, 'storage': 'mysql', 'node': NODE, 'now': time.time(),
                      'last_received': time.time(), 'source': PUBLISHER, 'retention_days': ONLINE_DAYS,
                      'last_batch_rows': len(payload['rows']), 'missing_rows': payload['missing'],
                      'last_prune': last_prune, 'warnings': ['sampled_payload_lower_bound_not_billing']}
            tmp = HEALTH.with_suffix('.tmp')
            tmp.write_text(json.dumps(health))
            tmp.replace(HEALTH)
            print(json.dumps({'ok': True, 'through': payload['through'], 'digest': hashlib.sha256(raw).hexdigest()}), flush=True)
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == '__main__':
    try:
        run()
    except Exception as exc:
        print('traffic-central receiver: ' + type(exc).__name__, file=sys.stderr)
        sys.exit(1)
