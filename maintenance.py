"""Bound SQLite maintenance transactions; preserve unconfirmed facts."""
import time
from contextlib import nullcontext

BATCH_ROWS = 500
PASS_SECONDS = 0.25


def delete_batches(db, table, where, args=(), limit=BATCH_ROWS, deadline=None, lock=None,
                   fold_samples=False):
    deleted = 0
    deadline = time.monotonic() + PASS_SECONDS if deadline is None else deadline
    while time.monotonic() < deadline:
        context = lock if lock is not None else nullcontext()
        with context, db:
            # Reserve the main writer before selecting eligible facts. A late
            # correlation must not turn an ACKed row into an unACKed deletion.
            if not db.in_transaction:
                db.execute('BEGIN IMMEDIATE')
            rows = db.execute(f'SELECT rowid FROM {table} WHERE {where} LIMIT ?',
                              (*args, limit)).fetchall()
            keys = tuple(row[0] for row in rows)
            if not keys:
                break
            placeholders = ','.join('?' for _ in keys)
            if fold_samples:
                db.execute('''INSERT INTO traffic_rollup(
                    day_start,source_ip,node,site,upload_bytes,download_bytes,latest_ts)
                  SELECT CAST((ts+28800)/86400 AS INTEGER)*86400-28800,
                    COALESCE(source_ip,''),COALESCE(node,''),COALESCE(site,''),
                    COALESCE(SUM(upload_bytes),0),COALESCE(SUM(download_bytes),0),MAX(ts)
                  FROM samples WHERE rowid IN (''' + placeholders + ''')
                  GROUP BY CAST((ts+28800)/86400 AS INTEGER)*86400-28800,
                    COALESCE(source_ip,''),COALESCE(node,''),COALESCE(site,'')
                  ON CONFLICT(day_start,source_ip,node,site) DO UPDATE SET
                    upload_bytes=traffic_rollup.upload_bytes+excluded.upload_bytes,
                    download_bytes=traffic_rollup.download_bytes+excluded.download_bytes,
                    latest_ts=MAX(traffic_rollup.latest_ts,excluded.latest_ts)''', keys)
            count = db.execute(f'DELETE FROM {table} WHERE rowid IN ({placeholders})', keys).rowcount
            deleted += count
        if len(keys) < limit:
            break
    return deleted
