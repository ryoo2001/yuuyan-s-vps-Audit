#!/usr/bin/env python3
"""Move authenticated edge batches through an existing MySQL connection."""
import argparse
import hashlib
import hmac
import http.server
import json
import math
from pathlib import Path
import re
import time
import urllib.error
import urllib.request
import zlib

from audit import derive_key, validate_event

MAX_BODY = 524288
MAX_STORED = 4 * MAX_BODY
NODE = 'entry-a1'
# An event-less batch only refreshes peer health; forward at most one per interval.
HEARTBEAT_SECONDS = 10
FETCH_ROWS = 8
# Pause after the queue drains, growing while it stays empty. A full page means
# backlog and is followed immediately; every poll is a public round trip.
IDLE_POLL_SECONDS = (1.0, 2.0, 3.0)
EXPIRE_HOURS = 24
EXPIRE_EVERY_SECONDS = 300
MAX_SKIPPED = 16


class Undeliverable(ValueError):
    """The stored batch can never be accepted; retrying it would block the queue."""


def connect(config):
    import pymysql
    kwargs = dict(host=config['host'], port=3306, user=config['user'],
                  password=config['password'], database='hk', charset='utf8mb4',
                  connect_timeout=5, read_timeout=10, write_timeout=10, autocommit=True)
    if config.get('tls') is True:
        # Opt-in transport encryption. The server certificate is not verified,
        # so this stops passive capture, not an active proxy.
        import ssl
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        kwargs['ssl'] = context
    return pymysql.connect(**kwargs)


def validate(body, node, signature, auth_file, expected_node=NODE):
    if node != expected_node or not 0 < len(body) <= MAX_BODY:
        raise ValueError('invalid_request')
    key = derive_key(auth_file, node)
    expected = hmac.new(key, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        raise ValueError('invalid_signature')
    data = json.loads(body)
    if (not isinstance(data, dict) or data.get('node') != node or
            not isinstance(data.get('events'), list) or len(data['events']) > 256 or
            type(data.get('sent_at')) not in (int, float) or not math.isfinite(data['sent_at']) or
            abs(time.time() - data['sent_at']) > 900):
        raise ValueError('invalid_batch')
    for item in data['events']:
        if not isinstance(item, dict) or not re.fullmatch(r'[a-f0-9-]{36}', item.get('event_id', '')):
            raise ValueError('invalid_event_id')
        event = item.get('event')
        validate_event(event)
        if event['type'] not in ('health', 'capture_stats') and event['dst_port'] != 2101:
            raise ValueError('invalid_port')
    return len(data['events'])


def adjust_delay(data, delay, now):
    """Preserve event age across the queue, including after a long outage."""
    if not math.isfinite(delay) or delay < 0:
        raise ValueError('invalid_queue_age')
    sent = data['sent_at']
    for item in data['events']:
        event = item['event']
        captured = event['capture_ts']
        if type(captured) not in (int, float) or not math.isfinite(captured):
            raise ValueError('invalid_capture_time')
        event['capture_ts'] = now - delay - max(0, sent - captured)
    data['sent_at'] = now
    return data


def unpack(body):
    """Queue rows are zlib streams; rows written before compression are raw JSON."""
    body = bytes(body)
    if body[:1] == b'{':
        return body
    inflater = zlib.decompressobj()
    data = inflater.decompress(body, MAX_STORED + 1)
    if len(data) > MAX_STORED or inflater.unconsumed_tail or inflater.unused_data or not inflater.eof:
        raise ValueError('invalid_queue_body')
    return data


class Sender:
    """Authenticate local edge batches and append them over one reused connection."""

    def __init__(self, config):
        self.config = config
        self.db = None
        self.last_forward = 0.0

    def close(self):
        if self.db is not None:
            try:
                self.db.close()
            except Exception:
                pass
            self.db = None

    def store(self, body):
        args = (hashlib.sha256(body).hexdigest(), zlib.compress(body, 6))
        for retry in (False, True):
            try:
                if self.db is None:
                    self.db = connect(self.config)
                with self.db.cursor() as cursor:
                    cursor.execute('INSERT IGNORE INTO `termb4_edge_queue` (batch_id,body) VALUES (%s,%s)', args)
                return
            except Exception:
                # A reused connection may have been dropped; the insert is idempotent.
                self.close()
                if retry:
                    raise

    def accept(self, body, node, signature, now=None):
        count = validate(body, node, signature, self.config['auth_file'], self.config.get('node', NODE))
        now = time.monotonic() if now is None else now
        if count or now - self.last_forward >= HEARTBEAT_SECONDS:
            self.store(body)
            self.last_forward = now
        return count


def sender(config):
    state = Sender(config)

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            try:
                if self.path != '/ingest':
                    self.send_error(404)
                    return
                self.connection.settimeout(5)
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= MAX_BODY:
                    raise ValueError('invalid_length')
                body = self.rfile.read(length)
                if len(body) != length:
                    raise ValueError('incomplete_request')
                count = state.accept(body, self.headers.get('X-Audit-Node', ''),
                                     self.headers.get('X-Audit-Signature', ''))
                payload = json.dumps({'accepted': count}).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except ValueError:
                self.send_error(400)
            except Exception:
                self.send_error(503)

    http.server.HTTPServer(('127.0.0.1', 19091), Handler).serve_forever()


def forward(body, delay, config, opener):
    """Deliver one stored batch to the local collector."""
    try:
        data = json.loads(unpack(body))
        if not isinstance(data, dict) or not isinstance(data.get('events'), list):
            raise ValueError('invalid_queue_batch')
        node = data.get('node')
        auth_files = config.get('auth_files', {NODE: config['auth_file']})
        if node not in auth_files:
            raise ValueError('unknown_queue_node')
        data = adjust_delay(data, delay, time.time())
        encoded = json.dumps(data, separators=(',', ':'), ensure_ascii=True).encode()
    except (ValueError, KeyError, TypeError, zlib.error) as exc:
        reason = str(exc) if type(exc) is ValueError else type(exc).__name__
        raise Undeliverable(reason) from None
    key = derive_key(auth_files[node], node)
    request = urllib.request.Request('http://127.0.0.1:19091/ingest', data=encoded, method='POST',
        headers={'Content-Type': 'application/json', 'X-Audit-Node': node,
                 'X-Audit-Signature': hmac.new(key, encoded, hashlib.sha256).hexdigest()})
    try:
        with opener.open(request, timeout=5) as response:
            result = json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code in (400, 413):
            raise Undeliverable('collector_rejected_' + str(exc.code)) from None
        raise
    if type(result.get('accepted')) is not int or result['accepted'] != len(data['events']):
        raise ValueError('incomplete_acknowledgement')


class Receiver:
    """Drain the queue in order; one undeliverable row must not block later rows."""

    def __init__(self, config, opener):
        self.config = config
        self.opener = opener
        self.skipped = {}
        self.last_expiry = 0.0

    def poll(self, db):
        """Deliver one page. Returns how many rows were delivered and deleted."""
        sql = ('SELECT batch_id,body,TIMESTAMPDIFF(MICROSECOND,created_at,NOW(6))/1000000 '
               'FROM `termb4_edge_queue`')
        args = list(self.skipped)
        if args:
            sql += ' WHERE batch_id NOT IN (' + ','.join(['%s'] * len(args)) + ')'
        with db.cursor() as cursor:
            cursor.execute(sql + ' ORDER BY created_at,batch_id LIMIT %s', args + [FETCH_ROWS])
            rows = cursor.fetchall()
        delivered = []
        try:
            for batch_id, body, delay in rows:
                try:
                    forward(body, max(0.0, float(delay)), self.config, self.opener)
                except Undeliverable as exc:
                    if len(self.skipped) >= MAX_SKIPPED:
                        # Too many bad rows to step over safely; stop and stay visible.
                        raise ValueError('undeliverable_queue_rows_exceed_limit') from None
                    self.skipped[batch_id] = str(exc)
                    print('edge queue: skipped %s len=%d %s' % (batch_id[:12], len(body), exc), flush=True)
                    continue
                delivered.append(batch_id)
        finally:
            if delivered:
                with db.cursor() as cursor:
                    cursor.execute('DELETE FROM `termb4_edge_queue` WHERE batch_id IN ('
                                   + ','.join(['%s'] * len(delivered)) + ')', delivered)
        return len(delivered)

    def expire(self, db, now=None):
        """Drop rows older than the edge spool lifetime, including skipped ones."""
        now = time.monotonic() if now is None else now
        if now - self.last_expiry < EXPIRE_EVERY_SECONDS:
            return 0
        self.last_expiry = now
        with db.cursor() as cursor:
            cursor.execute('DELETE FROM `termb4_edge_queue` WHERE created_at<NOW(6)-INTERVAL %s HOUR LIMIT 200',
                           (EXPIRE_HOURS,))
            expired = cursor.rowcount
        if expired:
            self.skipped.clear()
            print('edge queue: expired %d rows older than %dh' % (expired, EXPIRE_HOURS), flush=True)
        return expired


def next_pause(delivered, idle):
    """Return (seconds to wait, idle streak) after a poll that delivered `delivered` rows."""
    if delivered >= FETCH_ROWS:
        return 0.0, 0
    idle = 0 if delivered else idle + 1
    return IDLE_POLL_SECONDS[min(idle, len(IDLE_POLL_SECONDS) - 1)], idle


def receiver(config):
    state = Receiver(config, urllib.request.build_opener(urllib.request.ProxyHandler({})))
    while True:
        try:
            db = connect(config)
            try:
                idle = 0
                while True:
                    state.expire(db)
                    pause, idle = next_pause(state.poll(db), idle)
                    if pause:
                        time.sleep(pause)
            finally:
                db.close()
        except Exception as exc:
            print('edge queue: ' + type(exc).__name__, flush=True)
            time.sleep(3)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('mode', choices=('sender', 'receiver'))
    parser.add_argument('--config', required=True)
    args = parser.parse_args()
    config = json.loads(Path(args.config).read_text())
    (sender if args.mode == 'sender' else receiver)(config)


if __name__ == '__main__':
    main()
