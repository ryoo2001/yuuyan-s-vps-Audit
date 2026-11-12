import hashlib
import hmac
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
import urllib.error
from unittest.mock import patch
import zlib

from audit import derive_key
from central import edge_queue
from central.edge_queue import NODE, Receiver, Sender, Undeliverable, adjust_delay, forward, unpack, validate


class Cursor:
    def __init__(self, db):
        self.db = db
        self.rowcount = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def execute(self, sql, args=()):
        self.db.statements.append((sql, list(args)))
        if self.db.fail:
            self.db.fail -= 1
            raise OSError('connection_lost')
        if sql.startswith('INSERT'):
            self.db.rows.setdefault(args[0], args[1])
        elif sql.startswith('SELECT'):
            excluded = set(args[:-1])
            self.result = [(k, v, 2) for k, v in self.db.rows.items() if k not in excluded][:args[-1]]
        elif 'batch_id IN' in sql:
            for batch_id in args:
                self.db.rows.pop(batch_id)
            self.db.deleted.extend(args)
        elif sql.startswith('DELETE'):
            self.rowcount = self.db.expirable
            for batch_id in list(self.db.rows)[:self.db.expirable]:
                self.db.rows.pop(batch_id)

    def fetchall(self):
        return self.result


class DB:
    """In-memory stand-in for the ordered queue table."""

    def __init__(self, rows=()):
        self.rows = dict(rows)
        self.deleted, self.statements = [], []
        self.fail = self.expirable = 0
        self.closed = False

    def cursor(self):
        return Cursor(self)

    def close(self):
        self.closed = True


class Response:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def read(self, *args):
        return self.payload


class Opener:
    """Local collector double: acknowledges every event unless told otherwise."""

    def __init__(self, accepted=None, error=None):
        self.accepted, self.error = accepted, error
        self.requests = []

    def open(self, request, timeout):
        self.requests.append(request)
        if self.error:
            raise self.error
        count = len(json.loads(request.data)['events'])
        return Response({'accepted': count if self.accepted is None else self.accepted})


def http_error(code):
    return urllib.error.HTTPError('http://127.0.0.1:19091/ingest', code, 'x', {}, io.BytesIO())


class EdgeQueueTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.auth = Path(self.temp.name) / 'auth.toml'
        self.auth.write_text('[network_identity]\nnetwork_secret="example"\n')
        self.config = {'auth_file': str(self.auth)}

    def batch(self, events=1, node=NODE):
        event = {'type': 'flow_open', 'capture_ts': time.time(), 'src_ip': '198.51.100.1', 'src_port': 1234,
                 'dst_ip': '10.0.0.1', 'dst_port': 2101, 'transport': 'tcp', 'flow_id': 'f'}
        data = {'node': node, 'sent_at': time.time(),
                'events': [{'event_id': '00000000-0000-4000-8000-%012d' % i, 'event': dict(event)}
                           for i in range(events)]}
        return json.dumps(data).encode()

    def signed(self, body, node=NODE, auth=None):
        return hmac.new(derive_key(auth or self.auth, node), body, hashlib.sha256).hexdigest()

    def test_authentication_and_port_scope(self):
        body = self.batch(0)
        self.assertEqual(validate(body, NODE, self.signed(body), self.auth), 0)
        with self.assertRaises(ValueError):
            validate(body, NODE, 'bad', self.auth)

    def test_queue_delay_preserves_original_event_age(self):
        data = {'sent_at': 100, 'events': [{'event': {'capture_ts': 95}}]}
        adjust_delay(data, 30, 1000)
        self.assertEqual(data['sent_at'], 1000)
        self.assertEqual(data['events'][0]['event']['capture_ts'], 965)

    def test_delete_only_after_complete_ack(self):
        db = DB({'batch': self.batch()})
        with self.assertRaises(ValueError):
            Receiver(self.config, Opener(0)).poll(db)
        self.assertEqual(db.deleted, [])
        self.assertEqual(Receiver(self.config, Opener()).poll(db), 1)
        self.assertEqual(db.deleted, ['batch'])

    def test_independent_new_edge_identity(self):
        old_path, new_path = Path(self.temp.name) / 'old.toml', Path(self.temp.name) / 'new.toml'
        old_path.write_text('[network_identity]\nnetwork_secret="old"\n')
        new_path.write_text('[network_identity]\nnetwork_secret="new"\n')
        node = 'entry-a2'
        body = self.batch(0, node)
        signature = self.signed(body, node, new_path)
        self.assertEqual(validate(body, node, signature, new_path, node), 0)
        with self.assertRaises(ValueError):
            validate(body, node, signature, new_path)
        with self.assertRaises(ValueError):
            validate(body, node, signature, old_path, node)
        config = {'auth_file': str(old_path), 'auth_files': {NODE: str(old_path), node: str(new_path)}}
        opener = Opener()
        db = DB({'new-batch': body})
        self.assertEqual(Receiver(config, opener).poll(db), 1)
        request = opener.requests[0]
        self.assertEqual(request.get_header('X-audit-node'), node)
        self.assertEqual(validate(request.data, node, request.get_header('X-audit-signature'), new_path, node), 0)
        self.assertEqual(db.deleted, ['new-batch'])

    def test_bad_rows_are_stepped_over_and_kept(self):
        # Shapes seen in production: a bare event, unwrapped events, an unregistered edge.
        bare = json.dumps({'type': 'flow_close', 'capture_ts': 1.0}).encode()
        unwrapped = json.dumps({'node': NODE, 'sent_at': time.time(),
                                'events': [{'type': 'wire_delta', 'capture_ts': 1.0}]}).encode()
        db = DB([('bare', bare), ('unwrapped', unwrapped), ('unknown', self.batch(1, 'unregistered-edge')),
                 ('garbage', b'\x00not-a-batch'), ('good', self.batch(2))])
        opener = Opener()
        state = Receiver(self.config, opener)
        with patch('builtins.print'):
            self.assertEqual(state.poll(db), 1)
        self.assertEqual(db.deleted, ['good'])
        self.assertEqual(set(db.rows), {'bare', 'unwrapped', 'unknown', 'garbage'})
        self.assertEqual(len(opener.requests), 1)
        # The next poll excludes them in SQL instead of downloading them again.
        self.assertEqual(state.poll(db), 0)
        self.assertEqual(sorted(db.statements[-1][1][:-1]), ['bare', 'garbage', 'unknown', 'unwrapped'])
        self.assertEqual(len(opener.requests), 1)

    def test_collector_rejection_is_skipped_but_outage_is_retried(self):
        db = DB({'rejected': self.batch()})
        state = Receiver(self.config, Opener(error=http_error(400)))
        with patch('builtins.print'):
            self.assertEqual(state.poll(db), 0)
        self.assertIn('rejected', state.skipped)
        for error in (http_error(503), http_error(403), TimeoutError()):
            state = Receiver(self.config, Opener(error=error))
            with self.assertRaises(type(error)):
                state.poll(db)
            self.assertEqual((state.skipped, db.deleted), ({}, []))

    def test_too_many_bad_rows_stop_the_queue_instead_of_hiding_it(self):
        db = DB(('bad%02d' % i, b'{}') for i in range(edge_queue.MAX_SKIPPED + 1))
        state = Receiver(self.config, Opener())
        with patch('builtins.print'), self.assertRaisesRegex(ValueError, 'exceed_limit'):
            for _ in range(4):
                state.poll(db)
        self.assertEqual(len(db.rows), edge_queue.MAX_SKIPPED + 1)

    def test_partial_page_keeps_acknowledged_deletes(self):
        class FailSecond(Opener):
            def open(self, request, timeout):
                if self.requests:
                    raise TimeoutError()
                return super().open(request, timeout)
        db = DB([('a', self.batch()), ('b', self.batch())])
        with self.assertRaises(TimeoutError):
            Receiver(self.config, FailSecond()).poll(db)
        self.assertEqual((db.deleted, list(db.rows)), (['a'], ['b']))

    def test_expiry_is_rate_limited_and_rechecks_skipped_rows(self):
        db = DB({'old': b'{}'})
        state = Receiver(self.config, Opener())
        state.skipped['old'] = 'x'
        db.expirable = 1
        with patch('builtins.print'):
            self.assertEqual(state.expire(db, now=1000), 1)
        self.assertEqual((state.skipped, db.rows), ({}, {}))
        self.assertEqual(state.expire(db, now=1001), 0)
        self.assertEqual(sum(s.startswith('DELETE') for s, _ in db.statements), 1)

    def test_stored_rows_are_compressed_and_old_plain_rows_still_read(self):
        body = self.batch(3)
        db = DB()
        state = Sender(self.config)
        with patch.object(edge_queue, 'connect', return_value=db):
            self.assertEqual(state.accept(body, NODE, self.signed(body)), 3)
        (batch_id, stored), = db.rows.items()
        self.assertEqual(batch_id, hashlib.sha256(body).hexdigest())
        self.assertLess(len(stored), len(body))
        self.assertEqual(unpack(stored), body)
        self.assertEqual(unpack(body), body)
        opener = Opener()
        self.assertEqual(Receiver(self.config, opener).poll(db), 1)
        self.assertEqual(len(json.loads(opener.requests[0].data)['events']), 3)

    def test_oversized_or_trailing_compressed_rows_are_refused(self):
        for stored in (zlib.compress(b'{' + b' ' * edge_queue.MAX_STORED + b'}'), zlib.compress(b'{}') + b'x'):
            with self.assertRaises(Undeliverable):
                forward(stored, 0.0, self.config, Opener())

    def test_idle_heartbeats_are_coalesced_but_events_always_forwarded(self):
        db = DB()
        state = Sender(self.config)
        def post(events, now):
            body = self.batch(events)
            body = body.replace(b'"sent_at"', b'"n":%d,"sent_at"' % now)  # distinct payload per call
            return state.accept(body, NODE, self.signed(body), now=now)
        with patch.object(edge_queue, 'connect', return_value=db):
            self.assertEqual([post(0, 100), post(0, 103), post(0, 106), post(0, 109)], [0, 0, 0, 0])
            self.assertEqual(len(db.rows), 1)
            post(0, 110)
            self.assertEqual(len(db.rows), 2)
            self.assertEqual(post(2, 111), 2)
            self.assertEqual(len(db.rows), 3)
            post(0, 113)
            self.assertEqual(len(db.rows), 3)
            with self.assertRaises(ValueError):
                state.accept(self.batch(0), NODE, 'bad', now=200)
            self.assertEqual(len(db.rows), 3)

    def test_sender_reuses_one_connection_and_reconnects_once(self):
        first, second = DB(), DB()
        state = Sender(self.config)
        with patch.object(edge_queue, 'connect', side_effect=[first, second]) as connect:
            state.store(b'{"a":1}')
            state.store(b'{"a":2}')
            self.assertEqual(connect.call_count, 1)
            first.fail = 1
            state.store(b'{"a":3}')
            self.assertEqual(connect.call_count, 2)
            self.assertTrue(first.closed)
            self.assertEqual((len(first.rows), len(second.rows)), (2, 1))
        down = DB()
        down.fail = 2
        with patch.object(edge_queue, 'connect', return_value=down), self.assertRaises(OSError):
            Sender(self.config).store(b'{"a":4}')

    def test_poll_pacing_follows_backlog_and_backs_off_when_empty(self):
        full = edge_queue.FETCH_ROWS
        self.assertEqual(edge_queue.next_pause(full, 2), (0.0, 0))            # backlog: no wait
        self.assertEqual(edge_queue.next_pause(1, 2), (1.0, 0))               # drained: short wait, streak reset
        self.assertEqual([edge_queue.next_pause(0, i) for i in range(4)],
                         [(2.0, 1), (3.0, 2), (3.0, 3), (3.0, 4)])            # empty: capped back-off
        self.assertLessEqual(max(edge_queue.IDLE_POLL_SECONDS), 3)            # bounded added latency

    def test_tls_is_opt_in(self):
        import sys
        from unittest.mock import MagicMock
        mysql = MagicMock()
        base = {'host': '192.0.2.1', 'user': 'u', 'password': 'p'}
        with patch.dict(sys.modules, {'pymysql': mysql}):
            edge_queue.connect(base)
            self.assertNotIn('ssl', mysql.connect.call_args.kwargs)
            edge_queue.connect(dict(base, tls=True))
            self.assertIn('ssl', mysql.connect.call_args.kwargs)


if __name__ == '__main__':
    unittest.main()
