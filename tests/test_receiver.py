import hashlib
import hmac
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import audit


class ReceiverRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.a = audit.Audit({"mode": "terminal", "node": "terminal",
                              "db": str(Path(self.temp.name) / "audit.sqlite"),
                              "inbound_ports": [], "peers": {"edge": {"auth_file": "unused"}}})
        self.addCleanup(self.a.store.db.close)
        handlers = []

        class Server:
            def __init__(self, address, handler):
                handlers.append(handler)

            def server_close(self):
                pass

        with patch.object(audit.http.server, 'HTTPServer', Server), \
             patch.object(audit, 'STOP') as stop:
            stop.is_set.return_value = True
            self.a.receiver('127.0.0.1')
        handler_class = handlers[0]
        self.handler = object.__new__(handler_class)
        self.handler.connection = MagicMock()
        self.handler.path = '/ingest'
        body = json.dumps({"node": "edge", "events": []}).encode()
        self.handler.headers = {"Content-Length": str(len(body)), "X-Audit-Node": "edge",
                                "X-Audit-Signature": hmac.new(b'key', body, hashlib.sha256).hexdigest()}
        self.handler.rfile = io.BytesIO(body)
        self.handler.wfile = MagicMock()
        for name in ('send_response', 'send_header', 'end_headers', 'send_error'):
            setattr(self.handler, name, MagicMock())

    def call(self):
        with patch.object(audit, 'derive_key', return_value=b'key'), \
             patch.object(self.a, 'accept_batch', return_value={"accepted": 0}):
            self.handler.do_POST()

    def test_client_disconnect_does_not_raise_second_broken_pipe(self):
        self.handler.wfile.write.side_effect = BrokenPipeError()
        self.handler.send_error.side_effect = BrokenPipeError()
        self.call()
        self.assertEqual(self.a.errors['receiver_last_error'], 'BrokenPipeError')
        self.assertEqual(self.a.metrics['receiver_failed_requests'], 1)

    def test_success_clears_previous_receiver_error(self):
        self.a.errors['receiver_last_error'] = 'BrokenPipeError'
        self.call()
        self.assertNotIn('receiver_last_error', self.a.errors)
        self.handler.send_response.assert_called_once_with(200)

    def test_wrong_signature_remains_rejected(self):
        self.handler.headers['X-Audit-Signature'] = 'wrong'
        self.call()
        self.handler.send_error.assert_called_once_with(403)
        self.handler.wfile.write.assert_not_called()

    def test_database_failure_returns_retryable_status(self):
        import sqlite3
        with patch.object(audit, 'derive_key', return_value=b'key'), \
             patch.object(self.a, 'accept_batch', side_effect=sqlite3.OperationalError('fixture')):
            self.handler.do_POST()
        self.handler.send_error.assert_called_once_with(503)


if __name__ == '__main__':
    unittest.main()
