import tempfile
import threading
import unittest
from pathlib import Path

import audit


class CaptureWatchdogTests(unittest.TestCase):
    def setUp(self):
        audit.STOP.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.config = {
            "mode": "terminal",
            "node": "terminal",
            "db": str(Path(self.tmp.name) / "audit.sqlite"),
            "health": str(Path(self.tmp.name) / "health.json"),
            "retention_days": 7,
            "max_db_mb": 8,
            "inbound_ports": [3320],
            "peers": {},
            "capture_restart_backoff_seconds": 0,
        }
        self.audit = audit.Audit(self.config)

    def tearDown(self):
        audit.STOP.set()
        self.audit.store.db.close()
        self.tmp.cleanup()
        audit.STOP.clear()

    def test_capture_watchdog_restarts_failed_target(self):
        calls = []

        def target():
            calls.append(True)
            if len(calls) == 1:
                raise RuntimeError("pcap_read_failed")
            audit.STOP.set()

        self.audit.spawn("capture:etneta0", target, restart=True)
        self.audit.threads[0].join(timeout=2)

        self.assertGreaterEqual(len(calls), 2)
        self.assertEqual(self.audit.metrics["capture_restarts"], 1)
        self.assertNotIn("capture:etneta0", self.audit.errors)
        self.assertFalse(self.audit.threads[0].is_alive())


if __name__ == "__main__":
    unittest.main()
