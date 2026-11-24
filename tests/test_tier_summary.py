"""Window planning for summaries that span the 48 h raw tier and hourly totals."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'central'))
import tier_summary

NOW = 1795400000.0  # not hour-aligned on purpose
EDGE = tier_summary.boundary(NOW)


class PlanTests(unittest.TestCase):
    def test_boundary_is_first_whole_hour_inside_raw_tier(self):
        self.assertEqual(EDGE % 3600, 0)
        self.assertGreaterEqual(EDGE, NOW - 48 * 3600)
        self.assertLess(EDGE - (NOW - 48 * 3600), 3600)

    def test_window_inside_raw_tier_is_unchanged(self):
        raw, hourly, _ = tier_summary.plan(NOW - 3600 * 5 + 17, NOW, NOW)
        self.assertEqual(raw, (NOW - 3600 * 5 + 17, NOW))
        self.assertIsNone(hourly)

    def test_window_before_boundary_reads_only_whole_hours(self):
        start, end = EDGE - 86400 * 3 + 100, EDGE - 86400 - 50
        raw, hourly, _ = tier_summary.plan(start, end, NOW)
        self.assertIsNone(raw)
        self.assertEqual(hourly, (EDGE - 86400 * 3, EDGE - 86400))

    def test_spanning_window_splits_at_boundary_without_overlap(self):
        raw, hourly, _ = tier_summary.plan(EDGE - 7200 - 30, NOW, NOW)
        self.assertEqual(hourly, (EDGE - 10800, EDGE))
        self.assertEqual(raw, (EDGE, NOW))
        self.assertEqual(hourly[1], raw[0])


if __name__ == '__main__':
    unittest.main()
