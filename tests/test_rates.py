import unittest
from rates import SourceRates


class SourceRatesTests(unittest.TestCase):
    def setUp(self):
        self.rates = SourceRates()

    def row(self, cid="a", ip="198.51.100.1", up=0, down=0, start=0):
        return (cid, ip, up, down, start)

    def feed(self, tick, rows, wall=None):
        return self.rates.update(rows, tick, 1000+tick if wall is None else wall)

    def test_waits_for_full_five_seconds(self):
        self.feed(0, [self.row()])
        self.assertEqual(self.feed(4, [self.row(up=4000)])['a'], (None, None, None))
        self.assertEqual(self.feed(5, [self.row(up=5000)])['a'], (5, 1000, 0))

    def test_same_ip_aggregates_and_different_ip_stays_separate(self):
        self.feed(0, [self.row(), self.row('b'), self.row('c', '198.51.100.2')])
        out = self.feed(5, [self.row(up=5000), self.row('b', up=10000), self.row('c', '198.51.100.2', up=500)])
        self.assertEqual(out['a'], (5, 3000, 0))
        self.assertEqual(out['a'], out['b'])
        self.assertEqual(out['c'], (5, 100, 0))

    def test_departed_connection_contributes_until_window_expires(self):
        self.feed(0, [self.row(), self.row('b')])
        self.feed(1, [self.row(up=1000), self.row('b', up=4000)])
        for t in range(2, 6): out = self.feed(t, [self.row(up=1000*t)])
        self.assertEqual(out['a'], (5, 1800, 0))
        self.assertEqual(self.feed(6, [self.row(up=6000)])['a'], (5, 1000, 0))

    def test_fractional_window_boundary(self):
        self.feed(0, [self.row()])
        self.feed(3, [self.row(up=6000)])
        out = self.feed(6, [self.row(up=9000)])
        self.assertEqual(out['a'], (5, 1400, 0))

    def test_new_connection_born_in_interval_can_contribute(self):
        self.feed(0, [self.row()])
        self.feed(4, [self.row()])
        out = self.feed(5, [self.row(), self.row('b', up=5000, start=1004.5)])
        self.assertEqual(out['a'], (5, 1000, 0))
        self.assertEqual(out['a'], out['b'])

    def test_preexisting_newly_seen_counter_is_not_retroactive(self):
        self.feed(0, [self.row()])
        out = self.feed(5, [self.row(), self.row('b', up=999999999, start=0)])
        self.assertEqual(out['a'], (5, 0, 0))

    def test_unknown_sources_are_never_merged(self):
        self.feed(0, [self.row(ip=None), self.row('b', ip=None)])
        out = self.feed(5, [self.row(ip=None, up=5000), self.row('b', ip=None, up=10000)])
        self.assertEqual(out, {'a': (None, None, None), 'b': (None, None, None)})

    def test_counter_reset_invalidates_entire_ip_window(self):
        self.feed(0, [self.row(up=100)])
        self.feed(5, [self.row(up=5100)])
        self.assertEqual(self.feed(6, [self.row(up=1)])['a'], (None, None, None))
        self.assertEqual(self.feed(11, [self.row(up=5001)])['a'], (5, 1000, 0))

    def test_long_gap_requires_new_window(self):
        self.feed(0, [self.row()])
        self.assertEqual(self.feed(6, [self.row(up=6000)])['a'], (None, None, None))

    def test_ip_change_cannot_reuse_old_identity_window(self):
        self.feed(0, [self.row()])
        self.feed(5, [self.row(up=5000)])
        out = self.feed(6, [self.row(ip='198.51.100.2', up=6000)])
        self.assertEqual(out['a'], (None, None, None))

    def test_wall_clock_change_does_not_affect_consecutive_deltas(self):
        self.feed(0, [self.row()])
        self.assertEqual(self.feed(5, [self.row(up=5000)], wall=900)['a'], (5, 1000, 0))

    def test_expired_inactive_ips_are_removed(self):
        self.feed(0, [self.row()])
        for t in range(1, 20): self.feed(t, [])
        self.assertEqual(self.rates.since, {})
        self.assertEqual(self.rates.previous, {})
        self.assertLessEqual(len(self.rates.frames), 5)
