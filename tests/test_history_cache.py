"""Cold day chunks read through the incremental local history cache."""
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'central'))
import archive
import history_cache

DAY = 1795190400  # 2026-11-21 00:00 Beijing (16:00 UTC the day before)


def state(cid, seen, ip='1.2.3.4', site='a.example', node='n1', port=443, seq=1):
    # connection_id start_ts last_seen source_peer source_port inbound_port site prev_up prev_down flow_id source_ip node quality _seq
    return [cid, seen - 10, seen, '10.0.0.1', 5000, port, site, 0, 0, 'f' + cid, ip, node, 'ok', seq]


class HistoryCacheTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.store = archive.Store(root / 'archive', root / 'state')
        self.old = history_cache.ARCHIVE_ROOT, history_cache.CACHE_ROOT
        history_cache.ARCHIVE_ROOT = str(self.store.root)
        history_cache.CACHE_ROOT = str(root / 'cache')

    def tearDown(self):
        history_cache.ARCHIVE_ROOT, history_cache.CACHE_ROOT = self.old
        self.tmp.cleanup()

    def chunks(self, rows, prefix=''):
        return [(f['sha256'], prefix, f['day'], Path(f['file']).name, f['rows'])
                for f in self.store.write('region-a', prefix, 'connection_state', rows)]

    def test_load_is_incremental_and_rows_come_newest_first(self):
        first = self.chunks([state('a', DAY + 100), state('b', DAY + 200)])
        report = history_cache.load('region-a', first)
        self.assertEqual((report['fetched_chunks'], report['source_tier']), (1, 'remote'))
        second = first + self.chunks([state('c', DAY + 300)])
        report = history_cache.load('region-a', second)
        self.assertEqual((report['chunks'], report['fetched_chunks']), (2, 1))
        self.assertEqual(history_cache.load('region-a', second)['source_tier'], 'cache')
        got = [r[1] for r in history_cache.rows('region-a', second, DAY, DAY + 86400)]
        self.assertEqual(got, ['c', 'b', 'a'])

    def test_only_chunks_in_the_callers_snapshot_are_read(self):
        old = self.chunks([state('a', DAY + 100)])
        new = self.chunks([state('b', DAY + 200)])
        history_cache.load('region-a', old + new)
        self.assertEqual([r[1] for r in history_cache.rows('region-a', old, DAY, DAY + 86400)], ['a'])

    def test_filters_window_and_namespace_prefix(self):
        listed = self.chunks([state('x', DAY + 50, ip='9.9.9.9'), state('y', DAY + 60), state('z', DAY + 90000)], 'tb3_')
        history_cache.load('region-a', listed)
        got = list(history_cache.rows('region-a', listed, DAY, DAY + 86400, source_ip='1.2.3.4'))
        self.assertEqual([(r[0], r[1]) for r in got], [('tb3', 'tb3/y')])
        self.assertEqual(len({c[2] for c in listed}), 2)  # one chunk per Beijing day

    def test_a_chunk_that_does_not_match_its_index_row_is_refused(self):
        digest, prefix, day, name, count = self.chunks([state('a', DAY + 100)])[0]
        with self.assertRaises(history_cache.HistoryError):
            history_cache.load('region-a', [(digest, prefix, day, name, count + 1)])
        with self.assertRaises(history_cache.HistoryError):
            history_cache.load('region-a', [('0' * 64, prefix, day, name, count)])

    def test_missing_remote_file_reports_unavailable(self):
        with self.assertRaisesRegex(history_cache.HistoryError, 'remote_unavailable'):
            history_cache.load('region-a', [('1' * 64, '', '2026-11-21', 'connection_state.' + '1' * 64 + '.jsonl.gz', 1)])

    def test_eviction_drops_least_recently_read_days_first(self):
        listed = self.chunks([state('a', DAY + 100), state('b', DAY + 90000)])
        history_cache.load('region-a', listed)
        files = sorted(Path(history_cache.CACHE_ROOT, 'region-a').glob('*.sqlite'))
        import os
        os.utime(files[0], (1, 1))
        removed = history_cache.evict(limit=files[1].stat().st_size)
        self.assertEqual(removed, [files[0].name])


class WindowTests(unittest.TestCase):
    def parse(self, argv):
        from datetime import datetime, timezone

        def iso(value):
            return datetime.fromisoformat(value.replace('Z', '+00:00')).astimezone(timezone.utc)

        class Error(Exception):
            pass
        return history_cache.split_window(argv, iso, lambda code, message: Error(message))

    def test_details_window_is_removed_before_shared_parsing(self):
        rest, window = self.parse(['details', '--limit', '5', '--from', '2026-11-20T00:00:00Z', '--to=2026-11-21T00:00:00Z'])
        self.assertEqual(rest, ['details', '--limit', '5'])
        self.assertEqual(window[1] - window[0], 86400)

    def test_other_commands_and_plain_details_are_untouched(self):
        argv = ['summary', '--from', '2026-11-20T00:00:00Z']
        self.assertEqual(self.parse(argv), (argv, None))
        self.assertEqual(self.parse(['details']), (['details'], None))

    def test_window_longer_than_seven_days_or_without_from_is_refused(self):
        with self.assertRaises(Exception):
            self.parse(['details', '--from', '2026-11-01T00:00:00Z', '--to', '2026-11-09T00:00:01Z'])
        with self.assertRaises(Exception):
            self.parse(['details', '--to', '2026-11-09T00:00:01Z'])


if __name__ == '__main__':
    unittest.main()
