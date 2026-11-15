import ipaddress
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'central'))
import ipgeo  # noqa: E402


def make_xdb(path, version, start, end, region):
    index_size = 14 if version == 4 else 38
    base = 256 + 524288
    packed_start = ipaddress.ip_address(start).packed
    packed_end = ipaddress.ip_address(end).packed
    record = (packed_start[::-1] + packed_end[::-1] if version == 4 else packed_start + packed_end)
    region_bytes = region.encode('utf8')
    pointer = base + index_size
    record += struct.pack('<HI', len(region_bytes), pointer)
    content = bytearray(pointer + len(region_bytes))
    content[0:2] = struct.pack('<H', 3)
    content[4:8] = struct.pack('<I', 123)
    content[8:12] = struct.pack('<I', base)
    content[12:16] = struct.pack('<I', base + index_size)
    content[16:18] = struct.pack('<H', version)
    content[18:20] = struct.pack('<H', 4)
    vector = 256 + packed_start[0] * 256 * 8 + packed_start[1] * 8
    content[vector:vector + 4] = struct.pack('<I', base)
    content[vector + 4:vector + 8] = struct.pack('<I', base + index_size)
    content[base:base + index_size] = record
    content[pointer:pointer + len(region_bytes)] = region_bytes
    path.write_bytes(content)


class IpGeoTests(unittest.TestCase):
    def test_month_only_addresses_are_enriched_and_deduplicated(self):
        db = MagicMock()
        cursor = db.cursor.return_value.__enter__.return_value
        cursor.fetchall.side_effect = [[('connection_state',)], [('192.0.2.4',)],
                                      [('192.0.2.4',), ('5.6.7.8',)]]
        with patch.object(ipgeo, 'lookup_region', return_value=('北京市 联通', 'matched', '中国|北京|北京市|联通|CN')) as lookup:
            result = ipgeo.enrich_database(db, 'region-a', {}, cutoff=123)
        self.assertEqual(result['updated'], 2)
        self.assertEqual(lookup.call_count, 2)
        query = cursor.execute.call_args.args[0]
        query % ('namespace', 'version', 100)  # DB-API interpolation must preserve DATE_FORMAT percent signs.
        self.assertIn('traffic_monthly', query)
        self.assertIn('traffic_calendar', query)
        self.assertIn('month_start=', query)
        self.assertNotIn('samples', query)

    def test_xdb_reader_supports_v4_and_v6(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            v4 = root / 'v4.xdb'
            v6 = root / 'v6.xdb'
            make_xdb(v4, 4, '192.0.2.0', '192.0.2.255', '中国|江苏省|南京市|电信|CN')
            make_xdb(v6, 6, '2001:db8::', '2001:db8::ffff', '中国|北京|北京市|联通|CN')
            self.assertEqual(ipgeo.XdbReader(v4, 4).search('192.0.2.4'), '中国|江苏省|南京市|电信|CN')
            self.assertEqual(ipgeo.XdbReader(v6, 6).search('2001:db8::1'), '中国|北京|北京市|联通|CN')
            self.assertEqual(ipgeo.XdbReader(v4, 4).search('198.51.100.1'), '')

    def test_location_format(self):
        self.assertEqual(ipgeo.format_location('中国|江苏省|南京市|电信|CN'), '江苏省-南京市 电信')
        self.assertEqual(ipgeo.format_location('中国|北京|北京市|联通|CN'), '北京市 联通')
        self.assertEqual(ipgeo.format_location('United States|California|San Jose|ExampleISP|US'),
                         'California-San Jose ExampleISP')
        self.assertEqual(ipgeo.format_location('中国|0|0|0|CN'), '')

    def test_non_global_addresses_are_not_attributed(self):
        self.assertEqual(ipgeo.lookup({}, '10.0.0.1'), ('未识别', 'non_global'))
        self.assertEqual(ipgeo.lookup({}, 'not-an-ip'), ('未识别', 'invalid_ip'))


if __name__ == '__main__':
    unittest.main()
