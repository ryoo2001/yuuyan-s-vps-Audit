from pathlib import Path
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'central'))
import ipgeo  # noqa: E402


class IpGeoTests(unittest.TestCase):
    def test_month_only_addresses_are_enriched_and_deduplicated(self):
        db = MagicMock()
        cursor = db.cursor.return_value.__enter__.return_value
        cursor.fetchall.side_effect = [[('connection_state',)], [('1.2.3.4',)],
                                      [('1.2.3.4',), ('5.6.7.8',)]]
        with patch.object(ipgeo, 'lookup_region', return_value=('北京市 中国联通', 'matched', '北京市||中国联通')) as lookup:
            result = ipgeo.enrich_database(db, 'region-a', {}, cutoff=123)
        self.assertEqual(result['updated'], 2)
        self.assertEqual(lookup.call_count, 2)
        query = cursor.execute.call_args.args[0]
        query % ('namespace', 'version', 100)  # DB-API interpolation must preserve DATE_FORMAT percent signs.
        self.assertIn('traffic_monthly', query)
        self.assertIn('traffic_calendar', query)
        self.assertIn('month_start=', query)
        self.assertNotIn('samples', query)

    def test_dbip_location_format_and_reader_paths(self):
        self.assertEqual(ipgeo.format_dbip_location('江苏省', '南京市', '中国电信'), '江苏省-南京市 中国电信')
        self.assertEqual(ipgeo.format_dbip_location('北京市', '北京市', '中国联通'), '北京市 中国联通')
        city = MagicMock()
        city.lookup.side_effect = lambda ip, *path: {
            ('subdivisions', '0', 'names', 'zh-CN'): '江苏省',
            ('city', 'names', 'zh-CN'): '南京市',
        }.get(path, '')
        asn = MagicMock()
        asn.lookup.return_value = '中国电信'
        self.assertEqual(ipgeo.lookup({'city': city, 'asn': asn}, '1.2.3.4'), ('江苏省-南京市 中国电信', 'matched'))

    def test_location_format(self):
        self.assertEqual(ipgeo.format_location('中国|江苏省|南京市|电信|CN'), '江苏省-南京市 电信')
        self.assertEqual(ipgeo.format_location('中国|北京|北京市|联通|CN'), '北京市 联通')
        self.assertEqual(ipgeo.format_location('United States|California|San Jose|xTom|US'),
                         'California-San Jose xTom')
        self.assertEqual(ipgeo.format_location('中国|0|0|0|CN'), '')

    def test_non_global_addresses_are_not_attributed(self):
        self.assertEqual(ipgeo.lookup({}, '10.0.0.1'), ('未识别', 'non_global'))
        self.assertEqual(ipgeo.lookup({}, 'not-an-ip'), ('未识别', 'invalid_ip'))


if __name__ == '__main__':
    unittest.main()
