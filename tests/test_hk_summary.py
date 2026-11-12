import importlib.util
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location("hk_summary", Path(__file__).resolve().parents[1] / "central/hk_summary.py")
hk_summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hk_summary)


class HKSummarySQL(unittest.TestCase):
    def test_every_physical_branch_filters_and_groups_before_union(self):
        sql = hk_summary.summary_select()
        self.assertEqual(sql.count(" UNION ALL "), 14)
        self.assertEqual(sql.count(" GROUP BY "), 9)
        for source in hk_summary.SOURCES:
            for table, stamp in (("samples", "ts"), ("traffic_rollup", "latest_ts")):
                self.assertIn("FROM `hk`.`" + source + "_" + table + "` WHERE `" + stamp + "` >= ", sql)
        self.assertEqual(sql.count("<= UNIX_TIMESTAMP()"), 16)
        for unused in ("connection_id", "event_id", "_seq", "quality", " OVER ("):
            self.assertNotIn(unused, sql)

    def test_display_and_provenance_contract(self):
        sql = hk_summary.summary_select()
        for name in ("时间", "源 IP", "入口机器", "目标网站", "流量统计"):
            self.assertIn("AS `" + name + "`", sql)
        self.assertEqual(sql.count("'未识别'"), 48)
        self.assertIn("SELECT MAX(latest_ts) AS latest_ts", sql)
        self.assertIn("SUM(s.total_bytes)>=1000000000", sql)
        self.assertTrue(sql.endswith("ORDER BY SUM(s.total_bytes) DESC,s.source_ip,s.node,s.site"))
        self.assertIn("SQL SECURITY DEFINER VIEW `hk`.`流量汇总`", hk_summary.summary_ddl())
        self.assertNotIn("CREATE TABLE", hk_summary.summary_ddl())


if __name__ == "__main__":
    unittest.main()
