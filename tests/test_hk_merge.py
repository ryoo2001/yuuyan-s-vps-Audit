import importlib.util
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "central"))
try:
    import hk_merge
    import hk_receive
finally:
    sys.path.remove(str(ROOT / "central"))


class MergeTests(unittest.TestCase):
    def tearDown(self):
        hk_receive.PREFIX = ""

    def test_writer_targets_only_its_namespace(self):
        for prefix in ("tb1_", "tb2_", "termc_", "tb3_", "termb4_"):
            hk_receive.PREFIX = prefix
            for table in hk_receive.TABLES:
                sql = hk_receive.upsert_sql(table)
                self.assertTrue(sql.startswith("INSERT INTO `" + prefix + table + "`"))
                self.assertNotIn("INSERT INTO `" + table + "`", sql)
            self.assertEqual(hk_receive.table_name("sync_state"), "`" + prefix + "sync_state`")

    def test_legacy_sql_remains_unprefixed(self):
        self.assertEqual(hk_receive.upsert_sql("samples"), hk_receive.base_upsert_sql("samples"))

    def test_arbitrary_table_is_rejected(self):
        with self.assertRaises(ValueError):
            hk_receive.table_name("other;DROP DATABASE hk")

    def test_union_preserves_all_sources_and_namespaces_identifiers(self):
        sql = hk_merge.logical_view("samples", ["event_id", "connection_id", "source_ip", "node", "_seq"])
        self.assertEqual(sql.count(" UNION ALL "), 2)
        for source in hk_merge.SOURCES:
            self.assertIn("FROM `hk`.`" + source + "_samples`", sql)
            self.assertIn("CONCAT('" + source + "/',`connection_id`)", sql)
            self.assertIn("'" + source + "' AS source_id", sql)
        self.assertIn("`source_ip` AS `source_ip`", sql)
        self.assertIn("`node` AS `node`", sql)

    def test_duplicate_edge_and_publisher_names_are_scoped(self):
        self.assertIn("CONCAT('tb2/',`node`)", hk_merge.logical_view("peers", ["node"]))
        self.assertIn("CONCAT('tb2/',`publisher`)", hk_merge.logical_view("sync_state", ["publisher"]))

    def test_detail_route_and_dedup_carry_source_identity(self):
        ddl = "select `c`.`connection_id` AS `connection_id`,row_number() over (partition by case x end) from x left join r on (`r`.`node` = `c`.`node`)"
        sql = hk_merge.detail_view(ddl)
        self.assertIn("partition by `c`.`source_id`,case", sql)
        self.assertIn("`r`.`source_id` = `c`.`source_id`", sql)
        with self.assertRaises(ValueError):
            hk_merge.detail_view("unexpected SQL")

    def test_invalid_logical_identifiers_are_rejected(self):
        for table, columns in [("unexpected", ["node"]), ("samples", ["node;DROP"]), ("samples", [])]:
            with self.assertRaises(ValueError):
                hk_merge.logical_view(table, columns)

    def test_inline_preserves_aliases_and_qualified_columns(self):
        relations = {table: "SELECT 1 AS marker FROM `hk`.`tb1_" + table + "`" for table in hk_merge.TABLES}
        sql = "SELECT `hk`.`visits`.`ts` FROM `hk`.`visits` JOIN `hk`.`samples` `s` ON 1=1"
        actual = hk_merge.inline_relations(sql, relations)
        self.assertIn("SELECT `visits`.`ts` FROM (", actual)
        self.assertIn(") `visits` JOIN (", actual)
        self.assertIn(") `s` ON", actual)
        self.assertNotIn("FROM `hk`.`visits`", actual)

    def test_inline_does_not_change_literals_comments_or_physical_tables(self):
        relations = {table: "SELECT 1" for table in hk_merge.TABLES}
        sql = "SELECT 'FROM samples', `NULLIF(node,'')` FROM hk.samples WHERE site='JOIN visits' /* FROM peers */"
        actual = hk_merge.inline_relations(sql, relations)
        self.assertIn("'FROM samples'", actual)
        self.assertIn("`NULLIF(node,'')`", actual)
        self.assertIn("'JOIN visits' /* FROM peers */", actual)
        self.assertIn("FROM (SELECT 1) `samples`", actual)
        self.assertEqual(hk_merge.inline_relations("SELECT * FROM hk.tb1_samples", relations), "SELECT * FROM hk.tb1_samples")

    def test_inline_requires_all_fixed_relations(self):
        with self.assertRaises(ValueError):
            hk_merge.inline_relations("SELECT 1", {})

    def test_tb3_extension_preserves_live_branches_and_scopes_ids(self):
        relations = {}
        for table in hk_merge.TABLES:
            ddl = hk_merge.logical_view(table, ["node", "connection_id"])
            sql = ddl.split(" AS ", 1)[1]
            # MariaDB's SHOW CREATE normalizes keyword case and aliases.
            relations[table] = sql.replace("CONCAT", "concat").replace(" AS source_id", " AS `source_id`")
        extended = hk_merge.append_namespace(relations, "tb3")
        for table, original in relations.items():
            self.assertTrue(extended[table].startswith(original + " union all "))
            self.assertIn("'tb3/'", extended[table])
            self.assertIn("`tb3_" + table + "`", extended[table])
        view = "SELECT x FROM (" + relations["samples"] + ") s WHERE x='unchanged'"
        actual = hk_merge.extend_inlined_view(view, relations, extended)
        self.assertEqual(actual, view.replace(relations["samples"], extended["samples"]))
        with self.assertRaises(ValueError):
            hk_merge.append_namespace(extended, "tb3")
        with self.assertRaises(ValueError):
            hk_merge.extend_inlined_view("SELECT 1", relations, extended)

    def test_termb4_extension_keeps_tb3_and_rejects_duplicate(self):
        relations = {}
        for table in hk_merge.TABLES:
            ddl = hk_merge.logical_view(table, ["node", "connection_id"])
            relations[table] = ddl.split(" AS ", 1)[1].replace("CONCAT", "concat").replace(" AS source_id", " AS `source_id`")
        tb3 = hk_merge.append_namespace(relations, "tb3")
        extended = hk_merge.append_namespace(tb3, "termb4")
        for table, original in tb3.items():
            self.assertTrue(extended[table].startswith(original + " union all "))
            self.assertIn("`termb4_" + table + "`", extended[table])
            self.assertIn("'termb4' AS `source_id`", extended[table])
        with self.assertRaises(ValueError):
            hk_merge.append_namespace(extended, "termb4")

    def test_normalized_view_copies_filtered_branch(self):
        view = ("select * from (select `tb1_visits`.`ts` AS `ts`,'tb1' AS `source_id` "
                "from (select * from `hk`.`tb1_visits` where `ts`>=100) `tb1_visits` "
                "union all select `tb3_visits`.`ts` AS `ts`,'tb3' AS `source_id` "
                "from (select * from `hk`.`tb3_visits` where `ts`>=100) `tb3_visits`) `visits`")
        result, tables = hk_merge.extend_normalized_view(view, 'termb4')
        self.assertEqual(tables, {'visits'})
        self.assertIn("'termb4' AS `source_id`", result)
        self.assertIn('from `hk`.`termb4_visits` where `ts`>=100', result)
        self.assertIn("'tb3' AS `source_id`", result)
        with self.assertRaises(ValueError):
            hk_merge.extend_normalized_view(result, 'termb4')


if __name__ == "__main__":
    unittest.main()
