"""Identifier boundaries and structural requirements of regional storage."""
import importlib.util
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'central'))
spec = importlib.util.spec_from_file_location('region_storage', Path(__file__).resolve().parents[1]/'central/storage.py')
storage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(storage)


class RegionStorageTests(unittest.TestCase):
    def test_regions_are_generic_and_namespaces_are_isolated(self):
        for database,prefixes in [('region-a',('',)),('hk',('tb3_','termc_')),('future-region',('one_','two_'))]:
            sql=storage.summary_select(database,prefixes)
            for prefix in prefixes:
                self.assertIn('`'+database+'`.`'+prefix+'traffic_monthly`',sql)
                self.assertEqual(len(storage.trigger_statements(database,prefix)),6)
        self.assertNotIn(' OVER (',storage.summary_select('future-region',('',)))

    def test_system_databases_and_unsafe_names_are_rejected(self):
        for database in ('mysql','sys','information_schema','performance_schema','hk; DROP DATABASE hk','HK'):
            with self.assertRaises(ValueError):storage.summary_select(database,('',))
        for prefixes in ((),('',''),('bad-prefix_',),('x'*40+'_',)):
            with self.assertRaises(ValueError):storage.summary_select('hk',prefixes)

    def test_signed_exact_totals_and_zero_byte_presence(self):
        ddl=storage.monthly_ddl('future', 'edge_')
        self.assertIn('DECIMAL(38,0)',ddl)
        self.assertIn('fact_rows BIGINT NOT NULL',ddl)
        self.assertNotIn('UNSIGNED',ddl)
        self.assertIn('HAVING SUM(fact_rows)>0',storage.totals_select('future',('edge_',)))

    def test_absolute_upsert_replays_do_not_accumulate(self):
        sql=storage.trigger_statements('future')['samples_monthly_au']
        self.assertIn('OLD.`upload_bytes` <=> NEW.`upload_bytes`',sql)
        self.assertIn('-1*CAST(COALESCE(OLD.upload_bytes,0)',sql)
        self.assertIn('1*CAST(COALESCE(NEW.upload_bytes,0)',sql)
        self.assertIn('fact_rows=0',sql)

    def test_future_samples_are_excluded_until_observation_time(self):
        sql=storage.totals_select('future',('',))
        self.assertIn('`ts`>UNIX_TIMESTAMP()',sql)
        self.assertIn('`latest_ts`>UNIX_TIMESTAMP()',sql)
        self.assertIn('-COUNT(*) fact_rows',sql)

    def test_namespace_limit_fits_every_trigger_identifier(self):
        allowed='a'*22+'_'
        self.assertTrue(all(len(name)<=48 for name in storage.trigger_statements('future',allowed)))
        with self.assertRaises(ValueError):storage.trigger_statements('future','a'*23+'_')


if __name__=='__main__':unittest.main()
