"""Calendar totals use indexed compact accounting and committed archive receipts."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'central'))
import archive,monthbook,storage


class MonthBookTests(unittest.TestCase):
    def test_calendar_index_stays_on_local_state_path(self):
        with tempfile.TemporaryDirectory() as root,tempfile.TemporaryDirectory() as state:
            store=archive.Store(root,state_root=state)
            index=monthbook.Index(store,'future')
            try:
                self.assertEqual(index.db.execute('PRAGMA integrity_check').fetchone()[0],'ok')
                self.assertTrue((Path(state)/'future/.calendar-index.sqlite').exists())
                self.assertFalse((Path(root)/'future/.calendar-index.sqlite').exists())
            finally:index.close()

    def test_summary_starts_at_month_not_fourteen_day_cutoff(self):
        sql=storage.summary_select('future',('one_','two_'))
        self.assertNotIn('GREATEST(',sql);self.assertNotIn('UNIX_TIMESTAMP()-1209600',sql)
        self.assertIn('traffic_calendar',sql);self.assertIn('traffic_monthly',sql)
        self.assertIn('calendar_samples_cursor',sql);self.assertNotIn(' OVER (',sql)

    def test_index_only_loads_committed_receipts_and_latest_revision(self):
        with tempfile.TemporaryDirectory() as root:
            store=archive.Store(root);stamp=monthbook.month()[1]+3600
            row=['event',stamp,'conn','entry','192.0.2.1','site',10,20,'fixture',1]
            old=store.write('future','','samples',[row]);row[-1]=3;row[6]=50
            new=store.write('future','','samples',[row]);row[-1]=2;row[6]=900
            orphan=store.write('future','','samples',[row])
            db=MagicMock();cursor=db.cursor.return_value.__enter__.return_value
            cursor.fetchall.return_value=[(f['sha256'],Path(f['file']).name)for f in old+new]
            index=monthbook.Index(store,'future')
            try:
                index.sync(db);prior=index.previous('','samples',dict(zip(archive.specification('samples')[0],row)))
                self.assertEqual(prior['upload_bytes'],50);self.assertEqual(prior['_seq'],3)
                self.assertEqual(index.db.execute('SELECT COUNT(*) FROM applied').fetchone()[0],2)
                index.sync(db);self.assertEqual(index.db.execute('SELECT COUNT(*) FROM facts').fetchone()[0],1)
                self.assertTrue((Path(root)/orphan[0]['file']).exists())
            finally:index.close()

    def test_cursor_uses_timestamp_and_full_primary_key(self):
        row={'latest_ts':100.,'day_start':0,'source_ip':'a','node':'b','site':'c'}
        self.assertEqual(monthbook.order_key('traffic_rollup',row),[100.,0,'a','b','c'])
        sql=monthbook.suppressed_sql('future','edge_','traffic_rollup')
        self.assertIn('calendar_rollup_cursor',sql);self.assertIn('COLLATE utf8mb4_bin',sql)

    def test_namespace_is_part_of_archived_revision_identity(self):
        with tempfile.TemporaryDirectory() as root:
            store=archive.Store(root);stamp=monthbook.month()[1]+1
            row=['same',stamp,'conn','entry','192.0.2.1','site',5,6,'fixture',1]
            blobs=store.write('future','one_','samples',[row])+store.write('future','two_','samples',[row])
            index=monthbook.Index(store,'future')
            try:
                for f in blobs:index.apply_blob(f['sha256'],Path(f['file']).name,(Path(root)/f['file']).read_bytes())
                index.db.commit();self.assertEqual(index.db.execute('SELECT COUNT(*) FROM facts').fetchone()[0],2)
            finally:index.close()


if __name__=='__main__':unittest.main()
