"""Cold storage safety, explicit reads and exact integer regressions."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock,patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'central'))
import archive

def sample(event='a',seq=1,up=10,down=20,stamp=1791000000.):
    return [event,stamp,'conn','node','192.0.2.1','case.test',up,down,'fixture',seq]

class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.store=archive.Store(self.temp.name)
    def test_roundtrip_explicit_query_does_not_create_mysql_objects(self):
        self.store.write('region','one_','samples',[sample()]);self.store.write('region','two_','samples',[sample()])
        result=archive.query_month(self.store,'region','2026-10');self.assertEqual(result['totals']['total_bytes'],60)
        self.assertFalse(result['imported_into_mysql']);self.assertTrue(result['explicit_load'])
        self.assertFalse(list(Path(self.temp.name).glob('.query-*')))
    def test_duplicate_and_out_of_order_revisions_do_not_double_count(self):
        self.store.write('region','','samples',[sample(seq=3,up=50)],written_ns=10)
        self.store.write('region','','samples',[sample(seq=2,up=100)],written_ns=20)
        self.store.write('region','','samples',[sample(seq=3,up=50)],written_ns=30)
        self.assertEqual(archive.query_month(self.store,'region','2026-10')['totals']['total_bytes'],70)
    def test_pack_and_late_parts_preserve_exact_large_integer_bytes(self):
        huge=9223372036854775807
        self.store.write('region','','samples',[sample('a',up=huge),sample('b',up=huge)])
        before=archive.query_month(self.store,'region','2026-10');self.assertEqual(before['totals']['upload_bytes'],2*huge)
        self.assertTrue(self.store.pack('region','2026-10')['packed'])
        self.assertEqual(before,archive.query_month(self.store,'region','2026-10'))
        self.store.write('region','','samples',[sample('c',up=2)])
        self.store.pack('region','2026-10');self.assertEqual(archive.query_month(self.store,'region','2026-10')['totals']['upload_bytes'],2*huge+2)
    def test_corruption_is_rejected(self):
        result=self.store.write('region','','samples',[sample()]);path=Path(self.temp.name)/result[0]['file'];blob=bytearray(path.read_bytes());blob[-5]^=1;path.write_bytes(blob)
        with self.assertRaises((ValueError,OSError,EOFError)):archive.query_month(self.store,'region','2026-10')
    def test_no_archive_is_not_reported_as_zero_usage(self):
        with self.assertRaisesRegex(ValueError,'no_archive'):archive.query_month(self.store,'region','2026-09')

    def test_archive_data_and_sqlite_state_can_use_separate_filesystems(self):
        with tempfile.TemporaryDirectory() as state:
            store=archive.Store(self.temp.name,state_root=state)
            store.write('region','','samples',[sample()])
            self.assertTrue((Path(self.temp.name)/'region/2026-10').is_dir())
            self.assertEqual(archive.query_month(store,'region','2026-10')['totals']['total_bytes'],30)
            self.assertFalse(list(Path(self.temp.name).glob('.query-*')))
            self.assertFalse(list(Path(self.temp.name).glob('region/.calendar-index.sqlite*')))
            self.assertFalse(list(Path(state).glob('.query-*')))

    def test_configured_nfs_source_must_be_mounted_before_using_archive(self):
        config=Path(self.temp.name)/'storage.json'
        config.write_text(json.dumps({'state_root':self.temp.name+'/state','mount_source':'192.0.2.1:/'}))
        with patch.dict(archive.os.environ,{'TRAFFIC_CENTRAL_STORAGE_CONFIG':str(config)}),patch.object(archive,'ARCHIVE_ROOT',self.temp.name):
            with patch.object(Path,'read_text',side_effect=[config.read_text(),'1 0 8:1 / / rw - ext4 /dev/root rw']):
                with self.assertRaisesRegex(RuntimeError,'cold_archive_mount_required'):archive.Store(self.temp.name)
        self.assertFalse((Path(self.temp.name)/'state').exists())
    def test_bad_month_and_path_are_refused(self):
        for month in ['../secret','2026-13','2026-01/../../mysql']:
            with self.assertRaises(ValueError):list(self.store.chunks('region',month))
        with self.assertRaises(ValueError):list(self.store.chunks('../mysql','2026-10'))
    def test_archive_failure_rolls_back_without_delete(self):
        db=MagicMock();cursor=db.cursor.return_value.__enter__.return_value;cursor.fetchall.return_value=[sample()]
        store=MagicMock();store.write.side_effect=OSError('disk-full')
        with self.assertRaisesRegex(OSError,'disk-full'):archive.archive_batch(db,store,'region','','samples',1792000000)
        db.rollback.assert_called_once();self.assertFalse(any('DELETE FROM' in str(c) for c in cursor.execute.call_args_list))
    def test_failing_source_yields_next_invocation_to_another_region(self):
        with tempfile.TemporaryDirectory() as state:
            self.store.state_root=Path(state)
            self._check_failing_source_yields()
            self.assertTrue((Path(state)/'.cursor.json').exists())
            self.assertFalse((self.store.root/'.cursor.json').exists())

    def _check_failing_source_yields(self):
        with patch.object(archive,'discover',return_value=[('region',''),('region','two_')]),patch.object(archive.monthbook,'retire'):
            with patch.object(archive,'archive_batch',side_effect=OSError('one_source_failed')):
                with self.assertRaises(OSError):archive.run(None,self.store,budget=1)
            with patch.object(archive,'archive_batch',return_value={'rows':0,'files':[]}) as batch:
                result=archive.run(None,self.store,budget=1)
                self.assertEqual(batch.call_args_list[0].args[2:5],('region','two_','samples'))
                self.assertEqual(batch.call_count,12);self.assertEqual(len(result['sources']),2)
    def run_once(self,now):
        with patch.object(archive,'discover',return_value=[('region','')]),patch.object(archive.monthbook,'retire'),              patch.object(archive,'archive_batch',return_value={'rows':0,'files':[]}):
            return archive.run(None,self.store,budget=5,now=now)
    def test_open_month_parts_are_never_listed_by_the_worker(self):
        import datetime as dt
        self.store.write('region','','samples',[sample()])               # 2026-10 part
        closed=dt.datetime(2026,11,15,0,0,1,tzinfo=archive.TZ).timestamp()  # October left the 14-day window
        listed=[]
        original=Path.glob
        def spy(path,pattern):
            listed.append(path.name);return original(path,pattern)
        with patch.object(Path,'glob',spy):
            self.assertEqual(self.run_once(closed-10)['packed'],[])
            self.assertEqual(listed,[])                                  # open month: no folder listing at all
            self.assertEqual(len(self.run_once(closed+10)['packed']),1)
        self.assertIn('2026-10',listed)
        self.assertTrue((Path(self.temp.name)/'region/2026-10.tar').is_file())
        self.assertFalse((Path(self.temp.name)/'region/2026-10').exists())
    def test_sealed_month_absorbs_late_parts_at_most_daily_without_losing_them(self):
        import datetime as dt,os
        self.store.write('region','','samples',[sample('a')])
        now=dt.datetime(2026,11,20,tzinfo=archive.TZ).timestamp()
        tar=Path(self.temp.name)/'region/2026-10.tar'
        self.assertEqual(len(self.run_once(now)['packed']),1)
        os.utime(tar,(now,now))
        self.store.write('region','','samples',[sample('late',up=5)])
        self.assertEqual(self.run_once(now+3600)['packed'],[])             # same day: not rewritten
        self.assertEqual(archive.query_month(self.store,'region','2026-10')['totals']['upload_bytes'],15)  # still readable
        self.assertEqual(len(self.run_once(now+archive.RESEAL_SECONDS+1)['packed']),1)
        self.assertEqual(archive.query_month(self.store,'region','2026-10')['totals']['upload_bytes'],15)
        self.assertFalse((Path(self.temp.name)/'region/2026-10').exists())
        self.assertEqual([e['pending_parts'] for e in self.store.catalog('region')],[0])
        with self.assertRaises(ValueError):self.store.seal_due('region','../x')
    def test_verified_export_precedes_guarded_delete_and_commit(self):
        db=MagicMock();cursor=db.cursor.return_value.__enter__.return_value;cursor.fetchall.return_value=[sample()];cursor.rowcount=1
        store=MagicMock();store.write.return_value=[{'rows':1}];order=[]
        store.write.side_effect=lambda *a,**k:(order.append('durable_export') or [{'rows':1}])
        cursor.executemany.side_effect=lambda *a,**k:order.append('delete')
        db.commit.side_effect=lambda:order.append('commit')
        self.assertEqual(archive.archive_batch(db,store,'region','','samples',1792000000)['rows'],1)
        self.assertEqual(order,['durable_export','delete','commit']);self.assertIn('`_seq`=%s',cursor.executemany.call_args.args[0])
    def test_captured_receiver_patch_preserves_watermark_and_disables_legacy_delete(self):
        spec=importlib.util.spec_from_file_location('tier_patches',ROOT/'deploy/tiers.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        # The canonical receiver is retained as a source fixture by this test.
        source=(ROOT/'central/receive.py').read_text(encoding='utf-8')
        if 'SELECT epoch FROM' in source:
            patched=module.patch_receiver(source)
            self.assertIn('seq <= state[1]',patched);self.assertNotIn('DELETE FROM',patched);self.assertNotIn('values[columns.index(timestamp)] < cutoff',patched)
        else:
            with self.assertRaisesRegex(ValueError,'anchor_changed'):module.patch_receiver(source)

if __name__=='__main__':unittest.main()
