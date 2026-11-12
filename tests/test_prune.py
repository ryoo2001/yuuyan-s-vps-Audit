"""Publisher pruning must not bypass verified cold storage."""
import sys,unittest
from pathlib import Path
from unittest.mock import MagicMock
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'central'))
from receive import prune
class PrunePrivilegeTests(unittest.TestCase):
    def test_legacy_publisher_prune_is_non_destructive(self):
        db=MagicMock();self.assertEqual(prune(db),0);db.cursor.assert_not_called();db.commit.assert_not_called()
    def test_repeated_prune_cannot_remove_unarchived_facts(self):
        db=MagicMock()
        for _ in range(3):self.assertEqual(prune(db),0)
        self.assertEqual(db.mock_calls,[])
if __name__=='__main__':unittest.main()
