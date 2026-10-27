"""Pure actor-discovery regressions: no CLI/model/network calls."""
import importlib.util,json,pathlib,tempfile,unittest
R=pathlib.Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('records',R/'tools/ai_pro_run_records.py');m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class RunRecordsTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='npi-run-records-',dir='C:/Users/HODI/AppData/Local/hermes/cache/scratch');self.root=pathlib.Path(self.tmp.name)
 def tearDown(self):self.tmp.cleanup()
 def actor(self,stage,role,folder=None):
  p=self.root/(folder or stage+'-'+role);p.mkdir();(p/'started.json').write_text(json.dumps({'stage':stage,'role':role}),encoding='utf-8')
 def test_parent_stage_excludes_fallback_descendant(self):
  self.actor('g2repair','g2host');self.actor('g2repair-fallback1','g2host');self.assertEqual(m.stage_roles(self.root,'g2repair',{'g2host'}),['g2host'])
 def test_fallback_stage_is_independently_discoverable(self):
  self.actor('g2repair','g2host');self.actor('g2repair-fallback1','g2host');self.assertEqual(m.stage_roles(self.root,'g2repair-fallback1',{'g2host'}),['g2host'])
 def test_directory_role_mismatch_rejected(self):
  self.actor('stage','g2host',folder='stage-g2dns')
  with self.assertRaises(ValueError):m.stage_roles(self.root,'stage',{'g2host','g2dns'})
 def test_unknown_role_rejected(self):
  self.actor('stage','unknown')
  with self.assertRaises(ValueError):m.stage_roles(self.root,'stage',{'g2host'})
if __name__=='__main__':unittest.main()
