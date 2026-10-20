"""Harness regressions: fake secrets only, no model or network calls."""
import importlib.util,json,os,pathlib,tempfile,unittest
ROOT=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('harness',ROOT/'tools/ai_pro_harness.py');h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
class HarnessTests(unittest.TestCase):
 def test_model_exact(self):self.assertEqual(h.MODEL,'gemini-4-argon-high')
 def test_nested_redaction_preserves_json_shape(self):
  old=h.VALUES
  try:
   h.VALUES=['FAKE_SECRET_FOR_HARNESS_TEST'];value={'status':'UNKNOWN','rows':[{'CODE_PUB':'FAKE_SECRET_FOR_HARNESS_TEST','nested':'prefix FAKE_SECRET_FOR_HARNESS_TEST suffix'}]};out=h.clean(value)
   self.assertEqual(out['status'],'UNKNOWN');self.assertEqual(out['rows'][0]['CODE_PUB'],'[REDACTED]');self.assertEqual(out['rows'][0]['nested'],'prefix [REDACTED] suffix');json.dumps(out)
  finally:h.VALUES=old
 def test_original_input_not_mutated(self):
  value={'state':['OBSERVED','INFERRED','UNKNOWN']};self.assertEqual(h.clean(value),value);self.assertEqual(value['state'][2],'UNKNOWN')
 def test_bearer_redacted(self):self.assertEqual(h.clean('Bearer SYNTHETIC_TOKEN_1234'),'Bearer [REDACTED]')
 def test_multiline_preserved(self):self.assertEqual(h.clean('a\nb'),'a\nb')
 def test_unicode_schema_strings_preserved(self):self.assertEqual(h.clean('미확인\nUNKNOWN'),'미확인\nUNKNOWN')
 def test_json_line_sanitized_before_output(self):
  out=h.lines(b'{"event":"result","result":{"response":"Bearer SYNTHETIC_TOKEN_1234"}}\n');self.assertEqual(json.loads(out)['result']['response'],'Bearer [REDACTED]')
 def test_invalid_utf8_capture_does_not_crash(self):self.assertIn('\ufffd',h.lines(b'bad\xff\n'))
 def test_dotfile_and_source_hashes_are_kept(self):
  with tempfile.TemporaryDirectory(prefix='npi-harness-',dir=os.environ['TMPDIR'])as d:
   w=pathlib.Path(d);(w/'.gitignore').write_text('x\n');(w/'source.rs').write_text('// no-op\n');state=h.snapshot(w);self.assertEqual(set(state),{'.gitignore','source.rs'});self.assertEqual(len(state['source.rs']),64)
 def test_generated_and_git_files_excluded(self):
  with tempfile.TemporaryDirectory(prefix='npi-harness-',dir=os.environ['TMPDIR'])as d:
   w=pathlib.Path(d)
   for q in ['target/x','node_modules/x','.harness/x','.worktrees/x','.git/x']:
    p=w/q;p.parent.mkdir(parents=True,exist_ok=True);p.write_text('not source')
   self.assertEqual(h.snapshot(w),{})
 def test_changed_content_has_new_hash(self):
  with tempfile.TemporaryDirectory(prefix='npi-harness-',dir=os.environ['TMPDIR'])as d:
   p=pathlib.Path(d)/'a.txt';p.write_text('before');a=h.snapshot(pathlib.Path(d));p.write_text('after');b=h.snapshot(pathlib.Path(d));self.assertNotEqual(a,b)
if __name__=='__main__':unittest.main()
