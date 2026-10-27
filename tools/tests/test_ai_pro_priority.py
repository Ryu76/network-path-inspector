"""Offline model-priority regressions; no model calls and no quota consumption."""
import importlib.util,pathlib,unittest,json,tempfile,os,types
from unittest.mock import patch
R=pathlib.Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('priority',R/'tools/run_ai_pro_priority.py');p=importlib.util.module_from_spec(spec);spec.loader.exec_module(p)
class PriorityTests(unittest.TestCase):
 def test_order(self):self.assertEqual(p.load_policy()['verified_available'],['gemini-4-argon-high','claude-opus-5-5-high','gemini-3.8-flash-high'])
 def test_missing_pro_explicit(self):self.assertEqual(p.load_policy()['unavailable_requested_fallback'],'Gemini Pro')
 def test_individual_quota(self):self.assertTrue(p.quota_exhausted('Individual quota reached. Resets in 4h'))
 def test_usage_exhausted(self):self.assertTrue(p.quota_exhausted('Usage exhausted'))
 def test_quota_exceeded(self):self.assertTrue(p.quota_exhausted('quota exceeded'))
 def test_compile_failure_not_quota(self):self.assertFalse(p.quota_exhausted('error[E0308]: mismatched types'))
 def test_timeout_not_quota(self):self.assertFalse(p.quota_exhausted('print timeout, partial output'))
 def test_auth_not_quota(self):self.assertFalse(p.quota_exhausted('Authentication required'))
 def test_generic_429_not_quota(self):self.assertFalse(p.quota_exhausted('HTTP 429 rate limited'))
 def test_noop_not_quota(self):self.assertFalse(p.quota_exhausted('SUCCESS, changed_paths=[]'))
 def exercise(self,first_message,first_exit=1):
  calls=[]
  with tempfile.TemporaryDirectory(prefix='npi-priority-',dir=os.environ['TMPDIR'])as d:
   root=pathlib.Path(d);(root/'tools').mkdir();(root/'.harness/prompts').mkdir(parents=True);(root/'.harness/runs').mkdir();(root/'tools/ai_pro_model_policy.json').write_bytes((R/'tools/ai_pro_model_policy.json').read_bytes());(root/'.harness/prompts/unit-g2tcp.md').write_text('You are AI Pro Gemini 4 Argon High. synthetic unit fixture only.',encoding='utf-8')
   def fake_run(argv,**kwargs):
    stage=argv[-2];model=kwargs['env']['NPI_AI_PRO_MODEL'];calls.append(model);folder=root/'.harness/runs'/(stage+'-g2tcp');folder.mkdir();(folder/'started.json').write_text('{}');failed=len(calls)==1;result={'exit_code':first_exit if failed else 0,'partial':False,'changed_paths':['crates/npi-probes/src/tcp.rs'],'scope_violations':[]};(folder/'result.json').write_text(json.dumps(result));(folder/'stderr.log').write_text('');(folder/'stdout.jsonl').write_text(json.dumps({'event':'result','result':{'status':'ERROR'if failed else'SUCCESS','response':first_message if failed else'unit fixture completed'}})+'\n');return types.SimpleNamespace(returncode=result['exit_code'])
   with patch.object(p,'ROOT',root),patch.object(p.sys,'argv',['priority','unit','g2tcp']),patch.object(p.subprocess,'run',side_effect=fake_run):code=p.main()
   summary=json.loads((root/'.harness/runs/unit-priority-summary.json').read_text(encoding='utf-8'))
   return code,calls,summary
 def test_actual_supervisor_control_flow_falls_back_only_after_quota(self):
  code,calls,summary=self.exercise('Individual quota reached.');self.assertEqual(code,0);self.assertEqual(calls,['gemini-4-argon-high','claude-opus-5-5-high']);self.assertFalse(summary['product_accepted']);self.assertEqual(summary['blocked'],[])
 def test_actual_supervisor_compile_failure_does_not_switch(self):
  code,calls,summary=self.exercise('compile error[E0308]');self.assertEqual(code,1);self.assertEqual(calls,['gemini-4-argon-high']);self.assertTrue(summary['blocked'])
 def test_zero_exit_with_error_result_is_not_success_or_model_switch(self):
  code,calls,summary=self.exercise('The stream was interrupted.',first_exit=0);self.assertEqual(code,1);self.assertEqual(calls,['gemini-4-argon-high']);self.assertTrue(summary['blocked']);self.assertFalse(summary['product_accepted'])
 def test_cache_blocks_until_reset(self):
  with tempfile.TemporaryDirectory(prefix='npi-quota-',dir='C:/Users/HODI/AppData/Local/hermes/cache/scratch')as d:
   root=pathlib.Path(d);(root/'.harness').mkdir();future=(p.datetime.datetime.now().astimezone()+p.datetime.timedelta(hours=1)).isoformat();(root/'.harness/ai-pro-quota-state.json').write_text(json.dumps({'gemini-4-argon-high':{'reset_at':future}}))
   with patch.object(p,'ROOT',root):self.assertTrue(p.cached_quota('gemini-4-argon-high'));self.assertFalse(p.cached_quota('claude-opus-5-5-high'))
 def test_cache_expiry_unblocks(self):
  with tempfile.TemporaryDirectory(prefix='npi-quota-',dir='C:/Users/HODI/AppData/Local/hermes/cache/scratch')as d:
   root=pathlib.Path(d);(root/'.harness').mkdir();(root/'.harness/ai-pro-quota-state.json').write_text(json.dumps({'gemini-4-argon-high':{'reset_at':'2020-01-01T00:00:00+00:00'}}))
   with patch.object(p,'ROOT',root):self.assertFalse(p.cached_quota('gemini-4-argon-high'))
 def test_reset_is_parsed_from_completed_evidence(self):
  with tempfile.TemporaryDirectory(prefix='npi-quota-',dir='C:/Users/HODI/AppData/Local/hermes/cache/scratch')as d:
   root=pathlib.Path(d);(root/'.harness').mkdir();folder=root/'synthetic-test-evidence';folder.mkdir();(folder/'result.json').write_text(json.dumps({'completed_at':'2026-01-01T00:00:00+09:00'}));(folder/'stderr.log').write_text('Individual quota reached. Resets in 2h3m4s.')
   with patch.object(p,'ROOT',root):
    p.record_quota('gemini-4-argon-high',folder);state=json.loads(p.quota_state_path().read_text(encoding='utf-8'));self.assertEqual(state['gemini-4-argon-high']['reset_at'],'2026-01-01T02:03:04+09:00')
if __name__=='__main__':unittest.main()
