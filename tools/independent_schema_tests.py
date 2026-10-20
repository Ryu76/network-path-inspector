"""Supervisor-owned schema regressions: no network and no operational files."""
import copy,importlib.util,json,os,pathlib,sys,unittest
ROOT=pathlib.Path(__file__).resolve().parents[1]
WORK=pathlib.Path(os.environ.get('NPI_SCHEMA_ROOT',str(ROOT))).resolve()
spec=importlib.util.spec_from_file_location('actual_schema_validator',WORK/'tools/validate_schema.py');validator=importlib.util.module_from_spec(spec);spec.loader.exec_module(validator)
FIX=WORK/'fixtures/g1'
def schema_of(value):return 'registry'if isinstance(value,list)else'profile'if'profile_id'in value else'session'
def read(name):return json.loads((FIX/name).read_text(encoding='utf-8'))
def validate(value):return validator.validate_document(value,schema_of(value),root=WORK)
class IndependentSchemaTests(unittest.TestCase):
 def test_all_existing_positive_and_negative_fixtures(self):
  paths=sorted(FIX.glob('*.json'));checked=0
  for p in paths:
   if not p.name.startswith(('valid_','invalid_')):continue
   with self.subTest(file=p.name):
    value=json.loads(p.read_text(encoding='utf-8'));errors=validate(value);self.assertEqual(not errors,p.name.startswith('valid_'),errors);checked+=1
  self.assertEqual(checked,16)
 def test_canonical_registry_exact_input_accepted(self):
  c=json.loads((ROOT/'contracts/g1-interface-contract.json').read_text(encoding='utf-8'));self.assertEqual(validate(c['features']),[])
 def test_fixture_registry_must_equal_canonical(self):
  c=json.loads((ROOT/'contracts/g1-interface-contract.json').read_text(encoding='utf-8'));self.assertEqual(read('valid_registry_contract.json'),c['features'])
 def test_legacy_golden_schema_valid(self):self.assertEqual(validate(read('legacy_session_1_0_converted_1_1.golden.json')),[])
 def test_impossible_calendar_day(self):
  s=read('valid_socket_connected.json');s['started_at_utc']='2026-02-30T00:00:00Z';self.assertTrue(validate(s))
 def test_observed_empty_reference_invalid(self):
  s=read('valid_socket_connected.json');s['findings'][0]['evidence_ids']=[];self.assertTrue(validate(s))
 def test_socket_cannot_prove_syn(self):
  s=read('valid_socket_connected.json');s['findings'][0]['statement']='SYN 송신 확인';self.assertTrue(validate(s))
 def test_socket_cannot_prove_rst(self):
  s=read('valid_socket_connected.json');s['findings'][0]['statement']='RST 수신 확인';self.assertTrue(validate(s))
 def test_unrelated_negation_does_not_allow_false_firewall_certainty(self):
  s=read('valid_socket_connected.json');s['findings'][0]['statement']='방화벽 차단 확정. 미확인 사항 없음.';self.assertTrue(validate(s))
 def test_last_hop_not_blocker(self):
  s=read('valid_socket_connected.json');s['findings'][0]['statement']='마지막 응답 HOP=차단 장비';self.assertTrue(validate(s))
 def test_malformed_selected_feature_object_returns_errors_not_exception(self):
  s=read('valid_socket_connected.json');s['profile']['selected_features']=[{'bad':'shape'}];self.assertTrue(validate(s))
 def test_duplicate_feature_results_invalid(self):
  s=read('valid_socket_connected.json');s['feature_results'].append(copy.deepcopy(s['feature_results'][0]));self.assertTrue(validate(s))
 def test_unresolved_reference_invalid(self):
  s=read('valid_socket_connected.json');s['findings'][0]['evidence_ids']=['not-in-evidence'];self.assertTrue(validate(s))
 def test_bad_uuid_invalid(self):
  s=read('valid_socket_connected.json');s['session_id']='invalid';self.assertTrue(validate(s))
 def test_bool_port_invalid(self):
  p=read('valid_profile_quick.json');p['target']['port']=True;self.assertTrue(validate(p))
 def test_ipv6_mapped_address_valid(self):
  p=read('valid_profile_quick.json');p['target']['host']='::ffff:192.0.2.1';self.assertEqual(validate(p),[])
 def test_unknown_schema_invalid(self):
  p=read('valid_profile_quick.json');p['schema_version']='9.0';self.assertTrue(validate(p))
 def test_missing_source_timezone_remains_unknown(self):
  s=read('legacy_session_1_0_converted_1_1.golden.json');self.assertIsNone(s['timezone_offset_minutes'])
 def test_no_http_refs_can_be_accepted(self):
  with self.assertRaises(ValueError):validator._rewrite_local_refs({'$ref':'https://example.invalid/evil.json'})
 def test_input_not_mutated(self):
  p=read('valid_profile_quick.json');before=copy.deepcopy(p);validate(p);self.assertEqual(p,before)
 def test_registry_valid_dependency_dag_is_accepted(self):
  r=read('valid_registry_contract.json');r[0]['dependencies']=['icmp_ping'];self.assertEqual(validate(r),[])
 def test_unknown_legacy_host_role_not_invented(self):
  s=read('legacy_session_1_0_converted_1_1.golden.json');self.assertIsNone(s['host_role']);self.assertEqual(validate(s),[])
 def test_registry_cycles_rejected(self):
  r=read('valid_registry_contract.json');r[0]['dependencies']=[r[1]['feature_id']];r[1]['dependencies']=[r[0]['feature_id']];self.assertTrue(validate(r))
 def test_remote_schema_argument_rejected_without_fetch(self):
  with self.assertRaises(ValueError):validator.validate_document({},'https://example.invalid/session-1.1.schema.json',root=WORK)
if __name__=='__main__':
 result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(IndependentSchemaTests));record={'executed':result.testsRun,'passed':result.testsRun-len(result.failures)-len(result.errors),'failed':len(result.failures),'errors':len(result.errors),'failure_names':[x.id()for x,_ in result.failures],'error_names':[x.id()for x,_ in result.errors]};(ROOT/'artifacts/g1-schema-independent-result.json').write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps(record));sys.exit(not result.wasSuccessful())
