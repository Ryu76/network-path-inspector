"""GUI WIP 전달 검증. 기능 미수용과 승인 경계를 통과로 바꾸지 않는다."""
import datetime,hashlib,json,pathlib,re,subprocess
R=pathlib.Path(__file__).resolve().parents[1]
load=lambda p:json.loads((R/p).read_text(encoding='utf-8'))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
p=load('artifacts/qg3b-gui-inputs-parent-repair.json');pres=load('artifacts/qg3b-gui-inputs-preservation.json');W=pathlib.Path(p['worktree'])
assert not pres['root_integrated'] and not pres['accepted'] and pres['worktree_clean']
assert all(sha(W/n)==h for n,h in p['source_sha256'].items())
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
assert all(sha(W/n)==h for n,h in p['immutable_source_sha256'].items())
assert all(sha(W/n)==h for n,h in p['reference_sha256'].items())
for args,expected in [(['status','--porcelain'],''),(['rev-parse','HEAD'],pres['preserved_commit'])]:
 result=subprocess.run(['git','-C',str(W),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
 assert result.returncode==0 and result.stdout.rstrip('\r\n')==expected
baseline=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
engine='crates/npi-probes/src/engine.rs';assert len(baseline)==61
assert all(sha(R/n)==h for n,h in baseline.items() if n!=engine)
original=R/'.harness/baselines/qg2g-tcp-replay-root/engine.rs';assert sha(original)==baseline[engine]
assert (R/engine).read_bytes()==original.read_bytes().replace(b'fn apply_tcp_result(',b'pub fn apply_tcp_result(',1)
actor=load('artifacts/qg3b-gui-inputs-pipeline.json')
assert all(sha(R/'.harness/evidence/qg3b-gui-inputs-actor-original'/pathlib.Path(n).name)==h for n,h in actor['source_sha256'].items())
cli=load('artifacts/qg3b-gui-inputs-parent-commandline.json')
assert cli['status'].startswith('CURRENT_EXE_') and all(x['passed'] for name in ['commandline_cases','explicit_reject_cases','gui_reject_cases','supervisor_self_tests'] for x in cli[name])
assert [len(cli[k]) for k in ['commandline_cases','explicit_reject_cases','gui_reject_cases','supervisor_self_tests']]==[38,23,9,6]
visible=load('artifacts/qg3b-gui-inputs-visible-process.json');obs=load('artifacts/qg3b-gui-inputs-visible-observation.json')
assert visible['exit_code']==0 and visible['child_reaped'] and not visible['timed_out']
assert not obs['accepted'] and not obs['blocked_action']['retry_or_alternative_attempted']
assert sha(pathlib.Path(visible['executable']))==cli['binary_sha256']==pres['binary_sha256']
review=load('artifacts/qg3b-gui-inputs-final-independent-review.json')
assert review['native_review']['safe_to_execute_owned_native_tests'] and not review['native_review']['findings']
assert review['format_exception']['expected_after_rustfmt_equals_actual_bytes']
assert all(sha(pathlib.Path(n))==h for n,h in review['trace_sha256'].items())
progress=load('artifacts/quick-check-progress.json');assert progress['qg3_native_gui_inputs']==pres
assert not progress['gui_implemented'] and not progress['single_exe_accepted']
commands={}
for name in ['parent-workspace','parent-clippy-v3','parent-fmt-check','parent-product-build','parent-owned-native']:
 d=load('artifacts/commands/qg3b-gui-inputs-'+name+'.json');assert d['exit_code']==0 and not d['partial'];commands[name]=d
workspace=pathlib.Path(commands['parent-workspace']['log']).read_text(encoding='utf-8')
rows=[tuple(map(int,m)) for m in re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored',workspace)]
assert tuple(sum(row[i] for row in rows) for i in range(3))==(500,0,35)
assert '4 passed; 0 failed; 0 ignored' in pathlib.Path(commands['parent-owned-native']['log']).read_text(encoding='utf-8')
files=[W/n for n in p['source_sha256']]+[W/n for n in p['parent_metadata_changes']]
files += list((R/'tools').glob('*quick_gui_inputs*.py'))
files += [R/n for n in ['tools/ai_pro_harness.py','tools/audit_ai_pro_runs.py','tools/tests/test_quick_app_actor_scope.py',
 'PROGRESS.md','RESUME.md','docs/quick-check/native-gui-inputs-checkpoint-2026-10-26.md','artifacts/quick-check-progress.json']]
files += list((R/'artifacts').glob('qg3b-gui-inputs-*.json'))
files += list((R/'artifacts').glob('qg3b-gui-parent-*.json'))
files=sorted(set(files));checked={}
for path in files:
 text=path.read_text(encoding='utf-8');assert text.endswith('\n'),str(path)
 assert not any(line.rstrip(' \t')!=line for line in text.splitlines()),str(path)
 if path.suffix=='.json':json.loads(text)
 checked[str(path)]=sha(path)
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'WIP_DELIVERY_EVIDENCE_VERIFIED_NOT_GUI_ACCEPTANCE',
 'verified_text_files':len(checked),'sha256':checked,'clean_local_commit':pres['preserved_commit'],
 'root_input_files_unchanged':len(p['root_before_sha256']),'immutable_actor_input_files_unchanged':len(p['immutable_source_sha256']),
 'inspector_protection':'60 originals unchanged + exact approved pub four-byte exception in engine.rs',
 'default_counts':{'passed':500,'failed':0,'ignored':35},'owned_native_passed':4,
 'legacy_cli_cases':38,'explicit_reject_cases':23,'gui_reject_cases':9,'supervisor_cases':6,
 'visible_window_exited_cleanly':True,'visible_functional_acceptance':False,'approval_timeout_respected':True,
 'root_integrated':False,'accepted':False,'full_qg2_accepted':False,'full_qg3_accepted':False,'product_accepted':False}
out=R/'artifacts/qg3b-gui-inputs-final-delivery-check.json';assert not out.exists();out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:record[k] for k in ['status','verified_text_files','clean_local_commit','root_integrated','accepted']},ensure_ascii=False))
