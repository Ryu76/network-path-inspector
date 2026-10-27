"""제한 수용 뒤 source·보호 baseline·실제 실행·문서 예외·로컬 보존을 최종 확인한다."""
import datetime
import hashlib
import json
import pathlib
import re
import subprocess
R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgdevtcp'
load=lambda p:json.loads((R/p).read_text(encoding='utf-8'))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
a=load('artifacts/qg2i-explicit-tcp-acceptance.json')
p=load('artifacts/qg2i-explicit-tcp-parent-repair.json')
assert a['accepted'] and a['root_integrated'] and not a['full_qg2_accepted'] and not a['product_accepted'] and not a['qg3_started']
assert all(sha(R/path)==value==sha(W/path) for path,value in a['source_sha256'].items())
# 실행 전후 전체 동결은 root-validation에 있다. 수용 뒤 갱신한 문서2개만 최종 비교에서 명시 제외한다.
document_exceptions=['apps/network-quick-check/README.md','docs/quick-check/gates.md']
assert all(sha(R/path)==value for path,value in p['immutable_source_sha256'].items() if path not in document_exceptions)
assert all(sha(W/path)==value for path,value in p['immutable_source_sha256'].items())
protected=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
engine='crates/npi-probes/src/engine.rs'
assert all(sha(R/path)==value for path,value in protected.items() if path!=engine)
original=R/'.harness/baselines/qg2g-tcp-replay-root/engine.rs'
assert sha(original)==protected[engine]
assert (R/engine).read_bytes().replace(b'pub fn apply_tcp_result(',b'fn apply_tcp_result(',1)==original.read_bytes()
assert sha(R/'PRD.md')=='faffff45de66126dad6a0a81045dd22b536e9739e78947b426bd42d4a0ef7aa1'
assert sha(R/'docs/requirements/Network_Path_Inspector_Harness_PRD_v1.2.md')=='a999eaff063db5c1ecf11d616eb116735eb692833d33121026a53c06dddaaf6f'
cli=load('artifacts/qg2i-explicit-tcp-root-commandline.json')
assert len(cli['commandline_cases'])==cli['commandline_case_count']==38
assert len(cli['explicit_reject_cases'])==cli['explicit_reject_case_count']==23
assert len(cli['supervisor_self_tests'])==cli['supervisor_self_test_count']==6
assert all(item['passed'] for key in ['commandline_cases','explicit_reject_cases','supervisor_self_tests'] for item in cli[key])
assert all(sha(pathlib.Path(path))==value for path,value in cli['binary_sha256'].items())
s=load('artifacts/quick-check-progress.json')
assert s['latest_root_validation']['workspace']['passed']==446 and s['latest_root_validation']['native']['passed']==31
assert s['next_qg2_explicit_tcp_entry']['accepted'] and not s['next_qg2_explicit_tcp_entry']['native_execution_held']
assert s['next_qg2_app_integration_review']['decision_required'] is None
assert s['inspector_original_unchanged_count']==len(protected)-1
assert load('artifacts/commands/qg2i-explicit-tcp-delivery-harness.json')['exit_code']==0
log=(R/'artifacts/commands/qg2i-explicit-tcp-delivery-harness.log').read_text(encoding='utf-8')
assert re.search(r'Ran 29 tests',log) and 'OK' in log

def git(root,*args):
    x=subprocess.run(['git','-C',str(root),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60)
    assert x.returncode==0,x.stdout+x.stderr
    return x.stdout.rstrip('\r\n')

assert not git(W,'status','--porcelain','--untracked-files=all')
assert git(W,'rev-parse','HEAD')==a['preserved_source_commit']
assert sorted(git(W,'show','--format=','--name-only','HEAD').splitlines())==sorted(a['source_sha256'])
git(R,'diff','--check')
new_helpers=[path for path in (R/'tools').glob('*quick_explicit_tcp*.py')]
new_helpers.append(R/'tools/record_quick_entry_scope_review.py')
paths=set(a['source_sha256'])|{path.relative_to(R).as_posix() for path in new_helpers}
paths|={'tools/ai_pro_harness.py','tools/audit_ai_pro_runs.py','tools/verify_quick_app_entry_owned_native.py',
    'tools/tests/test_quick_app_actor_scope.py','PROGRESS.md','RESUME.md','작업내용/NPI_2026-10-23_001.md',*document_exceptions}
for path in paths:
    text=(R/path).read_text(encoding='utf-8')
    assert text.endswith('\n') and all(line.rstrip(' \t')==line for line in text.splitlines()),path
for name in document_exceptions+['PROGRESS.md','RESUME.md','작업내용/NPI_2026-10-23_001.md']:
    assert 'artifacts/qg2i-explicit-tcp-acceptance.json' in (R/name).read_text(encoding='utf-8')
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'FINAL_DELIVERY_CHECK_PASS',
    'accepted_scope':a['scope'],'source_sha256':a['source_sha256'],'workspace_passed':446,'workspace_ignored':31,
    'native_passed':31,'new_product_exe_native_included':4,'legacy_cli_passed':38,'explicit_reject_passed':23,
    'supervisor_passed':6,'harness_passed':29,'utf8_and_whitespace_files_checked':len(paths),
    'checked_helper_count':len(new_helpers),'preserved_source_commit':a['preserved_source_commit'],'worktree_clean':True,
    'root_branch':git(R,'branch','--show-current'),'root_claimed_clean':False,
    'post_execution_document_exceptions':document_exceptions,'original_inspector_unchanged':len(protected)-1,
    'approved_existing_pub_delta_files':1,'full_qg2_accepted':False,'product_accepted':False,'remote_push_or_deploy':False}
out=R/'artifacts/qg2i-explicit-tcp-final-delivery-check.json'
assert not out.exists()
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(record,ensure_ascii=False))
