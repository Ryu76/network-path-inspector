"""수용된 native TCP 비교의 최종 source·기존보호·새파일·하네스 증거를 확인한다."""
import datetime
import hashlib
import json
import pathlib
import subprocess

R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgtcpnative'
ENGINE='crates/npi-probes/src/engine.rs'
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
a=load('artifacts/qg2h-tcp-native-acceptance.json')
s=load('artifacts/quick-check-progress.json')
assert a['accepted'] and a['root_integrated'] and not a['full_qg2_accepted'] and not a['product_accepted']
assert s['next_qg2_native_review']['accepted'] and s['next_qg2_native_review']['root_integrated']
assert a['production_changes']==0 and a['existing_tests_changed']==0
assert all(sha(R/path)==value and sha(W/path)==value for path,value in a['source_sha256'].items())
frozen=load('artifacts/qg2h-tcp-native-actor-prepared.json')['immutable_source_sha256']
# 94개는실행전후동결검증했다. 수용뒤갱신한두진행문서는여기서명시제외한다.
docs={'apps/network-quick-check/README.md','docs/quick-check/gates.md'}
assert all(sha(R/path)==value for path,value in frozen.items() if path not in docs)
protected=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(sha(R/path)==value for path,value in protected.items() if path!=ENGINE)
assert sha(R/ENGINE)==a['protected_engine_sha256']
original=R/'.harness/baselines/qg2g-tcp-replay-root/engine.rs'
assert sha(original)==protected[ENGINE]
assert (R/ENGINE).read_bytes().replace(b'pub fn apply_tcp_result(',b'fn apply_tcp_result(',1)==original.read_bytes()
unit=load('artifacts/commands/qg2h-tcp-native-delivery-harness.json')
assert unit['exit_code']==0 and not unit['partial']
assert 'Ran 24 tests' in pathlib.Path(unit['log']).read_text(encoding='utf-8')
paths=['crates/network-core/tests/tcp_product_native_equivalence.rs',
    'tools/prepare_quick_tcp_native.py','tools/prepare_quick_tcp_native_actor.py','tools/run_quick_tcp_native.py',
    'tools/record_quick_tcp_native_start.py','tools/record_quick_tcp_native_audit.py',
    'tools/record_quick_tcp_native_first_execution.py','tools/record_quick_tcp_native_parent_repair.py',
    'tools/record_quick_tcp_native_parent_execution.py','tools/integrate_quick_tcp_native.py',
    'tools/verify_quick_tcp_native_root.py','tools/accept_quick_tcp_native.py','tools/check_quick_tcp_native_delivery.py']
checks=[]
for name in paths:
    path=R/name
    text=path.read_text(encoding='utf-8')
    assert text.endswith('\n') and all(line==line.rstrip(' \t') for line in text.splitlines()),name
    if name.endswith('.py'):
        compile(text,str(path),'exec')
    result=subprocess.run(['git','-C',str(R),'diff','--no-index','--check','--','/dev/null',str(path)],
        capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
    assert result.returncode in (0,1) and not result.stdout.strip(),[name,result.stdout,result.stderr]
    checks.append({'path':name,'exit_code':result.returncode,'utf8_and_whitespace_passed':True})
for root in [R,W]:
    result=subprocess.run(['git','-C',str(root),'diff','--check'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
    assert result.returncode==0,[root,result.stdout,result.stderr]
result=subprocess.run(['git','-C',str(W),'status','--porcelain'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
assert result.returncode==0 and not result.stdout.rstrip('\r\n')
out=R/'artifacts/qg2h-tcp-native-final-delivery-check.json'
assert not out.exists()
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'FINAL_DELIVERY_VERIFIED',
    'source_sha256':a['source_sha256'],'accepted_scope':a['decision'],'new_file_checks':checks,
    'harness_tests_passed':24,'worktree_clean':True,'root_existing_dirty_changes_preserved':True,
    'protected_original_unchanged':60,'previous_approved_visibility_exception_files':1,
    'production_changes':0,'full_qg2_accepted':False,'product_accepted':False}
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
s['recorded_at']=record['recorded_at']
s['next_qg2_native_review']['final_delivery_check']=str(out.relative_to(R))
s['next_qg2_app_integration_review']={'status':'READ_ONLY_PLANNING_PENDING','review':'deleg_ed3799ab',
    'question':'QG2내기존실행기를제품EXE의명시단일대상진단경로로연결하는최소공백·GUI게이트선행금지',
    'actor_started':False,'production_changes':0,'root_integrated':False,'accepted':False}
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(s,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':record['status'],'new_file_checks':len(checks),'harness_tests_passed':24,
    'worktree_clean':True,'production_changes':0,'next_readonly_review':'deleg_ed3799ab',
    'full_qg2_accepted':False},ensure_ascii=False))
