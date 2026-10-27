"""최종 수용 상태·제품 source·승인 예외·새 파일 whitespace를 독립 확인한다."""
import hashlib
import json
import pathlib
import subprocess

R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgtcpreplay'
ENGINE='crates/npi-probes/src/engine.rs'
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
a=load('artifacts/qg2g-tcp-replay-acceptance.json')
s=load('artifacts/quick-check-progress.json')
assert a['accepted'] and a['root_integrated'] and not a['full_qg2_accepted'] and not a['product_accepted']
assert s['next_qg2_review']['accepted'] and s['next_qg2_review']['root_integrated']
assert s['inspector_changed_files']==[ENGINE] and s['inspector_original_unchanged_count']==60
assert all(sha(R/path)==value and sha(W/path)==value for path,value in a['source_sha256'].items())
p=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(sha(R/path)==value for path,value in p.items() if path!=ENGINE)
original=R/'.harness/baselines/qg2g-tcp-replay-root/engine.rs'
assert sha(original)==p[ENGINE]
assert (R/ENGINE).read_bytes().replace(b'pub fn apply_tcp_result(',b'fn apply_tcp_result(',1)==original.read_bytes()
paths=['crates/network-core/tests/tcp_product_projection_replay.rs',
       'tools/prepare_quick_tcp_replay.py','tools/prepare_quick_tcp_replay_actor.py',
       'tools/run_quick_tcp_replay.py','tools/record_quick_tcp_replay_start.py',
       'tools/record_quick_tcp_replay_parent_execution.py','tools/integrate_quick_tcp_replay.py',
       'tools/verify_quick_tcp_replay_root.py','tools/accept_quick_tcp_replay.py',
       'tools/check_quick_tcp_replay_delivery.py']
checks=[]
for name in paths:
    path=R/name
    text=path.read_text(encoding='utf-8')
    assert text.endswith('\n'),name
    assert all(line==line.rstrip(' \t') for line in text.splitlines()),name
    if name.endswith('.py'):
        compile(text,str(path),'exec')
    result=subprocess.run(['git','-C',str(R),'diff','--no-index','--check','--','/dev/null',str(path)],
                          capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
    assert result.returncode in (0,1),[name,result.stdout,result.stderr]
    assert not result.stdout.strip(),[name,result.stdout]
    checks.append({'path':name,'exit_code':result.returncode,'utf8_and_no_trailing_whitespace':True})
for root in [R,W]:
    result=subprocess.run(['git','-C',str(root),'diff','--check'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
    assert result.returncode==0,[root,result.stdout,result.stderr]
result=subprocess.run(['git','-C',str(W),'status','--porcelain'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
assert result.returncode==0 and not result.stdout.rstrip('\r\n')
out=R/'artifacts/qg2g-tcp-replay-final-delivery-check.json'
assert not out.exists()
record={'status':'FINAL_DELIVERY_VERIFIED','source_sha256':a['source_sha256'],'accepted_scope':a['decision'],
        'whitespace_checks':checks,'worktree_clean':True,'root_existing_dirty_changes_preserved':True,
        'protected_original_unchanged':60,'approved_visibility_delta':1,'function_body_unchanged':True,
        'full_qg2_accepted':False,'product_accepted':False}
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':record['status'],'new_file_checks':len(checks),'scope_accepted':True,
                  'worktree_clean':True,'protected_original_unchanged':60,'approved_visibility_delta':1,
                  'full_qg2_accepted':False},ensure_ascii=False))
