"""기존 수용 source를 동결해 실제 양제품 TCP 루프백 비교 전용 worktree를 준비한다."""
import datetime
import hashlib
import json
import pathlib
import shutil
import subprocess

R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgtcpnative'
ENGINE='crates/npi-probes/src/engine.rs'
TEST='crates/network-core/tests/tcp_product_native_equivalence.rs'
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()

def git(root,*args):
    result=subprocess.run(['git','-C',str(root),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60)
    assert result.returncode==0,result.stderr
    return result.stdout.rstrip('\r\n')

assert not W.exists() and not (R/TEST).exists()
out=R/'artifacts/qg2h-tcp-native-prepared.json'
assert not out.exists() and not (R/'.harness/runs/qg2tcpnative-qgtcpnative').exists()
accepted=load('artifacts/qg2g-tcp-replay-acceptance.json')
assert accepted['accepted'] and all(sha(R/path)==value for path,value in accepted['source_sha256'].items())
worker=load('artifacts/qg2f-app-entry-acceptance.json')
assert all(sha(R/path)==value for path,value in worker['source_sha256'].items())
protected=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(sha(R/path)==value for path,value in protected.items() if path!=ENGINE)
original=R/'.harness/baselines/qg2g-tcp-replay-root/engine.rs'
assert sha(original)==protected[ENGINE]
assert (R/ENGINE).read_bytes()==original.read_bytes().replace(b'fn apply_tcp_result(',b'pub fn apply_tcp_result(',1)
harness=load('artifacts/commands/qg2h-tcp-native-harness-tests.json')
assert harness['exit_code']==0 and not harness['partial']
git(R,'worktree','add','-b','ai-pro/qgtcpnative',str(W),accepted['preserved_source_commit'])
assert not git(W,'status','--porcelain')
paths=set(load('artifacts/qg2g-tcp-replay-actor-prepared.json')['immutable_source_sha256'])|set(accepted['source_sha256'])
paths|={path.relative_to(R).as_posix() for path in (R/'crates').rglob('*.rs')}
paths|={path.relative_to(R).as_posix() for path in (R/'crates').rglob('Cargo.toml')}
for path in sorted(paths):
    assert (R/path).is_file(),path
    (W/path).parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(R/path,W/path)
    assert sha(W/path)==sha(R/path)
assert not (W/TEST).exists()
git(W,'add',*sorted(paths))
git(W,'-c','core.autocrlf=false','commit','-m','chore: freeze accepted source for owned native TCP product comparisons')
assert not git(W,'status','--porcelain')
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),
        'status':'PREPARED_NATIVE_TEST_SCOPE_DESIGN_REVIEW_PENDING','worktree':str(W),
        'baseline_commit':git(W,'rev-parse','HEAD'),'model':'gemini-3.8-flash-high',
        'stage':'qg2tcpnative','role':'qgtcpnative','actor_writes':[TEST],
        'immutable_source_sha256':{path:sha(W/path) for path in sorted(paths)},
        'root_original_protected_unchanged':len(protected)-1,'approved_visibility_exception_sha256':sha(R/ENGINE),
        'production_changes_allowed':False,'commands_allowed_to_actor':False,
        'design_review':'deleg_44dc1296','actor_started':False,'native_executed':False,
        'previous_acceptance':'artifacts/qg2g-tcp-replay-acceptance.json','accepted':False,'root_integrated':False,
        'remaining_exclusions':['실VLAN/DROP/ICMP차단·VPN/다중NIC환경','GUI/QG3이후','배포/OS/성능/Archive/Session수용']}
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
state=load('artifacts/quick-check-progress.json')
state['recorded_at']=record['recorded_at']
state['next_qg2_native_review']={key:record[key] for key in ['status','worktree','baseline_commit','stage','role',
    'actor_writes','production_changes_allowed','design_review','actor_started','native_executed','accepted','root_integrated']}
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':record['status'],'baseline_commit':record['baseline_commit'],
    'frozen_files':len(paths),'actor_started':False,'native_executed':False,'root_integrated':False},ensure_ascii=False))
