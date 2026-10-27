"""명시 승인 범위의 TCP 원시 replay를 별도 worktree에 준비한다. 아직 공개 변경 전이다."""
import datetime
import hashlib
import json
import pathlib
import shutil
import subprocess

R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgtcpreplay'
ENGINE='crates/npi-probes/src/engine.rs'
TEST='crates/network-core/tests/tcp_product_projection_replay.rs'
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()

def git(where,*args):
    p=subprocess.run(['git','-C',str(where),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60)
    assert p.returncode==0,p.stderr
    return p.stdout.rstrip('\r\n')

assert not W.exists() and not (R/TEST).exists()
assert not (R/'artifacts/qg2g-tcp-replay-prepared.json').exists()
assert not (R/'.harness/runs/qg2tcpreplay-qgtcpreplay').exists()
protected=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert ENGINE in protected and all(sha(R/path)==value for path,value in protected.items())
accepted=load('artifacts/qg2f-app-entry-acceptance.json')
assert accepted['accepted'] and all(sha(R/path)==value for path,value in accepted['source_sha256'].items())
assert b'\nfn apply_tcp_result(' in (R/ENGINE).read_bytes()
harness=load('artifacts/commands/qg2g-tcp-replay-harness-tests.json')
assert harness['exit_code']==0 and not harness['partial']
assert 'Ran 41 tests' in pathlib.Path(harness['log']).read_text(encoding='utf-8')
now=datetime.datetime.now().astimezone().isoformat()
approval={'recorded_at':now,'authorization_granted':True,'user_response_verbatim':'허용',
          'request':'기존apply_tcp_result 공개전환·양제품실제변환함수 순수회귀추가',
          'production_path':ENGINE,'production_change':'기존fn선언앞에pub 4바이트추가만·본문/매핑/측정동작불변',
          'test_path':TEST,'actor_may_edit_production':False,
          'prohibited':['함수본문/DTO/상태매핑/측정동작변경','다른보호소스변경','운영망/OS정책변경·배포'],
          'supersedes_timeout_record':'artifacts/qg2g-tcp-replay-approval.json',
          'scope_does_not_accept':['전체QG2실환경','GUI/QG3','제품배포인증'],
          'original_protected_baseline_unchanged':'artifacts/qg0-inspector-baseline.json'}
assert not (R/'artifacts/qg2g-tcp-replay-explicit-approval.json').exists()
(R/'artifacts/qg2g-tcp-replay-explicit-approval.json').write_text(json.dumps(approval,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
git(R,'worktree','add','-b','ai-pro/qgtcpreplay',str(W),accepted['preserved_source_commit'])
assert not git(W,'status','--porcelain')
paths=set(protected)|set(accepted['source_sha256'])|{
    'AGENTS.md','.gitattributes','PRD.md','docs/requirements/Network_Path_Inspector_Harness_PRD_v1.2.md',
    'contracts/g1-interface-contract.json','contracts/quick-check-interface-v0.1.json',
    'apps/network-quick-check/README.md','docs/quick-check/gates.md'}
paths|={path.relative_to(R).as_posix() for path in (R/'crates').rglob('*.rs')}
paths|={path.relative_to(R).as_posix() for path in (R/'crates').rglob('Cargo.toml')}
for path in sorted(paths):
    assert (R/path).is_file(),path
    (W/path).parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(R/path,W/path)
    assert sha(W/path)==sha(R/path)
assert not (W/TEST).exists()
signature='''//! 부모가 작성한 공개 API 가시성 회귀. 소켓·DNS·runtime·프로세스 호출 없음.
#[test]
fn parent_public_projector_signature_contract() {
    let _projector: fn(&mut npi_core::FeatureResult, &network_core::TcpMeasurement) =
        npi_probes::engine::apply_tcp_result;
}
'''
(W/TEST).write_text(signature,encoding='utf-8',newline='\n')
git(W,'add',*sorted(paths),TEST)
git(W,'-c','core.autocrlf=false','commit','-m','chore: freeze approved TCP replay visibility witness before public seam')
assert not git(W,'status','--porcelain')
record={'recorded_at':now,'status':'PREPARED_PRIVATE_VISIBILITY_WITNESS_NOT_EXECUTED',
        'approval':'artifacts/qg2g-tcp-replay-explicit-approval.json','worktree':str(W),
        'baseline_commit':git(W,'rev-parse','HEAD'),'root_engine_sha256':sha(R/ENGINE),
        'frozen_source_sha256':{path:sha(W/path) for path in sorted(paths)},
        'parent_test_sha256':sha(W/TEST),'engine_path':ENGINE,'test_path':TEST,
        'protected_unchanged_except_after_approval':[ENGINE],
        'actor_writes':[TEST],'accepted':False,'root_integrated':False}
(R/'artifacts/qg2g-tcp-replay-prepared.json').write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':record['status'],'baseline_commit':record['baseline_commit'],
                  'frozen_files':len(paths),'authorization_granted':True,'root_integrated':False},ensure_ascii=False))
