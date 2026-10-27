"""명시 승인된 pub 4바이트와 최종 정적 QA 완료 replay 시험만 root에 선택 통합한다."""
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
run=load('artifacts/qg2g-tcp-replay-parent-execution.json')
contract=load('artifacts/qg2g-tcp-replay-actor-prepared.json')
approval=load('artifacts/qg2g-tcp-replay-explicit-approval.json')
assert approval['authorization_granted'] and approval['user_response_verbatim']=='허용'
assert approval['production_path']==ENGINE and approval['test_path']==TEST
assert run['status']=='PURE_REPLAY_AND_WORKSPACE_PASS_FINAL_TEST_REVIEW_PENDING'
assert run['workspace_counts']=={'passed':433,'failed':0,'ignored':23} and run['new_replay_tests_passed']==6
assert load('artifacts/qg2tcpreplay-actor-policy-audit.json')['all_actor_policy_checks_passed']
assert all(run['execution'][key]['exit_code']==0 and not run['execution'][key]['partial'] for key in ['workspace','clippy','fmt','whitespace'])
assert all(sha(W/path)==value for path,value in run['source_sha256'].items())
assert all(sha(W/path)==value for path,value in contract['immutable_source_sha256'].items())
assert not (R/TEST).exists()
assert (W/ENGINE).read_bytes()==(R/ENGINE).read_bytes().replace(b'fn apply_tcp_result(',b'pub fn apply_tcp_result(',1)
assert sha(R/ENGINE)==contract['parent_engine_change']['root_original_sha256']
protected=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(sha(R/path)==value for path,value in protected.items())
assert all(sha(R/path)==value for path,value in contract['immutable_source_sha256'].items() if path!=ENGINE)
status=subprocess.run(['git','-C',str(W),'status','--porcelain'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
head=subprocess.run(['git','-C',str(W),'rev-parse','HEAD'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
assert status.returncode==head.returncode==0 and not status.stdout.rstrip('\r\n')
assert head.stdout.rstrip('\r\n')==run['preserved_source_commit']
# 요청 시점과 현재 파일은 실행 코드/단언 동일, doc 문단 빈 줄만 다르다.
raw=(W/TEST).read_bytes()
reconstructed=raw.replace('///\n/// 조합은 합성 DTO 보존 시험'.encode(),'/// 조합은 합성 DTO 보존 시험'.encode(),1)
assert hashlib.sha256(reconstructed).hexdigest()==run['test_review_requested_sha256']
transcripts={}
for index in range(2):
    path=pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/delegation/live/deleg_fa9790f8')/f'task-{index}.log'
    text=path.read_text(encoding='utf-8')
    assert 'delegation: deleg_fa9790f8' in text and 'end status=completed' in text
    assert any('assistant|' in line and '"findings": []' in line for line in text.splitlines())
    if index==1:
        assert '"safe_to_execute_default_tests": true' in text
    transcripts[f'task-{index}']={'path':str(path),'sha256':sha(path),'findings':[],
                                 'source':'완전한Hermes async응답확인·live본문잘림가능·완료marker/SHA별도보존'}
now=datetime.datetime.now().astimezone().isoformat()
review={'recorded_at':now,'review':'deleg_fa9790f8','findings':[],'safe_to_execute_default_tests':True,
        'transcripts':transcripts,'source_sha256':run['source_sha256'],
        'review_requested_test_sha256':run['test_review_requested_sha256'],
        'post_request_delta':'doc문단빈줄1개뿐·역변환SHA일치·실행코드/단언변경0',
        'normalized_resolution':['동일measurement로실제두함수호출·독립literal상태/근거기대값·상태차이무보정',
            'Inspector최종DTO수작업대체없음·프로젝터복제없음·기존본문불변부모증거와분리',
            'raw전체·코드None/0/MIN/MAX·stale초기화·nullablemetadata·동일중복순서검증',
            '새시험의검토된호출경로runtime/socket/DNS/process/OS/fileI/O0'],
        'limitations':['정적읽기만·시험/해시독립재계산없음','합성DTOcharacterization·실OS/TCP/packet/Archive/Session수용증거아님',
                      'nullable메타데이터의혼합Some/None4조합전체는아님·Inspector추가한계문구전체동등성아님']}
review_out=R/'artifacts/qg2g-tcp-replay-final-independent-review.json'
out=R/'artifacts/qg2g-tcp-replay-integration.json'
backup=R/'.harness/baselines/qg2g-tcp-replay-root'
assert not review_out.exists() and not out.exists() and not backup.exists()
backup.mkdir(parents=True)
shutil.copyfile(R/ENGINE,backup/'engine.rs')
assert sha(backup/'engine.rs')==protected[ENGINE]
meta=['Cargo.toml','Cargo.lock','contracts/quick-check-interface-v0.1.json']
record={'recorded_at':now,'state':'PREPARING','paths':[ENGINE,TEST],
        'approval':'artifacts/qg2g-tcp-replay-explicit-approval.json','accepted':False,'root_integrated':False,
        'before_engine_sha256':sha(R/ENGINE),'unchanged_metadata_sha256':{path:sha(R/path) for path in meta},
        'independent_review':str(review_out.relative_to(R)),'source_evidence':'artifacts/qg2g-tcp-replay-parent-execution.json'}
review_out.write_text(json.dumps(review,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
for path in [ENGINE,TEST]:
    shutil.copyfile(W/path,R/path)
assert all(sha(R/path)==value for path,value in run['source_sha256'].items())
assert (R/ENGINE).read_bytes().replace(b'pub fn apply_tcp_result(',b'fn apply_tcp_result(',1)==(backup/'engine.rs').read_bytes()
assert all(sha(R/path)==value for path,value in protected.items() if path!=ENGINE)
assert all(sha(R/path)==value for path,value in contract['immutable_source_sha256'].items())
assert all(sha(R/path)==value for path,value in record['unchanged_metadata_sha256'].items())
record.update(state='INTEGRATED_FOR_ROOT_REGRESSION_NOT_ACCEPTED',root_integrated=True,
              source_sha256=run['source_sha256'],protected_original_unchanged=len(protected)-1,
              approved_visibility_change_files=1,approved_added_bytes=4,function_body_unchanged=True,
              preserved_source_commit=run['preserved_source_commit'])
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
state=load('artifacts/quick-check-progress.json')
state['recorded_at']=now
state['next_qg2_review'].update(status=record['state'],root_integrated=True,accepted=False,
    test_review_received=True,final_review=str(review_out.relative_to(R)),test_findings=[],
    integration_artifact=str(out.relative_to(R)))
state['remaining_blockers']=['TCP공개변경+순수replay root조합회귀/native/CLI/경계/Clippy/fmt·제한수용기록전',
                            '전체QG2실환경/GUI/QG3/제품진단시작경로/배포·OS·성능미완료']
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'state':record['state'],'files_integrated':2,'protected_original_unchanged':len(protected)-1,
                  'approved_visibility_changes':1,'added_bytes':4,'function_body_unchanged':True,'accepted':False},ensure_ascii=False))
