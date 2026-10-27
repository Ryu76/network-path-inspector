"""명시 승인 후 실제 가시성 보정·시험 writer 가동 및 보호 범위를 기록한다."""
import csv
import datetime
import hashlib
import io
import json
import pathlib
import subprocess

R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgtcpreplay'
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
started=load('.harness/runs/qg2tcpreplay-qgtcpreplay/started.json')
contract=load('artifacts/qg2g-tcp-replay-actor-prepared.json')
assert started['model']=='gemini-3.8-flash-high' and started['role']=='qgtcpreplay'
assert load('artifacts/qg2g-tcp-replay-explicit-approval.json')['authorization_granted']
p=subprocess.run(['tasklist.exe','/FI',f"PID eq {started['pid']}",'/FO','CSV','/NH'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=20)
assert p.returncode==0
alive=any(len(row)>1 and row[1]==str(started['pid']) and row[0].lower()=='agy.exe' for row in csv.reader(io.StringIO(p.stdout)))
assert alive, '작성중표현은실제PID생존확인필요'
assert all(sha(W/path)==value for path,value in contract['immutable_source_sha256'].items())
protected=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(sha(R/path)==value for path,value in protected.items())
engine='crates/npi-probes/src/engine.rs'
assert (W/engine).read_bytes()==(R/engine).read_bytes().replace(b'fn apply_tcp_result(',b'pub fn apply_tcp_result(',1)
now=datetime.datetime.now().astimezone()
record={'recorded_at':now.isoformat(),'status':'APPROVED_VISIBILITY_ONLY_APPLIED_FLASH_PURE_REPLAY_WRITER_RUNNING',
        'authorization_granted':True,'approval_artifact':'artifacts/qg2g-tcp-replay-explicit-approval.json',
        'actor':started,'actor_alive':True,'supervisor_session':'proc_c2c2a428a3ce','supervisor_pid':24816,
        'pipeline':'artifacts/qg2g-tcp-replay-pipeline.json','baseline_commit':contract['baseline_commit'],
        'root_original_protected_unchanged':len(protected),'worktree_original_protected_unchanged':len(protected)-1,
        'approved_visibility_change_files':1,'visibility_added_bytes':4,'function_body_unchanged':True,
        'parent_signature_passed':1,'private_before_fix_exit':101,'private_before_fix_diagnostic':'E0603',
        'full_cross_product_replay_executed':False,'actor_writes':contract['actor_writes'],
        'harness_tests_passed':41,'root_integrated':False,'accepted':False,'full_qg2_accepted':False}
out=R/'artifacts/qg2g-tcp-replay-start.json'
assert not out.exists()
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
state=load('artifacts/quick-check-progress.json')
state['recorded_at']=record['recorded_at']
state['next_qg2_review'].update(status=record['status'],authorization_granted=True,
    approval_artifact=record['approval_artifact'],implementation_started=True,writer_started=True,
    worktree=str(W),baseline_commit=contract['baseline_commit'],actor_pid=started['pid'],
    supervisor_session=record['supervisor_session'],pipeline=record['pipeline'],parent_signature_passed=1,
    root_integrated=False,accepted=False,blocker='이전private차단은승인된W공개변경으로해소·전체replay작성/검증/독립QA전',
    next_decision_required=None)
state['remaining_blockers']=['승인된public TCP projector+양제품순수replay 작성중·정적검토/실제시험/독립QA/선택통합전',
                            '전체QG2실VLAN/DROP/ICMP차단·다중NIC/VPN환경미검증',
                            'GUI/QG3/제품명시진단시작경로/배포·OS·성능미완료']
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
section=f'''\n## 명시 승인: TCP projector 공개 4바이트 및 순수 replay 작성 실제 시작 — {now.isoformat()}
- 사용자의재전송된최소변경승인요청에대한실제응답「허용」을별도positive승인artifact에기록했다. 앞선timeout은역사로유지하며무응답을승인으로바꾸지않았다.
- 전용worktree {W} / ai-pro/qgtcpreplay를현재수용source에서만들고93파일을root원본바이트로동결했다. 부모signature회귀는실제E0603 private compile실패(exit101)를확인한뒤,기존apply_tcp_result 앞에pub 4바이트만추가하자1PASS로전환됐다. 이1개는가시성시험이지양제품replay완료증거가아니다.
- 공개보정후engine에서pub 4바이트를제거하면원본전체와byte-for-byte동일함을기계확인했다. 함수본문/상태매핑/측정동작/DTO불변. root61파일은아직원본그대로이고W에서는나머지60불변+승인된engine1개예외다. 기존보호baseline파일을덮어쓰지않으며후속검증에서도60불변+1승인delta를구분해야한다.
- Flash High실제actor PID{started['pid']}생존확인·감독proc_c2c2a428a3ce(PID24816). actor수정허용은crates/network-core/tests/tcp_product_projection_replay.rs 단1파일이고engine는읽기만허용. 하네스새역할범위3시험포함총41PASS. actor종료/감사/소스검토전에는W Cargo/format/시험없음.
- 부모공개보존commit {contract['baseline_commit']}. 두실제projector호출·제품별차이명시·None/0/i32경계/UTF8/전체raw보존을검증하도록작성중이다. 전체replay실행전·root미통합·미수용·기존worker수용유지. 전체QG2실환경/GUI/QG3/배포인증은승인되지않았다.
\n'''
for name in ['PROGRESS.md','RESUME.md']:
    path=R/name
    first,rest=path.read_text(encoding='utf-8').split('\n',1)
    path.write_text(first+'\n'+section+rest,encoding='utf-8',newline='\n')
path=R/'작업내용'/('NPI_'+now.strftime('%Y-%m-%d')+'_001.md')
prior=path.read_text(encoding='utf-8') if path.is_file() else '# NPI 작업 기록 — '+now.strftime('%Y-%m-%d')+'\n'
path.write_text(prior+section,encoding='utf-8',newline='\n')
print(json.dumps({'status':record['status'],'actor_pid':started['pid'],'actor_alive':True,
                  'parent_signature_passed':1,'visibility_only_bytes':4,'root_integrated':False,'accepted':False},ensure_ascii=False))
