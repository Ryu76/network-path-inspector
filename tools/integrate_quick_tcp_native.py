"""최종 독립 검토와 동일 SHA 실행 증거를 확인해 native TCP 비교 시험 한 파일만 통합한다."""
import datetime
import hashlib
import json
import pathlib
import shutil
import subprocess

R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgtcpnative'
TEST='crates/network-core/tests/tcp_product_native_equivalence.rs'
ENGINE='crates/npi-probes/src/engine.rs'
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
run=load('artifacts/qg2h-tcp-native-parent-execution.json')
assert run['status']=='NEW_NATIVE_AND_WORKSPACE_PASS_FINAL_REVIEW_PENDING'
assert run['workspace_counts']=={'passed':434,'failed':0,'ignored':27}
assert run['new_native_counts']=={'passed':4,'failed':0,'ignored':0}
assert all(item['exit_code']==0 and not item['partial'] for item in run['execution'].values())
assert all(sha(W/path)==value for path,value in run['source_sha256'].items())
assert not (R/TEST).exists()
frozen=load('artifacts/qg2h-tcp-native-actor-prepared.json')['immutable_source_sha256']
assert all(sha(W/path)==value and sha(R/path)==value for path,value in frozen.items())
assert load('artifacts/qg2tcpnative-actor-policy-audit.json')['all_actor_policy_checks_passed']
protected=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(sha(R/path)==value for path,value in protected.items() if path!=ENGINE)
old=load('artifacts/qg2g-tcp-replay-acceptance.json')
assert all(sha(R/path)==value for path,value in old['source_sha256'].items())
for args in [['status','--porcelain'],['rev-parse','HEAD']]:
    p=subprocess.run(['git','-C',str(W),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
    assert p.returncode==0,p.stderr
    if args[0]=='status':
        assert not p.stdout.rstrip('\r\n')
    else:
        assert p.stdout.rstrip('\r\n')==run['preserved_source_commit']
transcripts={}
for index in range(2):
    path=pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/delegation/live/deleg_5a10ae9f')/f'task-{index}.log'
    text=path.read_text(encoding='utf-8')
    assert 'end status=completed' in text
    assert any('assistant|' in line and '"findings": []' in line for line in text.splitlines())
    if index==0:
        assert '"safe_to_execute_default_tests": true' in text and '"safe_to_execute_owned_native_tests": true' in text
    transcripts[str(index)]={'path':str(path),'sha256':sha(path),'findings':[]}
now=datetime.datetime.now().astimezone().isoformat()
review={'recorded_at':now,'review':'deleg_5a10ae9f','findings':[],
    'safe_to_execute_default_tests':True,'safe_to_execute_owned_native_tests':True,
    'source_sha256':run['source_sha256'],'transcripts':transcripts,
    'representation':'완전한async전달판정을부모가정규화·human transcript본문잘림가능·marker/SHA별도보존',
    'source_changed_after_review_request':False,
    'resolved':['F1/TCP-NATIVE-001: JSON전체값과동일표현전후byte를분리',
        'F2: 전체입력Target/실측raw target/Some resolvedIP귀속',
        'F3: native와same-raw replay상태/근거/메타/limitations/msg/전체raw독립검증',
        'F4: nullable키누락과명시null구분·raw/Envelope/report전후보존',
        '정확owned단일endpoint·위임전guard·TCP외0·실EOF/peer관측·유한대기/RAII',
        '기존3000ms입력채택은제품성능목표완화/관측정규화아님·1000ms조건성공증거도아님',
        'close-gap제거이상의독점예약/모든race방지보장문구제거'],
    'limits':['정적읽기만·직접시험/해시독립재계산없음·실행은부모증거',
        'QuickNative반환QuickResult→report보존이며connect_once반환직전DTO별도capture아님',
        'metadata는null입력만·OS즉시취소/강제회수실측인증아님',
        '전체QG2/Archive/정규Session/제품진단EXE·GUI/배포/OS/성능수용아님']}
review_out=R/'artifacts/qg2h-tcp-native-final-independent-review.json'
out=R/'artifacts/qg2h-tcp-native-integration.json'
assert not review_out.exists() and not out.exists()
review_out.write_text(json.dumps(review,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
record={'recorded_at':now,'state':'PREPARING','paths':[TEST],'source_sha256':run['source_sha256'],
    'previous_protected_source_sha256':frozen[ENGINE],'production_changes':0,
    'preserved_source_commit':run['preserved_source_commit'],'independent_review':str(review_out.relative_to(R)),
    'root_integrated':False,'accepted':False}
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
shutil.copyfile(W/TEST,R/TEST)
assert sha(R/TEST)==run['source_sha256'][TEST]
assert all(sha(R/path)==value for path,value in frozen.items())
assert all(sha(R/path)==value for path,value in protected.items() if path!=ENGINE)
record.update(state='INTEGRATED_FOR_ROOT_REGRESSION_NOT_ACCEPTED',root_integrated=True,
    protected_original_unchanged=len(protected)-1,existing_approved_visibility_exception_files=1)
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
state=load('artifacts/quick-check-progress.json')
state['recorded_at']=now
state['next_qg2_native_review'].update(status=record['state'],root_integrated=True,accepted=False,
    test_review_received=True,final_review=str(review_out.relative_to(R)),test_findings=[],
    integration_artifact=str(out.relative_to(R)))
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'state':record['state'],'new_test_files_integrated':1,'production_changes':0,
    'protected_original_unchanged':len(protected)-1,'existing_approved_visibility_exception_files':1,'accepted':False},ensure_ascii=False))
