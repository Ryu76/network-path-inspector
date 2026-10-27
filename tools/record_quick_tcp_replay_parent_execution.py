"""가시성 독립 QA와 실제 replay/전체 순수 회귀를 보존하고 최종 시험 QA를 기다린다."""
import datetime
import hashlib
import json
import pathlib
import re
import subprocess

R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgtcpreplay'
ENGINE='crates/npi-probes/src/engine.rs'
TEST='crates/network-core/tests/tcp_product_projection_replay.rs'
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()

def git(*args):
    p=subprocess.run(['git','-C',str(W),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=40)
    assert p.returncode==0,p.stderr
    return p.stdout.rstrip('\r\n')

contract=load('artifacts/qg2g-tcp-replay-actor-prepared.json')
assert load('artifacts/qg2g-tcp-replay-pipeline.json')['status']=='AUDITED_SOURCE_READY_FOR_PARENT_REVIEW'
assert all(sha(W/path)==value for path,value in contract['immutable_source_sha256'].items())
assert (W/ENGINE).read_bytes()==(R/ENGINE).read_bytes().replace(b'fn apply_tcp_result(',b'pub fn apply_tcp_result(',1)
protected=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(sha(R/path)==value for path,value in protected.items())
assert all(sha(W/path)==value for path,value in protected.items() if path!=ENGINE)
raw=(W/TEST).read_bytes()
# QA 요청 뒤 바뀐 것은 Clippy가 요구한 doc 문단 구분 한 줄뿐이다.
needle='///\n/// 조합은 합성 DTO 보존 시험'.encode()
replacement='/// 조합은 합성 DTO 보존 시험'.encode()
assert raw.count(needle)==1
reviewed=raw.replace(needle,replacement,1)
assert hashlib.sha256(reviewed).hexdigest()=='8ea534878f39f7740e2e311f3c08032d819c0e3b43db8326df6058c86ecc195f'
items={}
for label,name,code in [
    ('first_replay_failure','qg2g-tcp-replay-first-default',101),
    ('first_clippy_failure','qg2g-tcp-replay-workspace-clippy',101),
    ('workspace','qg2g-tcp-replay-final-workspace-pure',0),
    ('clippy','qg2g-tcp-replay-final-workspace-clippy',0),
    ('fmt','qg2g-tcp-replay-final-fmt',0),
    ('whitespace','qg2g-tcp-replay-final-whitespace',0),
]:
    item=load('artifacts/commands/'+name+'.json')
    assert item['exit_code']==code and not item['partial']
    items[label]=item
text=pathlib.Path(items['workspace']['log']).read_text(encoding='utf-8')
rows=re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;',text)
assert rows
counts={key:sum(int(row[i]) for row in rows) for i,key in enumerate(['passed','failed','ignored'])}
new_tests=re.findall(r'#\[test\]\s*fn\s+(\w+)',raw.decode('utf-8'))
assert len(new_tests)==6
assert all(('test '+name+' ... ok') in text for name in new_tests)
old_count=load('artifacts/qg2f-app-entry-parent-execution.json')['workspace_default_counts']['passed']
assert counts=={'passed':old_count+len(new_tests),'failed':0,'ignored':23}
first=pathlib.Path(items['first_replay_failure']['log']).read_text(encoding='utf-8')
assert '5 passed; 1 failed;' in first
visibility_path=pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/delegation/live/deleg_6b0609ec/task-0.log')
visibility_text=visibility_path.read_text(encoding='utf-8')
assert 'end status=completed' in visibility_text and '"findings": []' in visibility_text
now=datetime.datetime.now().astimezone()
visibility={'recorded_at':now.isoformat(),'review':'deleg_6b0609ec','findings':[],
            'representation':'완전한async최종응답의부모정규화판정·live본문은잘릴수있음',
            'transcript':{'path':str(visibility_path),'sha256':sha(visibility_path)},
            'source_sha256':{ENGINE:sha(W/ENGINE)},
            'scope':'기존apply_tcp_result fn→pub fn만·본문/호출부/상태/오류/측정/부수효과불변·명시승인부합',
            'limitations':['정적읽기만·시험/해시독립재계산없음','작성중test미열람·replay구현완료판정아님',
                          '원래profile/target/featureID검증없음·evidence_ids비움·영구증거/정규Session수용아님']}
visibility_out=R/'artifacts/qg2g-tcp-replay-visibility-review.json'
assert not visibility_out.exists()
visibility_out.write_text(json.dumps(visibility,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
assert {line[3:] for line in git('status','--porcelain','--untracked-files=all').splitlines()}=={TEST}
git('add',TEST)
git('-c','core.autocrlf=false','commit','-m','test: preserve cross-product TCP replay validation pending final review')
assert not git('status','--porcelain')
record={'recorded_at':now.isoformat(),'status':'PURE_REPLAY_AND_WORKSPACE_PASS_FINAL_TEST_REVIEW_PENDING',
        'source_sha256':{ENGINE:sha(W/ENGINE),TEST:sha(W/TEST)},'preserved_source_commit':git('rev-parse','HEAD'),
        'worktree':str(W),'worktree_clean':True,'execution':items,'workspace_counts':counts,
        'new_replay_tests_passed':len(new_tests),'new_replay_test_names':new_tests,
        'visibility_review':str(visibility_out.relative_to(R)),'visibility_findings':[],
        'test_review':'deleg_fa9790f8','test_review_received':False,
        'test_review_requested_sha256':hashlib.sha256(reviewed).hexdigest(),
        'comment_only_delta_after_review_request':True,'comment_only_delta_proven_by_reverse_sha':True,
        'approved_production_added_bytes':4,'function_body_unchanged':True,
        'root_original_protected_unchanged':len(protected),'worktree_original_protected_unchanged':len(protected)-1,
        'parent_adjustments':['고정warning기대마침표를source원문과정확일치로정정','unusedIpAddr제거',
                              '진짜중복limitation·nullablemetadata·모든matrix raw/OScode/duration/stale/원본불변성단언추가',
                              'doc문단공백1줄추가·Clippy첫101과actor5PASS1FAIL원본보존'],
        'accepted':False,'root_integrated':False,'full_qg2_accepted':False,'product_accepted':False,
        'limitations':['새6시험은합성DTO순수replay·실OS/TCP/DNS/packet/archive/Session증거아님',
                       '제품별상태차이characterization유지·완전동등으로정규화하지않음','새native실행0·이전rootnative23기록과분리']}
out=R/'artifacts/qg2g-tcp-replay-parent-execution.json'
assert not out.exists()
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
state=load('artifacts/quick-check-progress.json')
state['recorded_at']=record['recorded_at']
state['next_qg2_review'].update(status=record['status'],actor_alive=False,visibility_review_received=True,
    visibility_review=record['visibility_review'],visibility_findings=[],test_review='deleg_fa9790f8',
    test_review_received=False,parent_execution=str(out.relative_to(R)),workspace_counts=counts,
    new_replay_tests_passed=len(new_tests),source_sha256=record['source_sha256'],
    preserved_source_commit=record['preserved_source_commit'],root_integrated=False,accepted=False)
state['remaining_blockers']=['TCP양제품replay 최종시험정적QA2건수신·대조/선택통합/root회귀전',
                            '전체QG2실환경·GUI/QG3·제품진단시작경로·배포/OS/성능미완료']
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
section=f'''\n## 실제 양제품 TCP replay6개·workspace{counts['passed']}PASS / 최종 시험 QA 대기 — {record['recorded_at']}
- 공개가시성 독립QA deleg_6b0609ec findings=[]·함수본문/호출부/상태·오류·측정·부수효과불변/승인범위확인. 본검토는test파일미열람·실행안함이며실제byte검증·컴파일은부모별도증거다. 원래profile/target/featureID검증이없는투영함수이고영구증거/G1Session수용API가아님을유지한다.
- Flash actor종료exit0·27 FILE READ/WRITE·허용test1파일만변경·위반0. 부모SHA확인과전체test안전검토후최초실행은6중5PASS1FAIL(warning문구기대의끝마침표가실제source와차이). 부모는test만정확문구로정정·unusedimport제거·진짜동일중복fixture/nullablemetadata/모든matrix전체raw·OScode·duration·stalereset·메시지/전후불변성단언을보강했다. production추가변경0.
- 최종workspace {counts['passed']}PASS/0FAIL/{counts['ignored']}ignored·새replay6PASS포함. strictClippy/fmt/whitespace exit0. 부모추가doc문단공백lint의첫101로그도보존했고공백1줄정리후전체시험과Clippy를재실행했다. code/assertion동결후최종QA deleg_fa9790f8 두검토요청·결과수신전. 요청뒤doc빈줄1개차이는역변환SHA로증명한다.
- Inspector원본보호root61SHA불변·W60불변+사용자승인pub4바이트1파일만·함수본문완전동일. 전용worktree clean/보존commit {record['preserved_source_commit']}. root미통합·미수용·새native실행0·기존worker수용root427/native23/CLI38은이전범위로유지.
- 새시험은같은원시DTO를양쪽실제함수에전달하는순수특성규명이며제품별CANCELLED/LOCAL_ERROR/DNS_ERROR/unknown차이를숨기지않는다. 실제소켓/OS오류발생/패킷/EngineEnvelope저장/Session수용/실VLAN·전체QG2/GUI·배포인증증거로승격하지않음.
\n'''
for name in ['PROGRESS.md','RESUME.md']:
    path=R/name
    first,rest=path.read_text(encoding='utf-8').split('\n',1)
    path.write_text(first+'\n'+section+rest,encoding='utf-8',newline='\n')
path=R/'작업내용'/('NPI_'+now.strftime('%Y-%m-%d')+'_001.md')
path.write_text(path.read_text(encoding='utf-8')+section,encoding='utf-8',newline='\n')
print(json.dumps({'status':record['status'],'workspace':counts,'new_replay_passed':len(new_tests),
                  'preserved_commit':record['preserved_source_commit'],'root_integrated':False,'accepted':False},ensure_ascii=False))
