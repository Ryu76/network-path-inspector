"""종료한 Flash actor 원본을 보존하고 실행 전 소스·범위 증거만 기록한다."""
import datetime
import hashlib
import json
import pathlib
import shutil

R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgdevtcp'
load=lambda p:json.loads((R/p).read_text(encoding='utf-8'))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
p=load('artifacts/qg2i-explicit-tcp-pipeline.json')
c=load('artifacts/qg2i-explicit-tcp-actor-prepared.json')
a=load('artifacts/qg2explicit-actor-policy-audit.json')
result=load('.harness/runs/qg2explicit-qgdevtcp/result.json')
after=load('.harness/runs/qg2explicit-qgdevtcp/after.json')
assert p['status']=='AUDITED_SOURCE_READY_FOR_PARENT_REVIEW'
assert result['exit_code']==0 and not result['partial'] and not result['scope_violations']
assert result['changed_paths']==sorted(c['actor_writes'])
assert a['all_actor_policy_checks_passed'] and a['actors'][0]['cli_status']=='SUCCESS'
assert a['actors'][0]['violations']==[] and a['actors'][0]['tool_invocation_count']==34
assert all(sha(W/path)==value==after[path] for path,value in p['source_sha256'].items())
assert all(sha(W/path)==value for path,value in c['immutable_source_sha256'].items())
assert all(sha(R/path)==value for path,value in c['root_before_sha256'].items())
# 실제 수정은 private module 선언·entry 분기·entry 문서뿐인지 원문으로 비교한다.
lib='apps/network-quick-check/src/lib.rs'
old=(R/lib).read_text(encoding='utf-8')
new=(W/lib).read_text(encoding='utf-8')
marker='/// Network Quick Check 진입점을 실행하고 종료 코드를 반환합니다.'
assert new.split(marker,1)[0].replace('mod diagnostic_cli;\n\n','',1)==old.split(marker,1)[0]
branch='    if let Some(code) = diagnostic_cli::try_entry(args, stdout, stderr) {\n        return code;\n    }\n'
assert new.split('pub fn entry(',1)[1].replace(branch,'',1)==old.split('pub fn entry(',1)[1]
archive=R/'.harness/evidence/qg2i-explicit-tcp-actor-original'
assert not archive.exists()
archive.mkdir(parents=True)
files={}
for path in c['actor_writes']:
    src=W/path
    data=src.read_bytes()
    text=data.decode('utf-8')
    assert text.endswith('\n') and not any(line.rstrip(' \t')!=line for line in text.splitlines())
    target=archive/src.name
    shutil.copyfile(src,target)
    assert sha(target)==p['source_sha256'][path]
    files[path]={'sha256':sha(src),'bytes':len(data),'lines':len(text.splitlines()),'archive':str(target)}
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'state':'SOURCE_AUDITED_REVIEW_RECEIVED_REPAIR_REQUIRED',
    'actor_result':result,'actor_policy':a,'source_files':files,'legacy_worker_parser_factory_and_tests_unchanged':True,
    'root_inputs_unchanged':len(c['root_before_sha256']),'writer_immutable_inputs_unchanged':len(c['immutable_source_sha256']),
    'independent_review':'deleg_1a31806f','independent_review_received':True,
    'review_representation':'완전한 async 결과를 부모가 정규화·원본 trace와 구분',
    'safe_to_execute_default_tests':True,'safe_to_execute_owned_native_tests':False,
    'normalized_review_findings':[
        {'id':'F1','kind':'moved AtomicUsize counter','severity':'P1','requires_compile_reproduction':True},
        {'id':'F2/INVALID-OUTPUT-FAILURE','kind':'invalid stderr failure must exit1','severity':'P2'},
        {'id':'F3','kind':'unbounded to_vec before wire limit','severity':'P2'},
        {'id':'F4/CANCEL-DRAIN-WITNESS-GAP','kind':'cancelArc identity/Pending/whole raw witness gap','severity':'P2'},
        {'id':'F5','kind':'trace counter never incremented','severity':'P2'},
        {'id':'F6/NATIVE-CHILD-OWNERSHIP','kind':'Child guard ownership gap','severity':'high'},
        {'id':'NATIVE-READER-CLEANUP','kind':'error/timeout skip readers cleanup','severity':'high'}],
    'parent_provisional_observations':[
        {'id':'P-BOUND','path':'apps/network-quick-check/src/diagnostic_cli.rs','line':195,
            'evidence':'emit_report는to_vec전체할당후길이를검사하므로상한있는Write로먼저제한하지않는다',
            'resolution':'독립검토뒤bounded memory writer와경계회귀보강필요'},
        {'id':'P-STDERR','path':'apps/network-quick-check/src/diagnostic_cli.rs','line':311,
            'evidence':'invalid분기에서write_static_stderr결과를버리고항상exit2·출력실패exit1계약과불일치'},
        {'id':'P-SEAM','path':'apps/network-quick-check/src/diagnostic_cli.rs','line':364,
            'evidence':'cfg(test) mock dispatcher가생산try_entry제어흐름을복제·생산신호대기경로와cancelArc/drain은시험안됨'},
        {'id':'P-CHILD','path':'apps/network-quick-check/tests/explicit_tcp_entry.rs','line':78,
            'evidence':'child소유를guard에서take한뒤try_wait error가kill/wait없이return·timeout도readerjoin없음',
            'parent_native_execution_held':True}],
    'rejected_provisional_observation':'raw_input host:port조립은실제parse_target_pair와동일·bareIPv6표현만으로별도결함단정안함',
    'parent_test_execution':False,'native_executed':False,'accepted':False,'root_integrated':False,
    'limitations':['FILEaudit는OS강제격리아님·inherited permission_mode always-proceed관찰',
        '동작/컴파일/실측/취소/메모리상한수용증거아님','전체QG2/GUI/배포미수용']}
out=R/'artifacts/qg2i-explicit-tcp-source-audit.json'
assert not out.exists()
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
s=load('artifacts/quick-check-progress.json')
s['recorded_at']=record['recorded_at']
s['next_qg2_explicit_tcp_entry'].update(status='REVIEW_RECEIVED_REPAIR_REQUIRED',actor_completed=True,independent_review='deleg_1a31806f',
    independent_review_received=True,source_audit=str(out.relative_to(R)),parent_native_execution_held=True)
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(s,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'state':record['state'],'files':files,'actor_tools':34,'root_inputs_unchanged':record['root_inputs_unchanged'],
    'parent_native_execution_held':True,'accepted':False},ensure_ascii=False))
