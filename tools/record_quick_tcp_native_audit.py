"""writer 종료·감사 및 고정 source 확인을 실제 compile/native 실행과 구분해 보존한다."""
import datetime
import hashlib
import json
import pathlib
import re

R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgtcpnative'
TEST='crates/network-core/tests/tcp_product_native_equivalence.rs'
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
pipeline=load('artifacts/qg2h-tcp-native-pipeline.json')
contract=load('artifacts/qg2h-tcp-native-actor-prepared.json')
audit=load('artifacts/qg2tcpnative-actor-policy-audit.json')
result=load('.harness/runs/qg2tcpnative-qgtcpnative/result.json')
assert pipeline['status']=='AUDITED_SOURCE_READY_FOR_PARENT_REVIEW'
assert audit['all_actor_policy_checks_passed'] and audit['actors'][0]['violations']==[]
assert result['exit_code']==0 and not result['partial'] and result['changed_paths']==[TEST]
assert sha(W/TEST)==pipeline['source_sha256'][TEST]
assert all(sha(W/path)==value and sha(R/path)==value for path,value in contract['immutable_source_sha256'].items())
body=(W/TEST).read_text(encoding='utf-8')
native_count=len(re.findall(r'^\s*#\[tokio::test\]',body,re.M))
pure_count=len(re.findall(r'^\s*#\[test\]',body,re.M))
ignored_count=len(re.findall(r'^\s*#\[ignore\s*=',body,re.M))
assert native_count==ignored_count==4 and pure_count==1
now=datetime.datetime.now().astimezone()
record={'recorded_at':now.isoformat(),'status':'AUDITED_NATIVE_TEST_SOURCE_STATIC_QA_PENDING',
        'source_sha256':pipeline['source_sha256'],'worktree':str(W),'actor_finished':True,
        'actor_exit_code':result['exit_code'],'actor_partial':False,'actor_tool_invocations':audit['actors'][0]['tool_invocation_count'],
        'actor_tool_names':audit['actors'][0]['tool_names'],'actor_policy_findings':[],
        'immutable_source_files':len(contract['immutable_source_sha256']),
        'native_tests_registered_by_static_inspection':native_count,'native_tests_ignored_by_static_inspection':ignored_count,
        'pure_tests_registered_by_static_inspection':pure_count,'test_counts_are_not_execution_evidence':True,
        'static_review':'deleg_f90b8199','static_review_received':False,
        'parent_review_questions':['struct 직렬화 bytes와Value 직렬화 bytes의키순서차이를원시값변경으로오판하는지확인',
                                  'replay상태/근거·target/timeout·전체raw/Envelope전후불변단언의계약충족확인'],
        'compiled':False,'native_executed':False,'root_integrated':False,'accepted':False,
        'inherited_permission_mode':audit['actors'][0]['inherited_permission_mode'],
        'is_os_sandbox_guaranteed':False}
out=R/'artifacts/qg2h-tcp-native-source-review-start.json'
assert not out.exists()
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
state=load('artifacts/quick-check-progress.json')
state['recorded_at']=record['recorded_at']
state['next_qg2_native_review'].update(record,actor_alive_verified=False,
    actor_started=True,source_review_artifact=str(out.relative_to(R)))
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
section=f'''\n## 실제 TCP 양제품 비교 source 감사 완료·정적 QA 대기 — {record['recorded_at']}
- FlashHigh actor15984 종료exit0/partialfalse·허용새test1파일만변경. 실제도구read_file/write_file {record['actor_tool_invocations']}회·정책지적0·엄격worktree내경로검사22회·source94개W/root고정확인. inherited permission_mode=always-proceed는관측사실이며OS강제격리보장을의미하지않는다.
- 고정시험SHA {pipeline['source_sha256'][TEST]}. 정적으로4native(tokio+ignore)와1pure guard시험등록을확인했지만발견/실행/통과증거와구분한다. API run_profile/run_quick·same actual raw replay·listener두단계유지/EOF·boundnonlisten예약·wrapper직전guard source를부모가읽었고독립정적QA deleg_f90b8199 두검토를시작했다.
- 부모초기확인질문은struct/Value직렬화키순서의바이트단순비교와추가보존단언충분성이다. 아직QA확정지적이나시험실패판정으로기록하지않는다. QA중source변경/format/compile/native0·새root통합/수용0. 기존root433/native23/CLI38은이전범위로유지·전체QG2/GUI/배포미완료.
\n'''
for name in ['PROGRESS.md','RESUME.md']:
    path=R/name
    first,rest=path.read_text(encoding='utf-8').split('\n',1)
    path.write_text(first+'\n'+section+rest,encoding='utf-8',newline='\n')
path=R/'작업내용'/('NPI_'+now.strftime('%Y-%m-%d')+'_001.md')
path.write_text(path.read_text(encoding='utf-8')+section,encoding='utf-8',newline='\n')
print(json.dumps({'status':record['status'],'actor_tool_invocations':record['actor_tool_invocations'],
    'source_files_changed':len(result['changed_paths']),'native_registered':native_count,'pure_registered':pure_count,
    'compiled':False,'native_executed':False,'root_integrated':False},ensure_ascii=False))
