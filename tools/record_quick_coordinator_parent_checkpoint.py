"""QG3C 부모 보정의 컴파일 성공과 실행 전 안전 QA 대기를 명확히 기록한다."""
import datetime,hashlib,json,pathlib,subprocess
R=pathlib.Path(__file__).resolve().parents[1];sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
def load(n):return json.loads((R/n).read_text(encoding='utf-8'))
def save(n,d):(R/n).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
p=load('artifacts/qg3c-parent-rewrite-prepared.json');W=pathlib.Path(p['worktree']);accepted=load('artifacts/qg5a-pure-result-acceptance.json')
assert all(sha(W/n)==h for n,h in p['source_sha256'].items())
assert all(sha(R/n)==h for n,h in accepted['source_sha256'].items())
clippy=load('artifacts/commands/qg3c-parent-clippy-v1.json');assert clippy['exit_code']==0 and not clippy['partial']
assert p['compile_command']['exit_code']==0 and not p['tests_executed']
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'PARENT_COORDINATOR_COMPILE_CLIPPY_PASSED_EXECUTION_SAFETY_QA_RUNNING',
 'original_corrective_review_received':'deleg_bede6d65','original_findings':list(p['parent_review']['finding_mapping']),
 'parent_implementation_credit':'Parent production and fixture rewrite after two rejected Flash drafts; not Flash-exclusive implementation',
 'compile_exit':0,'strict_clippy_exit':0,'test_functions_written_not_executed':p['source_test_functions'],
 'source_sha256':p['source_sha256'],'current_safety_review_batch':'deleg_eed4ff20','current_review_count':2,
 'expected_scope':'owned worker, CPU-only runtime, actual Core runner and memory mock; no Win32/native socket/process/backend factory',
 'root_integrated':False,'tests_executed':False,'accepted':False,'full_qg3_accepted':False,'product_accepted':False,
 'latest_main_root_counts':accepted['receiving_root_workspace_counts'],'latest_main_scope':accepted['scope'],
 'main_qg5a_only_integration_preserved':True,'specific_ui_consent_timeout_respected':True,'active_flash_writers':0}
save('artifacts/qg3c-parent-rewrite-checkpoint.json',record)
save('artifacts/qg3c-parent-write-preflight-failures.json',{'recorded_at':record['recorded_at'],'category':'parent file-write bookkeeping, not product failure',
 'refused_writes':[{'target':'apps/network-quick-check/src/gui_coordinator.rs','stale_write_blocked':True,'file_modified':False},
 {'target':'apps/network-quick-check/src/gui_coordinator.rs','stale_write_blocked':True,'file_modified':False}],
 'resolution':'Read full original, verify frozen hashes, retain new parent source in owned .harness/qa files, apply an exact full-source patch to the two explicitly authorized files; original actor evidence unchanged'})
progress=load('artifacts/quick-check-progress.json');progress.update(recorded_at=record['recorded_at'],qg3c_parent_rewrite=record)
progress['completion_continuation'].update(status=record['status'],current_review_batch='deleg_eed4ff20')
save('artifacts/quick-check-progress.json',progress)
directive=load('artifacts/quick-check-completion-directive-20261026.json');directive.update(last_checkpoint=record['recorded_at'],status=record['status'],current_review_batch='deleg_eed4ff20')
for s in directive['current_workstreams']:
 if s['id']=='execution-coordinator':s.update(mode='parent_repair_after_independent_rejections',status='compile_clippy_passed_execution_safety_qa_running',next='receive safety review -> bounded real memory-mock test execution -> fix actual failures -> final QA')
save('artifacts/quick-check-completion-directive-20261026.json',directive)
summary=f'''
## QG3C 부모 생산·시험 보정 컴파일 통과, 실행 전 안전QA — {record['recorded_at']}
- deleg_bede6d65수신: 수정Flash원본도QA01~12미충족·실test실행불허. 원본compile101/소스2보존후부모가coordinator수명주기·시험fixture를직접보정했다. Flash단독작성으로표현하지않는다.
- 생산보정: worker최외곽catch_unwind안에backend/config소멸포함·정상/패닉Atomic종료분류,완료채널Open/Drained/Lost분리,Failed에서도채널배출·실thread종료계속관측,receiverLost는절대Closed성공으로위장0,동일Empty→enqueue→finished정상봉투재독,전부snapshotguard/원문Result보존. 다른state로받은완료는최대1개unapplied로snapshot과함께보존하며타state강제적용0.
- 시험보정: worker시작전releaseguard설치,실제Pending분기·같은Arc·cleanup보류·후속호출0,실after-send확인뒤cancelrace,정확Emptyhook일정,실worker/backendDrop패닉/runtime/spawn실패,matchingrichResult/Finished시작실패전체불변/stale후속격리·채널유실·assertionunwind·Drop외부handle종료관측을작성했다. **시험함수23개는아직실행0**이며PASS23으로주장하지않는다.
- actual cargo test --lib --no-run **exit0**, cargo clippy --workspace --all-targets -- -D warnings **exit0**. 소스2동결·기존154입력/고정참조불변. 독립2안전QA **deleg_eed4ff20** 실제진행중·그결과전시험실행0·메인통합0·수용0. stdthread/runtime/시험timeout시계효과는의도적이며순수IO/clock0라고하지않는다.
- 메인은앞서제한수용한QG5A순수결과모듈까지 **492PASS0FAIL31ignored** 그대로다. source3확인·미수용GUI/host메인연결0,운영망/OS정책/배포/이전UI입력승인timeout우회0.
- 근거 artifacts/qg3c-parent-rewrite-{{prepared,checkpoint}}.json 및 commands/qg3c-parent-{{compile,clippy}}-v1.json/log. 다음은안전QA회수후부모상위timeout의실제mock회귀실행이다.
'''
for name,header in [('PROGRESS.md','# NPI 진행 기록'),('RESUME.md','# NPI 개발 재개 및 승인 경계')]:
 file=R/name;text=file.read_text(encoding='utf-8');assert text.count(header+'\n')==1
 file.write_text(text.replace(header+'\n',header+'\n'+summary,1),encoding='utf-8',newline='\n')
print(json.dumps({'status':record['status'],'compile_exit':0,'clippy_exit':0,'test_functions_written':p['source_test_functions'],'tests_executed':False,'review_batch':'deleg_eed4ff20','main_root_counts':record['latest_main_root_counts']},ensure_ascii=False))
