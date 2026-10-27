"""작성 종료와 원본 컴파일의 서로 다른 결과를 기존 진척과 구분해 기록한다."""
import datetime,hashlib,json,pathlib,subprocess
R=pathlib.Path(__file__).resolve().parents[1]
def load(name):return json.loads((R/name).read_text(encoding='utf-8'))
def save(name,data):(R/name).write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
p=load('artifacts/qg3c-qg5a-parallel-prepared.json');a=load('artifacts/qg3c-qg5a-parallel-pipeline.json');c=load('artifacts/qg3c-qg5a-original-compile.json')
assert a['status']=='BOTH_AUDITED_FOR_PARENT_REVIEW_NOT_COMPILED'
assert c['roles']['qgcoordinator']['exit_code']==101 and c['roles']['qgresults']['exit_code']==0
assert not c['tests_executed'] and not c['root_integrated']
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
checkpoint={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'ORIGINALS_PRESERVED_COMPILE_RECORDED_INDEPENDENT_QA_RUNNING',
 'review_batch':'deleg_e4d98270','actor_write_audit_passed':True,'actor_originals_unchanged':True,
 'new_actor_files':sum(len(s['actor_writes']) for s in p['roles'].values()),'compile_only_results':{role:spec['exit_code'] for role,spec in c['roles'].items()},
 'coordinator_compile_error':'E0063: HostSnapshot initializer lacks errors, limitations, selected_route; one unused-import warning',
 'coordinator_test_execution_blocked':'Await independent execution-safety review; parent suspects worker recv/join deadlock on Failed lifecycle. Not a reproduced runtime failure.',
 'result_test_execution':'Not run; original source held fixed for independent review; UTF8 parser and Busy fixture concerns are parent source observations, not yet executed failures.',
 'parent_changes_after_actor_audit':{role:spec['parent_registration'] for role,spec in c['roles'].items()},
 'native_or_network_tests_executed':False,'tests_executed':False,'root_integrated':False,'accepted':False,'full_qg2_accepted':False,'full_qg3_accepted':False,'full_qg5_accepted':False,'product_accepted':False,
 'actor_audit_is_not_os_sandbox_or_functional_verification':True,'prior_specific_ui_approval_timeout_preserved':True}
for role,spec in p['roles'].items():
 W=pathlib.Path(spec['worktree']);assert all(sha(W/n)==h for n,h in a['roles'][role]['source_sha256'].items())
 assert all(sha(W/n)==h for n,h in spec['immutable_sha256'].items() if n!='apps/network-quick-check/src/lib.rs')
 assert all(sha(W/n)==h for n,h in spec['reference_sha256'].items())
 status=subprocess.run(['git','-C',str(W),'status','--porcelain'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
 assert status.returncode==0
 checkpoint.setdefault('worktree_status',{})[role]=status.stdout.rstrip('\r\n')
save('artifacts/qg3c-qg5a-qa-checkpoint.json',checkpoint)
progress=load('artifacts/quick-check-progress.json');progress['recorded_at']=checkpoint['recorded_at'];progress['qg3c_qg5a_parallel']=checkpoint
progress['completion_continuation'].update(status=checkpoint['status'],current_review_batch=checkpoint['review_batch'],current_pipeline='artifacts/qg3c-qg5a-original-compile.json')
save('artifacts/quick-check-progress.json',progress)
directive=load('artifacts/quick-check-completion-directive-20261026.json');directive.update(status=checkpoint['status'],current_review_batch=checkpoint['review_batch'],last_checkpoint=checkpoint['recorded_at'])
for stream in directive['current_workstreams']:
 stream.update(mode='audited_file_only_implementation_independent_review',status='awaiting_original_qa',next='preserve original failure -> review -> narrow repairs -> real tests -> final QA')
for scope in directive['ordered_delivery_scope']:
 if scope['id'] in ['gui-execution-coordinator','result-view-filter','txt-csv-export']:scope['status']='independent_module_original_qa_running_not_gui_connected'
save('artifacts/quick-check-completion-directive-20261026.json',directive)
block=f'''
## QG3C/QG5A 원본 작성·감사 완료, 첫 컴파일 결과 — {checkpoint['recorded_at']}
- supervisor proc_60693d869976 exit0, 두 FlashHigh 역할의 실제FILE도구/절대W경로/정확2파일/기존154입력/참조/afterSHA/완료terminal/partial 감사PASS. 이는구현성공·시험통과가아니다. 권한모드always-proceed이며OS강제격리보장도아니다.
- 신규4개원본은 .harness/evidence/qg3c-qg5a-original-{{qgcoordinator,qgresults}}/에보존하고SHA확인. 부모가감사후각lib에선언만등록했다. coordinator는cfg(test)만소비되며제품호출미연결; result순수모듈2는공개선언이나GUI/파일저장미연결.
- 실제compile-only: qgcoordinator exit101(E0063 HostSnapshot errors/limitations/selected_route누락, unusedimport1), qgresults exit0. 명령은 cargo test --offline --locked --target-dir [role-specific] -p network-quick-check --lib --no-run. 테스트실행0; actor원본4개수정0; Cargo/lock/Core기존입력불변.
- 독립2QA deleg_e4d98270 실행중. 부모는Failed경로의workerrecv/join지속대기·완료큐관측경쟁·동기recv를Pending시험으로표현한점,CSV시험파서UTF8오류·Busy중draft수정fixture를원문우려로기록했다. 아직실행재현결과가아니며QA결과를받아보정한다. coordinator원본은컴파일부터실패이고실행안전판정도전이므로시험강행0.
- 근거 artifacts/qg3c-qg5a-{{parallel-pipeline,original-compile,qa-checkpoint}}.json 및 commands/qg3c-qg5a-original-compile-[role].json/log. 메인통합/전체QG2/QG3/QG5/제품수용0,이전root477·GUIWIP500과구분. 운영망/정책/배포/이전UI입력승인timeout우회0.
'''
for name,header in [('PROGRESS.md','# NPI 진행 기록'),('RESUME.md','# NPI 개발 재개 및 승인 경계')]:
 file=R/name;text=file.read_text(encoding='utf-8');assert text.count(header+'\n')==1
 file.write_text(text.replace(header+'\n',header+'\n'+block,1),encoding='utf-8',newline='\n')
print(json.dumps({'status':checkpoint['status'],'compile_only_exit':checkpoint['compile_only_results'],'test_execution':False,'original_actor_files_preserved':checkpoint['new_actor_files'],'root_integrated':False},ensure_ascii=False))
