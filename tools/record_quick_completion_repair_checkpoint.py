"""독립 원본 QA 수신·실패재현·수정 writer·결과모듈 실회귀를 하나의 체크포인트로 기록한다."""
import datetime,hashlib,json,pathlib,subprocess
R=pathlib.Path(__file__).resolve().parents[1];sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def load(n):return json.loads((R/n).read_text(encoding='utf-8'))
def save(n,d):(R/n).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
p=load('artifacts/qg3c-coordinator-repair-prepared.json');export=load('artifacts/qg5a-parent-repair.json')
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
W=pathlib.Path(export['worktree']);assert all(sha(W/n)==h for n,h in export['source_sha256'].items())
assert export['default_workspace_totals']=={'passed':514,'failed':0,'ignored':35}
started=load('.harness/runs/qg3cfix-qgcoordfix/started.json')
assert started['model']=='gemini-3.8-flash-high' and pathlib.Path(started['worktree']).resolve()==pathlib.Path(p['worktree']).resolve()
observed=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',
 'Get-CimInstance Win32_Process -Filter "ProcessId = '+str(started['pid'])+'" | Select-Object ProcessId,Name | ConvertTo-Json -Compress'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
assert observed.returncode==0
process=json.loads(observed.stdout or 'null')
traces={}
for i in range(2):
 trace=pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/delegation/live/deleg_e4d98270')/f'task-{i}.log'
 assert 'end status=completed exit_reason=completed' in trace.read_text(encoding='utf-8')[-500:];traces[str(trace)]=sha(trace)
coordinator={'original_review_findings':['F01 compile HostSnapshot','F02 Core list fixture grammar','F03 Failed shutdown drain blocked','F04 Empty/finished completion-loss race',
 'F05 lost error snapshot','F06 no actual Pending cancel/drain','F07 pre-cancel race','F08 missing whole-state/result and real failure tests','F09 visibility','F10 raw runtime OS error reflection'],
 'original_test_execution_safe':False,'original_compile_exit':101,'original_tests_executed':False,
 'original_wip_commit':p['preserved_original_wip_commit'],'original_wip_not_acceptance':True,
 'repair_worktree':p['worktree'],'repair_branch':p['branch'],'model':started['model'],'actor_pid':started['pid'],
 'alive_at_checkpoint':bool(process),'observed_process':process,'supervisor_session':'proc_6c5be5f0df50','supervisor_pid':45084,
 'actor_scope':p['actor_writes'],'repair_compiled':False,'repair_tests_executed':False,'accepted':False}
# body同등 비교에서rustfmt차이로막힌부모증거절차실패도제품실패와별도보존한다.
compare={'status':'PARENT_RAW_BYTE_GUARD_FAILED_THEN_FORMATTED_COPY_EQUIVALENCE_PROVED',
 'initial_command':'python tools/record_quick_results_repair.py','initial_exit':1,'error':'AssertionError at unformatted actor production vs cargo-fmt source comparison',
 'product_test_failure':False,'original_reference_modified':False,
 'formatted_copy':str(R/'.harness/qa/qg5a-original-rustfmt/result_export.rs'),
 'verification':'rustfmt --edition 2024 on an owned independent original copy; pre-cfg(test) normalized full source bytes equal',
 'initial_raw_equality_claim':False,'normalized_equality':True}
save('artifacts/qg5a-parent-format-comparison-evidence.json',compare)
checkpoint={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'QG5A_REGRESSION_PASSED_FINAL_QA_RUNNING_QG3C_CORRECTIVE_WRITER',
 'original_independent_review_batch':'deleg_e4d98270','original_trace_sha256':traces,'review_summaries_are_parent_normalized':True,
 'coordinator':coordinator,'result_export':{'worktree':str(W),'branch':'ai-pro/qgresults','default_workspace_totals':export['default_workspace_totals'],
 'new_module_tests_passed':14,'focused16_contains_two_existing_tests':True,'strict_clippy_exit':0,'fmt_exit':0,'final_review_batch':'deleg_493912d0',
 'source_sha256':export['source_sha256'],'repair_evidence':'artifacts/qg5a-parent-repair.json','file_write_clipboard_gui_connected':False,'accepted':False},
 'harness_tests_passed':39,'root_integrated':False,'full_qg2_accepted':False,'full_qg3_accepted':False,'full_qg5_accepted':False,'product_accepted':False,
 'old_main_477_vs_gui_wip_500_vs_results_514_are_distinct':True,'specific_ui_approval_timeout_preserved':True,'recurring_scheduler_created':False}
save('artifacts/qg3c-qg5a-repair-checkpoint.json',checkpoint)
progress=load('artifacts/quick-check-progress.json');progress.update(recorded_at=checkpoint['recorded_at'],qg3c_qg5a_parallel=checkpoint)
progress['completion_continuation'].update(status=checkpoint['status'],current_review_batch='deleg_493912d0',current_pipeline='artifacts/qg3c-coordinator-repair-pipeline.json')
save('artifacts/quick-check-progress.json',progress)
directive=load('artifacts/quick-check-completion-directive-20261026.json');directive.update(status=checkpoint['status'],current_review_batch='deleg_493912d0',last_checkpoint=checkpoint['recorded_at'])
for stream in directive['current_workstreams']:
 stream.update(status='corrective_flash_file_only_running' if stream['id']=='execution-coordinator' else 'pure_regression_passed_final_qa_running')
save('artifacts/quick-check-completion-directive-20261026.json',directive)
block=f'''
## QG5A 실회귀 통과·최종QA, QG3C 독립지적 수정 — {checkpoint['recorded_at']}
- 원본독립QA deleg_e4d98270수신: coordinator F01–F10(컴파일·목록문법·Failed드레인교착·Empty/finished정상완료유실경쟁·에러snapshot누락·Pending취소/실고장시험부족·가시성/원시OS오류반사), 실제default시험실행불허. 원본coordinator실행0, E0063원본compile101보존. 원본source2+부모cfgtest등록을clean로컬WIP commit {p['preserved_original_wip_commit']}에보존(통과/수용아님).
- 전용새 qgcoordfix/ai-pro/qgcoordfix에기존154입력고정·정확source2수정FILEONLY FlashHigh actual PID{started['pid']}, started={started['started_at']}. checkpoint실생존={bool(process)}. supervisor proc_6c5be5f0df50 PID45084. 부모는해당W의Cargofmt/테스트/metadata/소스수정0. 하네스39PASS·root보호입력불변.
- QG5A QA-01Busyfixture/QA-02CSV시험UTF8파서/QA-03메타전체공백/QA-04셀전체공백을수정. 원본안전순수시험실행9PASS2FAIL(기존GUIstate2포함)·추가부모시험1FAIL·Clippy6지적실패모두보존. invalidschema보안fixture는JSON값구조전체동등으로보정하되Core엄격Deserialize/제품serializer변경0. 큰JSON필드중간예산회귀로TooLarge종류소실가설은재현안됨.
- qgresults 실제workspace **514PASS0FAIL35ignored**, 신규순수모듈14시험포함. focused16은기존state2와겹쳐합산금지. strictClippy/fmt0. rawactor본문비교AssertionError는별도증거보존후독립원본복사본rustfmt처리하여export생산부분byte동등확인;view는동일의미Clippy보정. 기존lib선언외153입력불변.
- 결과최종독립2QA **deleg_493912d0** 진행중;source동결. 메인통합/단독QG5전체수용/제품수용0,파일쓰기·atomicwrite·clipboard·실가시GUI연결0. root477/GUIWIP500/결과W514는서로다른실행증거다.
- 근거 artifacts/qg5a-parent-repair.json / qg3c-coordinator-repair-prepared.json / qg3c-coordinator-repair-pipeline.json / qg3c-qg5a-repair-checkpoint.json. 운영망/OS정책/배포/이전UI입력승인timeout우회0. 다음은최종QA수신및수정actor완료후감사/독립실행안전QA/실회귀다.
'''
for name,header in [('PROGRESS.md','# NPI 진행 기록'),('RESUME.md','# NPI 개발 재개 및 승인 경계')]:
 file=R/name;text=file.read_text(encoding='utf-8');assert text.count(header+'\n')==1
 file.write_text(text.replace(header+'\n',header+'\n'+block,1),encoding='utf-8',newline='\n')
print(json.dumps({'status':checkpoint['status'],'coordinator_actor_pid':started['pid'],'coordinator_alive':bool(process),'results_workspace':export['default_workspace_totals'],'final_review_batch':'deleg_493912d0','root_integrated':False},ensure_ascii=False))
