"""두 Flash atom의 감사·원본 컴파일 결과와 독립 안전 검토 대기를 최신 상태로 기록한다."""
import datetime,hashlib,json,pathlib
R=pathlib.Path(__file__).resolve().parents[1];sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
def load(n):return json.loads((R/n).read_text(encoding='utf-8'))
def save(n,d):(R/n).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
p=load('artifacts/qg3d-runtime-render-prepared.json');a=load('artifacts/qg3d-runtime-render-pipeline.json');c=load('artifacts/qg3d-atoms-original-compile.json')
assert a['status']=='BOTH_ATOMS_AUDITED_NOT_COMPILED_NOT_EXECUTED'
assert c['roles']['qgruntime']['compile']['exit_code']==0 and c['roles']['qgrender']['compile']['exit_code']==101
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
for role,row in a['roles'].items():
 W=pathlib.Path(row['worktree']);assert all(sha(W/n)==h for n,h in row['source_sha256'].items())
 assert all(sha(W/n)==h for n,h in p['roles'][role]['immutable_sha256'].items() if not(role=='qgrender' and n=='apps/network-quick-check/src/lib.rs'))
 assert all(sha(W/n)==h for n,h in p['roles'][role]['reference_sha256'].items())
 assert sha(W/'apps/network-quick-check/src/lib.rs')==c['roles'][role]['lib_sha256']
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'RUNTIME_COMPILED_RENDER_COMPILE_FAILED_INDEPENDENT_SAFETY_QA_RUNNING',
 'actor_pipeline_evidence':'artifacts/qg3d-runtime-render-pipeline.json','original_compile_evidence':'artifacts/qg3d-atoms-original-compile.json',
 'actor_tools_scopes_and_after_sha_passed':True,'actor_total_changed_files':sum(len(r['source_sha256']) for r in a['roles'].values()),
 'roles':{role:{'source_sha256':row['source_sha256'],'policy':row['actor_policy'],'strict_path_checks':row['strict_path_checks'],
 'compile_exit':c['roles'][role]['compile']['exit_code'],'diagnostics_summary':c['roles'][role]['diagnostics_summary'],
 'tests_executed':False,'source_modified_by_parent':False,'accepted':False} for role,row in a['roles'].items()},
 'render_parent_registration_only':'pub mod gui_result_render; in isolated qgrender lib, source body unchanged',
 'safety_review_batch':'deleg_24bbf177','review_count':2,'runtime_test_execution_safety_approved':False,
 'render_test_execution_safety_approved':False,'safety_approval_state':'pending, false above means not yet approved rather than completed rejection',
 'root_integrated':False,'gui_connected':False,'native_executed':False,'tests_executed':False,'accepted':False,'product_accepted':False,
 'next':'receive exact read-only findings; then minimum compile/behavior/test repair, source refreeze and bounded reviewed tests; no native/GUI acceptance promotion'}
save('artifacts/qg3d-runtime-render-original-checkpoint.json',record)
progress=load('artifacts/quick-check-progress.json');progress.update(recorded_at=record['recorded_at'],qg3d_runtime_renderer_original=record)
progress['completion_continuation'].update(status=record['status'],current_review_batch=record['safety_review_batch'],current_pipeline='artifacts/qg3d-atoms-original-compile.json')
save('artifacts/quick-check-progress.json',progress)
d=load('artifacts/quick-check-completion-directive-20261026.json');d.update(last_checkpoint=record['recorded_at'],status=record['status'],current_review_batch=record['safety_review_batch'])
for s in d['current_workstreams']:
 if s['id']=='execution-coordinator':s.update(status='runtime_compile0_renderer_compile101_waiting_safety_reviews',next=record['next'])
save('artifacts/quick-check-completion-directive-20261026.json',d)
summary=f'''
## QG3D actor종료·원본compile 결과·안전QA 대기 — {record['recorded_at']}
- 두FlashHigh FILEwriter종료: pipeline exit0·terminalSUCCESS·정확3변경파일(호스트2/renderer1),runtimeFILE28/renderFILE26·도구/절대W경로·immutable156/158·각ref12·afterSHA감사모두통과. inheritedalways-proceed관찰유지·OS강제격리보증아님·감사는제품수용아님.
- 부모가원본3개및각lib를.harness/evidence/qg3d-atoms-original/에보존. renderer W에모듈등록1줄만부모추가후두W **실제compile-only**: runtime **exit0**, renderer **exit101/E0034 19건**(구체BoundedWriter의fmt::Write/io::Write write_fmt중복후보). 생산·시험원본문변경0·실test실행0. 원본실패근거보존,기계적compile보정만으로실행안전승인0.
- 독립읽기안전QA **deleg_24bbf177** 2건실제진행중: runtime once/성공·init고장·drain/driver OS효과/새시험정리, renderer 전체snapshot/DTO·budget/NUL/이전결과귀속/시험실효성. 실제compile결과도steer전달요청했다. 반환전sourceSHA동결유지.
- rootmain492/31ignored·이전hostW523/35ignored·combined기준538/35ignored는기존별도근거다. 새runtime/renderer아직未수용·GUI/nativebackend/실측연결0·메인통합0. 기존가시입력승인timeout우회/운영망/OS정책/배포0.
- 근거 artifacts/qg3d-{{runtime-render-pipeline,atoms-original-compile,runtime-render-original-checkpoint}}.json. 다음읽기QA수신후최소보정→source재동결/실행안전판정→부모상위timeout실시험→선택통합을이어간다.
'''
for name,header in [('PROGRESS.md','# NPI 진행 기록'),('RESUME.md','# NPI 개발 재개 및 승인 경계')]:
 f=R/name;t=f.read_text(encoding='utf-8');assert t.count(header+'\n')==1
 f.write_text(t.replace(header+'\n',header+'\n'+summary,1),encoding='utf-8',newline='\n')
print(json.dumps({'status':record['status'],'changed_files':record['actor_total_changed_files'],'compile_exit':{r:s['compile_exit'] for r,s in record['roles'].items()},'review_batch':record['safety_review_batch'],'tests_executed':False,'root_integrated':False},ensure_ascii=False))
