"""두 atom 수용·571 조합 회귀와 다음 typed session writer의 실제 시작을 영속 기록한다."""
import datetime,hashlib,json,pathlib,subprocess
R=pathlib.Path(__file__).resolve().parents[1];sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
def load(n):return json.loads((R/n).read_text(encoding='utf-8'))
def save(n,d):(R/n).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
p=load('artifacts/qg3e-session-bridge-prepared.json');b=load('artifacts/qg3e-session-bridge-baseline.json');runtime=load('artifacts/qg3d-native-runtime-acceptance.json');render=load('artifacts/qg3d-pure-renderer-acceptance.json')
s=load('.harness/runs/'+p['stage']+'-'+p['role']+'/started.json');pipeline=load('artifacts/qg3e-session-bridge-pipeline.json')
assert runtime['accepted'] and render['accepted'] and s['model']==p['model'] and s['worktree']==p['worktree']
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items());assert all(sha(pathlib.Path(b['worktree'])/n)==h for n,h in b['tracked_source_sha256'].items())
W=pathlib.Path(p['worktree']);assert all(sha(W/n)==h for n,h in {**p['immutable_sha256'],**p['reference_sha256']}.items())
ps=subprocess.run(['powershell.exe','-NoProfile','-Command',f'Get-CimInstance Win32_Process -Filter "ProcessId={s["pid"]}" | Select-Object ProcessId,Name | ConvertTo-Json -Compress'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
assert ps.returncode==0,ps.stderr;live=json.loads(ps.stdout) if ps.stdout.strip() else None
assert live is not None or (R/'.harness/runs'/(p['stage']+'-'+p['role'])/'result.json').exists()
h=load('artifacts/commands/qg3e-bridge-harness.json');assert h['exit_code']==0 and not h['partial'];assert 'Ran 64 tests' in pathlib.Path(h['log']).read_text(encoding='utf-8')
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'RUNTIME_RENDERER_ACCEPTED_COMBINED571_TYPED_SESSION_WRITER_STARTED',
 'runtime_acceptance':'artifacts/qg3d-native-runtime-acceptance.json','runtime_commit':runtime['preserved_commit'],'runtime_counts':runtime['focused_counts'],
 'renderer_acceptance':'artifacts/qg3d-pure-renderer-acceptance.json','renderer_commit':render['preserved_commit'],'renderer_counts':render['focused_counts'],
 'renderer_final_review_batch_received':'deleg_563bb086','renderer_A01_cause_label_and_regression_resolved':True,
 'combined_wip_worktree':b['worktree'],'combined_wip_branch':b['branch'],'combined_wip_commit':b['commit'],'combined_wip_workspace':b['workspace_counts'],
 'combined_current_gui_still_inputs_only':True,'new_execution_selector_not_implemented':True,'main_root_last_verified_counts':{'passed':492,'failed':0,'ignored':31},
 'new_session_worktree':p['worktree'],'stage':p['stage'],'role':p['role'],'model':p['model'],'supervisor_session':'proc_f4c682dbf040','supervisor_pid':12932,
 'actor_started':s,'actual_actor_process_observation':live,'pipeline':'artifacts/qg3e-session-bridge-pipeline.json',
 'actor_writes':p['actor_writes'],'new_session_default_consumption_scope':'cfg(test) prep layer; no native GUI consumer yet',
 'harness_tests':{'passed':64,'exit_code':0},'immutable_actor_input_count':len(p['immutable_sha256']),'frozen_reference_count':len(p['reference_sha256']),
 'parent_cargo_format_metadata_on_active_actor_worktree':0,'new_session_source_compiled':False,'new_session_tests_executed':False,
 'new_session_accepted':False,'root_integrated':False,'gui_execution_connected':False,'non_ui_supervisor_implemented':False,'native_backend_measured':False,'product_accepted':False,
 'specific_visible_input_permission_timeout_respected':True,'permission_settings_changed':False,'audit_is_not_os_enforced_sandbox':True,'cron_created':False,
 'next':'writer exit -> actual tools/path/SHA audit -> preserve original -> parent cfg(test) registration/compile-only -> independent execution-safety QA -> bounded real memory-backend tests -> typed-session acceptance -> native UI/supervisor wiring'}
save('artifacts/qg3e-session-bridge-start-checkpoint.json',record)
progress=load('artifacts/quick-check-progress.json');progress.update(recorded_at=record['recorded_at'],qg3e_session_bridge=record)
progress['completion_continuation'].update(status=record['status'],current_review_batch=None,current_pipeline=record['pipeline'])
save('artifacts/quick-check-progress.json',progress)
d=load('artifacts/quick-check-completion-directive-20261026.json');d.update(last_checkpoint=record['recorded_at'],status=record['status'],current_review_batch=None,current_pipeline=record['pipeline'])
for item in d['current_workstreams']:
 if item['id']=='execution-coordinator':item.update(status='runtime_renderer_limited_accepted_typed_session_flash_writer_started',next=record['next'])
save('artifacts/quick-check-completion-directive-20261026.json',d)
summary=f'''
## QG3D 두 atom 수용·조합571 검증·QG3E 세션 writer 시작 — {record['recorded_at']}
- renderer최종2QA deleg_563bb086수신: B findings[]/순수한정수용, A 원F01~05해소·신규A01취소출처라벨P2. 부모가 **사용자 취소→실행 취소**,원인미구분안내/한도·오류취소음성시험을추가. 생산delta는그라벨/안내뿐이며이전검토본문으로정확복원검증했다. **focused22PASS/해당W560PASS0FAIL35ignored/Clippyfmt0**,clean **{render['preserved_commit']}**·pure renderer한정수용. 이전21/W559를최신으로혼동하지않는다.
- runtime34/W549/Clippyfmt0의독립구성수용 **{runtime['preserved_commit']}**와renderer를 **.worktrees/qgguirun**에정확source4로선택조합했다. receivingW실제 **571PASS0FAIL35ignored/Clippyfmtcheck0**,cleanWIP **{b['commit']}**,tracked159 SHA고정. GUI실행/메인통합아니다. 입력화면가시미수용·host여전히cfgtest소비. main기존492/31ignored별도유지.
- 다음 **QG3E typed presenter/session** 계약과scope3(기존presenter1+新session/tests2)을고정. 범용state_mut/외부mutableclosure0·opaque후보먼저검증/최초freshhost factory한번/enqueue성공때만原presenter확정·단일state소유/Busy편집거부·cancel/poll/닫기drain/완료snapshot귀속을작성한다. nativeUI/selector/entry최종drainowner는후속이며이번새module도부모cfgtest등록준비층이다.
- 하네스 **64PASS/exit0** 뒤FlashHigh실제시작: supervisor **proc_f4c682dbf040/PID12932**,actor **PID{s['pid']}**,worktree **{p['worktree']}**,stage **{p['stage']}**. actorimmutable158/reference12·base/rootSHA불변. 실제프로세스관측={json.dumps(live,ensure_ascii=False)}. activeW Cargo/fmt/metadata0·새sourcecompile/test0·수용0. actual도구/경로준수는writer종료후감사하며상속permission/감사를OS강제격리보증으로표현0.
- 근거 artifacts/qg3d-{{pure-renderer-acceptance,accepted-atoms-combination}}.json, qg3e-session-bridge-{{baseline,prepared,pipeline,start-checkpoint}}.json. 기존가시입력승인timeout우회/실운영망/OS정책변경/배포/반복예약0. 다음writer종료감사/원본보존/compile-only/독립안전QA/실시험후native GUI실행연결을이어간다. 제품완료false.
'''
for name,header in [('PROGRESS.md','# NPI 진행 기록'),('RESUME.md','# NPI 개발 재개 및 승인 경계')]:
 f=R/name;t=f.read_text(encoding='utf-8');assert t.count(header+'\n')==1
 f.write_text(t.replace(header+'\n',header+'\n'+summary,1),encoding='utf-8',newline='\n')
print(json.dumps({'status':record['status'],'renderer':record['renderer_counts'],'combined':record['combined_wip_workspace'],
 'actor_pid':s['pid'],'actual_process':live,'harness_passed':64,'gui_execution_connected':False,'new_session_compiled':False,'product_accepted':False},ensure_ascii=False))
