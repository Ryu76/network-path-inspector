"""검증된 독립 호스트와 다음 GUI 연결 설계의 실제 상태를 최신 재개 문서에 반영한다."""
import datetime,hashlib,json,pathlib
R=pathlib.Path(__file__).resolve().parents[1];sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
def load(n):return json.loads((R/n).read_text(encoding='utf-8'))
def save(n,d):(R/n).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
host=load('artifacts/qg3c-coordinator-host-acceptance.json');baseline=load('artifacts/qg3d-gui-wiring-baseline.json');W=pathlib.Path(baseline['worktree'])
assert host['accepted'] and not host['root_integrated'] and not host['gui_connected']
assert not baseline['accepted'] and baseline['worktree_clean']
assert all(sha(W/n)==h for n,h in baseline['tracked_source_sha256'].items())
main=load('artifacts/qg5a-pure-result-acceptance.json');assert all(sha(R/n)==h for n,h in main['source_sha256'].items())
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'ISOLATED_HOST_ACCEPTED_GUI_WIRING_DESIGN_TWO_REVIEWS_RUNNING',
 'host_acceptance':'artifacts/qg3c-coordinator-host-acceptance.json','host_commit':host['preserved_commit'],'host_scope':'memory backend/actualCore independent host; test-only module, no GUI/native I/O connection',
 'host_focused_tests':host['focused_counts'],'host_workspace':host['workspace_counts'],
 'combined_wip_worktree':str(W),'combined_wip_branch':baseline['branch'],'combined_wip_commit':baseline['commit'],
 'combined_wip_workspace':baseline['workspace_counts'],'combined_wip_not_gui_acceptance':True,
 'design_batch':'deleg_015c4753','design_review_count':2,'design_workstreams':['native runtime/host shutdown/nonUI drain ownership','presenter/start-stop/timer/final result/new explicit selector'],
 'new_product_source_written_since_combination':False,'flash_writer_active':False,'native_or_visible_test_executed':False,
 'root_main_counts':main['receiving_root_workspace_counts'],'main_gui_connected':False,
 'full_qg2_accepted':False,'full_qg3_accepted':False,'full_qg5_accepted':False,'product_accepted':False,
 'next_action':'Receive both read-only designs -> freeze minimal exact interfaces and writer paths -> isolated Flash FILE ONLY implementation -> parent audit/safety QA -> real tests',
 'recurring_scheduler_created':False,'specific_ui_approval_timeout_respected':True}
save('artifacts/qg3d-gui-wiring-start-checkpoint.json',record)
progress=load('artifacts/quick-check-progress.json');progress.update(recorded_at=record['recorded_at'],qg3d_gui_wiring=record)
progress['completion_continuation'].update(status=record['status'],current_review_batch=record['design_batch'],current_pipeline='artifacts/qg3d-gui-wiring-start-checkpoint.json')
save('artifacts/quick-check-progress.json',progress)
directive=load('artifacts/quick-check-completion-directive-20261026.json');directive.update(last_checkpoint=record['recorded_at'],status=record['status'],current_review_batch=record['design_batch'])
for s in directive['current_workstreams']:
 if s['id']=='execution-coordinator':s.update(mode='isolated_host_accepted_gui_adapter_design',status='memory_host_scope_accepted_two_gui_design_reviews_running',next=record['next_action'])
for s in directive['ordered_delivery_scope']:
 if s['id']=='gui-execution-coordinator':s['status']='isolated_memory_host_limited_accepted_native_adapter_pending'
 if s['id']=='gui-run-and-final-results':s['status']='combined_wip_baseline_verified_gui_wiring_design_running'
save('artifacts/quick-check-completion-directive-20261026.json',directive)
summary=f'''
## 다음 QG3D 실행GUI 연결 기준·병렬설계 시작 — {record['recorded_at']}
- 독립host23PASS/전체W523PASS35ignored·Clippyfmt0 제한수용뒤,후속전용 **.worktrees/qgguirun / ai-pro/qgguirun** 조합기준을만들었다. 미가시수용QG3B GUI WIP+검증된memoryhost+메인QG5A純결과15를정확조합했다. 메인branch통합/GUI실행연결아니다.
- 조합기준actualworkspace **538PASS0FAIL35ignored**·strictClippy/fmt0·tracked158 SHA고정·clean로컬WIPcommit **{baseline['commit']}**. rootmain492/31ignored·hostW523/35ignored·조합538/35ignored는각기다른시험조합이며합산금지.
- 독립읽기설계2건 **deleg_015c4753** 실제시작: (1)Native runtime/host·닫기/fatal/비UI drainowner수명, (2)presenter bridge·StartStop/timerpoll·실최종결과·새명시selector. 기존 **--dev-gui-inputs-v1 입력/계획only**와noargs/help/CLI의미보존;새 **--dev-gui-run-v1**은아직제안/미구현이다. 파일쓰기/clipboard/GUI필터확대는후속분리.
- 새Flashwriter/실native·가시입력시험실행0. 기존UI입력승인timeout동일행위/대체툴우회0·운영망/OS정책/배포0. 근거 artifacts/qg3d-gui-wiring-{{prepared,baseline,start-checkpoint}}.json. 설계수신뒤정확writer범위·contract를고정하고실제구현/감사/독립안전QA/실시험을연결한다. 전체제품/QG3수용false.
'''
for name,header in [('PROGRESS.md','# NPI 진행 기록'),('RESUME.md','# NPI 개발 재개 및 승인 경계')]:
 file=R/name;text=file.read_text(encoding='utf-8');assert text.count(header+'\n')==1
 file.write_text(text.replace(header+'\n',header+'\n'+summary,1),encoding='utf-8',newline='\n')
print(json.dumps({'status':record['status'],'host_tests':record['host_focused_tests'],'combined_workspace':record['combined_wip_workspace'],'design_batch':record['design_batch'],'gui_connected':False,'product_accepted':False},ensure_ascii=False))
