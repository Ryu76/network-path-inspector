"""실제 두 writer 시작과 설계수신·준비실패/복구·검증 경계를 기록한다."""
import datetime,hashlib,json,pathlib,subprocess
R=pathlib.Path(__file__).resolve().parents[1];sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
def load(n):return json.loads((R/n).read_text(encoding='utf-8'))
def save(n,d):(R/n).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
p=load('artifacts/qg3d-runtime-render-prepared.json');pipeline=load('artifacts/qg3d-runtime-render-pipeline.json');baseline=load('artifacts/qg3d-gui-wiring-baseline.json')
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
assert all(sha(pathlib.Path(p['base_worktree'])/n)==h for n,h in baseline['tracked_source_sha256'].items())
started={role:load('.harness/runs/'+p['stage']+'-'+role+'/started.json') for role in p['roles']}
pids=[x['pid'] for x in started.values()]
query=' OR '.join('ProcessId='+str(pid) for pid in pids)
ps=subprocess.run(['powershell.exe','-NoProfile','-Command',f'Get-CimInstance Win32_Process -Filter "{query}" | Select-Object ProcessId,Name | ConvertTo-Json -Compress'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
assert ps.returncode==0,ps.stderr
live=json.loads(ps.stdout) if ps.stdout.strip() else [];live=live if isinstance(live,list) else [live]
live_ids={x['ProcessId'] for x in live}
for role,s in started.items():
 assert s['worktree']==p['roles'][role]['worktree'] and s['model']==p['model'] and s['stage']==p['stage']
 assert s['pid'] in live_ids or (R/'.harness/runs'/(p['stage']+'-'+role)/'result.json').is_file()
harness=load('artifacts/commands/qg3d-parallel-harness.json');assert harness['exit_code']==0 and not harness['partial']
text=pathlib.Path(harness['log']).read_text(encoding='utf-8');assert 'Ran 62 tests' in text and 'OK' in text
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'TWO_FLASH_ATOMS_STARTED_PARENT_EXECUTION_WITHHELD',
 'design_batch_received':'deleg_015c4753','design_reviews':2,'design_is_not_implementation':True,
 'pipeline':'artifacts/qg3d-runtime-render-pipeline.json','supervisor_process_session':'proc_9c48e042c21b','supervisor_pid':36348,
 'actor_started':started,'actual_live_processes':live,'model':p['model'],'cli_version':p['cli_version'],
 'roles':{role:{'worktree':s['worktree'],'writes':s['actor_writes'],'immutable_inputs':len(s['immutable_sha256']),'fixed_references':len(s['reference_sha256'])} for role,s in p['roles'].items()},
 'harness_regression':{'exit_code':0,'passed':62,'evidence':'artifacts/commands/qg3d-parallel-harness.json'},
 'parent_cargo_or_format_on_active_actor_worktrees':0,'source_compiled':False,'tests_executed':False,'native_executed':False,
 'base_combined_counts_not_new_work':baseline['workspace_counts'],'root_integrated':False,'accepted':False,'gui_connected':False,'product_accepted':False,
 'metadata_preflight_failure':{'scope':'unfiltered all-platform offline metadata before worktree creation/actors; not product compilation',
 'error':'failed to download errno v0.3.14; attempting HTTP but --offline specified','resolution':'same offline locked metadata filtered to installed x86_64-pc-windows-msvc; no package download or Cargo.lock change','recovered':True},
 'permission_settings_changed':False,'audit_is_not_os_enforced_sandbox':True,'specific_visible_input_permission_timeout_respected':True,
 'next':'actor termination -> exact tool/path/afterSHA audit -> preserve source originals -> compile-only -> independently classify execution safety -> real parent tests -> selected integration'}
save('artifacts/qg3d-runtime-render-start-checkpoint.json',record)
progress=load('artifacts/quick-check-progress.json');progress.update(recorded_at=record['recorded_at'],qg3d_runtime_renderer_atoms=record)
progress['completion_continuation'].update(status=record['status'],current_review_batch=None,current_pipeline=record['pipeline'])
save('artifacts/quick-check-progress.json',progress)
d=load('artifacts/quick-check-completion-directive-20261026.json');d.update(last_checkpoint=record['recorded_at'],status=record['status'],current_review_batch=None,current_pipeline=record['pipeline'])
for s in d['current_workstreams']:
 if s['id']=='execution-coordinator':s.update(mode='flash_two_isolated_atoms',status='native_runtime_and_pure_result_renderer_file_writers_running',next=record['next'])
save('artifacts/quick-check-completion-directive-20261026.json',d)
summary=f'''
## QG3D 두 Flash 독립 atom 실제 시작 — {record['recorded_at']}
- deleg_015c4753읽기설계2건수신완료. **NativeIoOnce runtime부터**,다음typed presenter bridge/실행session,별도runselector/Win32 timerpoll/비UI supervisor최종drain 순서로좁힌다. GUI전체를한writer에맡기지않는다. entry호출스레드가nonUI정리소유,전용UIthread는HWND없는원래session반환. 광범위state_mut금지·typedbridge,old입력only/CLI보존. 아직설계이고해당연결미구현이다.
- 별도W **qgruntime** source2(기존CPU-only보존+첫수락때nativeIO/time runtime한번·재사용·고정실패/최종종료관측), **qgrender** 신규source1(순수ResultView기반bounded최종표시·全DTO/raw/null/상태/evidence/metadata·화면생략분리)로분리. 정확FILEscope회귀보강뒤 **하네스62PASS/exit0**.
- model **gemini-3.8-flash-high**,설치agy실제version **{p['cli_version']}**. supervisor proc_9c48e042c21b/PID36348,actorPID runtime={started['qgruntime']['pid']}·render={started['qgrender']['pid']} 실제시작/상태확인. Wimmutable156/158·각reference12·부모root sourceSHA고정. 기존permission설정변경0·sandbox플래그유지·상속permission/감사는OS강제격리보증아님.
- 준비중전체플랫폼offline metadata가캐시errno0.3.14없어실패한원인을보존했다. actor/worktree생성전실패이며제품compile실패아니다. 설치Windows target만filter한동일offline/locked metadata로해결·다운로드/lock변경0.
- active W Cargo/format/metadata0·새소스compile/test/native/GUI실행0·수용0·메인통합0. combinedbaseline538/35ignored와main492/31ignored는이전근거그대로구분. 기존UI입력승인timeout우회/운영망/OS정책/배포0.
- 근거 artifacts/qg3d-runtime-render-{{prepared,pipeline,start-checkpoint}}.json 및동결runtime/render계약. 다음actor종료→도구/경로/afterSHA감사→원본보존/compile-only→독립실행안전QA→실시험→선택통합. runtime driver초기화OS효과는있을수있으나실nativebackend측정증거아니다.
'''
for name,header in [('PROGRESS.md','# NPI 진행 기록'),('RESUME.md','# NPI 개발 재개 및 승인 경계')]:
 f=R/name;t=f.read_text(encoding='utf-8');assert t.count(header+'\n')==1
 f.write_text(t.replace(header+'\n',header+'\n'+summary,1),encoding='utf-8',newline='\n')
print(json.dumps({'status':record['status'],'model':p['model'],'actor_pids':pids,'live_processes':live,'harness_passed':62,'compiled':False,'tests_executed':False,'root_integrated':False},ensure_ascii=False))
