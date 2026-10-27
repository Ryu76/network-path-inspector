"""후속 두 Flash 작성자의 실제 시작/격리 입력을 확인해 진행 문서에 기록한다."""
import datetime,hashlib,json,pathlib,re,subprocess
R=pathlib.Path(__file__).resolve().parents[1]
load=lambda p:json.loads((R/p).read_text(encoding='utf-8'))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
p=load('artifacts/qg3c-qg5a-parallel-prepared.json')
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
roles={}
for role,spec in p['roles'].items():
 W=pathlib.Path(spec['worktree']);started=load('.harness/runs/'+p['stage']+'-'+role+'/started.json')
 assert started['model']==p['model']=='gemini-3.8-flash-high'
 assert pathlib.Path(started['worktree']).resolve()==W.resolve()
 assert all(sha(W/n)==h for n,h in spec['immutable_sha256'].items())
 assert all(sha(W/n)==h for n,h in spec['reference_sha256'].items())
 proc=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',
  'Get-CimInstance Win32_Process -Filter "ProcessId = '+str(int(started['pid']))+'" | Select-Object ProcessId,ParentProcessId,Name | ConvertTo-Json -Compress'],
  capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
 assert proc.returncode==0 and proc.stdout.strip()
 observed=json.loads(proc.stdout);assert observed['Name'].lower()=='agy.exe' and observed['ProcessId']==started['pid']
 roles[role]={'worktree':str(W),'branch':spec['branch'],'actor_pid':started['pid'],'started_at':started['started_at'],
  'alive_at_checkpoint':True,'model':started['model'],'actor_writes':spec['actor_writes'],
  'immutable_input_count':len(spec['immutable_sha256']),'reference_file_count':len(spec['reference_sha256']),
  'source_compiled':False,'tests_executed':False,'root_integrated':False,'accepted':False}
harness=load('artifacts/commands/qg3c-qg5a-parallel-harness.json')
assert harness['exit_code']==0 and not harness['partial']
match=re.search(r'Ran (\d+) tests',pathlib.Path(harness['log']).read_text(encoding='utf-8'));assert match and int(match.group(1))==38
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'TWO_FLASH_FILE_ONLY_WRITERS_ALIVE',
 'stage':p['stage'],'base_commit':p['base_commit'],'base_is_unaccepted_gui_wip':True,
 'roles':roles,'supervisor_session':'proc_60693d869976','supervisor_pid':20924,
 'design_review_received':'deleg_d9b7ceee','design_not_execution_evidence':True,
 'harness_tests_passed':38,'root_frozen_inputs_unchanged':len(p['root_before_sha256']),
 'coordinator_registration_after_audit':'test-only module; not product dispatch connection',
 'export_registration_after_audit':'public pure modules; no GUI/file adapter connection',
 'native_gui_modified_by_actors':False,'new_dependencies':False,'gui_input_approval_timeout_preserved':True,
 'source_compiled':False,'tests_executed':False,'root_integrated':False,'accepted':False,
 'full_qg2_accepted':False,'full_qg3_accepted':False,'full_qg5_accepted':False,'product_accepted':False}
out=R/'artifacts/qg3c-qg5a-parallel-start.json';assert not out.exists();out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
progress=load('artifacts/quick-check-progress.json');progress['recorded_at']=record['recorded_at'];progress['qg3c_qg5a_parallel']=record
progress['completion_continuation']['status']='TWO_FLASH_FILE_ONLY_WRITERS_ALIVE'
progress['completion_continuation']['current_pipeline']='artifacts/qg3c-qg5a-parallel-pipeline.json'
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(progress,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
summary=f'''
## QG3C 실행 coordinator·QG5A 결과 내보내기 Flash 병렬 작성 시작 — {record['recorded_at']}
- 설계 deleg_d9b7ceee 두 결과를 수신했다. 기존 API·완료 후 snapshot 제거·nullable metadata를 확인하고 부모가 동결계약을 정했다. 신규 coordinator는 같은 RunID의 완료 snapshot 보존도 포함한다. 결과 모듈은 실제 DTO를 빌려 필터·bounded 메모리 TXT/CSV만 작성하며 파일/clipboard/가시GUI는 후속이다.
- 전용 qgcoordinator/ai-pro/qgcoordinator PID{roles['qgcoordinator']['actor_pid']}, qgresults/ai-pro/qgresults PID{roles['qgresults']['actor_pid']} 두 FlashHigh 실제생존확인. 공통base=0da7720fa3a943f3abeb5a34d0c12c24786bff62(WIP이며제품수용아님),각기존입력154 SHA동결·정확신규2파일씩만쓰기. 서로다른worktree이므로동일파일병렬writer없음.
- 하네스38PASS/허용scope역회귀확인. supervisor proc_60693d869976(PID20924)에서두FILEONLY작성·실제도구/경로/terminal/partial/SHA감사까지만실행한다. 작성중W의Cargo/fmt/metadata/부모source수정0. 새source컴파일/시험/수용아직0·lib등록은감사뒤부모가한다(코디네이터첫단위는test-only소비).
- 운영망/OS설정/원격배포/이전UI조작승인timeout의동일행위우회0. 기존GUI WIP와root477/31ignored·W500/35ignored/native4는별도이전증거다. 전체QG2/QG3/QG5/OS/제품미수용. 근거 artifacts/qg3c-qg5a-parallel-prepared.json / start.json / pipeline.json.
- 다음: 두actor완료뒤독립범위별감사→원본보존→정적실행안전QA→부모모듈등록/실제컴파일·기본회귀→최종QA·선택통합판정. callback/runner/GUIfinal연결은후속검증단위에서진행한다.
'''
for name,header in [('PROGRESS.md','# NPI 진행 기록'),('RESUME.md','# NPI 개발 재개 및 승인 경계')]:
 path=R/name;text=path.read_text(encoding='utf-8');assert summary not in text and header+'\n' in text
 path.write_text(text.replace(header+'\n',header+'\n'+summary,1),encoding='utf-8',newline='\n')
print(json.dumps({'status':record['status'],'actor_pids':{role:d['actor_pid'] for role,d in roles.items()},'harness_passed':38,'root_integrated':False,'accepted':False},ensure_ascii=False))
