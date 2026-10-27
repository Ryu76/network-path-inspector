"""완성 후속 coordinator/export의 충돌 없는 FILE ONLY 작업 트리 둘을 준비한다."""
import datetime,hashlib,json,pathlib,shutil,subprocess
R=pathlib.Path(__file__).resolve().parents[1]
load=lambda p:json.loads((R/p).read_text(encoding='utf-8'))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
BASE=R/'.worktrees/qgguiinputs';STAGE='qg3cexport'
SPECS={
 'qgcoordinator':{'files':['apps/network-quick-check/src/gui_coordinator.rs','apps/network-quick-check/src/gui_coordinator_tests.rs'],
 'contract':'qg3c-coordinator-contract-v0.1.md','registration':'#[cfg(test)]\nmod gui_coordinator;\n','runtime_scope':'memory mock + actual Core runner on owned std thread; CPU-only runtime; no real IO'},
 'qgresults':{'files':['apps/network-quick-check/src/result_view.rs','apps/network-quick-check/src/result_export.rs'],
 'contract':'qg5a-result-export-contract-v0.1.md','registration':'pub mod result_view;\npub mod result_export;\n','runtime_scope':'pure reference view/filter and bounded memory encoding; no IO/thread/runtime'}
}
OUT=R/'artifacts/qg3c-qg5a-parallel-prepared.json';assert not OUT.exists()
p=load('artifacts/qg3b-gui-inputs-preservation.json');previous=load('artifacts/qg3b-gui-inputs-parent-repair.json')
assert p['worktree_clean'] and not p['accepted'] and not p['root_integrated']
assert all(sha(BASE/n)==h for n,h in p['source_sha256'].items())
assert all(sha(R/n)==h for n,h in previous['root_before_sha256'].items())
def git(w,*args):
 result=subprocess.run(['git','-C',str(w),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60)
 assert result.returncode==0,result.stderr
 return result.stdout.rstrip('\r\n')
assert git(BASE,'rev-parse','HEAD')==p['preserved_commit'] and not git(BASE,'status','--porcelain')
processes=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',
 '$p=Get-CimInstance Win32_Process | Where-Object { $_.Name -ieq "agy.exe" -and $_.CommandLine -match "--print=" }; @($p | Select-Object ProcessId,Name) | ConvertTo-Json -Compress'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
assert processes.returncode==0 and not json.loads(processes.stdout or '[]'),'active print writer; stop before setup'
# 모든 경로 충돌을 첫 worktree 생성 전에 검사한다.
for role,spec in SPECS.items():
 assert not (R/'.worktrees'/role).exists()
 assert not (R/'.harness/runs'/(STAGE+'-'+role)).exists()
 assert not (R/'.harness/prompts'/(STAGE+'-'+role+'.md')).exists()
 assert all(not (BASE/n).exists() and not (R/n).exists() for n in spec['files'])
 assert (R/'.harness/references'/spec['contract']).is_file()
tracked=subprocess.check_output(['git','-C',str(BASE),'ls-files','-z']).decode('utf-8').split('\0')
tracked=[n for n in tracked if n and (BASE/n).is_file()]
base_sha={n:sha(BASE/n) for n in tracked}
reads=['AGENTS.md','PRD.md','docs/requirements/Network_Path_Inspector_Harness_PRD_v1.2.md',
 'contracts/quick-check-interface-v0.1.json','Cargo.toml','Cargo.lock','apps/network-quick-check/Cargo.toml',
 'apps/network-quick-check/src/lib.rs','apps/network-quick-check/src/main.rs',
 'apps/network-quick-check/src/gui_state.rs','apps/network-quick-check/src/gui_state_tests.rs',
 'apps/network-quick-check/src/gui_presenter.rs','apps/network-quick-check/src/gui_entry.rs',
 'apps/network-quick-check/src/diagnostic_cli.rs','crates/network-core/src/runner.rs',
 'crates/network-core/tests/runner.rs','crates/network-core/src/quick.rs','crates/network-core/src/targets.rs']
assert all((BASE/n).is_file() for n in reads)
traces={}
for i in range(2):
 trace=pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/delegation/live/deleg_d9b7ceee')/f'task-{i}.log'
 assert 'end status=completed exit_reason=completed' in trace.read_text(encoding='utf-8')[-500:]
 traces[str(trace)]=sha(trace)
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'PREPARED_TWO_ISOLATED_FILE_ONLY_WRITERS_NOT_STARTED',
 'stage':STAGE,'model':'gemini-3.8-flash-high','base_commit':p['preserved_commit'],
 'base_wip_not_product_acceptance':True,'design_delegation':'deleg_d9b7ceee','design_trace_sha256':traces,
 'design_representation':'PARENT_SELECTED_NORMALIZED_CONTRACTS_NOT_VERBATIM_REVIEW',
 'root_before_sha256':previous['root_before_sha256'],'base_tracked_sha256':base_sha,'roles':{},
 'writer_started':False,'root_integrated':False,'accepted':False,'full_qg2_accepted':False,'full_qg3_accepted':False,'full_qg5_accepted':False,'product_accepted':False}
for role,spec in SPECS.items():
 W=R/'.worktrees'/role
 git(R,'worktree','add','-b','ai-pro/'+role,str(W),p['preserved_commit'])
 assert not git(W,'status','--porcelain')
 normalized=[]
 for name,h in base_sha.items():
  target=W/name
  if sha(target)!=h:
   original=(BASE/name).read_bytes();derived=target.read_bytes()
   assert original.replace(b'\r\n',b'\n')==derived.replace(b'\r\n',b'\n'),name
   shutil.copyfile(BASE/name,target);normalized.append(name)
 assert all(sha(W/n)==h for n,h in base_sha.items())
 # 원문 bytes 복원은 index의 의미 diff를 만들면 안 된다.
 if normalized:git(W,'add','--',*normalized)
 assert not git(W,'status','--porcelain')
 ref=W/'.harness/inputs/frozen';ref.mkdir(parents=True,exist_ok=False)
 contract=ref/spec['contract'];shutil.copyfile(R/'.harness/references'/spec['contract'],contract)
 # 고정 API 원문만 제공한다. actor가 외부 cargo cache를 탐색하지 않게 한다.
 refs=[contract]
 if role=='qgcoordinator':
  vendor=pathlib.Path('C:/Users/HODI/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.52.3')
  for name in ['src/runtime/builder.rs','src/runtime/runtime.rs','src/sync/notify.rs','src/sync/oneshot.rs']:
   assert (vendor/name).is_file()
   dest=ref/'tokio-1.52.3'/name;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(vendor/name,dest);refs.append(dest)
 prompt=f'''작업은부모동결계약구현이다. W={W.as_posix()}, role={role}, baseline={p['preserved_commit']}.
FILE READ/CREATE/EDIT와W내discovery만허용. command/run_command/terminal/PowerShell/git/Cargo/build/test/fmt/network/install/manage_task/다른agent/재위임/credentials금지. 읽기목적command도금지. 모든actor경로는W안의절대경로여야한다. 문서안root·다른W·vendor/cache/온라인링크따라읽기금지.
가장먼저 {contract.as_posix()} 전체읽고정확계약대로두파일을실제로작성하라. 부모권한내선택범위이며이전설계원문그대로수용주장이아니다.
쓰기정확2={json.dumps([(W/n).as_posix() for n in spec['files']],ensure_ascii=False)}. 둘다신규이며이미있으면중단보고. lib모듈등록/Cargo/lock/기존state/CLI/GUI/Core/기존tests/docs는읽기만·쓰기0. 부모가actor감사후모듈등록을별도로수행한다. 현재작업단위는미등록이며코드작성자시험실행0.
검증된기존입력={json.dumps([(W/n).as_posix() for n in reads],ensure_ascii=False)}.
고정참조={json.dumps([n.as_posix() for n in refs],ensure_ascii=False)}. 위외파일이없으면추측경로반복/외부탐색말고BLOCKED를보고하라. runtime/API는원문과기존시험을참조하며새의존성추가0.
부작용범위={spec['runtime_scope']}. contract의public/private API·bounded·원문귀속·실패보존·시험조건을구현. fallback/stub/todo/unimplemented/가짜report·PASS발명0. 한국어설명주석·최종인계,UTF8최종LF·후행공백0. 실GUI의이전set_value승인timeout과운영망/OS변경/배포금지는그대로이며이번코드와무관한그행위를시도하지말라.
최종정확변경경로,구현API,미연결기능,위험/제약,부모모듈등록/실행필요사항을보고한다. 파일작성만이며빌드·테스트를수행하지않았다고명시하라. 외부제품완성/전체게이트수용주장금지.
'''
 prompt_path=R/'.harness/prompts'/(STAGE+'-'+role+'.md');prompt_path.write_text(prompt,encoding='utf-8',newline='\n')
 record['roles'][role]={'worktree':str(W),'branch':'ai-pro/'+role,'actor_writes':spec['files'],
  'immutable_sha256':base_sha,'reference_sha256':{n.relative_to(W).as_posix():sha(n) for n in refs},
  'contract':str(contract),'prompt_path':str(prompt_path),'registration_after_audit_by_parent':spec['registration'],
  'newline_only_derived_restore_paths':normalized,'parent_metadata_changes':[],'source_compiled':False}
assert all(sha(R/n)==h for n,h in previous['root_before_sha256'].items())
OUT.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':record['status'],'stage':STAGE,'roles':list(SPECS),'base_tracked_inputs':len(base_sha),'design_received':True,'root_integrated':False},ensure_ascii=False))
