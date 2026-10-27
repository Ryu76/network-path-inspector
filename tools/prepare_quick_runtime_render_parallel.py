"""네이티브 runtime 확장과 순수 결과표시를 서로 다른 clean FILE ONLY 작업 공간에 준비한다."""
import datetime,hashlib,json,pathlib,shutil,subprocess
R=pathlib.Path(__file__).resolve().parents[1];sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
def load(n):return json.loads((R/n).read_text(encoding='utf-8'))
def git(w,*args):
 p=subprocess.run(['git','-C',str(w),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=75)
 assert p.returncode==0,p.stderr;return p.stdout.rstrip('\r\n')
b=load('artifacts/qg3d-gui-wiring-baseline.json');B=pathlib.Path(b['worktree']);base=b['commit'];stage='qg3datoms'
OUT=R/'artifacts/qg3d-runtime-render-prepared.json';assert not OUT.exists()
assert git(B,'rev-parse','HEAD')==base and not git(B,'status','--porcelain')
assert all(sha(B/n)==h for n,h in b['tracked_source_sha256'].items())
main=load('artifacts/qg5a-pure-result-acceptance.json');old=load('artifacts/qg3c-coordinator-repair-prepared.json')
assert all(sha(R/n)==h for n,h in old['root_before_sha256'].items() if n!='apps/network-quick-check/src/lib.rs')
assert all(sha(R/n)==h for n,h in main['source_sha256'].items())
root_before={n:sha(R/n) for n in set(old['root_before_sha256'])|set(main['source_sha256'])}
# 설치된 실행기를 실제로 확인하되 설정·권한·모델은 변경하지 않는다.
cli=pathlib.Path('E:/antigravity-cli/agy.exe');assert cli.is_file()
version=subprocess.run([str(cli),'--version'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
assert version.returncode==0,version.stderr
# 실제 pinned registry source를 metadata로 찾은 뒤 필요한 time 원문만 W 내부에 복사한다.
metadata=subprocess.run(['cargo','metadata','--offline','--locked','--format-version','1','--filter-platform','x86_64-pc-windows-msvc'],cwd=B,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60)
assert metadata.returncode==0,metadata.stderr
packages=json.loads(metadata.stdout)['packages'];tokio=next(p for p in packages if p['name']=='tokio' and p['version']=='1.52.3')
tokio_root=pathlib.Path(tokio['manifest_path']).parent
assert all(sha(B/n)==h for n,h in b['tracked_source_sha256'].items())
traces={}
for i in range(2):
 trace=pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/delegation/live/deleg_015c4753')/f'task-{i}.log'
 assert 'end status=completed exit_reason=completed' in trace.read_text(encoding='utf-8')[-500:];traces[str(trace)]=sha(trace)
review={'representation':'parent normalized received read-only designs, not reconstructed verbatim results',
 'design_batch':'deleg_015c4753','selected_architecture':['native runtime once mode first, old CPU-only behavior retained','typed presenter execution bridge; no general state_mut API','new run selector separate from unchanged input-only selector','entry caller remains non-UI owner; dedicated UI thread returns original session to entry for final drain','owned WindowGuard outside recovery boundary; recover session even when UI context must remain attached','result renderer pure and bounded; no UI filters/files/clipboard in first vertical slice'],
 'current_implementation_scope':'two independent atoms only; no GUI/native backend wiring yet',
 'root_main_counts':main['receiving_root_workspace_counts'],'combined_wip_counts':b['workspace_counts'],
 'specific_visible_input_permission_timeout_respected':True,'no_whole_product_acceptance':True}
specs={'qgruntime':{'writes':['apps/network-quick-check/src/gui_coordinator.rs','apps/network-quick-check/src/gui_coordinator_tests.rs'],'contract':'qg3d-native-runtime-contract-v0.1.md','registration_after_audit_by_parent':None},
 'qgrender':{'writes':['apps/network-quick-check/src/gui_result_render.rs'],'contract':'qg3d-result-render-contract-v0.1.md','registration_after_audit_by_parent':'pub mod gui_result_render;'}}
roles={}
for role,spec in specs.items():
 W=R/'.worktrees'/role;assert not W.exists();assert not(R/'.harness/runs'/(stage+'-'+role)).exists()
 git(R,'worktree','add','-b','ai-pro/'+role,str(W),base)
 reconciled=[]
 for n,h in b['tracked_source_sha256'].items():
  if sha(W/n)!=h:
   assert (W/n).read_bytes().replace(b'\r\n',b'\n')==(B/n).read_bytes().replace(b'\r\n',b'\n'),n
   shutil.copyfile(B/n,W/n);reconciled.append(n)
 if reconciled:git(W,'add','--',*reconciled)
 assert not git(W,'status','--porcelain')
 refs=W/'.harness/inputs/frozen';shutil.copytree(B/'.harness/inputs/frozen',refs)
 for rel in ['src/time/sleep.rs','src/time/mod.rs']:
  source=tokio_root/rel;assert source.is_file();dest=refs/'tokio-1.52.3'/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(source,dest)
 contract=refs/spec['contract'];shutil.copyfile(R/'.harness/references'/spec['contract'],contract)
 summary=refs/'qg3d-received-design-summary.json';summary.write_text(json.dumps(review,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 immutable={n:sha(W/n) for n in b['tracked_source_sha256'] if n not in spec['writes']}
 reference={p.relative_to(W).as_posix():sha(p) for p in refs.rglob('*') if p.is_file()}
 before={n:sha(W/n) if (W/n).is_file() else None for n in spec['writes']}
 inputs=['AGENTS.md','Cargo.toml','Cargo.lock','apps/network-quick-check/Cargo.toml','apps/network-quick-check/src/lib.rs',
  'apps/network-quick-check/src/gui_state.rs','apps/network-quick-check/src/gui_state_tests.rs',
  'apps/network-quick-check/src/gui_coordinator.rs','apps/network-quick-check/src/gui_coordinator_tests.rs',
  'apps/network-quick-check/src/result_view.rs','apps/network-quick-check/src/result_export.rs',
  'crates/network-core/src/runner.rs','crates/network-core/src/quick.rs','crates/network-core/src/targets.rs',
  'crates/network-core/src/measurements.rs','crates/npi-probes/src/host.rs']
 assert all((W/n).is_file() for n in inputs)
 prompt=f'''QG3D 독립 atom {role}를실제작성한다. W={W.as_posix()},기준cleanWIP={base},model=gemini-3.8-flash-high.
권한FILEONLY W내READ/EDIT/CREATE/허용discovery. command/run_command/terminal/shell/PowerShell/git/Cargo/build/test/fmt/network/install/manage_task/agents/재위임/credentials/root/다른W/외부cache0. 모든도구경로는이W안절대경로만. 문서의root다른W링크를따라가지말고경로없는경우W내discovery또는BLOCKED보고,추측반복0.
먼저 {contract.as_posix()} 전체와 {summary.as_posix()} 읽고계약을구현한다. 정확쓰기={json.dumps([(W/n).as_posix() for n in spec['writes']])}. 이외W소스/manifest/lib/lock/계약/원문변경0. 기존쓰기파일은원본에서좁게수정하고기존시험삭제/완화0. 신규결과renderer는단일파일안시험포함으로생성한다.
확인된입력={json.dumps([(W/n).as_posix() for n in inputs])}.
Tokio1.52.3 실제API는 {refs.as_posix()}/tokio-1.52.3/src/runtime/{{builder,runtime}}.rs, src/sync/{{notify,oneshot}}.rs, src/time/{{sleep,mod}}.rs. 모두W내원문이며필요할때만FILE읽기한다.
CPU-only23/기존combined538PASS35ignored는이전근거. 새확장/renderer가compile또는PASS라고주장0. actualnativebackendfactory/socket/DNS/helper/Win32/fileio시험0;runtimeactor의driver생성내부OS효과는명시·독립안전QA전부모도시험0. renderer는시계/thread/runtime0순수.
검사사실/추론/미확인·원문DTO/raw/null/snapshot/한건채널/samecancel·Failed drain/정확Empty재독/UTF8상한불변을보존한다. lintallow/stub/가짜진행률/원시panicpayload반사0.
종료시변경정확경로/API·작성시험명/미검증/제약을한국어로보고,명령·시험실행0을명시한다. 부모가감사/compile-only/독립QA/실회귀한다.
'''
 pp=R/'.harness/prompts'/(stage+'-'+role+'.md');assert not pp.exists();pp.write_text(prompt,encoding='utf-8',newline='\n')
 roles[role]={'worktree':str(W),'branch':'ai-pro/'+role,'actor_writes':spec['writes'],'immutable_sha256':immutable,'reference_sha256':reference,'before_source_sha256':before,
  'contract':str(contract),'prompt':str(pp),'registration_after_audit_by_parent':spec['registration_after_audit_by_parent'],'newline_restored_paths':reconciled}
assert all(sha(R/n)==h for n,h in root_before.items())
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'stage':stage,'model':'gemini-3.8-flash-high','base_commit':base,'base_worktree':str(B),
 'cli_path':str(cli),'cli_version':(version.stdout+version.stderr).strip(),'cli_sha256':sha(cli),'permission_settings_changed':False,'audit_is_not_os_enforced_sandbox':True,
 'roles':roles,'root_before_sha256':root_before,'review_batch':'deleg_015c4753','review_trace_sha256':traces,'parent_normalized_design':review,
 'actor_started':False,'source_compiled':False,'tests_executed':False,'native_executed':False,'root_integrated':False,'accepted':False,'product_accepted':False}
OUT.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'stage':stage,'base':base,'cli_version':record['cli_version'],'roles':{r:{'worktree':s['worktree'],'immutable':len(s['immutable_sha256']),'references':len(s['reference_sha256']),'writes':s['actor_writes']} for r,s in roles.items()},'source_compiled':False},ensure_ascii=False))
