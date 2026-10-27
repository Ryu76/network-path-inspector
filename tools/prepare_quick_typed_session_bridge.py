"""검증된571 기준에서 typed presenter/session 전용 clean FILE ONLY writer를 준비한다."""
import datetime,hashlib,json,pathlib,shutil,subprocess
R=pathlib.Path(__file__).resolve().parents[1];sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
def load(n):return json.loads((R/n).read_text(encoding='utf-8'))
def git(w,*args):
 p=subprocess.run(['git','-C',str(w),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60);assert p.returncode==0,p.stderr;return p.stdout.rstrip('\r\n')
b=load('artifacts/qg3e-session-bridge-baseline.json');B=pathlib.Path(b['worktree']);role='qgbridge';stage='qg3esession';W=R/'.worktrees'/role
OUT=R/'artifacts/qg3e-session-bridge-prepared.json';assert not OUT.exists() and not W.exists()
assert git(B,'rev-parse','HEAD')==b['commit'] and not git(B,'status','--porcelain');assert all(sha(B/n)==h for n,h in b['tracked_source_sha256'].items())
assert all(sha(R/n)==h for n,h in b['root_before_sha256'].items())
prior=load('artifacts/qg3d-runtime-render-prepared.json');cli=pathlib.Path(prior['cli_path']);assert cli.is_file() and sha(cli)==prior['cli_sha256']
writes=['apps/network-quick-check/src/gui_presenter.rs','apps/network-quick-check/src/gui_run_session.rs','apps/network-quick-check/src/gui_run_session_tests.rs']
git(R,'worktree','add','-b','ai-pro/'+role,str(W),b['commit']);reconciled=[]
for n,h in b['tracked_source_sha256'].items():
 if sha(W/n)!=h:
  assert (W/n).read_bytes().replace(b'\r\n',b'\n')==(B/n).read_bytes().replace(b'\r\n',b'\n'),n
  shutil.copyfile(B/n,W/n);reconciled.append(n)
if reconciled:git(W,'add','--',*reconciled)
assert not git(W,'status','--porcelain')
refs=W/'.harness/inputs/frozen';shutil.copytree(B/'.harness/inputs/frozen',refs)
contract=refs/'qg3e-typed-session-bridge-contract-v0.1.md';shutil.copyfile(R/'.harness/references'/contract.name,contract)
inputs=['AGENTS.md','Cargo.toml','Cargo.lock','apps/network-quick-check/Cargo.toml','apps/network-quick-check/src/lib.rs',
 'apps/network-quick-check/src/gui_presenter.rs','apps/network-quick-check/src/gui_presenter_tests.rs','apps/network-quick-check/src/gui_state.rs','apps/network-quick-check/src/gui_state_tests.rs',
 'apps/network-quick-check/src/gui_coordinator.rs','apps/network-quick-check/src/gui_coordinator_tests.rs','apps/network-quick-check/src/gui_result_render.rs',
 'apps/network-quick-check/src/result_view.rs','apps/network-quick-check/src/result_export.rs',
 'crates/network-core/src/runner.rs','crates/network-core/src/quick.rs','crates/network-core/src/targets.rs','crates/network-core/src/measurements.rs','crates/npi-probes/src/host.rs']
assert all((W/n).is_file() for n in inputs);assert not(W/writes[1]).exists() and not(W/writes[2]).exists()
immutable={n:sha(W/n) for n in b['tracked_source_sha256'] if n not in writes};reference={f.relative_to(W).as_posix():sha(f) for f in refs.rglob('*') if f.is_file()}
prompt=f'''QG3E typed presenter bridge/단일소유 실행session을실제작성한다. W={W.as_posix()},기준cleanWIP={b['commit']},model=gemini-3.8-flash-high.
FILEONLY W내READ/EDIT/CREATE/허용discovery. command/run_command/terminal/shell/PowerShell/git/Cargo/fmt/build/test/network/install/manage_task/agents/재위임/credentials/root/다른W/외부cache0. 모든tool경로는이W안절대경로. 원문링크/JSON의외부root/다른W경로따라읽기0. 입력누락은W내discovery또는BLOCKED보고.
먼저 {contract.as_posix()} 전체및 {(refs/'qg3e-session-bridge-baseline-summary.json').as_posix()} 읽고고정API/범위를따른다. 이조합571/35ignored는이전검증이며새session PASS아님. 기존QG3C/QG3D계약은역사범위이며최신3E계약이이번쓰기범위.
쓰기정확3={json.dumps([(W/n).as_posix() for n in writes])}. 첫presenter는기존소스수정,나머지2개는신규생성이다. lib등록은actor종료후부모만. 기존presenter본문/시험/API동작보존·새typed실행타입/impl은cfg(test)한정,범용state_mut/외부mutableclosure0. GuiState/Core/coordinator/renderer/기존결과/nativeGUI/entry/Cargo/lock/계약/PRD수정0.
검증된입력={json.dumps([(W/n).as_posix() for n in inputs])}.
opaquePreparedRunCandidate를clone+confirm_plan으로만만들고trustedfreshhost factory는유효candidate뒤최초1회만. enqueue성공시에만原presenter확정. Session은原presenter와Optionhost한소유,복제GuiState/runner0. typed편집은Busy/Closing/Failed에서거부,readonlyaccess만노출. cancel은의사·poll은실Core완료·report+completedSnapshot원문귀속·Failed계속drain·닫기멱등/原context보존. close/nohost는진단결과를만들지않는다. 명시일치snapshot을현재draft/clock/hostname으로발명0.
기본시험은기존CPU-onlyGuiRunCoordinator::spawn에주입하는memoryBackend만. native_backend_for_current_exe/spawn_native/실socket/DNS/helper/Win32/file/environment0. stdthread/CPU-runtime/시간관측은의도효과. 실제Core run_quick과실제projector재사용,예상DTO만으로실행했다고위장0. async firstPollPending/cleanupRelease명시handshake·host/start전releaseRAII·실worker/channel최종종료·전체Presenter/Result/Snapshot·factory호출수/ID 불소비 검증작성. fixedsleep/고정yield횟수/무한join/missingfixture earlysuccess0.
이번은cfgtest연결준비층이지Win32 Start/Stop/새selector/nonUIentry최종drainowner/OS제품수용아님. 실제UI와종료소유권전체를구현했다고주장0. 한국어주석/설명·UTF8끝개행/후행공백0·lintallow/stub/약화시험0.
종료시정확3파일/API·시험명·未검증제약을한국어반환. 명령/빌드/실시험실행0을명시하며PASS발명0. 부모가source보존/감사/등록/compile-only/독립안전QA/실시험한다.
'''
pp=R/'.harness/prompts'/(stage+'-'+role+'.md');assert not pp.exists();pp.write_text(prompt,encoding='utf-8',newline='\n')
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'stage':stage,'role':role,'model':'gemini-3.8-flash-high','worktree':str(W),'branch':'ai-pro/'+role,
 'base_commit':b['commit'],'base_worktree':str(B),'base_workspace_counts':b['workspace_counts'],'actor_writes':writes,'immutable_sha256':immutable,'reference_sha256':reference,
 'before_source_sha256':{n:sha(W/n) if(W/n).is_file() else None for n in writes},'root_before_sha256':b['root_before_sha256'],'prompt':str(pp),'contract':str(contract),
 'registration_after_audit_by_parent':'#[cfg(test)] mod gui_run_session;','newline_restored_paths':reconciled,'cli_sha256':prior['cli_sha256'],'cli_version':prior['cli_version'],
 'permission_settings_changed':False,'actor_started':False,'compiled':False,'tests_executed':False,'gui_connected':False,'root_integrated':False,'accepted':False,'product_accepted':False}
assert all(sha(R/n)==h for n,h in record['root_before_sha256'].items())
OUT.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'stage':stage,'worktree':str(W),'base':b['commit'],'immutable_inputs':len(immutable),'references':len(reference),'source_scope':writes,'compiled':False},ensure_ascii=False))
