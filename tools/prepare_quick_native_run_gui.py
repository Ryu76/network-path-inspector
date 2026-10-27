"""검증된 typed facade 기준을 봉인하고 실행GUI의 entry/UI 독립 FILE writer를 준비한다."""
import datetime,hashlib,json,pathlib,re,shutil,subprocess,sys
R=pathlib.Path(__file__).resolve().parents[1];B=R/'.worktrees/qgguirun'
sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
def load(n):return json.loads((R/n).read_text(encoding='utf-8'))
def git(w,*args):
 p=subprocess.run(['git','-C',str(w),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=90)
 assert p.returncode==0,p.stderr
 return p.stdout.rstrip('\r\n')
def checked(n):
 c=load('artifacts/commands/'+n+'.json');assert c['exit_code']==0 and not c['partial'];return c
OUT=R/'artifacts/qg3f-native-run-gui-prepared.json';assert not OUT.exists()
foundation=load('artifacts/qg3e-typed-session-acceptance.json')
assert git(B,'rev-parse','HEAD')==foundation['preserved_commit']
changes=['apps/network-quick-check/src/gui_presenter.rs','apps/network-quick-check/src/gui_run_session.rs','apps/network-quick-check/src/gui_run_session_tests.rs']
assert set(x[3:] for x in git(B,'status','--porcelain').splitlines())==set(changes)
for n,h in foundation['source_sha256'].items():
 if n not in changes:assert sha(B/n)==h,n
commands={n:checked(n) for n in ['qg3f-facade-v2-workspace','qg3f-facade-v2-clippy','qg3f-parallel-harness']}
text=pathlib.Path(commands['qg3f-facade-v2-workspace']['log']).read_text(encoding='utf-8')
rows=re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;',text)
counts={k:sum(int(x[i]) for x in rows) for i,k in enumerate(['passed','failed','ignored'])}
assert counts==dict(passed=594,failed=0,ignored=35),counts
assert 'Ran 65 tests' in pathlib.Path(commands['qg3f-parallel-harness']['log']).read_text(encoding='utf-8')
git(B,'add','--',*changes);git(B,'diff','--cached','--check')
git(B,'commit','-m','WIP: add guarded UI session facade and separate execution plan preview before native wiring')
commit=git(B,'rev-parse','HEAD');assert not git(B,'status','--porcelain')
tracked={n:sha(B/n) for n in git(B,'ls-files').splitlines() if (B/n).is_file()}
prior=load('artifacts/qg3e-session-bridge-prepared.json')
assert all(sha(R/n)==h for n,h in prior['root_before_sha256'].items())
# 실제 설치 target으로 한정한 locked/offline discovery. actor 시작 전이며 lock 변경0.
lock=sha(B/'Cargo.lock')
meta=subprocess.run(['cargo','metadata','--offline','--locked','--format-version','1','--filter-platform','x86_64-pc-windows-msvc'],cwd=B,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60)
assert meta.returncode==0,meta.stderr
assert sha(B/'Cargo.lock')==lock
packages=json.loads(meta.stdout)['packages'];windows=next(x for x in packages if x['name']=='windows-sys' and x['version']=='0.61.2')
bindings=pathlib.Path(windows['manifest_path']).parent/'src/Windows/Win32/UI/WindowsAndMessaging/mod.rs'
selected=[]
for i,line in enumerate(bindings.read_text(encoding='utf-8').splitlines(),1):
 if re.search(r'fn (SetTimer|KillTimer|GetMessageW|PostMessageW|PostQuitMessage|DestroyWindow|SetWindowLongPtrW|GetWindowLongPtrW|IsDialogMessageW)\b|pub (const WM_TIMER|type TIMERPROC)',line):selected.append(f'{i}: {line}')
assert any('SetTimer' in x for x in selected) and any('TIMERPROC' in x for x in selected)
cli=pathlib.Path('E:/antigravity-cli/agy.exe');assert cli.is_file()
roles={
 'qgrunentry':['apps/network-quick-check/src/gui_run_entry.rs','apps/network-quick-check/src/gui_run_entry_tests.rs'],
 'qgrunui':['apps/network-quick-check/src/native_gui.rs','apps/network-quick-check/src/native_gui_tests.rs'],
}
stage='qg3frungui';record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'stage':stage,'model':'gemini-3.8-flash-high','base_commit':commit,'base_worktree':str(B),'base_workspace_counts':counts,'tracked_source_sha256':tracked,'root_before_sha256':prior['root_before_sha256'],'cli_path':str(cli),'cli_sha256':sha(cli),'cli_version':'1.4.7','roles':{},'commands':commands,'source_compiled':False,'tests_executed':False,'gui_connected':False,'accepted':False,'product_accepted':False}
inputs=['AGENTS.md','Cargo.toml','Cargo.lock','apps/network-quick-check/Cargo.toml','apps/network-quick-check/src/lib.rs','apps/network-quick-check/src/main.rs','apps/network-quick-check/src/gui_entry.rs','apps/network-quick-check/src/gui_presenter.rs','apps/network-quick-check/src/gui_run_session.rs','apps/network-quick-check/src/gui_run_session_tests.rs','apps/network-quick-check/src/gui_coordinator.rs','apps/network-quick-check/src/gui_coordinator_tests.rs','apps/network-quick-check/src/gui_state.rs','apps/network-quick-check/src/gui_result_render.rs','apps/network-quick-check/src/result_view.rs','apps/network-quick-check/src/native_gui.rs','apps/network-quick-check/src/native_gui_tests.rs','crates/network-core/src/runner.rs','crates/network-core/src/quick.rs','crates/network-core/src/targets.rs']
for role,writes in roles.items():
 W=R/'.worktrees'/role;assert not W.exists()
 git(R,'worktree','add','-b','ai-pro/'+role,str(W),commit)
 reconciled=[]
 for n,h in tracked.items():
  if sha(W/n)!=h:
   assert (W/n).read_bytes().replace(b'\r\n',b'\n')==(B/n).read_bytes().replace(b'\r\n',b'\n'),n
   shutil.copyfile(B/n,W/n);reconciled.append(n)
 if reconciled:git(W,'add','--',*reconciled)
 assert not git(W,'status','--porcelain')
 refs=W/'.harness/inputs/frozen';shutil.copytree(B/'.harness/inputs/frozen',refs)
 contract=refs/'qg3f-native-run-gui-contract-v0.1.md';shutil.copyfile(R/'.harness/references'/contract.name,contract)
 api=refs/'windows-sys-0.61.2-ui-selected-bindings.txt';api.write_text('Pinned WindowsAndMessaging declarations (source line numbers)\n'+'\n'.join(selected)+'\n',encoding='utf-8')
 summary=refs/'qg3f-native-run-gui-baseline-summary.json';summary.write_text(json.dumps({'commit':commit,'workspace_counts':counts,'gui_execution_connected':False,'new_actor_outputs_not_compiled':True},indent=2)+'\n',encoding='utf-8')
 assert all((W/n).is_file() for n in inputs)
 immutable={n:h for n,h in tracked.items() if n not in writes};reference={f.relative_to(W).as_posix():sha(f) for f in refs.rglob('*') if f.is_file()}
 purpose='caller 슬롯소유·전용 UIthread·원session회수/nonUI최종drain·새정확selector dispatcher 신규2파일' if role=='qgrunentry' else '기존 입력모드보존·Run slot모드·실Start/Stop/Close/timer·실결과renderer/안전창수명 및 ignored memory native시험 기존2파일'
 prompt=f'''QG3F 실제검사 GUI연결 중 {purpose}을 실제작성. W={W.as_posix()},role={role},model=gemini-3.8-flash-high. FILEONLY.
먼저 {contract.as_posix()} 전체와 {summary.as_posix()}를 읽고 공통signature/소유/시험/역할범위를그대로따른다. 기존참조문서의오래된범위보다이번3F계약이우선. 원문안root/다른W링크따라읽기금지.
정확쓰기={json.dumps([(W/n).as_posix() for n in writes])}. {'이2파일은신규출력으로아직존재하지않는다. 입력파일로읽지말고생성한다.' if role=='qgrunentry' else '기존2파일이다. 기존input-only동작/기존native4시험삭제·약화0.'}
검증된입력={json.dumps([(W/n).as_posix() for n in inputs])}. pinnedWindowsAPI={api.as_posix()}.
command/run_command/terminal/shell/PowerShell/git/Cargo/fmt/build/test/network/install/manage_task/agents/재위임/credentials/외부root·다른W·cache0. READ/EDIT/CREATE/허용discovery는이W내절대경로만. 없는API는실제manifest/discovery후BLOCKED또는계약에명시된신규API를정확구현. 다른actor신규파일은존재안함/읽지말것. lib등록/cfg승격/기존gui_entry선행분기는종료후부모가한다. production lintallow/stub/빈성공/예상DTO실행위장0.
593기반+부모facade1로실제594PASS35ignored인clean기준이지만너의신규구현검증은0이다. actualCore/원session/同결과snapshot만. HWND/context수명·lock재진입·StartedClosingFailed계속drain·no-native-before-Start 핵심. nativefactory는Start try_start_with closure안에만,기본시험은CPU메모리/직접Win320. UI새native시험은전부ignore且CPUmockoverride필수. 필요worker정리는실종료관측,Drop취소요청을즉시정리완료라하지말것.
한국어UI/주석·UTF8끝개행/후행공백0. 종료시변경정확경로/구현API/작성시험명/미검증·한계를보고. 명령/컴파일/시험실행은0이고PASS/제품완료를주장하지말것.'''
 pp=R/'.harness/prompts'/(stage+'-'+role+'.md');assert not pp.exists();pp.write_text(prompt,encoding='utf-8',newline='\n')
 record['roles'][role]={'worktree':str(W),'branch':'ai-pro/'+role,'actor_writes':writes,'immutable_sha256':immutable,'reference_sha256':reference,'before_source_sha256':{n:sha(W/n) if (W/n).is_file() else None for n in writes},'prompt':str(pp),'registration_after_audit_by_parent':'combine outputs, register gui_run_entry, promote cfg and add exact new selector branch; compile-only then safety review','newline_restored_paths':reconciled}
assert all(sha(R/n)==h for n,h in record['root_before_sha256'].items())
OUT.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':'PREPARED_TWO_NATIVE_RUN_GUI_WRITERS_NOT_STARTED','commit':commit,'base_counts':counts,'stage':stage,'roles':{k:{'worktree':v['worktree'],'immutable':len(v['immutable_sha256']),'references':len(v['reference_sha256'])} for k,v in record['roles'].items()}},ensure_ascii=False))
