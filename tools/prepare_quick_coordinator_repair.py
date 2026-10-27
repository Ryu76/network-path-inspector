"""실패 원본을 WIP 로컬 커밋에 보존하고 별도 clean 수정 worktree를 준비한다."""
import datetime,hashlib,json,pathlib,shutil,subprocess
R=pathlib.Path(__file__).resolve().parents[1];sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
load=lambda f:json.loads((R/f).read_text(encoding='utf-8'))
p=load('artifacts/qg3c-qg5a-parallel-prepared.json');a=load('artifacts/qg3c-qg5a-parallel-pipeline.json');c=load('artifacts/qg3c-qg5a-original-compile.json')
role='qgcoordfix';stage='qg3cfix';old=pathlib.Path(p['roles']['qgcoordinator']['worktree']);W=R/'.worktrees'/role
OUT=R/'artifacts/qg3c-coordinator-repair-prepared.json';assert not OUT.exists() and not W.exists()
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
assert all(sha(old/n)==h for n,h in a['roles']['qgcoordinator']['source_sha256'].items())
assert sha(old/'apps/network-quick-check/src/lib.rs')==c['roles']['qgcoordinator']['lib_sha256']
for name,h in p['roles']['qgcoordinator']['immutable_sha256'].items():
 if name!='apps/network-quick-check/src/lib.rs':assert sha(old/name)==h
writes=p['roles']['qgcoordinator']['actor_writes'];keep=['apps/network-quick-check/src/lib.rs',*writes]
def git(w,*args):
 r=subprocess.run(['git','-C',str(w),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=75)
 assert r.returncode==0,r.stderr;return r.stdout.rstrip('\r\n')
assert git(old,'rev-parse','HEAD')==p['base_commit']
assert set(line[3:] for line in git(old,'status','--porcelain').splitlines())==set(keep)
git(old,'add','--',*keep);git(old,'diff','--cached','--check')
git(old,'commit','-m','WIP: preserve unaudited-function coordinator original with failed libtest compile')
commit=git(old,'rev-parse','HEAD');assert not git(old,'status','--porcelain')
git(R,'worktree','add','-b','ai-pro/'+role,str(W),commit)
paths=git(old,'ls-files','-z').split('\0');paths=[n for n in paths if n and (old/n).is_file()]
newlines=[]
for name in paths:
 if sha(W/name)!=sha(old/name):
  assert (W/name).read_bytes().replace(b'\r\n',b'\n')==(old/name).read_bytes().replace(b'\r\n',b'\n'),name
  shutil.copyfile(old/name,W/name);newlines.append(name)
if newlines:git(W,'add','--',*newlines)
assert not git(W,'status','--porcelain')
refs=W/'.harness/inputs/frozen';shutil.copytree(old/'.harness/inputs/frozen',refs)
contract=refs/'qg3c-original-review-repair-contract.md';shutil.copyfile(R/'.harness/references'/contract.name,contract)
# exact host DTOを閉じた許容参照として追加する。
assert (W/'crates/npi-probes/src/host.rs').is_file()
immutable={name:sha(W/name) for name in paths if name not in writes}
reference={f.relative_to(W).as_posix():sha(f) for f in refs.rglob('*') if f.is_file()}
traces={}
for i in range(2):
 trace=pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/delegation/live/deleg_e4d98270')/f'task-{i}.log'
 assert 'end status=completed exit_reason=completed' in trace.read_text(encoding='utf-8')[-500:];traces[str(trace)]=sha(trace)
prompt=f'''작업은기존독립QA F01–F10의수정이다. W={W.as_posix()},baseWIP={commit},role={role}.
FILEONLY(read/edit/create·W내discovery)만허용. command/run_command/terminal/PowerShell/git/Cargo/build/test/fmt/network/install/manage_task/agents/재위임/credentials/root/다른W/외부cache0. 모든actor경로는이W안절대경로로만. root링크/문서안다른W경로따라읽기금지.
먼저 {contract.as_posix()} 와 {(refs/'qg3c-coordinator-contract-v0.1.md').as_posix()} 전체읽고필수수정/시험을실제작성하라. 원본실패2개는이미있으며이W에만고쳐라. 쓰기정확2={json.dumps([(W/n).as_posix() for n in writes])}. lib는이미부모cfg(test)등록되었으며읽기만,Cargo/lock/Core/state/기존GUI/CLI/tests/문서수정0. 아래확인된입력만FILE읽기하라.
검증경로={json.dumps([(W/n).as_posix() for n in ['apps/network-quick-check/src/gui_coordinator.rs','apps/network-quick-check/src/gui_coordinator_tests.rs','apps/network-quick-check/src/gui_state.rs','apps/network-quick-check/src/gui_state_tests.rs','apps/network-quick-check/src/lib.rs','apps/network-quick-check/Cargo.toml','crates/network-core/src/runner.rs','crates/network-core/src/quick.rs','crates/network-core/src/targets.rs','crates/network-core/tests/runner.rs','crates/npi-probes/src/host.rs','AGENTS.md','Cargo.toml','Cargo.lock']])}.
Tokio정확원문은 W/.harness/inputs/frozen/tokio-1.52.3/src/runtime/{{builder,runtime}}.rs 와 src/sync/{{notify,oneshot}}.rs에존재한다. 실제API를확인·없으면BLOCKED보고/외부탐색0.
실제Core runner와동일cancelArc·bounded1·start원자성·report/snapshot전체보존·비차단UI/고장drain시험을완성한다. HostSnapshot필드/목록문법수정뿐아니라Failedrecv교착·Empty/finished경쟁·Pendingcancel/drain·실panic/runtimefail/endpoint주입과테스트해제를해결해야한다. timer기능추가/실network/GUI연결0. lintallow/stub/예상PASS발명0.
빌드/시험은절대실행하지말고부모에게정확source경로2·API·F01–F10대응시험이름·미검증제약을한국어로인계. 원본compilefail은보존되었고새통과가아직없으며제품수용0.
'''
pp=R/'.harness/prompts'/(stage+'-'+role+'.md');assert not pp.exists();pp.write_text(prompt,encoding='utf-8',newline='\n')
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'stage':stage,'role':role,'worktree':str(W),'branch':'ai-pro/'+role,'model':p['model'],
 'preserved_original_wip_commit':commit,'preserved_original_worktree':str(old),'preservation_is_not_acceptance':True,'original_compile_exit':101,'original_default_tests_executed':False,
 'actor_writes':writes,'immutable_sha256':immutable,'reference_sha256':reference,'before_source_sha256':{n:sha(W/n) for n in writes},
 'root_before_sha256':p['root_before_sha256'],'prompt':str(pp),'contract':str(contract),'review_batch':'deleg_e4d98270','review_trace_sha256':traces,
 'parent_normalized_review_not_verbatim':True,'newline_restored_paths':newlines,'root_integrated':False,'accepted':False,'product_accepted':False}
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
OUT.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'stage':stage,'worktree':str(W),'original_wip_commit':commit,'immutable_files':len(immutable),'reference_files':len(reference),'root_integrated':False},ensure_ascii=False))
