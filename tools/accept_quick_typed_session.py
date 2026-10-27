"""QG3E typed session와 전달보존의 검증된 범위만 로컬 보존한다."""
import datetime,hashlib,json,pathlib,re,subprocess
R=pathlib.Path(__file__).resolve().parents[1];W=R/'.worktrees/qgbridge'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def load(n):return json.loads((R/n).read_text(encoding='utf-8'))
def git(*args):
 p=subprocess.run(['git','-C',str(W),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=90)
 assert p.returncode==0,p.stderr
 return p.stdout.rstrip('\r\n')
def command(n):
 c=load('artifacts/commands/'+n+'.json');assert c['exit_code']==0 and not c['partial']
 text=pathlib.Path(c['log']).read_text(encoding='utf-8')
 rows=re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;',text)
 if rows:c['counts']={k:sum(int(x[i]) for x in rows) for i,k in enumerate(['passed','failed','ignored'])}
 return c
out=R/'artifacts/qg3e-typed-session-acceptance.json';assert not out.exists()
p=load('artifacts/qg3e-session-bridge-prepared.json')
paths=p['actor_writes']+['apps/network-quick-check/src/gui_coordinator_tests.rs','apps/network-quick-check/src/lib.rs']
assert set(x[3:] for x in git('status','--porcelain').splitlines())==set(paths)
assert all(sha(W/n)==h for n,h in p['immutable_sha256'].items() if n not in paths)
assert all(sha(W/n)==h for n,h in p['reference_sha256'].items())
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
old=(R/'.harness/evidence/qg3e-before-session-delivery/gui_coordinator_tests.rs').read_bytes()
assert (W/'apps/network-quick-check/src/gui_coordinator_tests.rs').read_bytes().startswith(old)
commands={n:command(n) for n in ['qg3e-session19-focused','qg3e-delivery-focused3','qg3e-delivery-final-workspace','qg3e-delivery-final-clippy','qg3e-delivery-final-fmt-check']}
assert commands['qg3e-session19-focused']['counts']==dict(passed=19,failed=0,ignored=0)
assert commands['qg3e-delivery-focused3']['counts']==dict(passed=3,failed=0,ignored=0)
assert commands['qg3e-delivery-final-workspace']['counts']==dict(passed=593,failed=0,ignored=35)
source={n:sha(W/n) for n in paths}
git('add','--',*paths);git('diff','--cached','--check')
git('commit','-m','feat(quick-check): preserve typed GUI session lifecycle and whole runner delivery')
commit=git('rev-parse','HEAD');assert not git('status','--porcelain')
record=dict(recorded_at=datetime.datetime.now().astimezone().isoformat(),status='ACCEPTED_TYPED_SESSION_AND_MEMORY_BACKEND_DELIVERY_ONLY',accepted=True,worktree=str(W),branch=git('branch','--show-current'),preserved_commit=commit,worktree_clean=True,source_sha256=source,commands=commands,workspace_counts=commands['qg3e-delivery-final-workspace']['counts'],focused_session_counts=commands['qg3e-session19-focused']['counts'],focused_delivery_counts=commands['qg3e-delivery-focused3']['counts'],independent_reviews=['deleg_0b56c9b3','deleg_e5b933fb','deleg_7c92901a','deleg_b7d7d1db'],unwind_negative_evidence='artifacts/qg3e-session-unwind-negative.json',writer_credit='Flash exact3 draft plus parent compile/test repairs and tests-only delivery regressions; independent read-only QA',nonblocking_session_api=True,single_presenter_owner=True,pre_send_same_run_full_result_equality=True,cpu_init_error_is_not_core_error=True,core_top_error_structurally_unreachable_from_valid_snapshot=True,limitations=['memory backend plus CPU runtime only; thread/channel/clock effects exist','fresh-closed-host NotAccepting witness is not Full/Disconnected injection','unwind witness certifies physical drain, not necessarily normal Closed; normal close cases separately assert Closed','session and coordinator still cfg(test); no GUI execution integration','no native network or OS-wide compatibility certification'],root_integrated=False,gui_connected=False,full_qg3_accepted=False,product_accepted=False,remote_push_or_deploy=False)
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:record[k] for k in ['status','preserved_commit','workspace_counts','focused_session_counts','focused_delivery_counts','gui_connected']},ensure_ascii=False))
