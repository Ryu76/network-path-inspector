"""검증된 개발 GUI EXE 한 개만 소유·감독한다(네트워크 진단은 미연결)."""
import datetime,hashlib,json,pathlib,subprocess,sys
R=pathlib.Path(__file__).resolve().parents[1]
load=lambda p:json.loads((R/p).read_text(encoding='utf-8'))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
p=load('artifacts/qg3b-gui-inputs-parent-repair.json');W=pathlib.Path(p['worktree'])
review=load('artifacts/qg3b-gui-inputs-final-independent-review.json')
assert review['native_review']['safe_to_execute_owned_native_tests']
assert all(sha(W/n)==h for n,h in p['source_sha256'].items())
exe=R/'.harness/targets/qg3b-gui-inputs-shared/debug/NetworkQuickCheck.exe';assert exe.is_file()
out=R/'artifacts/qg3b-gui-inputs-visible-process.json';assert not out.exists()
folder=R/'.harness/evidence/qg3b-visible';folder.mkdir(parents=True,exist_ok=True)
state={'started_at':datetime.datetime.now().astimezone().isoformat(),'status':'OWNED_VISIBLE_GUI_RUNNING_NOT_ACCEPTED',
 'executable':str(exe),'binary_sha256':sha(exe),'source_sha256':p['source_sha256'],
 'args':['--dev-gui-inputs-v1'],'timeout_seconds':900,'network_diagnostics_connected':False,'accepted':False}
with (folder/'stdout.bin').open('wb') as stdout,(folder/'stderr.bin').open('wb') as stderr:
 child=subprocess.Popen([str(exe),'--dev-gui-inputs-v1'],cwd=W,stdout=stdout,stderr=stderr)
 state['pid']=child.pid
 out.write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 try:
  state['exit_code']=child.wait(timeout=900);state['timed_out']=False
 except subprocess.TimeoutExpired:
  child.kill();state['exit_code']=child.wait(timeout=10);state['timed_out']=True
state.update(status='OWNED_VISIBLE_GUI_EXITED' if state['exit_code']==0 and not state['timed_out'] else 'OWNED_VISIBLE_GUI_FAILED',
 finished_at=datetime.datetime.now().astimezone().isoformat(),child_reaped=True,
 stdout_bytes=(folder/'stdout.bin').stat().st_size,stderr_bytes=(folder/'stderr.bin').stat().st_size)
out.write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(state,ensure_ascii=False));sys.exit(0 if state['status']=='OWNED_VISIBLE_GUI_EXITED' else 1)
