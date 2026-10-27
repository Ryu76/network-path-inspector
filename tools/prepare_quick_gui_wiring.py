"""GUI 후속 연결용 전용 WIP 기준을 조합한다. 기존 입력전용 화면 의미는 바꾸지 않는다."""
import datetime,hashlib,json,pathlib,shutil,subprocess
R=pathlib.Path(__file__).resolve().parents[1];sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
def load(n):return json.loads((R/n).read_text(encoding='utf-8'))
def git(w,*args):
 r=subprocess.run(['git','-C',str(w),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60)
 assert r.returncode==0,r.stderr;return r.stdout.rstrip('\r\n')
host=load('artifacts/qg3c-coordinator-host-acceptance.json');result=load('artifacts/qg5a-pure-result-acceptance.json');base=pathlib.Path(host['worktree'])
W=R/'.worktrees/qgguirun';OUT=R/'artifacts/qg3d-gui-wiring-prepared.json';assert not W.exists() and not OUT.exists()
assert host['accepted'] and not host['root_integrated'] and result['accepted'] and result['root_integrated']
assert git(base,'rev-parse','HEAD')==host['preserved_commit'] and not git(base,'status','--porcelain')
assert all(sha(base/n)==h for n,h in host['source_sha256'].items())
assert all(sha(R/n)==h for n,h in result['source_sha256'].items())
tracked=[n for n in git(base,'ls-files','-z').split('\0') if n and (base/n).is_file()]
base_sha={n:sha(base/n) for n in tracked};git(R,'worktree','add','-b','ai-pro/qgguirun',str(W),host['preserved_commit'])
normalized=[]
for name,h in base_sha.items():
 if sha(W/name)!=h:
  assert (W/name).read_bytes().replace(b'\r\n',b'\n')==(base/name).read_bytes().replace(b'\r\n',b'\n')
  shutil.copyfile(base/name,W/name);normalized.append(name)
if normalized:git(W,'add','--',*normalized)
assert not git(W,'status','--porcelain')
files=['apps/network-quick-check/src/result_view.rs','apps/network-quick-check/src/result_export.rs']
for name in files:assert not (W/name).exists();shutil.copyfile(R/name,W/name)
lib=W/'apps/network-quick-check/src/lib.rs';text=lib.read_text(encoding='utf-8');anchor='pub mod gui_state;\n';assert text.count(anchor)==1
lib.write_text(text.replace(anchor,anchor+'pub mod result_export;\npub mod result_view;\n',1),encoding='utf-8',newline='\n')
refs=W/'.harness/inputs/frozen';shutil.copytree(base/'.harness/inputs/frozen',refs)
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'COMBINED_BASELINE_PREPARED_NOT_GUI_EXECUTION_IMPLEMENTATION',
 'worktree':str(W),'branch':'ai-pro/qgguirun','base_host_commit':host['preserved_commit'],
 'host_acceptance':'artifacts/qg3c-coordinator-host-acceptance.json','result_acceptance':'artifacts/qg5a-pure-result-acceptance.json',
 'gui_input_source_origin':'qgguiinputs original WIP 0da7720fa3a943f3abeb5a34d0c12c24786bff62 remains not visibly accepted',
 'parent_selected_combination_paths':['apps/network-quick-check/src/lib.rs',*files],'source_sha256':{n:sha(W/n) for n in ['apps/network-quick-check/src/lib.rs',*files,*host['source_sha256']]},
 'root_source_frozen_sha256':result['source_sha256'],'base_source_sha256':base_sha,'newline_reconciled_paths':normalized,
 'actor_started':False,'gui_runner_connected':False,'root_integrated':False,'accepted':False,'product_accepted':False,
 'specific_ui_approval_timeout_preserved':True,'normal_noargs_help_and_inputs_selector_unchanged':True,'new_dependencies':False}
OUT.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':record['status'],'worktree':str(W),'combined_paths':record['parent_selected_combination_paths'],'root_integrated':False},ensure_ascii=False))
