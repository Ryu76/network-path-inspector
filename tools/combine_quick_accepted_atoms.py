"""검증된 runtime2와 renderer1+lib선언을 후속 GUI 전용 WIP에 정확 선택 조합한다."""
import datetime,hashlib,json,pathlib,shutil,subprocess
R=pathlib.Path(__file__).resolve().parents[1];sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
def load(n):return json.loads((R/n).read_text(encoding='utf-8'))
def git(w,*args):
 p=subprocess.run(['git','-C',str(w),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60);assert p.returncode==0,p.stderr;return p.stdout.rstrip('\r\n')
b=load('artifacts/qg3d-gui-wiring-baseline.json');W=pathlib.Path(b['worktree']);runtime=load('artifacts/qg3d-native-runtime-acceptance.json');render=load('artifacts/qg3d-pure-renderer-acceptance.json')
OUT=R/'artifacts/qg3d-accepted-atoms-combination.json';assert not OUT.exists()
assert git(W,'rev-parse','HEAD')==b['commit'] and not git(W,'status','--porcelain')
assert all(sha(W/n)==h for n,h in b['tracked_source_sha256'].items())
root=load('artifacts/qg3d-runtime-render-prepared.json')['root_before_sha256'];assert all(sha(R/n)==h for n,h in root.items())
sources={}
for acceptance in [runtime,render]:
 assert acceptance['accepted'] and not acceptance['root_integrated'] and not acceptance['gui_connected']
 source=pathlib.Path(acceptance['worktree']);assert git(source,'rev-parse','HEAD')==acceptance['preserved_commit'] and not git(source,'status','--porcelain')
 assert all(sha(source/n)==h for n,h in acceptance['source_sha256'].items())
 for n,h in acceptance['source_sha256'].items():assert n not in sources;sources[n]={'source':str(source/n),'sha256':h}
saved=R/'.harness/evidence/qg3d-combined-before-accepted-atoms';saved.mkdir(parents=True,exist_ok=False)
for n,row in sources.items():
 if(W/n).exists():shutil.copyfile(W/n,saved/pathlib.Path(n).name)
 else:assert n=='apps/network-quick-check/src/gui_result_render.rs'
 shutil.copyfile(pathlib.Path(row['source']),W/n);assert sha(W/n)==row['sha256']
assert set(line[3:] for line in git(W,'status','--porcelain').splitlines())==set(sources)
assert all(sha(W/n)==h for n,h in b['tracked_source_sha256'].items() if n not in sources)
for name in ['qg3d-native-runtime-contract-v0.1.md','qg3d-result-render-contract-v0.1.md']:
 dest=W/'.harness/inputs/frozen'/name;assert not dest.exists();shutil.copyfile(R/'.harness/references'/name,dest)
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'ACCEPTED_ATOMS_SELECTED_INTO_GUI_WIP_PENDING_RECEIVING_REGRESSION',
 'worktree':str(W),'branch':b['branch'],'base_commit':b['commit'],'selected_source':sources,
 'immutable_base_sha256':{n:h for n,h in b['tracked_source_sha256'].items() if n not in sources},'root_before_sha256':root,
 'runtime_acceptance':'artifacts/qg3d-native-runtime-acceptance.json','renderer_acceptance':'artifacts/qg3d-pure-renderer-acceptance.json',
 'root_integrated':False,'gui_runner_connected':False,'native_backend_measurement_done':False,'gui_input_wip_visibly_accepted':False,
 'coordinator_module_still_cfg_test_only':True,'product_accepted':False,'accepted':False}
OUT.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':record['status'],'paths':list(sources),'root_integrated':False,'gui_connected':False},ensure_ascii=False))
