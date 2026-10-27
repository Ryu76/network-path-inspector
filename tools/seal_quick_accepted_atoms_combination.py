"""검증된 두 atom의 조합 회귀를 고정하고 후속 실행 세션 작업 기준을 만든다."""
import datetime,hashlib,json,pathlib,re,subprocess
R=pathlib.Path(__file__).resolve().parents[1];sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
def load(n):return json.loads((R/n).read_text(encoding='utf-8'))
def save(n,d):(R/n).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def git(w,*args):
 p=subprocess.run(['git','-C',str(w),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60);assert p.returncode==0,p.stderr;return p.stdout.rstrip('\r\n')
p=load('artifacts/qg3d-accepted-atoms-combination.json');W=pathlib.Path(p['worktree']);OUT=R/'artifacts/qg3e-session-bridge-baseline.json';assert not OUT.exists()
assert git(W,'rev-parse','HEAD')==p['base_commit'] and git(W,'branch','--show-current')==p['branch']
assert all(sha(W/n)==h for n,h in p['immutable_base_sha256'].items())
assert all(sha(W/n)==row['sha256'] for n,row in p['selected_source'].items());assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
commands={}
for name in ['qg3d-atoms-combined-workspace','qg3d-atoms-combined-clippy','qg3d-atoms-combined-fmt-check']:
 row=load('artifacts/commands/'+name+'.json');assert row['exit_code']==0 and not row['partial']
 counts=re.findall(r'test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored;',pathlib.Path(row['log']).read_text(encoding='utf-8'))
 if counts:row['counts']={k:sum(int(c[i]) for c in counts) for i,k in enumerate(['passed','failed','ignored'])}
 commands[name]=row
assert commands['qg3d-atoms-combined-workspace']['counts']=={'passed':571,'failed':0,'ignored':35}
paths=list(p['selected_source']);assert set(line[3:] for line in git(W,'status','--porcelain').splitlines())==set(paths)
git(W,'add','--',*paths);git(W,'diff','--cached','--check');git(W,'commit','-m','WIP: combine reviewed runtime configuration and pure renderer for typed GUI session wiring')
commit=git(W,'rev-parse','HEAD');assert not git(W,'status','--porcelain')
tracked=[n for n in git(W,'ls-files','-z').split('\0') if n and (W/n).is_file()]
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'CLEAN_SELECTED_ATOMS_BASELINE_READY_FOR_TYPED_SESSION_BRIDGE',
 'worktree':str(W),'branch':p['branch'],'commit':commit,'worktree_clean':True,'tracked_source_sha256':{n:sha(W/n) for n in tracked},
 'workspace_counts':commands['qg3d-atoms-combined-workspace']['counts'],'commands':commands,
 'runtime_acceptance':p['runtime_acceptance'],'renderer_acceptance':p['renderer_acceptance'],'root_before_sha256':p['root_before_sha256'],
 'first_next_atom':'typed presenter execution candidate/bridge plus single-owned session, still cfg(test)-registered until native UI consumer wiring',
 'next_native_ui_architecture':'dedicated UI thread returns HWND-free original session to entry caller non-UI final drain owner; no post-failure drain thread spawn',
 'no_general_state_mut_api':True,'old_gui_inputs_selector_unchanged':True,'gui_runner_connected':False,'native_backend_measured':False,
 'coordinator_still_cfg_test_only':True,'root_integrated':False,'gui_visibly_accepted':False,'full_qg3_accepted':False,'product_accepted':False,'accepted':False}
save('artifacts/qg3e-session-bridge-baseline.json',record)
ref=W/'.harness/inputs/frozen/qg3e-session-bridge-baseline-summary.json';assert not ref.exists();ref.write_text(json.dumps({k:v for k,v in record.items() if k not in ['tracked_source_sha256','commands','root_before_sha256']},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':record['status'],'commit':commit,'workspace':record['workspace_counts'],'tracked_files':len(tracked),'root_integrated':False,'gui_runner_connected':False},ensure_ascii=False))
