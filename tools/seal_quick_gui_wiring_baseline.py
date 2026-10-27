"""다음 GUI 연결 작업의 조합 기준을 실제 회귀 뒤 clean 로컬 WIP로 고정한다."""
import datetime,hashlib,json,pathlib,re,subprocess
R=pathlib.Path(__file__).resolve().parents[1];sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
def load(n):return json.loads((R/n).read_text(encoding='utf-8'))
def git(w,*args):
 r=subprocess.run(['git','-C',str(w),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60)
 assert r.returncode==0,r.stderr;return r.stdout.rstrip('\r\n')
p=load('artifacts/qg3d-gui-wiring-prepared.json');W=pathlib.Path(p['worktree']);OUT=R/'artifacts/qg3d-gui-wiring-baseline.json';assert not OUT.exists()
lib='apps/network-quick-check/src/lib.rs';assert all(sha(W/n)==h for n,h in p['base_source_sha256'].items() if n!=lib)
assert all(sha(R/n)==h for n,h in p['root_source_frozen_sha256'].items())
assert set(line[3:] for line in git(W,'status','--porcelain').splitlines())==set(p['parent_selected_combination_paths'])
commands={}
for name in ['qg3d-baseline-workspace','qg3d-baseline-clippy','qg3d-baseline-fmt-check']:
 row=load('artifacts/commands/'+name+'.json');assert row['exit_code']==0 and not row['partial']
 text=pathlib.Path(row['log']).read_text(encoding='utf-8');counts=re.findall(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;',text)
 if counts:row['counts']={key:sum(int(c[j+1]) for c in counts) for j,key in enumerate(['passed','failed','ignored'])}
 commands[name]=row
assert commands['qg3d-baseline-workspace']['counts']=={'passed':538,'failed':0,'ignored':35}
git(W,'add','--',*p['parent_selected_combination_paths']);git(W,'diff','--cached','--check')
git(W,'commit','-m','WIP: combine isolated reviewed host and pure results with unaccepted input GUI for next wiring slice')
commit=git(W,'rev-parse','HEAD');assert not git(W,'status','--porcelain')
paths=[n for n in git(W,'ls-files','-z').split('\0') if n and (W/n).is_file()]
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'CLEAN_COMBINED_WIP_BASELINE_VERIFIED_NOT_GUI_RUNNING',
 'worktree':str(W),'branch':'ai-pro/qgguirun','commit':commit,'worktree_clean':True,'tracked_source_sha256':{n:sha(W/n) for n in paths},
 'commands':commands,'workspace_counts':commands['qg3d-baseline-workspace']['counts'],
 'base_host_commit':p['base_host_commit'],'gui_input_wip_still_not_visibly_accepted':True,
 'coordinator_still_test_only':True,'diagnostic_gui_not_implemented':True,'root_integrated':False,'accepted':False,'full_qg3_accepted':False,'product_accepted':False,
 'exact_old_input_selector':'--dev-gui-inputs-v1','proposed_new_execution_selector_not_yet_implemented':'--dev-gui-run-v1',
 'new_selector_must_remain_separate':True,'specific_ui_approval_timeout_preserved':True,'no_native_or_visible_test_execution_this_baseline':True}
OUT.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
ref=W/'.harness/inputs/frozen/qg3d-combined-baseline-summary.json';assert not ref.exists()
ref.write_text(json.dumps({k:v for k,v in record.items() if k not in ['tracked_source_sha256','commands']},ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':record['status'],'commit':commit,'workspace':record['workspace_counts'],'tracked_files':len(paths),'accepted':False,'gui_connected':False},ensure_ascii=False))
