"""Flash 원본3개를 보존하고 실행 없이 두 작업의 libtest 컴파일 결과를 각각 수집한다."""
import concurrent.futures,datetime,hashlib,json,pathlib,shutil,subprocess,sys
R=pathlib.Path(__file__).resolve().parents[1];sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
def load(n):return json.loads((R/n).read_text(encoding='utf-8'))
p=load('artifacts/qg3d-runtime-render-prepared.json');a=load('artifacts/qg3d-runtime-render-pipeline.json')
OUT=R/'artifacts/qg3d-atoms-original-compile.json';assert not OUT.exists()
assert a['status']=='BOTH_ATOMS_AUDITED_NOT_COMPILED_NOT_EXECUTED'
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
records={}
for role,spec in p['roles'].items():
 W=pathlib.Path(spec['worktree']);assert all(sha(W/n)==h for n,h in {**spec['immutable_sha256'],**spec['reference_sha256']}.items())
 assert all(sha(W/n)==h for n,h in a['roles'][role]['source_sha256'].items())
 saved=R/'.harness/evidence/qg3d-atoms-original'/role;saved.mkdir(parents=True,exist_ok=False)
 for n in spec['actor_writes']:shutil.copyfile(W/n,saved/pathlib.Path(n).name)
 lib=W/'apps/network-quick-check/src/lib.rs';shutil.copyfile(lib,saved/'lib-before-registration.rs')
 if role=='qgrender':
  text=lib.read_text(encoding='utf-8');anchor='pub mod result_export;\n';assert text.count(anchor)==1
  lib.write_text(text.replace(anchor,'pub mod gui_result_render;\n'+anchor,1),encoding='utf-8',newline='\n')
 records[role]={'worktree':str(W),'source_sha256':a['roles'][role]['source_sha256'],'evidence_dir':str(saved),
 'parent_registration':spec['registration_after_audit_by_parent'],'lib_sha256':sha(lib),'source_modified_by_parent':False,'tests_executed':False}
def compile_one(role):
 name='qg3d-'+role+'-original-compile';W=pathlib.Path(p['roles'][role]['worktree']);target=R/'.harness/targets'/('qg3d-'+role+'-shared')
 cmd=[sys.executable,'tools/run_command_evidence.py','--cwd',str(W),'--name',name,'--timeout','180','--',
 'cargo','test','--offline','--locked','--target-dir',str(target),'-p','network-quick-check','--lib','--no-run']
 result=subprocess.run(cmd,cwd=R,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=215)
 log=load('artifacts/commands/'+name+'.json');assert result.returncode==log['exit_code']
 text=pathlib.Path(log['log']).read_text(encoding='utf-8')
 errors=[s for s in text.splitlines() if s.startswith('error')]
 records[role].update(compile=log,diagnostics_summary=errors)
 return role,log['exit_code'],errors
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
 for role,rc,errors in pool.map(compile_one,p['roles']):print(json.dumps({'role':role,'compile_exit':rc,'diagnostics':errors,'tests_executed':False},ensure_ascii=False),flush=True)
for role,spec in p['roles'].items():
 W=pathlib.Path(spec['worktree']);assert all(sha(W/n)==h for n,h in a['roles'][role]['source_sha256'].items())
 assert all(sha(W/n)==h for n,h in spec['immutable_sha256'].items() if not(role=='qgrender' and n=='apps/network-quick-check/src/lib.rs'))
 assert all(sha(W/n)==h for n,h in spec['reference_sha256'].items())
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'ORIGINAL_COMPILE_ONLY_RESULTS_PRESERVED_SAFETY_QA_PENDING','roles':records,
 'safety_review_batch':'deleg_24bbf177','tests_executed':False,'native_executed':False,'root_integrated':False,'accepted':False,'product_accepted':False}
OUT.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':record['status'],'compile_exit':{r:d['compile']['exit_code'] for r,d in records.items()},'tests_executed':False},ensure_ascii=False))
