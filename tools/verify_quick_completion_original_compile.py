"""원본 actor 산출물 보존·부모 모듈 등록 뒤 실행 없는 첫 컴파일을 기록한다."""
import concurrent.futures,datetime,hashlib,json,pathlib,shutil,subprocess,sys
R=pathlib.Path(__file__).resolve().parents[1]
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
p=json.loads((R/'artifacts/qg3c-qg5a-parallel-prepared.json').read_text(encoding='utf-8'))
a=json.loads((R/'artifacts/qg3c-qg5a-parallel-pipeline.json').read_text(encoding='utf-8'))
assert a['status']=='BOTH_AUDITED_FOR_PARENT_REVIEW_NOT_COMPILED'
OUT=R/'artifacts/qg3c-qg5a-original-compile.json';assert not OUT.exists()
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
state={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'independent_review_batch':'deleg_e4d98270','actor_original_preserved':{},'roles':{},'tests_executed':False,'root_integrated':False,'accepted':False}
for role,spec in p['roles'].items():
 W=pathlib.Path(spec['worktree'])
 assert all(sha(W/n)==h for n,h in spec['immutable_sha256'].items())
 assert all(sha(W/n)==h for n,h in spec['reference_sha256'].items())
 evidence=R/'.harness/evidence'/('qg3c-qg5a-original-'+role);assert not evidence.exists()
 evidence.mkdir(parents=True)
 for name in spec['actor_writes']:
  assert sha(W/name)==a['roles'][role]['source_sha256'][name]
  shutil.copyfile(W/name,evidence/pathlib.Path(name).name)
 state['actor_original_preserved'][role]={'directory':str(evidence),'sha256':a['roles'][role]['source_sha256']}
 lib=W/'apps/network-quick-check/src/lib.rs';text=lib.read_text(encoding='utf-8')
 registration=spec['registration_after_audit_by_parent'];assert registration.strip() not in text
 anchor='mod diagnostic_cli;\n';assert text.count(anchor)==1
 lib.write_text(text.replace(anchor,anchor+registration,1),encoding='utf-8',newline='\n')
 state['roles'][role]={'parent_registration':registration,'lib_sha256':sha(lib),'actor_files_modified_by_parent':False}
OUT.write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def compile_role(role):
 spec=p['roles'][role];name='qg3c-qg5a-original-compile-'+role
 cmd=[sys.executable,'tools/run_command_evidence.py','--cwd',spec['worktree'],'--name',name,'--timeout','180','--',
      'cargo','test','--offline','--locked','--target-dir',str(R/'.harness/targets'/('qg3c-qg5a-'+role)),'-p','network-quick-check','--lib','--no-run']
 result=subprocess.run(cmd,cwd=R,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=215)
 evidence=R/'artifacts/commands'/(name+'.json');assert evidence.is_file(),result.stdout[-1500:]+result.stderr[-1500:]
 report=json.loads(evidence.read_text(encoding='utf-8'))
 return role,{'command_evidence':str(evidence),'exit_code':report['exit_code'],'partial':report['partial'],'wrapper_exit':result.returncode,'tests_executed':False}
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
 for role,res in pool.map(compile_role,p['roles']):state['roles'][role].update(res)
for role,spec in p['roles'].items():
 W=pathlib.Path(spec['worktree'])
 assert all(sha(W/n)==h for n,h in a['roles'][role]['source_sha256'].items())
 assert all(sha(W/n)==h for n,h in spec['immutable_sha256'].items() if n!='apps/network-quick-check/src/lib.rs')
 assert all(sha(W/n)==h for n,h in spec['reference_sha256'].items())
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
state['status']='ORIGINAL_COMPILE_RECORDED_NO_TEST_EXECUTION';state['finished_at']=datetime.datetime.now().astimezone().isoformat()
OUT.write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(state,ensure_ascii=False,indent=2))
