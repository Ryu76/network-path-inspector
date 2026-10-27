"""감사를 통과한 coordinator 수정본을 보존하고 실행 없는 컴파일만 수행한다."""
import datetime,hashlib,json,pathlib,shutil,subprocess,sys
R=pathlib.Path(__file__).resolve().parents[1];sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
load=lambda n:json.loads((R/n).read_text(encoding='utf-8'))
p=load('artifacts/qg3c-coordinator-repair-prepared.json');a=load('artifacts/qg3c-coordinator-repair-pipeline.json');W=pathlib.Path(p['worktree'])
assert a['status']=='AUDITED_REPAIR_SOURCE_READY_FOR_PARENT_REVIEW_NOT_COMPILED'
assert all(sha(W/n)==h for n,h in {**p['immutable_sha256'],**p['reference_sha256'],**a['source_sha256']}.items())
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
E=R/'.harness/evidence/qg3c-corrective-actor-original';assert not E.exists();E.mkdir(parents=True)
for name in p['actor_writes']:shutil.copyfile(W/name,E/pathlib.Path(name).name)
name='qg3c-corrective-original-compile'
rc=subprocess.run([sys.executable,'tools/run_command_evidence.py','--cwd',str(W),'--name',name,'--timeout','180','--',
 'cargo','test','--offline','--locked','--target-dir',str(R/'.harness/targets/qg3c-coordinator-repair'),'-p','network-quick-check','--lib','--no-run'],cwd=R,timeout=220).returncode
command=load('artifacts/commands/'+name+'.json')
assert all(sha(W/n)==h for n,h in {**p['immutable_sha256'],**p['reference_sha256'],**a['source_sha256']}.items())
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
out=R/'artifacts/qg3c-corrective-original-compile.json';assert not out.exists()
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'CORRECTIVE_ORIGINAL_COMPILE_RECORDED_EXECUTION_NOT_AUTHORIZED',
 'worktree':str(W),'source_sha256':a['source_sha256'],'immutable_inputs':len(p['immutable_sha256']),'reference_files':len(p['reference_sha256']),
 'compile_exit':command['exit_code'],'wrapper_exit':rc,'partial':command['partial'],'log':command['log'],
 'preserved_source':str(E),'safety_review_batch':'deleg_bede6d65','tests_executed':False,'root_integrated':False,'accepted':False,'product_accepted':False}
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(record,ensure_ascii=False))
