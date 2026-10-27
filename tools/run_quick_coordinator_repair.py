"""QG3C 수정 FILE ONLY writer를 감독하고 실행 없이 결과만 감사한다."""
import datetime,hashlib,json,os,pathlib,subprocess,sys
R=pathlib.Path(__file__).resolve().parents[1];sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
p=json.loads((R/'artifacts/qg3c-coordinator-repair-prepared.json').read_text(encoding='utf-8'));W=pathlib.Path(p['worktree'])
OUT=R/'artifacts/qg3c-coordinator-repair-pipeline.json';assert not OUT.exists()
assert all(sha(W/n)==h for n,h in {**p['immutable_sha256'],**p['reference_sha256'],**p['before_source_sha256']}.items())
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
assert not(R/'.harness/runs'/(p['stage']+'-'+p['role'])).exists()
s={'started_at':datetime.datetime.now().astimezone().isoformat(),'status':'RUNNING_CORRECTIVE_FLASH_FILE_ONLY','stage':p['stage'],'role':p['role'],'model':p['model'],'steps':[],'tests_executed':False,'compiled':False,'accepted':False,'root_integrated':False,'product_accepted':False}
def save():OUT.write_text(json.dumps(s,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
os.environ['NPI_AI_PRO_MODEL']=p['model'];save()
try:
 for name,cmd in [('writer',[sys.executable,'-u','tools/ai_pro_harness.py',p['stage'],p['role']]),('audit',[sys.executable,'tools/audit_ai_pro_runs.py',p['stage']])]:
  rc=subprocess.run(cmd,cwd=R,timeout=1100).returncode;s['steps'].append({'name':name,'exit':rc});save()
 folder=R/'.harness/runs'/(p['stage']+'-'+p['role']);result=json.loads((folder/'result.json').read_text(encoding='utf-8'));after=json.loads((folder/'after.json').read_text(encoding='utf-8'))
 audit=json.loads((R/'artifacts'/(p['stage']+'-actor-policy-audit.json')).read_text(encoding='utf-8'))
 actor=next(x for x in audit['actors'] if x['role']==p['role'])
 checks={'writer_exit':result['exit_code']==0,'not_partial':not result['partial'],'exact_model':result['model']==p['model'],'policy':actor['passed'],
 'exact_files':set(result['changed_paths'])==set(p['actor_writes']),'immutable':all(sha(W/n)==h for n,h in p['immutable_sha256'].items()),
 'reference':all(sha(W/n)==h for n,h in p['reference_sha256'].items()),'after_hash':all(sha(W/n)==after.get(n) for n in p['actor_writes']),
 'root_frozen':all(sha(R/n)==h for n,h in p['root_before_sha256'].items())}
 count=0
 for line in (folder/'stdout.jsonl').read_text(encoding='utf-8').splitlines():
  try:event=json.loads(line)
  except json.JSONDecodeError:continue
  step=event.get('step_update',{})
  if step.get('step_type')!='tool' or step.get('state')!='ACTIVE':continue
  for key,value in step.get('tool_info',{}).get('parameters',{}).items():
   if key.lower() not in ['path','absolutepath','targetfile','file_path','directorypath','searchdirectory'] or not isinstance(value,str):continue
   path=pathlib.Path(value)
   if not path.is_absolute() or not path.resolve().is_relative_to(W.resolve()):checks['absolute_w_paths']=False
   count+=1
 checks.setdefault('absolute_w_paths',count>0)
 s.update(checks=checks,path_checks=count,source_sha256={n:sha(W/n) for n in p['actor_writes']},actor_policy=actor)
 assert all(checks.values()) and all(step['exit']==0 for step in s['steps'])
 s['status']='AUDITED_REPAIR_SOURCE_READY_FOR_PARENT_REVIEW_NOT_COMPILED'
except Exception as err:s.update(status='BLOCKED_PRESERVED',error_type=type(err).__name__,error=str(err))
finally:s['finished_at']=datetime.datetime.now().astimezone().isoformat();save()
print(json.dumps(s,ensure_ascii=False),flush=True)
sys.exit(0 if s['status']=='AUDITED_REPAIR_SOURCE_READY_FOR_PARENT_REVIEW_NOT_COMPILED' else 1)
