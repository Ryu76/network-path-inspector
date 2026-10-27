"""typed presenter/session FILE ONLY writer를 감독하고 작성 종료 후 경로·도구·SHA만 감사한다."""
import datetime,hashlib,json,os,pathlib,subprocess,sys
R=pathlib.Path(__file__).resolve().parents[1];sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
p=json.loads((R/'artifacts/qg3e-session-bridge-prepared.json').read_text(encoding='utf-8'));W=pathlib.Path(p['worktree'])
OUT=R/'artifacts/qg3e-session-bridge-pipeline.json';assert not OUT.exists()
assert all(sha(W/n)==h for n,h in {**p['immutable_sha256'],**p['reference_sha256']}.items())
for n,h in p['before_source_sha256'].items():assert (sha(W/n)==h) if h is not None else not(W/n).exists()
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
folder=R/'.harness/runs'/(p['stage']+'-'+p['role']);assert not folder.exists()
for started in (R/'.harness/runs').glob('*-'+p['role']+'/started.json'):assert (started.parent/'result.json').exists()
sys.path.insert(0,str(R/'tools'));from run_ai_pro_priority import cached_quota
assert not cached_quota(p['model']),'Explicit cached quota; preserve prep and use separately audited quota-only fallback'
s={'started_at':datetime.datetime.now().astimezone().isoformat(),'status':'RUNNING_TYPED_SESSION_FLASH_FILE_ONLY','stage':p['stage'],'role':p['role'],'model':p['model'],
 'steps':[],'compiled':False,'tests_executed':False,'native_executed':False,'gui_connected':False,'root_integrated':False,'accepted':False,'product_accepted':False,
 'audit_is_not_os_enforced_sandbox_guarantee':True,'permission_settings_changed':False}
def save():
 temp=OUT.with_suffix('.json.tmp');temp.write_text(json.dumps(s,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');temp.replace(OUT)
os.environ['NPI_AI_PRO_MODEL']=p['model'];save()
try:
 for name,cmd in [('writer',[sys.executable,'-u','tools/ai_pro_harness.py',p['stage'],p['role']]),('audit',[sys.executable,'tools/audit_ai_pro_runs.py',p['stage']])]:
  rc=subprocess.run(cmd,cwd=R,timeout=1100).returncode;s['steps'].append({'name':name,'exit_code':rc});save()
 result=json.loads((folder/'result.json').read_text(encoding='utf-8'));after=json.loads((folder/'after.json').read_text(encoding='utf-8'))
 audit=json.loads((R/'artifacts'/(p['stage']+'-actor-policy-audit.json')).read_text(encoding='utf-8'));actor=next(x for x in audit['actors'] if x['role']==p['role'])
 checks={'exit_terminal_success':result['exit_code']==0 and not result['partial'] and actor['passed'],'exact_model':result['model']==p['model'],
 'exact_files':set(result['changed_paths'])==set(p['actor_writes']),'immutable_inputs':all(sha(W/n)==h for n,h in p['immutable_sha256'].items()),
 'immutable_references':all(sha(W/n)==h for n,h in p['reference_sha256'].items()),'after_hash':all((W/n).is_file() and sha(W/n)==after.get(n) for n in p['actor_writes']),
 'root_frozen':all(sha(R/n)==h for n,h in p['root_before_sha256'].items())}
 count=0
 for line in (folder/'stdout.jsonl').read_text(encoding='utf-8').splitlines():
  try:event=json.loads(line)
  except json.JSONDecodeError:continue
  step=event.get('step_update',{})
  if step.get('step_type')!='tool' or step.get('state')!='ACTIVE':continue
  for key,value in step.get('tool_info',{}).get('parameters',{}).items():
   if key.lower()not in ['path','absolutepath','targetfile','file_path','directorypath','searchdirectory'] or not isinstance(value,str):continue
   path=pathlib.Path(value)
   if not path.is_absolute() or not path.resolve().is_relative_to(W.resolve()):checks['absolute_worktree_paths']=False
   count+=1
 checks.setdefault('absolute_worktree_paths',count>0)
 s.update(checks=checks,path_checks=count,source_sha256={n:sha(W/n) for n in p['actor_writes'] if(W/n).is_file()},actor_policy=actor)
 assert all(checks.values()) and all(step['exit_code']==0 for step in s['steps'])
 s['status']='AUDITED_TYPED_SESSION_SOURCE_NOT_COMPILED_NOT_EXECUTED'
except Exception as err:s.update(status='BLOCKED_PRESERVED_FOR_REVIEW',error_type=type(err).__name__,error=str(err))
finally:s['finished_at']=datetime.datetime.now().astimezone().isoformat();save()
print(json.dumps(s,ensure_ascii=False),flush=True)
sys.exit(0 if s['status']=='AUDITED_TYPED_SESSION_SOURCE_NOT_COMPILED_NOT_EXECUTED' else 1)
