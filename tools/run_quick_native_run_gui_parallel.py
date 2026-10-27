"""실행 GUI entry/nativeUI를 다른 두 W에서 작성하고 실제 도구·경로·SHA만 감사한다."""
import datetime,hashlib,json,os,pathlib,subprocess,sys
R=pathlib.Path(__file__).resolve().parents[1]
load=lambda p:json.loads((R/p).read_text(encoding='utf-8'));sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
p=load('artifacts/qg3f-native-run-gui-prepared.json');STAGE=p['stage'];ROLES=list(p['roles'])
OUT=R/'artifacts/qg3f-native-run-gui-pipeline.json';assert not OUT.exists()
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
for role,spec in p['roles'].items():
 W=pathlib.Path(spec['worktree']);assert all(sha(W/n)==h for n,h in {**spec['immutable_sha256'],**spec['reference_sha256']}.items())
 for n,h in spec['before_source_sha256'].items():assert (sha(W/n)==h) if h is not None else not(W/n).exists()
 assert not(R/'.harness/runs'/(STAGE+'-'+role)).exists()
 for started in (R/'.harness/runs').glob('*-'+role+'/started.json'):assert (started.parent/'result.json').exists(),'writer owns '+role
sys.path.insert(0,str(R/'tools'));from run_ai_pro_priority import cached_quota
assert not cached_quota(p['model']),'Explicit cached quota blocks this model; preserve preparation, choose authorized quota-only fallback separately'
state={'started_at':datetime.datetime.now().astimezone().isoformat(),'status':'RUNNING_TWO_FLASH_FILE_ONLY_ATOMS','stage':STAGE,'model':p['model'],
 'steps':[],'roles':{},'source_compiled':False,'tests_executed':False,'native_executed':False,'gui_connected':False,'root_integrated':False,'accepted':False,'product_accepted':False,
 'audit_is_not_os_enforced_sandbox_guarantee':True,'permission_settings_changed':False}
def save():
 tmp=OUT.with_suffix('.json.tmp');tmp.write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');tmp.replace(OUT)
def call(name,argv):
 state['current_step']=name;save();rc=subprocess.run(argv,cwd=R,timeout=1150).returncode
 state['steps'].append({'name':name,'exit_code':rc});save();return rc
os.environ['NPI_AI_PRO_MODEL']=p['model'];save()
try:
 writer=call('parallel-flash-file-only',[sys.executable,'-u','tools/ai_pro_harness.py',STAGE,*ROLES])
 audit_exit=call('actual-tools-policy-audit',[sys.executable,'tools/audit_ai_pro_runs.py',STAGE])
 audit=load('artifacts/'+STAGE+'-actor-policy-audit.json')
 for role,spec in p['roles'].items():
  W=pathlib.Path(spec['worktree']);folder=R/'.harness/runs'/(STAGE+'-'+role)
  result=json.loads((folder/'result.json').read_text(encoding='utf-8'));after=json.loads((folder/'after.json').read_text(encoding='utf-8'))
  review=next(a for a in audit['actors'] if a['role']==role)
  checks={'exit_terminal_success':result['exit_code']==0 and not result['partial'] and review['passed'],
   'exact_write_scope':set(result['changed_paths'])==set(spec['actor_writes']),'exact_model':result['model']==p['model'],
   'immutable_inputs':all(sha(W/n)==h for n,h in spec['immutable_sha256'].items()),'immutable_references':all(sha(W/n)==h for n,h in spec['reference_sha256'].items()),
   'after_source_hashes':all((W/n).is_file() and sha(W/n)==after.get(n) for n in spec['actor_writes'])}
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
  state['roles'][role]={'status':'AUDITED_SOURCE_READY_FOR_INDEPENDENT_REVIEW' if all(checks.values()) else 'BLOCKED_PRESERVED',
   'worktree':str(W),'checks':checks,'strict_path_checks':count,'immutable_input_count':len(spec['immutable_sha256']),
   'source_sha256':{n:sha(W/n) for n in spec['actor_writes'] if(W/n).is_file()},'actor_policy':review,
   'registration_after_audit_by_parent':spec['registration_after_audit_by_parent'],'compiled':False,'tests_executed':False,'accepted':False};save()
 assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
 assert writer==audit_exit==0 and all(s['status']=='AUDITED_SOURCE_READY_FOR_INDEPENDENT_REVIEW' for s in state['roles'].values())
 state['status']='BOTH_ATOMS_AUDITED_NOT_COMPILED_NOT_EXECUTED'
except Exception as error:state.update(status='BLOCKED_PRESERVED_FOR_REVIEW',error_type=type(error).__name__,error=str(error))
finally:state['finished_at']=datetime.datetime.now().astimezone().isoformat();save()
print(json.dumps(state,ensure_ascii=False),flush=True)
sys.exit(0 if state['status']=='BOTH_ATOMS_AUDITED_NOT_COMPILED_NOT_EXECUTED' else 1)
