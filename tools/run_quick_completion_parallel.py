"""두 전용 worktree의 Flash FILE 작성과 도구/경로/SHA 감사까지만 병렬 실행한다."""
import datetime,hashlib,json,os,pathlib,subprocess,sys
R=pathlib.Path(__file__).resolve().parents[1]
load=lambda p:json.loads((R/p).read_text(encoding='utf-8'))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
p=load('artifacts/qg3c-qg5a-parallel-prepared.json');STAGE=p['stage'];ROLES=list(p['roles'])
OUT=R/'artifacts/qg3c-qg5a-parallel-pipeline.json';assert not OUT.exists()
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
for role,spec in p['roles'].items():
 W=pathlib.Path(spec['worktree'])
 assert all(sha(W/n)==h for n,h in spec['immutable_sha256'].items())
 assert all(sha(W/n)==h for n,h in spec['reference_sha256'].items())
 assert all(not(W/n).exists() for n in spec['actor_writes'])
 assert not(R/'.harness/runs'/(STAGE+'-'+role)).exists()
state={'started_at':datetime.datetime.now().astimezone().isoformat(),'status':'RUNNING_TWO_FLASH_FILE_ONLY_WRITERS',
 'stage':STAGE,'model':'gemini-3.8-flash-high','steps':[],'roles':{},'source_compiled':False,
 'tests_executed':False,'native_executed':False,'root_integrated':False,'accepted':False,
 'full_qg2_accepted':False,'full_qg3_accepted':False,'full_qg5_accepted':False,'product_accepted':False,
 'audit_is_not_os_enforced_sandbox_guarantee':True}
def save():
 temp=OUT.with_suffix('.json.tmp');temp.write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');temp.replace(OUT)
def call(name,argv):
 state['current_step']=name;save()
 result=subprocess.run(argv,cwd=R,timeout=1150)
 state['steps'].append({'name':name,'exit_code':result.returncode});save();return result.returncode
os.environ['NPI_AI_PRO_MODEL']='gemini-3.8-flash-high';save()
try:
 writer_exit=call('parallel-flash-file-only',[sys.executable,'-u','tools/ai_pro_harness.py',STAGE,*ROLES])
 audit_exit=call('actual-tools-policy-audit',[sys.executable,'tools/audit_ai_pro_runs.py',STAGE])
 audit=load('artifacts/'+STAGE+'-actor-policy-audit.json')
 for role,spec in p['roles'].items():
  W=pathlib.Path(spec['worktree']);folder=R/'.harness/runs'/(STAGE+'-'+role)
  result=json.loads((folder/'result.json').read_text(encoding='utf-8'))
  after=json.loads((folder/'after.json').read_text(encoding='utf-8'))
  review=next(item for item in audit['actors'] if item['role']==role)
  checks={'actor_exit_and_terminal_success':result['exit_code']==0 and not result['partial'] and review['passed'],
   'exact_new_file_scope':result['changed_paths']==sorted(spec['actor_writes']),
   'exact_model':result['model']==p['model']=='gemini-3.8-flash-high',
   'immutable_inputs':all(sha(W/n)==h for n,h in spec['immutable_sha256'].items()),
   'immutable_references':all(sha(W/n)==h for n,h in spec['reference_sha256'].items()),
   'after_source_hashes':all((W/n).is_file() and sha(W/n)==after.get(n) for n in spec['actor_writes'])}
  count=0
  for line in (folder/'stdout.jsonl').read_text(encoding='utf-8').splitlines():
   try:event=json.loads(line)
   except json.JSONDecodeError:continue
   step=event.get('step_update',{})
   if step.get('step_type')!='tool' or step.get('state')!='ACTIVE':continue
   for key,value in step.get('tool_info',{}).get('parameters',{}).items():
    if key.lower() not in ['path','absolutepath','targetfile','file_path','directorypath','searchdirectory'] or not isinstance(value,str):continue
    item=pathlib.Path(value)
    if not item.is_absolute() or not item.resolve().is_relative_to(W.resolve()):checks['strict_absolute_in_worktree_paths']=False
    count+=1
  checks.setdefault('strict_absolute_in_worktree_paths',count>0)
  state['roles'][role]={'status':'AUDITED_SOURCE_READY_FOR_INDEPENDENT_REVIEW' if all(checks.values()) else 'BLOCKED_PRESERVED_NOT_EXECUTABLE',
   'worktree':str(W),'checks':checks,'strict_path_checks':count,'immutable_input_count':len(spec['immutable_sha256']),
   'source_sha256':{n:sha(W/n) for n in spec['actor_writes'] if(W/n).is_file()},
   'actor_policy':review,'parent_module_registration_pending':spec['registration_after_audit_by_parent'],
   'source_compiled':False,'tests_executed':False,'accepted':False};save()
 assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
 assert writer_exit==audit_exit==0 and all(r['status']=='AUDITED_SOURCE_READY_FOR_INDEPENDENT_REVIEW' for r in state['roles'].values())
 state['status']='BOTH_AUDITED_FOR_PARENT_REVIEW_NOT_COMPILED'
except Exception as error:
 state.update(status='BLOCKED_PRESERVED_FOR_REVIEW',error_type=type(error).__name__,error=str(error))
finally:
 state['finished_at']=datetime.datetime.now().astimezone().isoformat();save()
print(json.dumps(state,ensure_ascii=False),flush=True)
sys.exit(0 if state['status']=='BOTH_AUDITED_FOR_PARENT_REVIEW_NOT_COMPILED' else 1)
