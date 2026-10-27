"""Run scoped AI Pro jobs with quota-only model fallback; never parallel writers per role."""
import argparse,contextlib,datetime,json,os,pathlib,re,subprocess,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
QUOTA=re.compile(r'(?:individual\s+quota\s+reached|(?:model\s+)?(?:usage|quota)\s+(?:limit\s+)?(?:exceeded|exhausted|reached)|exhausted\s+(?:your\s+)?(?:quota|usage)|insufficient\s+(?:model\s+)?quota)',re.I)
def quota_exhausted(text):
 # A synthetic prompt mentioning quota must not trigger. Call only on result/error text.
 return bool(QUOTA.search(text))
def terminal_quota(folder):
 result=json.loads((folder/'result.json').read_text(encoding='utf-8'))
 text=(folder/'stderr.log').read_text(encoding='utf-8');status=None
 for line in (folder/'stdout.jsonl').read_text(encoding='utf-8').splitlines():
  try:row=json.loads(line)
  except json.JSONDecodeError:continue
  if row.get('event',row.get('type')) in ('result','error'):
   terminal=row.get('result',row.get('error',row));text+='\n'+json.dumps(terminal,ensure_ascii=False)
   if row.get('event',row.get('type'))=='result' and isinstance(terminal,dict):status=terminal.get('status')
 result['cli_status']=status
 return quota_exhausted(text),result
def load_policy():
 p=json.loads((ROOT/'tools/ai_pro_model_policy.json').read_text(encoding='utf-8'))
 assert p['verified_available']==['gemini-4-argon-high','claude-opus-5-5-high','gemini-3.8-flash-high']
 return p
def quota_state_path():return ROOT/'.harness/ai-pro-quota-state.json'
@contextlib.contextmanager
def quota_lock():
 path=quota_state_path().with_suffix('.lock');path.parent.mkdir(parents=True,exist_ok=True)
 with path.open('a+b')as lock:
  lock.seek(0,2)
  if lock.tell()==0:lock.write(b'0');lock.flush()
  lock.seek(0)
  if os.name=='nt':
   import msvcrt
   msvcrt.locking(lock.fileno(),msvcrt.LK_LOCK,1)
  else:
   import fcntl
   fcntl.flock(lock.fileno(),fcntl.LOCK_EX)
  try:yield
  finally:
   lock.seek(0)
   if os.name=='nt':msvcrt.locking(lock.fileno(),msvcrt.LK_UNLCK,1)
   else:fcntl.flock(lock.fileno(),fcntl.LOCK_UN)
def cached_quota(model):
 path=quota_state_path()
 if not path.exists():return False
 with quota_lock():item=json.loads(path.read_text(encoding='utf-8')).get(model)
 if not item:return False
 until=item.get('reset_at')
 return until is None or datetime.datetime.now().astimezone()<datetime.datetime.fromisoformat(until)
def record_quota(model,folder):
 meta=json.loads((folder/'result.json').read_text(encoding='utf-8'));text=(folder/'stderr.log').read_text(encoding='utf-8')
 m=re.search(r'Resets in\s+(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?',text,re.I)
 reset=None
 if m and any(m.groups()):
  days,hours,minutes,seconds=[int(x or 0)for x in m.groups()]
  at=datetime.datetime.fromisoformat(meta.get('completed_at',datetime.datetime.now().astimezone().isoformat()))
  reset=(at+datetime.timedelta(days=days,hours=hours,minutes=minutes,seconds=seconds)).isoformat()
 path=quota_state_path()
 with quota_lock():
  state=json.loads(path.read_text(encoding='utf-8'))if path.exists()else{}
  state[model]={'reset_at':reset,'source_result':str(folder/'result.json'),'reason':'explicit individual model quota exhausted','recorded_at':datetime.datetime.now().astimezone().isoformat()}
  temporary=path.with_suffix('.'+str(os.getpid())+'.tmp');temporary.write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n');os.replace(temporary,path)
def main():
 p=argparse.ArgumentParser();p.add_argument('stage');p.add_argument('roles',nargs='+');a=p.parse_args();policy=load_policy();pending=a.roles[:];attempts=[];blocked=[]
 assert len(set(pending))==len(pending)
 original={role:(ROOT/'.harness/prompts'/(a.stage+'-'+role+'.md')).read_text(encoding='utf-8')for role in pending}
 for index,model in enumerate(policy['verified_available']):
  if not pending:break
  if cached_quota(model):continue
  stage=a.stage if index==0 else a.stage+'-fallback'+str(index)
  if index:
   for role in pending:
    prompt=original[role].replace('You are AI Pro Gemini 4 Argon High.','You are AI Pro '+model+'.')
    prompt+='\n이전 모델의 사용량 상한으로 중단되었습니다. 기존 부분 변경과 실패 증거를 보존하고 동일한 허용 경로에서 미완료 부분만 이어서 구현하세요.Do not reset or duplicate other writers. Respond Korean.\n'
    (ROOT/'.harness/prompts'/(stage+'-'+role+'.md')).write_text(prompt,encoding='utf-8',newline='\n')
  # No simultaneous job may own these same worktrees.
  for role in pending:
   for started in (ROOT/'.harness/runs').glob('*-'+role+'/started.json'):
    assert (started.parent/'result.json').exists(), 'Another writer still owns '+role
  env=dict(os.environ,NPI_AI_PRO_MODEL=model)
  process=subprocess.run([sys.executable,'-u',str(ROOT/'tools/ai_pro_harness.py'),stage,*pending],cwd=ROOT,env=env)
  next_roles=[]
  for role in pending:
   folder=ROOT/'.harness/runs'/(stage+'-'+role)
   if not (folder/'result.json').exists():blocked.append({'role':role,'reason':'missing terminal evidence','stage':stage});continue
   quota,result=terminal_quota(folder);attempts.append({'stage':stage,'role':role,'model':model,'quota_exhausted':quota,'result_path':str(folder/'result.json')})
   if result.get('scope_violations')or result.get('permission_required'):blocked.append({'role':role,'reason':'policy or permission required','stage':stage})
   elif quota:
    record_quota(model,folder);next_roles.append(role)
   elif result['exit_code']!=0 or result.get('partial')or result.get('cli_status')!='SUCCESS'or not result.get('changed_paths'):blocked.append({'role':role,'reason':'non-quota failure, stream error, or no-op: independent review required','stage':stage})
  pending=next_roles
 if pending:blocked.extend({'role':role,'reason':'verified model quota exhausted; Gemini Pro not available'}for role in pending)
 out={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'stage':a.stage,'attempts':attempts,'blocked':blocked,'product_accepted':False,'requires_independent_tests':True}
 path=ROOT/'.harness/runs'/(a.stage+'-priority-summary.json');path.write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n');print(json.dumps(out,ensure_ascii=False,indent=2));return int(bool(blocked))
if __name__=='__main__':sys.exit(main())
