"""새 증거명으로 기존 CLI38/개발TCP거부23·GUI거부를 실제 EXE에서 회귀한다."""
import ast,datetime,hashlib,json,os,pathlib,socket,sys
from owned_bounded_child import run_bounded
R=pathlib.Path(__file__).resolve().parents[1]
load=lambda p:json.loads((R/p).read_text(encoding='utf-8'))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
p=load('artifacts/qg3b-gui-inputs-parent-repair.json');W=pathlib.Path(p['worktree'])
assert all(sha(W/n)==h for n,h in p['source_sha256'].items())
EXE=R/'.harness/targets/qg3b-gui-inputs-shared/debug/NetworkQuickCheck.exe';fixed_sha=sha(EXE)
OUT=R/'artifacts/qg3b-gui-inputs-parent-commandline.json';assert not OUT.exists()
legacy_path=R/'tools/verify_quick_app_entry_owned_native.py';tree=ast.parse(legacy_path.read_text(encoding='utf-8'))
body=next(node.body for node in tree.body if isinstance(node,ast.Try))
start=next(i for i,n in enumerate(body) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='flag' for t in n.targets))
end=next(i for i,n in enumerate(body[start:],start) if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and isinstance(n.value.func,ast.Attribute) and isinstance(n.value.func.value,ast.Name) and n.value.func.value.id=='cases' and n.value.func.attr=='extend')
selected=body[start:end+1]
# 보존된 기존 generation-only AST를 그대로 사용한다. 실행/소켓/파일검증 본문을 재바인딩하지 않는다.
assert selected[0].value.value=='--npi-dns-worker-v1'
namespace={'os':os};exec(compile(ast.Module(body=selected,type_ignores=[]),str(legacy_path),'exec'),namespace)
cases,bad_args,flag,invalid,marker=(namespace[n] for n in ['cases','bad_args','flag','invalid','marker'])
assert len(cases)==36
reference=load('artifacts/qg2i-explicit-tcp-parent-commandline.json')
assert len(reference['commandline_cases'])==38
assert [x[0] for x in cases]==[x['id'] for x in reference['commandline_cases'][:-2]]
state={'started_at':datetime.datetime.now().astimezone().isoformat(),'status':'RUNNING_NOT_ACCEPTED',
 'executable':str(EXE),'binary_sha256':fixed_sha,'source_sha256':p['source_sha256'],
 'legacy_generation_source_sha256':sha(legacy_path),
 'legacy_generation_ast_sha256':hashlib.sha256(ast.dump(ast.Module(body=selected,type_ignores=[]),include_attributes=False).encode()).hexdigest(),
 'legacy_reference':'artifacts/qg2i-explicit-tcp-parent-commandline.json','commandline_cases':[],
 'explicit_reject_cases':[],'gui_reject_cases':[],'supervisor_self_tests':[],
 'network_connection_attempted':False,'literal_fixture_socket_options_changed':False,
 'actual_gui_opened_by_this_script':False,'root_integrated':False,'accepted':False}
def save(): OUT.write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def completed(r):
 assert r['child_reaped'] and not r['timed_out'] and not r['stdout_overflow'] and not r['stderr_overflow']
def summary(r):
 return {k:v for k,v in r.items() if k not in ['stdout','stderr']}|{'stdout_bytes':len(r['stdout']),'stderr_bytes':len(r['stderr'])}
def command(args):
 assert sha(EXE)==fixed_sha
 r=run_bounded([str(EXE),*args],cwd=W);completed(r);return r
save()
try:
 fixtures=[('normal',"import sys;sys.stdout.write('ok');sys.stderr.write('err')",0,False,False,False),
 ('nonzero','import sys;sys.exit(7)',7,False,False,False),
 ('stdout_exact',"import sys;sys.stdout.buffer.write(b'x'*16384)",0,False,False,False),
 ('stdout_overflow',"import sys;sys.stdout.buffer.write(b'x'*16385)",None,True,False,False),
 ('stderr_overflow',"import sys;sys.stderr.buffer.write(b'x'*1025)",None,False,True,False),
 ('deadline','import time;time.sleep(3)',None,False,False,True)]
 for label,code,exit_code,out_over,err_over,timeout in fixtures:
  r=run_bounded([sys.executable,'-c',code],cwd=R,timeout=0.1 if timeout else 5)
  assert r['child_reaped'] and r['timed_out']==timeout and r['stdout_overflow']==out_over and r['stderr_overflow']==err_over
  if exit_code is not None: assert r['exit_code']==exit_code
  if label=='normal': assert r['stdout']==b'ok' and r['stderr']==b'err'
  if label=='stdout_exact': assert len(r['stdout'])==16384
  state['supervisor_self_tests'].append({'id':label,'passed':True,**summary(r)})
 for label,args,code,stderr in cases:
  r=command(args);assert r['exit_code']==code and r['stdout']==b'' and r['stderr']==stderr,label
  assert marker.encode() not in r['stdout']+r['stderr']
  state['commandline_cases'].append({'id':label,'passed':True,**summary(r)});save()
 # 동일 port를 두 literal loopback에 한 번만 bind하며 OS 옵션/재시도/fallback을 사용하지 않는다.
 with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as v4,socket.socket(socket.AF_INET6,socket.SOCK_STREAM) as v6:
  v4.bind(('127.0.0.1',0));port=v4.getsockname()[1];v6.bind(('::1',port))
  for host,address,label in [('127.0.0.1',f'127.0.0.1:{port}','literal_v4'),('::1',f'[::1]:{port}','literal_v6')]:
   r=command([flag,host,str(port)]);assert r['exit_code']==0 and r['stderr']==b''
   wire=r['stdout'];assert wire.endswith(b'\n') and wire.count(b'\n')==1 and b'\r' not in wire
   assert json.loads(wire.decode())=={'format':'npi-dns-worker-1','host':host,'port':port,'addresses':[address],'truncated':False,'error_code':None,'error_message':None}
   state['commandline_cases'].append({'id':label,'passed':True,**summary(r)})
  state['owned_literal_fixture']={'ipv4':'127.0.0.1','ipv6':'::1','port':port,'both_bound_during_worker_calls':True,'connected':False}
 for label,args in bad_args:
  if not args or args[0]!=flag: continue
  r=command(['--dev-tcp-once-v1',*args[1:]])
  assert r['exit_code']==2 and r['stdout']==b'' and r['stderr']==invalid,label
  state['explicit_reject_cases'].append({'id':label,'passed':True,**summary(r)})
 selector='--dev-gui-inputs-v1'
 gui=[('extra',[selector,'extra']),('many',[selector,'a','b','c','d']),('non_unicode_extra',[selector,'\ud800']),
 ('duplicate',[selector,selector]),('equals',[selector+'=x']),('old_version',['--dev-gui-inputs-v0']),
 ('future_version',['--dev-gui-inputs-v2']),('help_then_gui',['--help',selector]),('gui_then_help',[selector,'--help'])]
 for label,args in gui:
  r=command(args);assert r['exit_code']==2 and r['stdout']==b'' and r['stderr']==invalid,label
  state['gui_reject_cases'].append({'id':label,'passed':True,**summary(r)})
 assert [x['id'] for x in state['commandline_cases']]==[x['id'] for x in reference['commandline_cases']]
 assert [x['id'] for x in state['explicit_reject_cases']]==[x['id'] for x in reference['explicit_reject_cases']]
 assert (len(state['commandline_cases']),len(state['explicit_reject_cases']),len(state['gui_reject_cases']),len(state['supervisor_self_tests']))==(38,23,9,6)
 assert all(sha(W/n)==h for n,h in p['source_sha256'].items())
 state['status']='CURRENT_EXE_LEGACY38_EXPLICIT_REJECT23_GUI_REJECT9_SUPERVISOR6_PASS_NOT_ACCEPTED'
except Exception as e:
 state.update(status='FAILED_PRESERVED',error_type=type(e).__name__)
finally:
 state['finished_at']=datetime.datetime.now().astimezone().isoformat();save()
print(json.dumps({'status':state['status'],'counts':{n:len(state[n]) for n in ['commandline_cases','explicit_reject_cases','gui_reject_cases','supervisor_self_tests']}},ensure_ascii=False))
sys.exit(0 if state['status'].startswith('CURRENT_EXE_') else 1)
