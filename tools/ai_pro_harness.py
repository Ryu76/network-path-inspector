import concurrent.futures,datetime,hashlib,json,os,pathlib,re,subprocess,sys,time
ROOT=pathlib.Path('E:/harnes/network-path-inspector');H=ROOT/'.harness'
MODEL=os.environ.get('NPI_AI_PRO_MODEL','gemini-3.8-flash-high')
if MODEL not in ('gemini-4-argon-high','claude-opus-5-5-high','gemini-3.8-flash-high'):raise ValueError('Unverified or unauthorized AI Pro model')
SECRET=re.compile(r'(token|password|secret|credential|api.?key|authorization|private.?key)',re.I)
VALUES=sorted({v for k,v in os.environ.items() if SECRET.search(k) and len(v)>=8},key=len,reverse=True)
def clean(x):
 if isinstance(x,dict):return{k:clean(v) for k,v in x.items()}
 if isinstance(x,list):return[clean(v) for v in x]
 if isinstance(x,str):
  for v in VALUES:x=x.replace(v,'[REDACTED]')
  x=re.sub(r'(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]+',r'\1[REDACTED]',x)
 return x
def lines(data):
 out=[]
 for line in data.decode('utf-8','replace').splitlines():
  try:out.append(json.dumps(clean(json.loads(line)),ensure_ascii=False))
  except json.JSONDecodeError:out.append(clean(line))
 return '\n'.join(out)+'\n'
def snapshot(w):
 return {p.relative_to(w).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in w.rglob('*') if p.is_file() and not any(x in('.git','target','node_modules','dist','.harness','.worktrees','__pycache__') for x in p.relative_to(w).parts)}
def run(role,stage):
 w=ROOT/'.worktrees'/role;prompt=(H/'prompts'/(stage+'-'+role+'.md')).read_text(encoding='utf-8');folder=H/'runs'/(stage+'-'+role);folder.mkdir(parents=True,exist_ok=False)
 before=snapshot(w);(folder/'before.json').write_text(json.dumps(before,indent=2),encoding='utf-8')
 env={k:v for k,v in os.environ.items() if not SECRET.search(k)};scratch=pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/scratch')/('npi-'+stage+'-'+role);scratch.mkdir(parents=True,exist_ok=True);env.update(TMP=str(scratch),TEMP=str(scratch),TMPDIR=str(scratch))
 command=['E:/antigravity-cli/agy.exe','--model',MODEL,'--sandbox','--mode','accept-edits','--add-dir',str(H),'--output-format','stream-json','--print-timeout','900s','--print='+prompt]
 begin=time.monotonic();p=subprocess.Popen(command,cwd=w,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 result={'stage':stage,'role':role,'model':MODEL,'worktree':str(w),'pid':p.pid,'started_at':datetime.datetime.now().astimezone().isoformat(),'partial':False,'verified':False}
 (folder/'started.json').write_text(json.dumps(result,indent=2),encoding='utf-8');print(json.dumps(result),flush=True)
 try:out,err=p.communicate(timeout=960)
 except subprocess.TimeoutExpired:
  result['partial']=True;subprocess.run(['taskkill.exe','/PID',str(p.pid),'/T','/F'],capture_output=True,timeout=20);out,err=p.communicate(timeout=20)
 stdout,stderr=lines(out),lines(err);combined=(stdout+stderr).lower();result['partial']|=any(marker in combined for marker in ('print timeout','returning partial output','the stream was interrupted'))
 (folder/'stdout.jsonl').write_text(stdout,encoding='utf-8');(folder/'stderr.log').write_text(stderr,encoding='utf-8')
 after=snapshot(w);changed=sorted(k for k in set(before)|set(after) if before.get(k)!=after.get(k))
 allowed={'qgrunentry':('apps/network-quick-check/src/gui_run_entry.rs','apps/network-quick-check/src/gui_run_entry_tests.rs'),'qgrunui':('apps/network-quick-check/src/native_gui.rs','apps/network-quick-check/src/native_gui_tests.rs'),'qgbridge':('apps/network-quick-check/src/gui_presenter.rs','apps/network-quick-check/src/gui_run_session.rs','apps/network-quick-check/src/gui_run_session_tests.rs'),'qgruntime':('apps/network-quick-check/src/gui_coordinator.rs','apps/network-quick-check/src/gui_coordinator_tests.rs'),'qgrender':('apps/network-quick-check/src/gui_result_render.rs',),'qgcoordfix':('apps/network-quick-check/src/gui_coordinator.rs','apps/network-quick-check/src/gui_coordinator_tests.rs'),'qgcoordinator':('apps/network-quick-check/src/gui_coordinator.rs','apps/network-quick-check/src/gui_coordinator_tests.rs'),'qgresults':('apps/network-quick-check/src/result_view.rs','apps/network-quick-check/src/result_export.rs'),'qgguiinputs':('apps/network-quick-check/src/lib.rs','apps/network-quick-check/src/gui_entry.rs','apps/network-quick-check/src/gui_presenter.rs','apps/network-quick-check/src/gui_presenter_tests.rs','apps/network-quick-check/src/native_gui.rs','apps/network-quick-check/src/native_gui_tests.rs'),'qgguistate':('apps/network-quick-check/src/lib.rs','apps/network-quick-check/src/gui_state.rs','apps/network-quick-check/src/gui_state_tests.rs'),'qgdevtcp':('apps/network-quick-check/src/lib.rs','apps/network-quick-check/src/diagnostic_cli.rs','apps/network-quick-check/tests/explicit_tcp_entry.rs'),'qgtcpnative':('crates/network-core/tests/tcp_product_native_equivalence.rs',),'qgtcpreplay':('crates/network-core/tests/tcp_product_projection_replay.rs',),'qgquickapp':('apps/network-quick-check/Cargo.toml','apps/network-quick-check/src/lib.rs','apps/network-quick-check/src/main.rs','apps/network-quick-check/tests/resolver_dispatch.rs'),'qgdns':('crates/network-core/src/dns.rs','crates/network-core/tests/dns.rs'),'qgtrace':('crates/network-core/src/traceroute.rs','crates/network-core/tests/traceroute.rs'),'qg2runner':('crates/network-core/src/runner.rs','crates/network-core/tests/runner.rs'),'qg2input':('crates/network-core/src/targets.rs','crates/network-core/tests/targets.rs'),'qg2measure':('crates/network-core/src/measurements.rs','crates/network-core/tests/measurements.rs'),'qgplan2':('docs/quick-check/','apps/network-quick-check/README.md'),'qgcore':('crates/network-core/','schemas/quick-check-result-1.0.schema.json','fixtures/quick-check/'),'qgplan':('docs/quick-check/','apps/network-quick-check/README.md'),'g2bridge':('crates/npi-probes/src/main.rs','crates/npi-probes/tests/cli_dns.rs'),'g2guide':('README.md','docs/g2a-developer-guide.md'),'g2hostclean':('crates/npi-probes/src/host.rs','crates/npi-probes/tests/host.rs'),'g2dns':('crates/npi-probes/src/dns.rs','crates/npi-probes/tests/dns.rs'),'g2tcp':('crates/npi-probes/src/tcp.rs','crates/npi-probes/tests/tcp.rs'),'g2icmp':('crates/npi-probes/src/icmp.rs','crates/npi-probes/tests/icmp.rs'),'g2host':('crates/npi-probes/src/host.rs','crates/npi-probes/tests/host.rs'),'g2engine':('crates/npi-probes/src/engine.rs','crates/npi-probes/src/main.rs','crates/npi-probes/tests/engine.rs'),'architecture':('docs/',),'core':('crates/npi-core/',),'schema':('schemas/','fixtures/','tests/schema/','tools/validate_schema.py'),'ui':('ui/',),'planner':('crates/npi-core/src/planning.rs','crates/npi-core/tests/planning.rs','crates/npi-core/src/lib.rs',)}
 violations=[k for k in changed if not any(k.startswith(q) if q.endswith('/') else k==q for q in allowed[role])]
 result.update(exit_code=p.returncode,elapsed_seconds=round(time.monotonic()-begin,3),completed_at=datetime.datetime.now().astimezone().isoformat(),changed_paths=changed,scope_violations=violations,permission_required='[PERMISSION_REQUIRED]'in stdout+stderr)
 (folder/'after.json').write_text(json.dumps(after,indent=2),encoding='utf-8');(folder/'result.json').write_text(json.dumps(clean(result),ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps(result,ensure_ascii=False),flush=True);return result
if __name__=='__main__':
 stage=sys.argv[1] if len(sys.argv)>1 else'g01';roles=sys.argv[2:] or['architecture','core','schema','ui']
 with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:results=list(pool.map(lambda r:run(r,stage),roles))
 (H/'runs'/(stage+'-summary.json')).write_text(json.dumps(results,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 sys.exit(0 if all(r['exit_code']==0 and not r['partial'] and not r['scope_violations'] and r['changed_paths'] for r in results)else 1)
