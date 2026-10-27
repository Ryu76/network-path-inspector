"""Check the user's second-priority Claude family without changing product files."""
import datetime,importlib.util,json,os,pathlib,subprocess,time
R=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('redaction',R/'tools/ai_pro_harness.py');h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
folder=R/'.harness/model-preflight/flash-high';folder.mkdir(parents=True,exist_ok=False)
model='gemini-3.8-flash-high';env={k:v for k,v in os.environ.items()if not h.SECRET.search(k)};scratch=pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/scratch/npi-flash-smoke');scratch.mkdir(exist_ok=True);env.update(TMP=str(scratch),TEMP=str(scratch),TMPDIR=str(scratch))
started=datetime.datetime.now().astimezone().isoformat();p=subprocess.run(['E:/antigravity-cli/agy.exe','--model',model,'--sandbox','--mode','accept-edits','--output-format','stream-json','--print-timeout','60s','--print=No files, no tools, no commands. Reply exactly FLASH_AVAILABLE.'],cwd=scratch,env=env,capture_output=True,timeout=80)
stdout=h.lines(p.stdout);stderr=h.lines(p.stderr);(folder/'stdout.jsonl').write_text(stdout,encoding='utf-8');(folder/'stderr.log').write_text(stderr,encoding='utf-8');rows=[]
for line in stdout.splitlines():
 try:rows.append(json.loads(line))
 except json.JSONDecodeError:pass
last=next((x.get('result',x)for x in reversed(rows)if x.get('event',x.get('type'))=='result'),{});tools=[x for x in rows if x.get('step_update',{}).get('step_type')=='tool'];ok=p.returncode==0 and last.get('status')=='SUCCESS'and'FLASH_AVAILABLE'in last.get('response','')and not tools
record={'model':model,'started_at':started,'completed_at':datetime.datetime.now().astimezone().isoformat(),'exit_code':p.returncode,'success':ok,'status':last.get('status'),'tools_used':len(tools),'error':last.get('error'),'preflight_only':True};(folder/'result.json').write_text(json.dumps(h.clean(record),ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps(h.clean(record),ensure_ascii=False,indent=2));raise SystemExit(0 if ok else 1)
