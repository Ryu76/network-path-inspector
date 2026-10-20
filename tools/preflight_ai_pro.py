import importlib.util,json,pathlib,subprocess,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('npi_harness',ROOT/'tools/ai_pro_harness.py');h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
w=ROOT/'.worktrees/architecture';target=w/'docs/preflight.json';assert not target.exists()
prompt='FILE ONLY preflight. Do not execute commands, spawn agents, read credentials or access network. Read AGENTS.md and contracts/g1-interface-contract.json in your CURRENT cwd, which must be E:/harnes/network-path-inspector/.worktrees/architecture. Create ONLY docs/preflight.json containing JSON keys contract_version and feature_count from that contract. Then reply PREFLIGHT_OK. If file tool permission denied emit [PERMISSION_REQUIRED], no bypass.'
env={k:v for k,v in h.os.environ.items() if not h.SECRET.search(k)}
p=subprocess.Popen(['E:/antigravity-cli/agy.exe','--model',h.MODEL,'--sandbox','--mode','accept-edits','--output-format','stream-json','--print-timeout','90s','--print='+prompt],cwd=w,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
try:out,err=p.communicate(timeout=110)
except subprocess.TimeoutExpired:
 subprocess.run(['taskkill.exe','/PID',str(p.pid),'/T','/F'],capture_output=True,timeout=20);out,err=p.communicate(timeout=20)
folder=ROOT/'.harness/runs/preflight';folder.mkdir(parents=True,exist_ok=False);(folder/'stdout.jsonl').write_text(h.lines(out),encoding='utf-8');(folder/'stderr.log').write_text(h.lines(err),encoding='utf-8')
value=json.loads(target.read_text(encoding='utf-8')) if target.exists() else None
ok=p.returncode==0 and value=={'contract_version':'g1-1.1.0','feature_count':23}
result={'model':h.MODEL,'exit_code':p.returncode,'workspace_marker_verified':ok,'marker':value};(folder/'result.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8');print(json.dumps(result))
if ok:target.unlink()
sys.exit(0 if ok else 1)
