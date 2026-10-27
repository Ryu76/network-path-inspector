"""Bounded parent-owned commands, with retained UTF-8 logs and exact exits."""
import argparse,datetime,importlib.util,json,os,pathlib,shutil,subprocess,sys,time
ROOT=pathlib.Path(__file__).resolve().parents[1]
_spec=importlib.util.spec_from_file_location('npi_evidence_redaction',ROOT/'tools/ai_pro_harness.py')
_redaction=importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_redaction)
p=argparse.ArgumentParser();p.add_argument('--cwd',type=pathlib.Path,required=True);p.add_argument('--name',required=True);p.add_argument('--timeout',type=int,default=180);p.add_argument('command',nargs=argparse.REMAINDER);a=p.parse_args()
command=a.command[1:]if a.command[:1]==['--']else a.command
assert command
if command[0]=='npm':command=['cmd.exe','/d','/c',shutil.which('npm.cmd')or'npm.cmd',*command[1:]]
folder=ROOT/'artifacts/commands';folder.mkdir(parents=True,exist_ok=True);stem=folder/a.name;assert not stem.with_suffix('.json').exists(),'Use a new evidence name, never overwrite a prior result'
env=os.environ.copy();env['CARGO_TARGET_DIR']=str(ROOT/'.harness/targets'/a.name)
scratch=pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/scratch')/('npi-evidence-'+a.name);scratch.mkdir(parents=True,exist_ok=True)
env.update(TMP=str(scratch),TEMP=str(scratch),TMPDIR=str(scratch))
started=datetime.datetime.now().astimezone().isoformat();begin=time.monotonic();proc=subprocess.Popen(command,cwd=a.cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
partial=False
try:stdout,stderr=proc.communicate(timeout=a.timeout)
except subprocess.TimeoutExpired:
 partial=True;subprocess.run(['taskkill.exe','/PID',str(proc.pid),'/T','/F'],capture_output=True,timeout=20);stdout,stderr=proc.communicate(timeout=20)
text=_redaction.clean(stdout.decode('utf-8','replace')+'\n'+stderr.decode('utf-8','replace'));stem.with_suffix('.log').write_text(text,encoding='utf-8');result={'command':command,'cwd':str(a.cwd),'started_at':started,'elapsed_seconds':round(time.monotonic()-begin,3),'exit_code':proc.returncode,'partial':partial,'log':str(stem.with_suffix('.log'))};stem.with_suffix('.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(text);print(json.dumps(result,ensure_ascii=False));sys.exit(124 if partial else proc.returncode)
