"""One-shot G2-A selective integration from completed audited writers only."""
import argparse,datetime,hashlib,json,pathlib,shutil,subprocess
R=pathlib.Path(__file__).resolve().parents[1];p=argparse.ArgumentParser();p.add_argument('--host-stage',default='g2a');p.add_argument('--icmp-stage',default='g2a');a=p.parse_args()
stages={'g2tcp':'g2tcpfix','g2icmp':a.icmp_stage,'g2host':a.host_stage,'g2engine':'g2a'}
manifest=R/'artifacts/g2a-selected-integration.json';assert not manifest.exists(),'Historical one-shot integration cannot overwrite later QA repairs'
for stage in sorted(set(stages.values())):
 subprocess.run(['python',str(R/'tools/audit_ai_pro_runs.py'),stage],cwd=R,check=True)
files=[]
for role,stage in stages.items():
 for started in (R/'.harness/runs').glob('*-'+role+'/started.json'):assert (started.parent/'result.json').exists(), 'writer still active'
 folder=R/'.harness/runs'/(stage+'-'+role);record=json.loads((folder/'result.json').read_text(encoding='utf-8'));after=json.loads((folder/'after.json').read_text(encoding='utf-8'));assert record['exit_code']==0 and not record['partial']and not record['scope_violations']
 relatives=['crates/npi-probes/src/'+role.removeprefix('g2')+'.rs','crates/npi-probes/tests/'+role.removeprefix('g2')+'.rs']
 if role=='g2engine':relatives.append('crates/npi-probes/src/main.rs')
 for relative in relatives:
  src=R/'.worktrees'/role/relative;dest=R/relative;digest=hashlib.sha256(src.read_bytes()).hexdigest();assert after[relative]==digest,(relative,'source changed after audited job');assert not dest.exists(),relative
  files.append({'source':str(src),'destination':relative,'sha256':digest,'role':role,'stage':stage})
for row in files:
 dest=R/row['destination'];dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(row['source'],dest)
manifest.write_text(json.dumps({'recorded_at':datetime.datetime.now().astimezone().isoformat(),'files':files,'accepted':False},ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n');print(json.dumps({'integrated_files':len(files),'tests_pending':True,'manifest':str(manifest)},ensure_ascii=False,indent=2))
