"""Apply only audited G2 host/engine repairs, preserve parent mechanical history."""
import datetime,hashlib,json,pathlib,shutil,subprocess
R=pathlib.Path(__file__).resolve().parents[1];out=R/'artifacts/g2repair-selected-integration.json';assert not out.exists(),'Never replay repairs over subsequent work'
summary=json.loads((R/'.harness/runs/g2repair-priority-summary.json').read_text(encoding='utf-8'));assert not summary['blocked']
latest={'g2engine':next(row['stage']for row in reversed(summary['attempts'])if row['role']=='g2engine')}
clean=json.loads((R/'.harness/runs/g2hostfinal-priority-summary.json').read_text(encoding='utf-8'));assert not any(x.get('role')=='g2hostclean'for x in clean['blocked'])
latest['g2hostclean']=next(row['stage']for row in reversed(clean['attempts'])if row['role']=='g2hostclean')
for stage in set(latest.values()):
 subprocess.run(['python',str(R/'tools/audit_ai_pro_runs.py'),stage],cwd=R,check=False)
 audit=json.loads((R/'artifacts'/(stage+'-actor-policy-audit.json')).read_text(encoding='utf-8'))
 for role,chosen in latest.items():
  if chosen==stage:assert next(x for x in audit['actors']if x['role']==role)['passed'],(stage,role,'latest actor not policy-valid')
rows=[]
for role,component in [('g2hostclean','host'),('g2engine','engine')]:
 stage=latest[role];folder=R/'.harness/runs'/(stage+'-'+role);after=json.loads((folder/'after.json').read_text(encoding='utf-8'))
 for started in (R/'.harness/runs').glob('*-'+role+'/started.json'):assert (started.parent/'result.json').exists(),'writer still active'
 for suffix in ['src','tests']:
  relative='crates/npi-probes/'+suffix+'/'+component+'.rs';src=R/'.worktrees'/role/relative;dest=R/relative;digest=hashlib.sha256(src.read_bytes()).hexdigest();assert after[relative]==digest
  rows.append({'path':relative,'role':role,'before_sha256':hashlib.sha256(dest.read_bytes()).hexdigest(),'actor_sha256':digest,'stage':stage})
for row in rows:shutil.copyfile(R/'.worktrees'/row['role']/row['path'],R/row['path'])
out.write_text(json.dumps({'at':datetime.datetime.now().astimezone().isoformat(),'files':rows,'accepted':False},ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n');print(json.dumps({'repaired_files':len(rows),'stages':latest,'product_accepted':False},ensure_ascii=False))
