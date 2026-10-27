"""검증된 G2-A 기준의 독립 bridge/guide worktree를 준비한다."""
import hashlib,json,pathlib,shutil,subprocess
R=pathlib.Path(__file__).resolve().parents[1]
def git(*args):
 p=subprocess.run(['git','-C',str(R),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60);assert p.returncode==0,p.stderr;return p.stdout
for role in ['g2bridge','g2guide']:
 w=R/'.worktrees'/role;assert not w.exists(),f'기존 worktree 보존: {w}'
 git('worktree','add','-b','ai-pro/'+role,str(w),'HEAD')
 package=R/'crates/npi-probes'
 for src in package.rglob('*'):
  if src.is_file() and (src.suffix=='.rs' or src.name=='Cargo.toml'):
   dst=w/src.relative_to(R);dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(src.read_bytes())
 refs=w/'.harness/references';refs.mkdir(parents=True,exist_ok=True)
 shutil.copyfile(R/'artifacts/g2a-flash-reverified.json',refs/'g2a-checkpoint.json')
 if role=='g2bridge':
  after=json.loads((R/'.harness/runs/g2dnsfix-fallback2-g2dns/after.json').read_text(encoding='utf-8'))
  for section in ['src','tests']:
   rel=f'crates/npi-probes/{section}/dns.rs';src=R/'.worktrees/g2dns'/rel;assert hashlib.sha256(src.read_bytes()).hexdigest()==after[rel];(w/rel).write_bytes(src.read_bytes())
  lib=w/'crates/npi-probes/src/lib.rs';text=lib.read_text(encoding='utf-8');assert 'pub mod dns;'not in text;lib.write_text(text+'\npub mod dns;\n',encoding='utf-8',newline='\n')
 p=subprocess.run(['git','-C',str(w),'add','crates/npi-probes'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30);assert p.returncode==0,p.stderr
 p=subprocess.run(['git','-C',str(w),'-c','core.autocrlf=false','commit','-m','chore: prepare reviewed '+role+' baseline'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30);assert p.returncode==0,p.stderr
 status=subprocess.run(['git','-C',str(w),'status','--porcelain'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=15);assert status.returncode==0 and not status.stdout,status.stdout
 print(role,'isolated baseline clean; no production or remote operation')
