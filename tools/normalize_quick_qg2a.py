"""QG2 초기 actor 원본 SHA를 보존하고 trait bound/서식만 최소 보정한다."""
import datetime,hashlib,json,pathlib,subprocess
R=pathlib.Path(__file__).resolve().parents[1];load=lambda p:json.loads(p.read_text(encoding='utf-8'))
audit=load(R/'artifacts/qg2a-actor-policy-audit.json');assert audit['all_actor_policy_checks_passed']
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'stage':'qg2a','parent_adjustments':['targets duplicate-feature HashSet key uses feature.as_str() instead of requiring Hash on unchanged QG1 enum','edition2024 rustfmt/EOF only'],'roles':{},'accepted':False}
for role in ['qg2input','qg2measure']:
 w=R/'.worktrees'/role;run=R/'.harness/runs'/f'qg2a-{role}';after=load(run/'after.json');result=load(run/'result.json');original={rel:(w/rel).read_bytes()for rel in result['changed_paths']}
 for rel,data in original.items():assert hashlib.sha256(data).hexdigest()==after[rel],rel
 if role=='qg2input':
  p=w/'crates/network-core/src/targets.rs';text=p.read_text(encoding='utf-8');assert text.count('seen_features.insert(feature)')==1;text=text.replace('seen_features.insert(feature)','seen_features.insert(feature.as_str())');p.write_text(text,encoding='utf-8',newline='\n')
 canonical={}
 for rel in original:
  p=subprocess.run(['rustfmt','--emit','stdout','--edition','2024'],cwd=w,input=(w/rel).read_bytes(),capture_output=True,timeout=20);assert p.returncode==0,p.stderr;canonical[rel]=p.stdout
 p=subprocess.run(['cargo','fmt','-p','network-core'],cwd=w,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30);assert p.returncode==0,p.stderr
 files={}
 for rel,raw in original.items():
  data=(w/rel).read_bytes();assert data==canonical[rel];files[rel]={'actor_sha256':after[rel],'normalized_sha256':hashlib.sha256(data).hexdigest()}
 record['roles'][role]=files
out=R/'artifacts/qg2a-canonical-source.json';assert not out.exists();out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps(record,ensure_ascii=False,indent=2))
