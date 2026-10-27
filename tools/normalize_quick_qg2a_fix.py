"""QG2 보정 actor의 최신 SHA를 확인하고 테스트 clone 경고·서식만 정리한다."""
import datetime,hashlib,json,pathlib,re,subprocess
R=pathlib.Path(__file__).resolve().parents[1];load=lambda p:json.loads(p.read_text(encoding='utf-8'))
assert load(R/'artifacts/qg2afix-actor-policy-audit.json')['all_actor_policy_checks_passed']
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'stage':'qg2afix','parent_adjustments':'targets test single-element clone slices replaced by std::slice::from_ref; edition2024 rustfmt only','roles':{},'accepted':False}
for role in ['qg2input','qg2measure']:
 w=R/'.worktrees'/role;run=R/'.harness/runs'/f'qg2afix-{role}';after=load(run/'after.json');result=load(run/'result.json');raw={rel:(w/rel).read_bytes()for rel in result['changed_paths']}
 for rel,data in raw.items():assert hashlib.sha256(data).hexdigest()==after[rel],rel
 if role=='qg2input':
  p=w/'crates/network-core/tests/targets.rs';text=p.read_text(encoding='utf-8');text,count=re.subn(r'&\[([A-Za-z_][A-Za-z0-9_]*)\.clone\(\)\]',r'std::slice::from_ref(&\1)',text);assert count==9,count;p.write_text(text,encoding='utf-8',newline='\n')
 canonical={}
 for rel in raw:
  p=subprocess.run(['rustfmt','--emit','stdout','--edition','2024'],cwd=w,input=(w/rel).read_bytes(),capture_output=True,timeout=20);assert p.returncode==0,p.stderr;canonical[rel]=p.stdout
 p=subprocess.run(['cargo','fmt','-p','network-core'],cwd=w,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30);assert p.returncode==0,p.stderr
 for rel in raw:assert(w/rel).read_bytes()==canonical[rel]
 record['roles'][role]={rel:{'actor_sha256':after[rel],'normalized_sha256':hashlib.sha256((w/rel).read_bytes()).hexdigest()}for rel in raw}
out=R/'artifacts/qg2afix-canonical-source.json';assert not out.exists();out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print('QG2 보정4파일 원본SHA/정규형 확인. 테스트slice clone9곳만동등변환,제품구현추가변경0.')
