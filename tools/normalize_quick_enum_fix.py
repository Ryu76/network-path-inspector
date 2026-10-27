"""enum 보정의 테스트 메시지 구문·EOF만 보정하고 rustfmt 정규형 증거를 보존한다."""
import datetime,hashlib,json,pathlib,subprocess
R=pathlib.Path(__file__).resolve().parents[1];w=R/'.worktrees/qgcore';run=R/'.harness/runs/qgenumfix-qgcore'
load=lambda p:json.loads(p.read_text(encoding='utf-8'))
assert load(R/'artifacts/qgenumfix-actor-policy-audit.json')['all_actor_policy_checks_passed']
after=load(run/'after.json');before=load(run/'before.json');result=load(run/'result.json');allowed={'crates/network-core/src/quick.rs','crates/network-core/tests/quick_core_regression_tests.rs'};assert set(result['changed_paths'])==allowed
original={}
for rel in allowed:
 data=(w/rel).read_bytes();assert hashlib.sha256(data).hexdigest()==after[rel];assert hashlib.sha256((R/rel).read_bytes()).hexdigest()==before[rel],f'통합root후속변경거부:{rel}';original[rel]=data
rel='crates/network-core/tests/quick_core_regression_tests.rs';text=original[rel].decode('utf-8')
for key,tag in [('feature','tcp_connect'),('status','PASS'),('evidence_level','OBSERVED')]:
 old=key+': {\\"'+tag+'\\": null} 객체는 거부되어야 함';new=key+': {{\\"'+tag+'\\": null}} 객체는 거부되어야 함';assert text.count(old)==1,(key,'시험진단문자열범위오류');text=text.replace(old,new,1)
(w/rel).write_text(text,encoding='utf-8',newline='\n')
canonical={}
for rel in allowed:
 p=subprocess.run(['rustfmt','--emit','stdout','--edition','2024'],cwd=w,input=(w/rel).read_bytes(),capture_output=True,timeout=20);assert p.returncode==0,p.stderr;canonical[rel]=p.stdout
p=subprocess.run(['cargo','fmt','-p','network-core'],cwd=w,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30);assert p.returncode==0,p.stderr
for rel in allowed:assert(w/rel).read_bytes()==canonical[rel],rel
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'stage':'qgenumfix','parent_adjustments':'3 test diagnostic format-string braces escaped; Rust edition2024 rustfmt/EOF only. Production behavior is actor implementation. Failed compile evidence retained.','files':{rel:{'root_before_sha256':before[rel],'actor_sha256':after[rel],'normalized_sha256':hashlib.sha256((w/rel).read_bytes()).hexdigest()}for rel in sorted(allowed)},'integrated':False}
out=R/'artifacts/qg1-enum-canonical-source.json';assert not out.exists();out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps(record,ensure_ascii=False,indent=2))
