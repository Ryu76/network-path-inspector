"""실행기 원본을 보존하고 검증된 의존 모듈과 필요한 컴파일 수정만 적용한다."""
import datetime,hashlib,json,pathlib,shutil,subprocess
R=pathlib.Path(__file__).resolve().parents[1];w=R/'.worktrees/qg2runner';load=lambda rel:json.loads((R/rel).read_text(encoding='utf-8'))
assert load('artifacts/qg2brunner-actor-policy-audit.json')['all_actor_policy_checks_passed']
run=load('.harness/runs/qg2brunner-qg2runner/result.json');after=load('.harness/runs/qg2brunner-qg2runner/after.json');allowed={'crates/network-core/src/runner.rs','crates/network-core/tests/runner.rs'};assert set(run['changed_paths'])==allowed
for rel in allowed:assert hashlib.sha256((w/rel).read_bytes()).hexdigest()==after[rel],rel
for args in [['add',*sorted(allowed),'Cargo.lock'],['-c','core.autocrlf=false','commit','-m','chore: preserve QG2 runner before typed-request compile repair']]:
 p=subprocess.run(['git','-C',str(w),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30);assert p.returncode==0,p.stderr
proof=load('artifacts/qg2a-integration.json');copied={}
for rel,sha in proof['root_source_sha256'].items():
 if rel.endswith('src/lib.rs'):continue
 assert hashlib.sha256((R/rel).read_bytes()).hexdigest()==sha,rel
 copied[rel]={'before_sha256':hashlib.sha256((w/rel).read_bytes()).hexdigest(),'after_sha256':sha};shutil.copyfile(R/rel,w/rel)
p=w/'crates/network-core/src/runner.rs';text=p.read_text(encoding='utf-8');needle='#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]\npub struct QuickRunRequest';assert text.count(needle)==1;text=text.replace(needle,'// 요청은 내부 Rust 타입이며 아직 JSON wire DTO 계약이 아니다.\n#[derive(Debug, Clone, PartialEq, Eq)]\npub struct QuickRunRequest',1);p.write_text(text,encoding='utf-8',newline='\n')
p=subprocess.run(['cargo','fmt','-p','network-core'],cwd=w,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=40);assert p.returncode==0,p.stderr
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'scope':'실행기 draft 원본보존후컴파일/의존모듈동기화.제품수용아님','compile_failure':'qg2b-runner-first-tests: QuickRunRequest의요구되지않은serde derives가비serde QuickTarget/QuickOptions를요구하여8 trait bound오류','parent_change':'불필요한request Serialize/Deserialize derive만제거,기존타입의trait/API변경없음;edition2024rustfmt','updated_dependencies':copied,'actor_runner_sha256':{rel:after[rel]for rel in allowed},'current_runner_sha256':{rel:hashlib.sha256((w/rel).read_bytes()).hexdigest()for rel in allowed},'accepted':False}
out=R/'artifacts/qg2b-runner-prepared-for-tests.json';assert not out.exists();out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print('runner 원본보존. 수정된의존4파일동기화+불필요한requestserde derive제거,실제실행시험준비.')
