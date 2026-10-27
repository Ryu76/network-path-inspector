"""DNS 공용 구현과 검증된 어댑터만 root 회귀용으로 선택 통합한다. 최종 수용은 별도다."""
import datetime,hashlib,json,pathlib,shutil,subprocess,tomllib
R=pathlib.Path(__file__).resolve().parents[1];W=R/'.worktrees/qgdns';load=lambda rel:json.loads((R/rel).read_text(encoding='utf-8'))
for name in ['qg2c-dns-final-clippy','qg2c-dns-canonical-tests','qg2c-dns-boundaries-after-fix','qg2c-dns-native-adapter-after-fix']:
 d=load('artifacts/commands/'+name+'.json');assert d['exit_code']==0 and not d['partial'],name
previous=load('artifacts/qg2b-runner-acceptance.json');protected=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
for rel,sha in {**previous['source_sha256'],**protected}.items():assert hashlib.sha256((R/rel).read_bytes()).hexdigest()==sha,rel
proof=load('artifacts/qg2c-dns-canonical-source.json');copies={**proof['canonical_source_sha256'],'crates/network-resolver/Cargo.toml':hashlib.sha256((W/'crates/network-resolver/Cargo.toml').read_bytes()).hexdigest()}
for rel,sha in copies.items():assert hashlib.sha256((W/rel).read_bytes()).hexdigest()==sha and not(R/rel).exists(),rel
manifest=R/'crates/network-core/Cargo.toml';lib=R/'crates/network-core/src/lib.rs';workspace=R/'Cargo.toml';lock=R/'Cargo.lock';before={str(p.relative_to(R)):hashlib.sha256(p.read_bytes()).hexdigest()for p in [manifest,lib,workspace,lock]};old_lock=tomllib.loads(lock.read_text(encoding='utf-8'));old_manifest=tomllib.loads(manifest.read_text(encoding='utf-8'));new_manifest=tomllib.loads((W/'crates/network-core/Cargo.toml').read_text(encoding='utf-8'));edge=new_manifest['dependencies'].pop('network-resolver');assert edge=={'path':'../network-resolver'} and new_manifest==old_manifest
out=R/'artifacts/qg2c-dns-integration.json';assert not out.exists();record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'state':'PREPARING','before_sha256':before,'source_proof':'artifacts/qg2c-dns-canonical-source.json','static_recheck_pending':'deleg_75f42e38','slice_accepted':False,'full_qg2_accepted':False};out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
for rel in copies:(R/rel).parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(W/rel,R/rel)
shutil.copyfile(W/'crates/network-core/Cargo.toml',manifest);s=workspace.read_text(encoding='utf-8');old='"crates/network-core"]';assert s.count(old)==1;workspace.write_text(s.replace(old,'"crates/network-core", "crates/network-resolver"]'),encoding='utf-8',newline='\n');lib.write_text(lib.read_text(encoding='utf-8')+'\n// 두 제품이 공유하는 OS resolver 단일 구현. DNS 서버/RR/TTL 관측을 의미하지 않는다.\npub use network_resolver as dns_engine;\npub mod dns;\n',encoding='utf-8',newline='\n')
p=subprocess.run(['cargo','metadata','--offline','--filter-platform','x86_64-pc-windows-msvc','--format-version','1'],cwd=R,capture_output=True,timeout=45);assert p.returncode==0,p.stderr.decode('utf-8','replace')
new_lock=tomllib.loads(lock.read_text(encoding='utf-8'));key=lambda d:(d['name'],d['version'],d.get('source'));before_packages={key(d):d for d in old_lock['package']};after_packages={key(d):d for d in new_lock['package']};assert len(before_packages)==len(old_lock['package']) and len(after_packages)==len(new_lock['package']);assert set(after_packages)-set(before_packages)=={('network-resolver','0.1.0',None)};assert not set(before_packages)-set(after_packages)
for k,data in before_packages.items():
 if k[0]=='network-core':
  candidate=dict(after_packages[k]);candidate['dependencies']=[v for v in candidate['dependencies']if v!='network-resolver'];assert candidate==data
 else:assert after_packages[k]==data,k
p=subprocess.run(['cargo','fmt','-p','network-core','-p','network-resolver'],cwd=R,capture_output=True,timeout=30);assert p.returncode==0,p.stderr
for rel,sha in copies.items():assert hashlib.sha256((R/rel).read_bytes()).hexdigest()==sha,rel
for rel,sha in protected.items():assert hashlib.sha256((R/rel).read_bytes()).hexdigest()==sha,rel
record.update(state='INTEGRATED_FOR_ROOT_REGRESSION_NOT_ACCEPTED',source_sha256={rel:hashlib.sha256((R/rel).read_bytes()).hexdigest()for rel in [*copies,'crates/network-core/src/lib.rs','crates/network-core/Cargo.toml','Cargo.toml','Cargo.lock']},inspector_changed=0,dependency_change='새로운 외부 버전 없음. workspace-local network-resolver 공용 crate 및 edge만 추가');out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps({'new_source_and_tests':len(copies),'inspector_changed':0,'accepted':False,'static_recheck':'deleg_75f42e38'},ensure_ascii=False))
