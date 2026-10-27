"""최종 경고 보정 실행기만 SHA 검증 후 root에 선택 통합한다."""
import datetime,hashlib,json,pathlib,shutil,subprocess,tomllib
R=pathlib.Path(__file__).resolve().parents[1];W=R/'.worktrees/qg2runner';load=lambda p:json.loads(p.read_text(encoding='utf-8'))
for name in ['qg2b-runner-style-repaired','qg2b-runner-final-clippy']:
 d=load(R/'artifacts/commands'/(name+'.json'));assert d['exit_code']==0 and not d['partial']
proof=load(R/'artifacts/qg2b-runner-style-canonical.json');accepted=load(R/'artifacts/qg2a-acceptance.json');protected=load(R/'artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
for rel,sha in {**accepted['source_sha256'],**protected}.items():assert hashlib.sha256((R/rel).read_bytes()).hexdigest()==sha,rel
for rel,sha in proof['canonical_source_sha256'].items():assert hashlib.sha256((W/rel).read_bytes()).hexdigest()==sha and not(R/rel).exists(),rel
for rel,sha in accepted['source_sha256'].items():
 if not rel.endswith('src/lib.rs'):assert hashlib.sha256((W/rel).read_bytes()).hexdigest()==sha,rel
manifest=R/'crates/network-core/Cargo.toml';lib=R/'crates/network-core/src/lib.rs';lock=R/'Cargo.lock';before={'manifest_sha256':hashlib.sha256(manifest.read_bytes()).hexdigest(),'lib_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'lock_sha256':hashlib.sha256(lock.read_bytes()).hexdigest()};old_lock=tomllib.loads(lock.read_text(encoding='utf-8'));old_manifest=tomllib.loads(manifest.read_text(encoding='utf-8'));new_manifest=tomllib.loads((W/'crates/network-core/Cargo.toml').read_text(encoding='utf-8'));added=new_manifest['dependencies'].pop('tokio');assert new_manifest==old_manifest;assert added['version']=='=1.52.3'
out=R/'artifacts/qg2b-runner-integration.json';assert not out.exists();record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'state':'PREPARING','before':before,'source_proof':'artifacts/qg2b-runner-style-canonical.json','full_qg2_accepted':False};out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
for rel in proof['canonical_source_sha256']:shutil.copyfile(W/rel,R/rel)
shutil.copyfile(W/'crates/network-core/Cargo.toml',manifest);lib.write_text(lib.read_text(encoding='utf-8')+'\npub mod runner;\n',encoding='utf-8',newline='\n')
p=subprocess.run(['cargo','metadata','--offline','--filter-platform','x86_64-pc-windows-msvc','--format-version','1'],cwd=R,capture_output=True,timeout=45);assert p.returncode==0,p.stderr.decode('utf-8','replace')
new_lock=tomllib.loads(lock.read_text(encoding='utf-8'));old_packages={d['name']:d for d in old_lock['package']};new_packages={d['name']:d for d in new_lock['package']};assert old_packages.keys()==new_packages.keys()
for name,data in old_packages.items():
 if name=='network-core':
  candidate=dict(new_packages[name]);candidate['dependencies']=[v for v in candidate['dependencies']if v!='tokio'];assert candidate==data
 else:assert new_packages[name]==data,name
p=subprocess.run(['cargo','fmt','-p','network-core'],cwd=R,capture_output=True,timeout=30);assert p.returncode==0,p.stderr
for rel,sha in proof['canonical_source_sha256'].items():assert hashlib.sha256((R/rel).read_bytes()).hexdigest()==sha
for rel,sha in protected.items():assert hashlib.sha256((R/rel).read_bytes()).hexdigest()==sha,rel
record.update(state='INTEGRATED_FOR_ROOT_REGRESSION',source_sha256={rel:hashlib.sha256((R/rel).read_bytes()).hexdigest()for rel in [*proof['canonical_source_sha256'],'crates/network-core/src/lib.rs','crates/network-core/Cargo.toml','Cargo.lock']},lock_change='기존 package/version 변경0, network-core에 기존 잠금 Tokio 직접 edge만 추가',inspector_changed=0,slice_accepted=False);out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps({'integrated_files':2,'existing_probe_copies':0,'inspector_changed':0,'disk_free_gib':round(shutil.disk_usage(R).free/1024**3,2),'accepted':False},ensure_ascii=False))
