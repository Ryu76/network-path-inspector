"""감사·단위/독립 회귀를 통과한 공통 Core만 동일 프로젝트에 선택 통합한다."""
import argparse,datetime,hashlib,json,pathlib,shutil,subprocess,tomllib,os
p=argparse.ArgumentParser();p.add_argument('--resume-verified-copy',action='store_true');a=p.parse_args()
R=pathlib.Path(__file__).resolve().parents[1];w=R/'.worktrees/qgcore'
def load(rel):return json.loads((R/rel).read_text(encoding='utf-8'))
assert load('artifacts/qg0-design-acceptance.json')['decision']=='ACCEPTED_FOR_LOCAL_DEVELOPMENT_DESIGN_AND_TEST_PLAN_ONLY'
for name in ['qg1-core-final-tests','qg1-independent-final-tests','qg1-core-final-clippy','qg1-core-canonical-fmt']:
 x=load('artifacts/commands/'+name+'.json');assert x['exit_code']==0 and not x['partial'],name
manifest=load('artifacts/qg1-canonical-source.json')['files'];baseline=load('artifacts/qg0-inspector-baseline.json')
for rel,sha in baseline['protected_inspector_sha256'].items():assert hashlib.sha256((R/rel).read_bytes()).hexdigest()==sha,f'기존Inspector변경: {rel}'
for rel,info in manifest.items():
 assert rel.startswith(('crates/network-core/','fixtures/quick-check/'))or rel=='schemas/quick-check-result-1.0.schema.json'
 if a.resume_verified_copy:assert hashlib.sha256((R/rel).read_bytes()).hexdigest()==info['normalized_sha256'],f'부분통합후부모변경 덮기거부: {rel}'
 else:assert not (R/rel).exists(),f'기존파일 덮기 거부: {rel}'
 assert hashlib.sha256((w/rel).read_bytes()).hexdigest()==info['normalized_sha256'],f'검증후 소스변경: {rel}'
original_toml=(R/'Cargo.toml').read_text(encoding='utf-8');needle='members = ["crates/npi-core", "crates/npi-probes"]';new_members='members = ["crates/npi-core", "crates/npi-probes", "crates/network-core"]'
lock=R/'Cargo.lock'
if a.resume_verified_copy:
 assert original_toml.count(new_members)==1
 p=subprocess.run(['git','-C',str(w),'show','bc56f27:Cargo.lock'],capture_output=True,timeout=20);assert p.returncode==0,p.stderr
 old_lock_bytes=p.stdout;assert hashlib.sha256(old_lock_bytes).hexdigest()==load('.harness/runs/qg01-qgcore/before.json')['Cargo.lock'],'초기원본lock복구근거불일치'
else:
 assert original_toml.count(needle)==1
 old_lock_bytes=lock.read_bytes()
 for rel in manifest:
  dst=R/rel;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(w/rel,dst)
 (R/'Cargo.toml').write_text(original_toml.replace(needle,new_members),encoding='utf-8',newline='\n')
old_pkgs={p['name']:p for p in tomllib.loads(old_lock_bytes.decode('utf-8'))['package']};assert 'network-core'not in old_pkgs
env=os.environ.copy();scratch=pathlib.Path(os.environ['TMPDIR']);env.update(TMP=str(scratch),TEMP=str(scratch))
p=subprocess.run(['cargo','metadata','--offline','--filter-platform','x86_64-pc-windows-msvc','--format-version','1'],cwd=R,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=40);assert p.returncode==0,p.stderr
metadata=json.loads(p.stdout);new_pkgs={p['name']:p for p in tomllib.loads(lock.read_text(encoding='utf-8'))['package']}
assert all(new_pkgs.get(name)==pkg for name,pkg in old_pkgs.items()),'기존 dependency lock변경 거부'
assert set(new_pkgs)-set(old_pkgs)=={'network-core'},set(new_pkgs)-set(old_pkgs)
blocked={'tauri','wry','webview2-com','pcap','pcap-sys','npcap','rusqlite','libsqlite3-sys','sqlite','printpdf','headless_chrome','chromiumoxide'}
resolve={node['id']:node for node in metadata['resolve']['nodes']};packages={p['id']:p for p in metadata['packages']};core=next(p['id']for p in metadata['packages']if p['name']=='network-core');seen=set();queue=[core]
while queue:
 identity=queue.pop()
 if identity in seen:continue
 seen.add(identity);queue.extend(resolve[identity]['dependencies'])
names=sorted(packages[identity]['name']for identity in seen);assert not(set(names)&blocked),set(names)&blocked
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'scope':'QG1 공통facade/계약 선택통합, GUI/EXE/프로브전체수용아님','source_manifest':'artifacts/qg1-canonical-source.json','integrated_file_count':len(manifest),'protected_source_changed':[],'cargo_manifest_change':'network-core workspace member only','lockfile_old_sha256':hashlib.sha256(old_lock_bytes).hexdigest(),'lockfile_new_sha256':hashlib.sha256(lock.read_bytes()).hexdigest(),'new_lock_packages':['network-core'],'existing_lock_packages_unchanged':True,'normal_core_dependency_packages':names,'banned_dependency_matches':[],'qg1_accepted':False}
out=R/'artifacts/qg1-integration.json';assert not out.exists();out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps(record,ensure_ascii=False,indent=2))
