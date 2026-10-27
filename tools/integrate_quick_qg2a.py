"""실행 검증을 통과한 QG2 입력/매핑4파일만 root검증용으로선택반영한다."""
import datetime,hashlib,json,pathlib,shutil,subprocess
R=pathlib.Path(__file__).resolve().parents[1];load=lambda rel:json.loads((R/rel).read_text(encoding='utf-8'))
for name in ['qg2afix-input-tests','qg2afix-measure-tests','qg2afix-input-canonical-clippy','qg2afix-measure-clippy','qg2a-independent-after-fix']:
 data=load('artifacts/commands/'+name+'.json');assert data['exit_code']==0 and not data['partial'],name
qg1=load('artifacts/qg1-acceptance.json')
for rel,sha in qg1['source_sha256'].items():assert hashlib.sha256((R/rel).read_bytes()).hexdigest()==sha,rel
protected=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
for rel,sha in protected.items():assert hashlib.sha256((R/rel).read_bytes()).hexdigest()==sha,rel
manifest=load('artifacts/qg2afix-canonical-source.json');copies={}
for role,files in manifest['roles'].items():
 for rel,info in files.items():
  src=R/'.worktrees'/role/rel;assert hashlib.sha256(src.read_bytes()).hexdigest()==info['normalized_sha256'];assert not(R/rel).exists(),rel;copies[rel]=src
lib=R/'crates/network-core/src/lib.rs';original=lib.read_text(encoding='utf-8');assert original.count('pub mod quick;')==1
out=R/'artifacts/qg2a-integration.json';assert not out.exists();record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'PREPARING','source_manifest':'artifacts/qg2afix-canonical-source.json','root_qg1_lib_before_sha256':hashlib.sha256(lib.read_bytes()).hexdigest(),'files':list(copies),'inspector_source_changed':0,'qg2_gate_accepted':False};out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
for rel,src in copies.items():shutil.copyfile(src,R/rel)
lib.write_text(original.replace('pub mod quick;','pub mod quick;\npub mod targets;\npub mod measurements;'),encoding='utf-8',newline='\n')
p=subprocess.run(['cargo','fmt','-p','network-core'],cwd=R,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30);assert p.returncode==0,p.stderr
for role,files in manifest['roles'].items():
 for rel,info in files.items():assert hashlib.sha256((R/rel).read_bytes()).hexdigest()==info['normalized_sha256'],rel
record.update(status='INTEGRATED_FOR_ROOT_REGRESSION_AND_FINAL_REVIEW',root_source_sha256={rel:hashlib.sha256((R/rel).read_bytes()).hexdigest()for rel in [*copies,'crates/network-core/src/lib.rs']},isolated_parent_regressions_passed=3,remaining_independent_review=True);out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps({'files':len(copies),'shared_lib_module_declarations_added':2,'inspector_changed':0,'qg2_accepted':False},ensure_ascii=False))
