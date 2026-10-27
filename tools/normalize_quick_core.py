"""감사된 Quick Core를 rustfmt로만 정렬하고 바이트·정규형 증거를 남긴다."""
import datetime,hashlib,json,pathlib,subprocess
R=pathlib.Path(__file__).resolve().parents[1];w=R/'.worktrees/qgcore'
for stage in ['qg01','qgcorefix','qgfinalfix']:
 audit=json.loads((R/'artifacts'/f'{stage}-actor-policy-audit.json').read_text(encoding='utf-8'));actor=next(a for a in audit['actors']if a['role']=='qgcore');assert actor['passed'],(stage,actor)
after=json.loads((R/'.harness/runs/qgfinalfix-qgcore/after.json').read_text(encoding='utf-8'))
paths=sorted(p for folder in ['crates/network-core','fixtures/quick-check']for p in (w/folder).rglob('*')if p.is_file());paths.append(w/'schemas/quick-check-result-1.0.schema.json')
original={p.relative_to(w).as_posix():p.read_bytes()for p in paths}
for rel,data in original.items():assert hashlib.sha256(data).hexdigest()==after[rel],f'감사후 변경: {rel}'
canonical={}
for rel,data in original.items():
 if rel.endswith('.rs'):
  p=subprocess.run(['rustfmt','--emit','stdout','--edition','2024'],input=data,capture_output=True,timeout=20,cwd=w);assert p.returncode==0,p.stderr;canonical[rel]=p.stdout
p=subprocess.run(['cargo','fmt','-p','network-core'],cwd=w,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30);assert p.returncode==0,p.stderr
manifest={}
for rel,data in original.items():
 current=(w/rel).read_bytes();assert current==(canonical[rel]if rel in canonical else data),f'rustfmt 정규형 외 변경: {rel}'
 manifest[rel]={'actor_sha256':hashlib.sha256(data).hexdigest(),'normalized_sha256':hashlib.sha256(current).hexdigest(),'format_only_changed':data!=current}
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'actor_stages':['qg01:qgcore','qgcorefix:qgcore','qgfinalfix:qgcore'],'worktree':str(w),'normalization':'rustfmt stdin canonical bytes, edition2024; cargo fmt -p network-core only','files':manifest,'accepted':False}
out=R/'artifacts/qg1-canonical-source.json';assert not out.exists();out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps({'files':len(manifest),'format_only_changed':sum(m['format_only_changed']for m in manifest.values()),'non_format_changes':0},ensure_ascii=False))
