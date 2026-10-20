"""Selectively integrate reviewed G1 modules, never generated artifacts."""
import hashlib,json,os,pathlib,shutil
ROOT=pathlib.Path('E:/harnes/network-path-inspector');records=[]
assert not (ROOT/'artifacts/g01-integration-files.json').exists(), 'Historical one-shot integration already ran; do not overwrite later QA fixes'
def copy_file(source,target):
 assert source.is_file()and not source.is_symlink();target.parent.mkdir(parents=True,exist_ok=True)
 before=hashlib.sha256(target.read_bytes()).hexdigest()if target.exists()else None;data=source.read_bytes();target.write_bytes(data);records.append({'source':str(source),'target':str(target),'before':before,'after':hashlib.sha256(data).hexdigest()})
def copy_tree(role,prefix):
 base=ROOT/'.worktrees'/role/prefix
 for here,dirs,files in os.walk(base):
  dirs[:]=[d for d in dirs if d not in {'target','node_modules','dist','__pycache__','.harness','.git'}]
  for name in files:
   p=pathlib.Path(here)/name;copy_file(p,ROOT/prefix/p.relative_to(base))
for role in ['core','planner','schema','ui']:
 result=json.loads((ROOT/'.harness/runs'/('g01d-'+role)/'result.json').read_text(encoding='utf-8'));assert result['exit_code']==0 and not result['partial']and not result['scope_violations']
copy_tree('core',pathlib.Path('crates/npi-core'));copy_file(ROOT/'.worktrees/core/Cargo.lock',ROOT/'Cargo.lock')
for rel in ['src/planning.rs','tests/planning.rs']:
 copy_file(ROOT/'.worktrees/planner/crates/npi-core'/rel,ROOT/'crates/npi-core'/rel)
p=ROOT/'crates/npi-core/src/lib.rs';text=p.read_text(encoding='utf-8');assert 'pub mod planning;'not in text;p.write_text('pub mod planning;\npub use planning::{plan_features, restore_profile};\n'+text,encoding='utf-8',newline='\n')
for prefix in ['schemas','fixtures']:copy_tree('schema',pathlib.Path(prefix))
copy_file(ROOT/'.worktrees/schema/tools/validate_schema.py',ROOT/'tools/validate_schema.py')
copy_tree('ui',pathlib.Path('ui'));copy_tree('architecture',pathlib.Path('docs'))
assert hashlib.sha256((ROOT/'PRD.md').read_bytes()).hexdigest()=='faffff45de66126dad6a0a81045dd22b536e9739e78947b426bd42d4a0ef7aa1'
(ROOT/'artifacts/g01-integration-files.json').write_text(json.dumps({'file_count':len(records),'files':records,'g1_passed':False},ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps({'copied_files':len(records),'g1_passed':False,'root':str(ROOT)}))
