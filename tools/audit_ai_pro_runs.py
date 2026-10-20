"""Inspect actual CLI events and scoped file changes; never treat SUCCESS as acceptance."""
import argparse,json,pathlib,sys
ROOT=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('stage',nargs='?',default='g01');args=p.parse_args()
ALLOWED={'read_file','view_file','write_file','write_to_file','edit_file','replace_file_content','multi_replace_file_content','multi_edit','list_dir','list_directory','find_by_name','grep_search','finish'}
WRITES={'write_file','write_to_file','edit_file','replace_file_content','multi_replace_file_content','multi_edit'}
RULES={'architecture':('docs/',),'core':('crates/npi-core/',),'schema':('schemas/','fixtures/','tests/schema/','tools/validate_schema.py'),'ui':('ui/',),'planner':('crates/npi-core/src/planning.rs','crates/npi-core/tests/planning.rs','crates/npi-core/src/lib.rs',)}
def under(path,root):
 try:path.resolve().relative_to(root.resolve());return True
 except ValueError:return False
reports=[]
roles=sorted(p.name[len(args.stage)+1:] for p in (ROOT/'.harness/runs').glob(args.stage+'-*') if p.is_dir() and (p/'started.json').exists())
if not roles or any(role not in RULES for role in roles):
 raise SystemExit('No known actor runs for requested stage')
for role in roles:
 prefixes=RULES[role]
 folder=ROOT/'.harness/runs'/(args.stage+'-'+role)
 if not (folder/'result.json').exists():
  reports.append({'role':role,'complete':False,'passed':False,'reason':'result missing; still running or interrupted'});continue
 result=json.loads((folder/'result.json').read_text(encoding='utf-8'));records=[]
 for line in (folder/'stdout.jsonl').read_text(encoding='utf-8').splitlines():
  try:records.append(json.loads(line))
  except json.JSONDecodeError:pass
 initial=next((r.get('init',{})for r in records if r.get('event')=='init'),{})
 final=next((r.get('result',r)for r in reversed(records)if r.get('event',r.get('type'))=='result'),{})
 violations=[];tools=[];w=pathlib.Path(result['worktree'])
 for r in records:
  step=r.get('step_update',{})
  if step.get('step_type')!='tool' or step.get('state')!='ACTIVE':continue
  name=step.get('tool_name',step.get('tool_info',{}).get('name',''));tools.append(name)
  if name not in ALLOWED:violations.append({'kind':'forbidden-tool','tool':name,'step':step.get('step_index')})
  params=step.get('tool_info',{}).get('parameters',{})
  for key,value in params.items():
   if key.lower()not in ('path','absolutepath','targetfile','file_path','directorypath','searchdirectory')or not isinstance(value,str):continue
   path=pathlib.Path(value)
   if not path.is_absolute():path=w/path
   if name in WRITES:
    relative=path.resolve().relative_to(w.resolve()).as_posix()if under(path,w)else None
    if relative is None or not any(relative.startswith(q)if q.endswith('/')else relative==q for q in prefixes):violations.append({'kind':'write-outside-role','path':str(path),'tool':name})
   elif not under(path,w)and not under(path,ROOT/'.harness/references'):violations.append({'kind':'read-outside-role','path':str(path),'tool':name})
 if initial.get('model')!='gemini-4-argon-high':violations.append({'kind':'wrong-model','actual':initial.get('model')})
 if pathlib.Path(initial.get('cwd','')).resolve()!=w.resolve():violations.append({'kind':'wrong-workspace','actual':initial.get('cwd')})
 if result.get('scope_violations'):violations.append({'kind':'file-diff-scope','paths':result['scope_violations']})
 report={'role':role,'complete':True,'passed':result.get('exit_code')==0 and not result.get('partial')and final.get('status')=='SUCCESS'and not violations,'model':initial.get('model'),'inherited_permission_mode':initial.get('permission_mode'),'changed_file_count':len(result.get('changed_paths',[])),'cli_status':final.get('status'),'tool_invocation_count':len(tools),'tool_names':sorted(set(tools)),'violations':violations,'implementation_verified':False}
 reports.append(report)
out={'stage':args.stage,'actors':reports,'all_actor_policy_checks_passed':all(r['passed']for r in reports),'product_accepted':False}
(ROOT/'artifacts').mkdir(exist_ok=True);(ROOT/'artifacts'/(args.stage+'-actor-policy-audit.json')).write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps(out,ensure_ascii=False,indent=2));sys.exit(0 if out['all_actor_policy_checks_passed']else 1)
