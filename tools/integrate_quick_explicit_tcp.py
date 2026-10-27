"""검증된 앱 source3+부모metadata2만 로컬 보존·선택 통합한다. 제품 수용은 별도다."""
import datetime
import hashlib
import json
import pathlib
import shutil
import subprocess
R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgdevtcp'
load=lambda p:json.loads((R/p).read_text(encoding='utf-8'))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
p=load('artifacts/qg2i-explicit-tcp-parent-repair.json')
review=load('artifacts/qg2i-explicit-tcp-final-independent-review.json')
native=load('artifacts/qg2i-explicit-tcp-parent-native.json')
cli=load('artifacts/qg2i-explicit-tcp-parent-commandline.json')
assert review['findings']==[] and review['safe_to_execute_default_tests'] and review['safe_to_execute_owned_native_tests']
assert native['status']=='PARENT_NATIVE_PASS_NOT_ACCEPTED' and native['counts']=={'passed':p['expected_native_total'],'failed':0,'ignored':0}
assert cli['status']=='EXPLICIT_PARENT_LEGACY_COMMANDLINE_PASS_NOT_ACCEPTED'
assert cli['commandline_case_count']==38 and cli['supervisor_self_test_count']==6 and cli['explicit_reject_case_count']==23
assert all(sha(W/path)==value for path,value in p['source_sha256'].items())
assert all(sha(W/path)==value for path,value in p['immutable_source_sha256'].items())
assert all(sha(R/path)==value for path,value in p['root_before_sha256'].items())
assert all(sha(pathlib.Path(path))==value for path,value in native['binary_sha256'].items())
source=p['source_sha256']
paths=sorted(source)
assert len(paths)==5
for path in paths:
    if path not in p['root_before_sha256']: assert not (R/path).exists(),path
protected=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
engine='crates/npi-probes/src/engine.rs'
assert all(sha(R/path)==value for path,value in protected.items() if path!=engine)
assert (R/engine).read_bytes().replace(b'pub fn apply_tcp_result(',b'fn apply_tcp_result(',1)==(R/'.harness/baselines/qg2g-tcp-replay-root/engine.rs').read_bytes()

def git(*args):
    x=subprocess.run(['git','-C',str(W),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60)
    assert x.returncode==0,x.stderr
    return x.stdout.rstrip('\r\n')

changed=git('status','--porcelain','--untracked-files=all').splitlines()
assert sorted(line[3:] for line in changed)==paths,changed
git('add','--',*paths)
git('diff','--cached','--check')
git('-c','core.autocrlf=false','commit','-m','feat: add explicit development-only single-target TCP app entry with bounded report and cancellation')
assert not git('status','--porcelain')
commit=git('rev-parse','HEAD')
now=datetime.datetime.now().astimezone().isoformat()
parent={'recorded_at':now,'status':'PARENT_ALL_CHECKS_PASS_NOT_ACCEPTED','source_sha256':source,
    'workspace_counts':p['workspace_counts'],'native_counts':native['counts'],'new_product_exe_native_tests':4,
    'legacy_cli_cases':cli['commandline_case_count'],'explicit_reject_cases':cli['explicit_reject_case_count'],
    'supervisor_self_tests':cli['supervisor_self_test_count'],'strict_clippy_exit':0,
    'preserved_source_commit':commit,'worktree_clean':True,'parent_is_coauthor':True,
    'root_integrated':False,'accepted':False,'full_qg2_accepted':False,'product_accepted':False}
out=R/'artifacts/qg2i-explicit-tcp-parent-execution.json'
assert not out.exists()
out.write_text(json.dumps(parent,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
for path in paths:
    (R/path).parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(W/path,R/path)
    assert sha(R/path)==source[path]
assert all(sha(R/path)==value for path,value in p['root_before_sha256'].items() if path not in source)
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'state':'INTEGRATED_FOR_ROOT_REGRESSION_NOT_ACCEPTED',
    'source_sha256':source,'preserved_source_commit':commit,'source_scope':paths,
    'immutable_source_sha256':p['immutable_source_sha256'],'parent_execution':str(out.relative_to(R)),
    'independent_review':'deleg_62debd02','root_integrated':True,'accepted':False,
    'inspector_original_protected_unchanged':len(protected)-1,'approved_existing_visibility_exception_files':1,
    'inspector_core_resolver_new_changes':0,'full_qg2_accepted':False,'product_accepted':False,'qg3_started':False}
out=R/'artifacts/qg2i-explicit-tcp-integration.json'
assert not out.exists()
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'state':record['state'],'changed_paths':paths,'preserved_source_commit':commit,
    'parent_workspace':parent['workspace_counts'],'parent_native':parent['native_counts'],
    'parent_legacy_cli':38,'parent_explicit_rejects':23,'accepted':False},ensure_ascii=False))
