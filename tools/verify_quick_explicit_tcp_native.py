"""최종 안전 검토 뒤에만 기존27+새제품EXE4 소유 native를 같은 W 조합에서 실행한다."""
import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import time
R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgdevtcp'
load=lambda p:json.loads((R/p).read_text(encoding='utf-8'))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
p=load('artifacts/qg2i-explicit-tcp-parent-repair.json')
review=load('artifacts/qg2i-explicit-tcp-final-independent-review.json')
assert review['findings']==[] and review['safe_to_execute_owned_native_tests'] and review['parent_owned_native_scope_authorized']
assert all(sha(W/path)==value for path,value in p['source_sha256'].items())
assert all(sha(W/path)==value for path,value in p['immutable_source_sha256'].items())
assert all(sha(R/path)==value for path,value in p['root_before_sha256'].items())
assert all(sha(pathlib.Path(path))==value for path,value in review['binary_sha256_before_native'].items())
helper=R/'.harness/targets/qg2c-resolver-isolated-pure/debug/quick-resolver-qa.exe'
assert sha(helper)=='f9d32baf6861fb2a8442a5c2b759b0d2ac68520ae13343e575fc2b8781d4a959'
name='qg2i-explicit-tcp-parent-native'
meta=R/'artifacts/commands'/f'{name}.json'
out=R/'artifacts/qg2i-explicit-tcp-parent-native.json'
assert not meta.exists() and not out.exists()
env=os.environ.copy()
env.update(CARGO_TARGET_DIR=str(R/'.harness/targets/qg2i-explicit-tcp-first-default'),NPI_TEST_HELPER_EXE=str(helper.resolve()))
scratch=pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/scratch/npi-explicit-tcp-parent-native')
scratch.mkdir(parents=True,exist_ok=True)
env.update(TMP=str(scratch),TEMP=str(scratch),TMPDIR=str(scratch))
argv=['cargo','test','--offline','--locked','--workspace','--all-targets','--','--ignored','--test-threads=1']
started=datetime.datetime.now().astimezone().isoformat()
begin=time.monotonic()
child=subprocess.Popen(argv,cwd=W,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
partial=False
try:
    stdout,stderr=child.communicate(timeout=240)
except subprocess.TimeoutExpired:
    partial=True
    subprocess.run(['taskkill.exe','/PID',str(child.pid),'/T','/F'],capture_output=True,timeout=20)
    stdout,stderr=child.communicate(timeout=20)
spec=importlib.util.spec_from_file_location('redact',R/'tools/ai_pro_harness.py')
redact=importlib.util.module_from_spec(spec)
spec.loader.exec_module(redact)
log=redact.clean(stdout.decode('utf-8','replace')+'\n'+stderr.decode('utf-8','replace'))
logpath=meta.with_suffix('.log')
logpath.write_text(log,encoding='utf-8')
command={'command':argv,'cwd':str(W),'started_at':started,'pid':child.pid,'exit_code':child.returncode,
    'partial':partial,'elapsed_seconds':round(time.monotonic()-begin,3),'log':str(logpath)}
meta.write_text(json.dumps(command,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
rows=[tuple(map(int,row)) for row in re.findall(r'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;',log)]
counts={key:sum(row[i] for row in rows) for i,key in enumerate(['passed','failed','ignored'])}
verified=[name for name in p['new_native_tests'] if 'test '+name+' ... ok' in log]
same_binaries=all(sha(pathlib.Path(path))==value for path,value in review['binary_sha256_before_native'].items())
okay=child.returncode==0 and not partial and counts=={'passed':p['expected_native_total'],'failed':0,'ignored':0} and verified==p['new_native_tests'] and same_binaries
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'PARENT_NATIVE_PASS_NOT_ACCEPTED' if okay else 'FAILED_PRESERVED',
    'command':command,'counts':counts,'new_native_tests_verified':verified,'source_sha256':p['source_sha256'],
    'same_product_and_test_binaries':same_binaries,'binary_sha256':review['binary_sha256_before_native'],
    'prior_native_tests':p['expected_native_total']-len(p['new_native_tests']),'new_product_exe_native_tests':len(verified),
    'source_unchanged_after_execution':all(sha(W/path)==value for path,value in p['source_sha256'].items()),
    'native_executed':True,'root_integrated':False,'accepted':False}
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(record,ensure_ascii=False))
assert okay and record['source_unchanged_after_execution'],'소유 native 실제 실패·증거 보존·수용 금지'
