"""선택 통합한 명시 TCP 앱 경로를 메인 workspace·소유 native·기존 CLI와 함께 검증한다."""
import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import time
R=pathlib.Path(__file__).resolve().parents[1]
PREFIX='qg2i-explicit-tcp-root'
OUT=R/'artifacts'/f'{PREFIX}-validation.json'
load=lambda p:json.loads((R/p).read_text(encoding='utf-8'))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert not OUT.exists()
proof=load('artifacts/qg2i-explicit-tcp-integration.json')
parent=load('artifacts/qg2i-explicit-tcp-parent-execution.json')
review=load('artifacts/qg2i-explicit-tcp-final-independent-review.json')
assert proof['state']=='INTEGRATED_FOR_ROOT_REGRESSION_NOT_ACCEPTED'
assert review['findings']==[] and review['safe_to_execute_default_tests'] and review['safe_to_execute_owned_native_tests']
assert all(sha(R/path)==value for path,value in proof['source_sha256'].items())
assert all(sha(R/path)==value for path,value in proof['immutable_source_sha256'].items())
state={'started_at':datetime.datetime.now().astimezone().isoformat(),'status':'RUNNING','steps':[],
    'source_sha256':proof['source_sha256'],'accepted':False,'root_integrated':True,'independent_review':'deleg_62debd02'}

def save():
    tmp=OUT.with_suffix('.json.tmp')
    tmp.write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    tmp.replace(OUT)

spec=importlib.util.spec_from_file_location('redact',R/'tools/ai_pro_harness.py')
redact=importlib.util.module_from_spec(spec)
spec.loader.exec_module(redact)
env=os.environ.copy()
target=R/'.harness/targets/qg2i-explicit-tcp-root-shared'
env['CARGO_TARGET_DIR']=str(target)
helper=R/'.harness/targets/qg2c-resolver-isolated-pure/debug/quick-resolver-qa.exe'
assert sha(helper)=='f9d32baf6861fb2a8442a5c2b759b0d2ac68520ae13343e575fc2b8781d4a959'
env['NPI_TEST_HELPER_EXE']=str(helper.resolve())
scratch=pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/scratch/npi-explicit-tcp-root')
scratch.mkdir(parents=True,exist_ok=True)
env.update(TMP=str(scratch),TEMP=str(scratch),TMPDIR=str(scratch))
gates=[('workspace',R,['cargo','test','--offline','--locked','--workspace','--all-targets']),
    ('native',R,['cargo','test','--offline','--locked','--workspace','--all-targets','--','--ignored','--test-threads=1']),
    ('trace-boundaries',R/'.harness/qa/quick-trace-boundaries',['cargo','test','--offline','--all-targets']),
    ('dns-boundaries',R/'.harness/qa/quick-dns-boundaries',['cargo','test','--offline','--all-targets']),
    ('clippy',R,['cargo','clippy','--offline','--locked','--workspace','--all-targets','--','-D','warnings']),
    ('fmt',R,['cargo','fmt','--all','--check']),
    ('commandline',R,[sys.executable,'tools/verify_quick_app_entry_owned_native.py','--root','--cli-only','--explicit-tcp-entry'])]
for suffix,_,_ in gates:
    assert not (R/'artifacts/commands'/f'{PREFIX}-{suffix}.json').exists()
save()
try:
    for suffix,cwd,argv in gates:
        name=f'{PREFIX}-{suffix}'
        state['current_step']=name
        save()
        print('STEP '+name,flush=True)
        if suffix=='native':
            exe=target/'debug/NetworkQuickCheck.exe'
            assert exe.is_file()
            state['product_binary_before_native_sha256']={str(exe):sha(exe)}
        started=datetime.datetime.now().astimezone().isoformat()
        begin=time.monotonic()
        child=subprocess.Popen(argv,cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        partial=False
        try:
            stdout,stderr=child.communicate(timeout=240)
        except subprocess.TimeoutExpired:
            partial=True
            subprocess.run(['taskkill.exe','/PID',str(child.pid),'/T','/F'],capture_output=True,timeout=20)
            stdout,stderr=child.communicate(timeout=20)
        log=redact.clean(stdout.decode('utf-8','replace')+'\n'+stderr.decode('utf-8','replace'))
        path=R/'artifacts/commands'/f'{name}.json'
        path.with_suffix('.log').write_text(log,encoding='utf-8')
        meta={'command':argv,'cwd':str(cwd),'started_at':started,'pid':child.pid,'exit_code':child.returncode,
            'partial':partial,'elapsed_seconds':round(time.monotonic()-begin,3),'log':str(path.with_suffix('.log'))}
        path.write_text(json.dumps(meta,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        entry={'name':name,'exit_code':child.returncode,'partial':partial}
        rows=[tuple(map(int,row)) for row in re.findall(r'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;',log)]
        if rows: entry.update({field:sum(row[i] for row in rows) for i,field in enumerate(['passed','failed','ignored'])})
        state['steps'].append(entry)
        save()
        print(json.dumps(entry,ensure_ascii=False),flush=True)
        assert child.returncode==0 and not partial,name
        if suffix=='workspace':
            assert {key:entry[key] for key in ['passed','failed','ignored']}==parent['workspace_counts']
        if suffix=='native':
            assert {key:entry[key] for key in ['passed','failed','ignored']}==parent['native_counts']
            for test in ['native_ipv4_connected','native_ipv4_refused','native_ipv6_connected','native_ipv6_refused']:
                assert 'test '+test+' ... ok' in log
            assert all(sha(pathlib.Path(path))==value for path,value in state['product_binary_before_native_sha256'].items())
        if suffix in ('trace-boundaries','dns-boundaries'):
            assert rows and entry['passed']>0 and entry['failed']==0
        if suffix=='commandline':
            cli=load(f'artifacts/{PREFIX}-commandline.json')
            assert cli['status']=='ROOT_COMMANDLINE_PASS_NOT_ACCEPTED'
            assert cli['commandline_case_count']==38 and cli['explicit_reject_case_count']==23 and cli['supervisor_self_test_count']==6
            state.update(commandline_cases_passed=38,explicit_reject_cases_passed=23,supervisor_self_tests_passed=6)
    assert all(sha(R/path)==value for path,value in proof['source_sha256'].items())
    assert all(sha(R/path)==value for path,value in proof['immutable_source_sha256'].items())
    state['status']='ROOT_EXECUTION_PASS_ACCEPTANCE_RECORD_PENDING'
except Exception as error:
    state.update(status='BLOCKED_PRESERVED_FOR_REVIEW',error=str(error))
finally:
    state['finished_at']=datetime.datetime.now().astimezone().isoformat()
    save()
print(json.dumps(state,ensure_ascii=False),flush=True)
sys.exit(0 if state['status']=='ROOT_EXECUTION_PASS_ACCEPTANCE_RECORD_PENDING' else 1)
