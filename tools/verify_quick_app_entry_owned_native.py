"""제품 worker EXE의 부모 소유 명령행과 localhost IPC를 제한 실행해 검증한다."""
import datetime
import hashlib
import json
import os
import pathlib
import socket
import sys

from owned_bounded_child import run_bounded

R=pathlib.Path(__file__).resolve().parents[1]
EXPLICIT_ROOT_MODE=sys.argv[1:]==['--root','--cli-only','--explicit-tcp-entry']
EXPLICIT_ENTRY_MODE=EXPLICIT_ROOT_MODE or sys.argv[1:]==['--explicit-tcp-entry']
TCP_NATIVE_MODE=sys.argv[1:]==['--root','--cli-only','--tcp-native']
TCP_REPLAY_MODE=sys.argv[1:]==['--root','--cli-only','--tcp-replay']
ROOT_MODE=EXPLICIT_ROOT_MODE or TCP_NATIVE_MODE or TCP_REPLAY_MODE or sys.argv[1:]==['--root','--cli-only']
assert ROOT_MODE or EXPLICIT_ENTRY_MODE or not sys.argv[1:], '허용모드: 인자없음 또는 --root --cli-only [--tcp-replay|--tcp-native]'
W=R if ROOT_MODE else R/('.worktrees/qgdevtcp' if EXPLICIT_ENTRY_MODE else '.worktrees/qgquickapp')
ROOT_PREFIX='qg2h-tcp-native-root' if TCP_NATIVE_MODE else ('qg2g-tcp-replay-root' if TCP_REPLAY_MODE else 'qg2f-app-entry-root')
TARGET=R/(f'.harness/targets/{ROOT_PREFIX}-shared/debug' if ROOT_MODE else '.harness/targets/qg2f-app-parent-final-all-targets/debug')
OUT=R/(f'artifacts/{ROOT_PREFIX}-commandline.json' if ROOT_MODE else 'artifacts/qg2f-app-entry-owned-native.json')
if EXPLICIT_ENTRY_MODE:
    ROOT_PREFIX='qg2i-explicit-tcp-root' if ROOT_MODE else 'qg2i-explicit-tcp-parent'
    TARGET=R/('.harness/targets/qg2i-explicit-tcp-root-shared/debug' if ROOT_MODE else '.harness/targets/qg2i-explicit-tcp-first-default/debug')
    OUT=R/('artifacts/'+ROOT_PREFIX+'-commandline.json')
FINAL={
    'apps/network-quick-check/Cargo.toml':'ab106cdff97ef2df98a530da203e163969e5167b478f9fc7cb5e45c3266ee221',
    'apps/network-quick-check/src/lib.rs':'683097037fe29c59af84d69dbddc50bdd27f7a16bd272cb86553b3c3038353f7',
    'apps/network-quick-check/src/main.rs':'2ab9cc2c603b520a7d62110ccafe4c984015fa378ce0b6f555df381bec48f5fb',
    'apps/network-quick-check/tests/resolver_dispatch.rs':'0834670ddcf9b53ca4a08a58de5b5ff6a1c2bc3ce6b9822248c702d62074d0ae',
}
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))
assert os.name=='nt' and not OUT.exists()
repair=load('artifacts/qg2f-app-entry-repair-pipeline.json')
assert repair['status']=='AUDITED_SOURCE_READY_FOR_PARENT_REVIEW'
if EXPLICIT_ENTRY_MODE:
    explicit=load('artifacts/qg2i-explicit-tcp-parent-repair.json')
    native=load('artifacts/qg2i-explicit-tcp-parent-native.json')
    assert native['status']=='PARENT_NATIVE_PASS_NOT_ACCEPTED'
    assert native['source_sha256']==explicit['source_sha256']
    FINAL.update(explicit['source_sha256'])
    ROOT_PREFIX='qg2i-explicit-tcp-root' if ROOT_MODE else 'qg2i-explicit-tcp-parent'
    TARGET=R/('.harness/targets/qg2i-explicit-tcp-root-shared/debug' if ROOT_MODE else '.harness/targets/qg2i-explicit-tcp-first-default/debug')
    OUT=R/('artifacts/'+ROOT_PREFIX+'-commandline.json')
    assert not OUT.exists()
assert all(sha(W/path)==value for path,value in FINAL.items())
frozen_record='artifacts/qg2h-tcp-native-actor-prepared.json' if TCP_NATIVE_MODE else ('artifacts/qg2g-tcp-replay-actor-prepared.json' if TCP_REPLAY_MODE else 'artifacts/qg2f-app-entry-independent-review.json')
frozen=(explicit if EXPLICIT_ENTRY_MODE else load(frozen_record))['immutable_source_sha256']
assert all(sha(W/path)==value for path,value in frozen.items())
if TCP_REPLAY_MODE or TCP_NATIVE_MODE:
    assert load('artifacts/qg2g-tcp-replay-explicit-approval.json')['authorization_granted']
if ROOT_MODE:
    integration_record='artifacts/qg2h-tcp-native-integration.json' if TCP_NATIVE_MODE else ('artifacts/qg2g-tcp-replay-integration.json' if TCP_REPLAY_MODE else 'artifacts/qg2f-app-entry-integration.json')
    if EXPLICIT_ROOT_MODE: integration_record='artifacts/qg2i-explicit-tcp-integration.json'
    proof=load(integration_record)
    assert proof['state']=='INTEGRATED_FOR_ROOT_REGRESSION_NOT_ACCEPTED'
    assert all(sha(R/path)==value for path,value in proof['source_sha256'].items())
    gates=load(f'artifacts/{ROOT_PREFIX}-validation.json')
    expected_workspace=434 if TCP_NATIVE_MODE else (433 if TCP_REPLAY_MODE else 427)
    expected_native=27 if TCP_NATIVE_MODE else 23
    if EXPLICIT_ROOT_MODE:
        expected_workspace=explicit['workspace_counts']['passed']
        expected_native=explicit['expected_native_total']
    assert any(step['name'].endswith('-workspace') and step['passed']==expected_workspace and step['exit_code']==0 for step in gates['steps'])
    assert any(step['name'].endswith('-native') and step['passed']==expected_native and step['exit_code']==0 for step in gates['steps'])
for name in ['qg2f-app-parent-final-all-targets','qg2f-app-parent-final-clippy']:
    evidence=load('artifacts/commands/'+name+'.json')
    assert evidence['exit_code']==0 and not evidence['partial']
exe=TARGET/'NetworkQuickCheck.exe'
harnesses=list((TARGET/'deps').glob('resolver_dispatch-*.exe'))
if EXPLICIT_ENTRY_MODE and not ROOT_MODE:
    # Cargo가 실제 실행한 바이너리를 기록에서 고른다. 재빌드된 stale glob을 임의로 고르지 않는다.
    harnesses=[pathlib.Path(load('artifacts/qg2i-explicit-tcp-final-independent-review.json')['active_test_binaries']['resolver_dispatch'])]
assert exe.is_file() and len(harnesses)==1 and harnesses[0].is_file()
harness=harnesses[0]
fixed_binary_sha={str(path):sha(path) for path in [exe,harness]}
state={'started_at':datetime.datetime.now().astimezone().isoformat(),'status':'RUNNING',
       'source_sha256':FINAL,'binary_sha256':fixed_binary_sha,'supervisor_self_tests':[],
       'commandline_cases':[],'explicit_reject_cases':[],'native_harness':None,'accepted':False,'root_integrated':False,
       'limitations':['소유localhost 해석은hosts/cache/DNS경로나패킷부재증거아님',
                      '리터럴worker는OS도메인해석증거아님','GUI/QG3·배포인증·전체QG2미수용']}

def save():
    OUT.write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')

def summary(result):
    return {key:value for key,value in result.items() if key not in ['stdout','stderr']} | {
        'stdout_bytes':len(result['stdout']),'stderr_bytes':len(result['stderr'])}

def completed(result):
    assert result['child_reaped'] and not result['timed_out']
    assert not result['stdout_overflow'] and not result['stderr_overflow']

try:
    # 감독기 자체는 실제 소유 Python Child로 출력 상한·종료값·deadline 정리를 먼저 확인한다.
    fixture_cases=[
        ('normal',"import sys;sys.stdout.write('ok');sys.stderr.write('err')",0,False,False,False),
        ('nonzero',"import sys;sys.exit(7)",7,False,False,False),
        ('stdout_exact',"import sys;sys.stdout.buffer.write(b'x'*16384)",0,False,False,False),
        ('stdout_overflow',"import sys;sys.stdout.buffer.write(b'x'*16385)",None,True,False,False),
        ('stderr_overflow',"import sys;sys.stderr.buffer.write(b'x'*1025)",None,False,True,False),
        ('deadline',"import time;time.sleep(3)",None,False,False,True),
    ]
    for label,code,exit_code,out_over,err_over,timeout in fixture_cases:
        result=run_bounded([sys.executable,'-c',code],cwd=R,timeout=0.1 if timeout else 5)
        assert result['child_reaped'] and result['timed_out']==timeout
        assert result['stdout_overflow']==out_over and result['stderr_overflow']==err_over
        if exit_code is not None:
            assert result['exit_code']==exit_code
        if label=='normal':
            assert result['stdout']==b'ok' and result['stderr']==b'err'
        if label=='stdout_exact':
            assert len(result['stdout'])==16384
        state['supervisor_self_tests'].append({'id':label,'passed':True,**summary(result)})
    flag='--npi-dns-worker-v1'
    invalid='Network Quick Check: 지원하지 않거나 잘못된 인자입니다.\n'.encode()
    cases=[('noargs',[],0,'Network Quick Check: 진단 실행 진입점은 아직 제공하지 않습니다.\n'.encode()),
           ('help',['--help'],0,'Network Quick Check: 현재 진단 실행 기능은 제공하지 않습니다.\n'.encode())]
    bad_args=[
        ('unknown',['--unknown']),('run',['--run']),('dns',['--dns']),('helper_path',['--helper-path','not-used']),
        ('target_only',['localhost']),('flag_only',[flag]),('missing_port',[flag,'localhost']),
        ('extra',[flag,'localhost','80','extra']),('extra_many',[flag,'localhost','80','extra','extra']),
        ('old_flag',['--npi-dns-worker-v0','localhost','80']),('new_flag',['--npi-dns-worker-v2','localhost','80']),
        ('flag_equals',[flag+'=localhost','80']),('duplicate_flag',[flag,flag,'80']),
        ('wrong_order',['localhost',flag,'80']),('help_combo',['--help','localhost','80']),
    ]
    # 고유 합성 marker는 입력에만 사용하고 기록에는 인자값을 보관하지 않는다.
    marker='entry-reject-'+os.urandom(8).hex()
    for label,host in [('empty',''),('whitespace','localhost '),('control','local\nhost'),
                       ('uri','http://'+marker+'.invalid'),('userinfo','user:'+marker+'@localhost'),
                       ('long','a'*254),('surrogate','\ud800')]:
        bad_args.append(('host_'+label,[flag,host,'80']))
    for index,port in enumerate(['','0','65536','-1','+80','080',' 80','80 ','1e2','８０','\ud800']):
        bad_args.append(('port_'+str(index),[flag,'localhost',port]))
    bad_args.append(('flag_surrogate',['\ud800','localhost','80']))
    cases.extend((label,args,2,invalid) for label,args in bad_args)
    for label,args,code,stderr in cases:
        assert sha(exe)==fixed_binary_sha[str(exe)]
        result=run_bounded([str(exe),*args],cwd=W)
        completed(result)
        assert result['exit_code']==code and result['stdout']==b'' and result['stderr']==stderr, label
        assert marker.encode() not in result['stdout']+result['stderr']
        state['commandline_cases'].append({'id':label,'passed':True,**summary(result)})
    # 양쪽 주소의 같은 포트를 끝까지 소유하며 리터럴 worker만 실행한다(접속/스캔 없음).
    pair=None
    for _ in range(10):
        v4=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        v6=socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
        try:
            v6.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
            v4.bind(('127.0.0.1',0))
            port=v4.getsockname()[1]
            v6.bind(('::1',port))
            v4.listen(1)
            v6.listen(1)
            pair=(v4,v6,port)
            break
        except OSError:
            v4.close()
            v6.close()
    assert pair is not None, '정확소유IPv4/IPv6동일포트확보실패'
    v4,v6,port=pair
    try:
        for host,address in [('127.0.0.1',f'127.0.0.1:{port}'),('::1',f'[::1]:{port}')]:
            assert sha(exe)==fixed_binary_sha[str(exe)]
            result=run_bounded([str(exe),flag,host,str(port)],cwd=W)
            completed(result)
            assert result['exit_code']==0 and result['stderr']==b''
            wire=result['stdout']
            assert wire.endswith(b'\n') and wire.count(b'\n')==1 and b'\r' not in wire
            payload=json.loads(wire.decode('utf-8'))
            expected={'format':'npi-dns-worker-1','host':host,'port':port,'addresses':[address],
                      'truncated':False,'error_code':None,'error_message':None}
            assert payload==expected
            state['commandline_cases'].append({'id':'literal_v4' if host=='127.0.0.1' else 'literal_v6',
                                                 'passed':True,**summary(result)})
        state['owned_fixture']={'ipv4':'127.0.0.1','ipv6':'::1','port':port,'both_bound_during_literal_runs':True}
    finally:
        v4.close()
        v6.close()
    # EXPLICIT_ENTRY_PARENT_REJECTION_CASES: 기존38개 corpus는 위에서 그대로 실행했다.
    if EXPLICIT_ENTRY_MODE:
        for label,args in bad_args:
            if not args or args[0]!=flag: continue
            current=['--dev-tcp-once-v1',*args[1:]]
            result=run_bounded([str(exe),*current],cwd=W)
            completed(result)
            assert result['exit_code']==2 and result['stdout']==b'' and result['stderr']==invalid,label
            assert marker.encode() not in result['stdout']+result['stderr']
            state['explicit_reject_cases'].append({'id':label,'passed':True,**summary(result)})
        assert len(state['commandline_cases'])==38 and state['explicit_reject_cases']
    # root모드는앞선workspace native23에동일IPC시험이포함되어있으므로중복실행/합산하지않는다.
    if not ROOT_MODE and not EXPLICIT_ENTRY_MODE:
        # 별도 Rust ignored 시험은 스스로 동일포트 양쪽 listener를 확보하고 기존 resolver 감독만 사용한다.
        assert all(sha(pathlib.Path(path))==value for path,value in fixed_binary_sha.items())
        result=run_bounded([str(harness),'--ignored','--exact','test_product_exe_dns_worker_dispatch_localhost','--test-threads=1'],
                           cwd=W,timeout=12,stdout_limit=32768,stderr_limit=4096)
        completed(result)
        assert result['exit_code']==0 and b'1 passed; 0 failed;' in result['stdout']
        state['native_harness']={'passed':1,'ignored':0,'stdout':result['stdout'].decode('utf-8'),
                                  'stderr':result['stderr'].decode('utf-8'),**summary(result)}
    assert all(sha(W/path)==value for path,value in FINAL.items())
    assert all(sha(pathlib.Path(path))==value for path,value in fixed_binary_sha.items())
    state['status']='ROOT_COMMANDLINE_PASS_NOT_ACCEPTED' if ROOT_MODE else ('EXPLICIT_PARENT_LEGACY_COMMANDLINE_PASS_NOT_ACCEPTED' if EXPLICIT_ENTRY_MODE else 'OWNED_COMMANDLINE_AND_LOCALHOST_IPC_PASS_REVIEW_PENDING')
except Exception as error:
    state['status']='FAILED_PRESERVED'
    state['error_type']=type(error).__name__
    # 원문 인자/오류 반사를 피하기 위해 메시지나 전체 traceback을 기록하지 않는다.
    raise
finally:
    state['finished_at']=datetime.datetime.now().astimezone().isoformat()
    state['supervisor_self_test_count']=len(state['supervisor_self_tests'])
    state['commandline_case_count']=len(state['commandline_cases'])
    state['explicit_reject_case_count']=len(state['explicit_reject_cases'])
    save()
print(json.dumps({'status':state['status'],'supervisor_self_tests':state['supervisor_self_test_count'],
                  'commandline_cases':state['commandline_case_count'],'explicit_reject_cases':state['explicit_reject_case_count'],'native_passed':(state['native_harness'] or {}).get('passed',0),
                  'accepted':False},ensure_ascii=False))
