"""첫 native 실패 원문에서 직렬화 표현 오판과 1초 거부 fixture 한계를 분리한다."""
import datetime
import hashlib
import json
import pathlib
import re
import shutil

R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgtcpnative'
TEST='crates/network-core/tests/tcp_product_native_equivalence.rs'
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
assert sha(W/TEST)==load('artifacts/qg2h-tcp-native-pipeline.json')['source_sha256'][TEST]
original=R/'.harness/evidence/qg2h-tcp-native-actor-original.rs'
assert not original.exists()
original.parent.mkdir(parents=True,exist_ok=True)
shutil.copyfile(W/TEST,original)
commands={}
for key,name,code in [('default','qg2h-tcp-native-first-default',0),
                      ('native','qg2h-tcp-native-first-owned',101),
                      ('clippy','qg2h-tcp-native-first-clippy',101)]:
    item=load('artifacts/commands/'+name+'.json')
    assert item['exit_code']==code and not item['partial']
    commands[key]=item
text=pathlib.Path(commands['native']['log']).read_text(encoding='utf-8')
assert '0 passed; 4 failed;' in text
pairs=re.findall(r'---- windows_native_equivalence::(native_\w+) stdout ----.*?  left: (\[[^\r\n]+\])\s+right: (\[[^\r\n]+\])',text,re.S)
assert len(pairs)==4
observations=[]
for name,left,right in pairs:
    a=bytes(json.loads(left));b=bytes(json.loads(right))
    av=json.loads(a);bv=json.loads(b)
    assert av==bv and a!=b
    observations.append({'test':name,'json_values_equal':True,'serialization_bytes_different':True,
        'actual_inspector_outcome':av['outcome'],'actual_os_error_code':av['error_code'],
        'actual_elapsed_ms':av['elapsed_ms'],'source':'실패assertion의원본byte배열을JSON으로복원·값변조없음'})
assert all(item['actual_inspector_outcome']=='CONNECTED' for item in observations if item['test'].endswith('_connected'))
assert all(item['actual_inspector_outcome']=='TIMED_OUT' for item in observations if item['test'].endswith('_refused'))
transcripts={}
for index in range(2):
    path=pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/delegation/live/deleg_f90b8199')/f'task-{index}.log'
    assert 'end status=completed' in path.read_text(encoding='utf-8')
    transcripts[str(index)]={'path':str(path),'sha256':sha(path)}
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),
    'status':'FIRST_NATIVE_FAILED_TEST_ASSERTION_AND_ONE_SECOND_FIXTURE_LIMIT_PRESERVED',
    'actor_original':str(original),'actor_original_sha256':sha(original),'command_evidence':commands,
    'independent_review':'deleg_f90b8199','normalized_from_complete_async_delivery':True,
    'review_transcripts':transcripts,'safe_to_execute_default_tests_static':True,
    'safe_to_execute_owned_native_tests_static':True,
    'confirmed_findings':['F1/TCP-NATIVE-001: struct/Value내용동일에도키순서바이트차이로4native실패재현',
        'F2: target/Envelope귀속·resolved_ip Some단언누락',
        'F3: replay상태/근거·메타/limitations·오류메시지보존단언누락',
        'F4: 필수nullable키누락과명시null구분누락',
        'strictClippy: unusedQuickResult/collapsible_if/needless_borrow 세지적'],
    'first_native_raw_observations':observations,
    'fixture_limitation':'1000ms bound/nonlisten에서는이번실측REFUSED가아니라TIMED_OUT·JSON수정과별도로원인분리필요',
    'next_steps':['F1만먼저구조동등성으로수정해4native실패원인을재확인',
                  '추가단언보강·제품코드불변·1000ms실패원본보존',
                  '필요시PRD기본3000ms를동일두제품에주는별도fixture특성규명·10061판정변경/OS정책변경금지'],
    'production_changed':False,'root_integrated':False,'accepted':False,'full_qg2_accepted':False}
out=R/'artifacts/qg2h-tcp-native-first-execution.json'
assert not out.exists()
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':record['status'],'observations':observations,'production_changed':False},ensure_ascii=False))
