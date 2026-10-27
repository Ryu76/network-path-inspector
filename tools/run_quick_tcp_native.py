"""Flash는 native 시험 source 한 파일만 작성하고 실행은 부모 검토 뒤로 유예한다."""
import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import sys

R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgtcpnative'
STAGE='qg2tcpnative'
ROLE='qgtcpnative'
TEST='crates/network-core/tests/tcp_product_native_equivalence.rs'
OUT=R/'artifacts/qg2h-tcp-native-pipeline.json'
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
state={'started_at':datetime.datetime.now().astimezone().isoformat(),'stage':STAGE,'status':'RUNNING',
       'steps':[],'root_integrated':False,'accepted':False,'formatting_and_execution_deferred':True,
       'independent_review_required':True,'native_executed':False}

def save():
    temp=OUT.with_suffix('.json.tmp')
    temp.write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    temp.replace(OUT)

def call(name,argv):
    state['current_step']=name
    save()
    print('STEP '+name,flush=True)
    result=subprocess.run(argv,cwd=R,timeout=1100)
    state['steps'].append({'name':name,'exit_code':result.returncode})
    save()
    assert result.returncode==0,name

assert not OUT.exists() and not (R/'.harness/runs'/(STAGE+'-'+ROLE)).exists()
os.environ['NPI_AI_PRO_MODEL']='gemini-3.8-flash-high'
save()
try:
    call('prepare-actor',[sys.executable,'tools/prepare_quick_tcp_native_actor.py'])
    contract=load('artifacts/qg2h-tcp-native-actor-prepared.json')
    call('flash-file-only',[sys.executable,'-u','tools/ai_pro_harness.py',STAGE,ROLE])
    call('actor-policy-audit',[sys.executable,'tools/audit_ai_pro_runs.py',STAGE])
    folder=R/'.harness/runs'/(STAGE+'-'+ROLE)
    result=json.loads((folder/'result.json').read_text(encoding='utf-8'))
    assert result['changed_paths']==[TEST] and result['exit_code']==0 and not result['partial']
    assert result['model']==contract['model']=='gemini-3.8-flash-high'
    after=json.loads((folder/'after.json').read_text(encoding='utf-8'))
    assert sha(W/TEST)==after[TEST]
    assert all(sha(W/path)==value and sha(R/path)==value for path,value in contract['immutable_source_sha256'].items())
    # 공용 auditor보다 좁은 native 역할: shared root references조차 읽기 허용하지 않는다.
    records=[]
    for line in (folder/'stdout.jsonl').read_text(encoding='utf-8').splitlines():
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    checked=0
    for record in records:
        step=record.get('step_update',{})
        if step.get('step_type')!='tool' or step.get('state')!='ACTIVE':
            continue
        params=step.get('tool_info',{}).get('parameters',{})
        for key,value in params.items():
            if key.lower() not in {'path','absolutepath','targetfile','file_path','directorypath','searchdirectory'} or not isinstance(value,str):
                continue
            path=pathlib.Path(value)
            assert path.is_absolute(),[key,'경로는절대경로여야함']
            assert path.resolve().is_relative_to(W.resolve()),[key,'전용worktree밖읽기쓰기금지']
            checked+=1
    audit=load('artifacts/'+STAGE+'-actor-policy-audit.json')
    assert audit['all_actor_policy_checks_passed'] and checked>0
    protected=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
    engine='crates/npi-probes/src/engine.rs'
    assert all(sha(R/path)==value for path,value in protected.items() if path!=engine)
    assert sha(R/engine)==load('artifacts/qg2g-tcp-replay-acceptance.json')['source_sha256'][engine]
    state.update(status='AUDITED_SOURCE_READY_FOR_PARENT_REVIEW',source_sha256={TEST:sha(W/TEST)},
                 immutable_source_files=len(contract['immutable_source_sha256']),strict_in_worktree_path_checks=checked,
                 root_original_protected_unchanged=len(protected)-1,approved_existing_visibility_exception_files=1)
except Exception as error:
    state['status']='BLOCKED_PRESERVED_FOR_REVIEW'
    state['error']=str(error)
finally:
    state['finished_at']=datetime.datetime.now().astimezone().isoformat()
    save()
print(json.dumps(state,ensure_ascii=False),flush=True)
sys.exit(0 if state['status']=='AUDITED_SOURCE_READY_FOR_PARENT_REVIEW' else 1)
