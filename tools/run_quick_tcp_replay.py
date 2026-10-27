"""승인된 공개 함수는 부모가 고정하고 Flash는 순수 replay 시험 한 파일만 작성한다."""
import datetime
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgtcpreplay'
STAGE='qg2tcpreplay'
ROLE='qgtcpreplay'
TEST='crates/network-core/tests/tcp_product_projection_replay.rs'
OUT=R/'artifacts/qg2g-tcp-replay-pipeline.json'
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
state={'started_at':datetime.datetime.now().astimezone().isoformat(),'stage':STAGE,'status':'RUNNING',
       'steps':[],'root_integrated':False,'accepted':False,'independent_review_required':True,
       'formatting_and_execution_deferred':True}

def save():
    temp=OUT.with_suffix('.json.tmp')
    temp.write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    temp.replace(OUT)

def call(name,argv):
    state['current_step']=name
    save()
    print('STEP '+name,flush=True)
    p=subprocess.run(argv,cwd=R,timeout=1100)
    state['steps'].append({'name':name,'exit_code':p.returncode})
    save()
    assert p.returncode==0,name

assert not OUT.exists() and not (R/'.harness/runs'/(STAGE+'-'+ROLE)).exists()
os.environ['NPI_AI_PRO_MODEL']='gemini-3.8-flash-high'
save()
try:
    call('prepare-actor',[sys.executable,'tools/prepare_quick_tcp_replay_actor.py'])
    contract=load('artifacts/qg2g-tcp-replay-actor-prepared.json')
    call('flash-file-only',[sys.executable,'-u','tools/ai_pro_harness.py',STAGE,ROLE])
    call('actor-policy-audit',[sys.executable,'tools/audit_ai_pro_runs.py',STAGE])
    folder=R/'.harness/runs'/(STAGE+'-'+ROLE)
    result=json.loads((folder/'result.json').read_text(encoding='utf-8'))
    assert result['changed_paths']==[TEST] and not result['partial'] and result['exit_code']==0
    after=json.loads((folder/'after.json').read_text(encoding='utf-8'))
    assert sha(W/TEST)==after[TEST]
    assert all(sha(W/path)==value for path,value in contract['immutable_source_sha256'].items())
    original=(R/'crates/npi-probes/src/engine.rs').read_bytes()
    assert (W/'crates/npi-probes/src/engine.rs').read_bytes()==original.replace(b'fn apply_tcp_result(',b'pub fn apply_tcp_result(',1)
    protected=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
    assert all(sha(R/path)==value for path,value in protected.items())
    body=(W/TEST).read_text(encoding='utf-8').split('fn parent_public_projector_signature_contract()',1)[1].split('}',1)[0]
    assert re.sub(r'\s+','',body)=='{let_projector:fn(&mutnpi_core::FeatureResult,&network_core::TcpMeasurement)=npi_probes::engine::apply_tcp_result;'
    state.update(status='AUDITED_SOURCE_READY_FOR_PARENT_REVIEW',
                 source_sha256={TEST:sha(W/TEST),'crates/npi-probes/src/engine.rs':sha(W/'crates/npi-probes/src/engine.rs')},
                 root_inspector_original_unchanged=len(protected),
                 worktree_original_protected_unchanged=len(protected)-1,approved_visibility_change_files=1)
except Exception as error:
    state['status']='BLOCKED_PRESERVED_FOR_REVIEW'
    state['error']=str(error)
finally:
    state['finished_at']=datetime.datetime.now().astimezone().isoformat()
    save()
print(json.dumps(state,ensure_ascii=False),flush=True)
sys.exit(0 if state['status']=='AUDITED_SOURCE_READY_FOR_PARENT_REVIEW' else 1)
