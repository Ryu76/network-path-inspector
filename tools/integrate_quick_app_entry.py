"""최종 정적 QA와 고정 소스 실행 증거를 확인한 뒤 app4+부모 metadata2만 통합한다."""
import datetime
import hashlib
import json
import pathlib
import shutil
import subprocess
import tomllib

R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgquickapp'
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
run=load('artifacts/qg2f-app-entry-parent-execution.json')
assert run['status']=='PURE_AND_OWNED_NATIVE_PASS_FINAL_REVIEW_PENDING'
assert run['workspace_default_counts']=={'passed':427,'failed':0,'ignored':23}
assert run['app_default_counts']=={'passed':12,'failed':0,'ignored':1}
assert run['native_test_passed']==1 and run['commandline_cases_passed']==38
assert all(sha(W/path)==value for path,value in run['source_sha256'].items())
assert load('artifacts/qg2appentryfix-actor-policy-audit.json')['all_actor_policy_checks_passed']
for key in ['final_app_default','final_app_clippy','final_app_fmt','final_app_whitespace','owned_native_driver','workspace_default','workspace_clippy']:
    item=run['evidence'][key]
    assert item['exit_code']==0 and not item['partial'] and pathlib.Path(item['log']).is_file()
head=subprocess.run(['git','-C',str(W),'rev-parse','HEAD'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
status=subprocess.run(['git','-C',str(W),'status','--porcelain'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
assert head.returncode==status.returncode==0 and head.stdout.strip()==run['preserved_source_commit'] and not status.stdout.rstrip('\r\n')
prepared=load('artifacts/qg2f-app-entry-prepared.json')
meta=['Cargo.toml','Cargo.lock']
assert all(sha(R/path)==prepared['source_sha256'][path] for path in meta), '기존root변경을덮어쓰지않음'
outputs=list(run['source_sha256'])
assert all(not (R/path).exists() for path in outputs)
protected=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert not set(protected).intersection(outputs+meta)
assert all(sha(R/path)==value for path,value in protected.items())
frozen=load('artifacts/qg2f-app-entry-independent-review.json')['immutable_source_sha256']
assert all(sha(W/path)==value for path,value in frozen.items())
assert all(sha(R/path)==value for path,value in frozen.items() if path not in meta)
old_manifest=tomllib.loads((R/'Cargo.toml').read_text(encoding='utf-8'))
new_manifest=tomllib.loads((W/'Cargo.toml').read_text(encoding='utf-8'))
expected=json.loads(json.dumps(old_manifest))
expected['workspace']['members'].append('apps/network-quick-check')
assert expected==new_manifest
old={p['name']:p for p in tomllib.loads((R/'Cargo.lock').read_text(encoding='utf-8'))['package']}
new={p['name']:p for p in tomllib.loads((W/'Cargo.lock').read_text(encoding='utf-8'))['package']}
assert set(new)-set(old)=={'network-quick-check'} and all(new[k]==v for k,v in old.items())
assert new['network-quick-check']['dependencies']==['network-core','tokio']
transcripts={}
delivery=load('artifacts/qg2f-app-entry-final-review-delivery.json')
assert len(delivery['results'])==2
for index in range(2):
    path=pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/delegation/live/deleg_c26f9c10')/f'task-{index}.log'
    text=path.read_text(encoding='utf-8')
    assert 'delegation: deleg_c26f9c10' in text and 'end status=completed' in text
    prefixes=[line for line in text.splitlines() if 'assistant|' in line and '"findings": []' in line]
    assert len(prefixes)==1
    normalized=delivery['results'][index]
    assert normalized['task']==index and normalized['findings']==[]
    if index==1:
        assert '"safe_to_execute_native_tests": true' in prefixes[0]
        assert normalized['safe_to_execute_native_tests'] is True
    transcripts[f'task-{index}']={'path':str(path),'sha256':sha(path),'normalized_delivery_result':normalized,
                                 'body_truncated':True,'full_result_source':'Hermes async notification',
                                 'delivery_artifact':'artifacts/qg2f-app-entry-final-review-delivery.json'}
now=datetime.datetime.now().astimezone().isoformat()
review={'recorded_at':now,'review':'deleg_c26f9c10','source_sha256':run['source_sha256'],
        'transcripts':transcripts,'findings':[],'previous_findings_resolved':True,
        'limitations':['두검토는정적읽기만·실행/해시재계산은부모증거와분리','Windows경로기반·타OS/GUI/배포인증아님']}
review_out=R/'artifacts/qg2f-app-entry-final-independent-review.json'
out=R/'artifacts/qg2f-app-entry-integration.json'
assert not review_out.exists() and not out.exists()
backup=R/'.harness/baselines/qg2f-app-entry-root'
assert not backup.exists()
backup.mkdir(parents=True)
for path in meta:
    shutil.copyfile(R/path,backup/path)
    assert sha(backup/path)==sha(R/path)
record={'recorded_at':now,'state':'PREPARING','before_metadata_sha256':{path:sha(R/path) for path in meta},
        'new_outputs_absent':True,'paths':outputs+meta,'source_evidence':'artifacts/qg2f-app-entry-parent-execution.json',
        'independent_review':str(review_out.relative_to(R)),'accepted':False,'root_integrated':False,
        'full_qg2_accepted':False,'product_accepted':False}
review_out.write_text(json.dumps(review,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
for path in outputs+meta:
    (R/path).parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(W/path,R/path)
assert all(sha(R/path)==sha(W/path) for path in outputs+meta)
assert all(sha(R/path)==value for path,value in protected.items())
assert all(sha(R/path)==value for path,value in frozen.items())
record.update(state='INTEGRATED_FOR_ROOT_REGRESSION_NOT_ACCEPTED',root_integrated=True,
              source_sha256={path:sha(R/path) for path in outputs+meta},inspector_changed=0,
              existing_lock_packages_identical=len(old),new_lock_package=new['network-quick-check'])
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
state=load('artifacts/quick-check-progress.json')
state['recorded_at']=now
state['qg2_app_entry'].update(status=record['state'],root_integrated=True,accepted=False,
    final_review_received=True,independent_review_status='최종두QA추가지적0·기존7종해소',
    integration_artifact=str(out.relative_to(R)))
state['remaining_blockers']=['제품worker진입점root조합회귀/native/명령행/경계/Clippy/fmt실행·제한수용기록전',
                            '전체QG2실환경/GUI/QG3/진단시작경로/배포·OS/성능미완료']
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'state':record['state'],'files_integrated':len(outputs+meta),'existing_lock_packages_identical':len(old),
                  'independent_findings':0,'inspector_unchanged':len(protected),'accepted':False},ensure_ascii=False))
