"""보호 파일 변경 승인이 전달되지 않은 경우 범위를 유지하고 회귀 구현을 보류한다."""
import datetime
import hashlib
import json
import pathlib

R=pathlib.Path(__file__).resolve().parents[1]
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))
protected=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(hashlib.sha256((R/path).read_bytes()).hexdigest()==value for path,value in protected.items())
now=datetime.datetime.now().astimezone().isoformat()
record={'recorded_at':now,'status':'APPROVAL_NOT_RECEIVED_PROTECTION_PRESERVED',
        'requested_scope':['crates/npi-probes/src/engine.rs의기존apply_tcp_result공개만·함수본문/매핑/측정동작변경0','양제품순수replay회귀추가'],
        'clarify_timed_out':True,'user_response':'','authorization_granted':False,
        'action':'보호유지·이회귀구현보류·추가writer시작안함',
        'product_source_changed':False,'new_tests_executed':0,'protected_inspector_unchanged':len(protected),
        'existing_worker_accepted':load('artifacts/qg2f-app-entry-acceptance.json')['accepted']}
out=R/'artifacts/qg2g-tcp-replay-approval.json'
assert not out.exists()
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
state=load('artifacts/quick-check-progress.json')
state['recorded_at']=now
state['next_qg2_review'].update(status='BLOCKED_APPROVAL_NOT_RECEIVED',authorization_granted=False,
    approval_artifact=str(out.relative_to(R)),implementation_started=False,writer_started=False)
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
section=f'''\n## 보호 변경 승인 미수신: 현 경계 유지 — {now}
- apply_tcp_result 공개접근점과순수replay회귀의최소변경을clarify로질의했으나10분내응답이없었다. 무응답은승인으로간주하지않으며이회귀를보류한다. 보호소스변경0·새writer시작0·새시험실행0·Inspector61SHA불변재확인. 기존worker기반제한수용은유지한다.
- 상태 artifacts/qg2g-tcp-replay-approval.json. 사용자가별도범위를승인하거나다른다음작업을지시하기전에는보호파일/API/제품별판정계약을변경하지않는다.
\n'''
for name in ['PROGRESS.md','RESUME.md']:
    path=R/name
    first,rest=path.read_text(encoding='utf-8').split('\n',1)
    path.write_text(first+'\n'+section+rest,encoding='utf-8',newline='\n')
path=R/'작업내용/NPI_2026-10-22_001.md'
path.write_text(path.read_text(encoding='utf-8')+section,encoding='utf-8',newline='\n')
print(json.dumps(record,ensure_ascii=False))
