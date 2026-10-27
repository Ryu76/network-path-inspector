"""동일 원시 TCP replay의 private/protected 경계를 확인하고 미구현·차단 상태를 기록한다."""
import datetime
import hashlib
import json
import pathlib

R=pathlib.Path(__file__).resolve().parents[1]
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
protected=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
engine='crates/npi-probes/src/engine.rs'
quick='crates/network-core/src/quick.rs'
contract='contracts/quick-check-interface-v0.1.json'
assert engine in protected
assert all(sha(R/path)==value for path,value in protected.items())
accepted=load('artifacts/qg2f-app-entry-acceptance.json')
assert accepted['accepted'] and not accepted['full_qg2_accepted']
assert all(sha(R/path)==value for path,value in accepted['source_sha256'].items())
engine_text=(R/engine).read_text(encoding='utf-8')
assert '\nfn apply_tcp_result(row: &mut FeatureResult, meas: &TcpMeasurement)' in engine_text
assert 'pub fn apply_tcp_result' not in engine_text
assert 'pub fn tcp_to_quick_result(' in (R/quick).read_text(encoding='utf-8')
public_mapping=load(contract)['tcp_status_mapping']
assert public_mapping['CANCELLED']==['UNKNOWN','UNKNOWN']
assert public_mapping['LOCAL_ERROR']==['UNKNOWN','OBSERVED']
assert public_mapping['DNS_ERROR']==['FAIL','OBSERVED']
transcript=pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/delegation/live/deleg_7532729a/task-0.log')
text=transcript.read_text(encoding='utf-8')
assert 'delegation: deleg_7532729a' in text and 'end status=completed' in text
# 판정 본문은 길면 live log에서 잘린다. 완료 marker와 전달된 최종 응답을 구분한다.
now=datetime.datetime.now().astimezone().isoformat()
record={
    'recorded_at':now,'slice':'QG2-G-CROSS-PRODUCT-TCP-RAW-REPLAY-REVIEW',
    'status':'BLOCKED_FOR_FULL_CROSS_PRODUCT_REPLAY','review':'deleg_7532729a',
    'result_representation':'완전한async최종응답을부모가정규화한판정·원본무손실JSON사본아님',
    'transcript':{'path':str(transcript),'sha256':sha(transcript),'human_readable_body_may_be_truncated':True},
    'evidence_collection_recovery':{'first_attempt_exit_code':1,
        'cause':'live log의잘린본문에BLOCKED판정문자열을요구한부모사전단언실패',
        'product_files_changed':False,'tests_started':False,
        'recovery':'완료marker/transcriptSHA와완전한async전달판정을구분·실제private경계는부모source로재확인'},
    'parent_confirmation':['실제engine.rs의private apply_tcp_result 확인',
                           '현재Quick공개tcp_to_quick_result와frozen상태계약확인',
                           'crates전체의apply_tcp_result/public replay·project·tcp_result 및TcpMeasurement 인자검색에서다른Inspector replay진입점미발견',
                           'Inspector engine이보호목록에포함되고61파일SHA전부불변확인',
                           '기존worker수용source6SHA불변확인'],
    'source_sha256':{path:sha(R/path) for path in [engine,quick,contract,'crates/npi-probes/src/lib.rs']},
    'existing_evidence':['공유classify_tcp_error/TcpMeasurement/connect_once재사용',
                         'Quick전체outcome/OS오류/컨텍스트/IP·포트오염/원시DTO보존회귀',
                         'Inspector코드분류·취소/timeout우선순위·단독루프백시험'],
    'missing_evidence':'동일원시TcpMeasurement를양제품실제projector에공급한무부수효과replay연결',
    'confirmed_current_mapping':[
        {'outcome':'CONNECTED','inspector':['PASS','OBSERVED'],'quick':['PASS','OBSERVED']},
        {'outcome':'REFUSED/RESET/TIMED_OUT/UNREACHABLE','inspector':['FAIL','OBSERVED'],'quick':['FAIL','OBSERVED']},
        {'outcome':'CANCELLED','inspector':['CANCELLED','UNKNOWN'],'quick':['UNKNOWN','UNKNOWN']},
        {'outcome':'LOCAL_ERROR','inspector':['ERROR','코드Some이면OBSERVED·None이면UNKNOWN'],'quick':['UNKNOWN','OBSERVED']},
        {'outcome':'DNS_ERROR','inspector':['ERROR','코드Some이면OBSERVED·None이면UNKNOWN'],'quick':['FAIL','OBSERVED']},
        {'outcome':'unrecognized','inspector':['ERROR','코드Some이면OBSERVED·None이면UNKNOWN'],'quick':['UNKNOWN','UNKNOWN']},
    ],
    'mapping_disposition':'현동작과제품별계약의characterization이다. 동일성의미를합의하기전결함/동등으로단정하거나자동상태정규화하지않음.',
    'blocked_reason':'Inspector apply_tcp_result는private·public run_profile에는raw/backend주입없음. 현재보호소스변경0/판정복제0/runtime·network0동시제약을충족할완결test-only경로가없음.',
    'rejected_workarounds':['Inspector결과DTO를손으로구성해실제판정기검증이라주장',
                           'private소스복사/include/문자열추출을정상public replay로취급',
                           '기존Quick단독시험반복을양제품공백해소로표현',
                           '실제순차TCP결과무조건동등또는루프백을실VLAN/DROP대체로주장'],
    'next_decision_required':'보호유지·본회귀보류 또는 Inspector판정기최소공개접근점의별도승인. 승인전보호파일/API/기존계약변경0.',
    'implementation_started':False,'new_tests_implemented':0,'new_tests_executed':0,
    'network_or_runtime_executed':False,'protected_inspector_unchanged':len(protected),
    'existing_worker_acceptance_preserved':True,'accepted':False,'full_qg2_accepted':False,
    'product_accepted':False,'qg3_started':False,
}
out=R/'artifacts/qg2g-tcp-equivalence-review.json'
assert not out.exists()
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
state=load('artifacts/quick-check-progress.json')
state['recorded_at']=now
state['next_qg2_review'].update(status=record['status'],review_received=True,
    review_artifact=str(out.relative_to(R)),implementation_started=False,tests_executed=0,
    blocker=record['blocked_reason'],next_decision_required=record['next_decision_required'])
state['remaining_blockers']=['TCP원시replay는Inspectorprivate/protected경계로차단·최소접근점변경별도승인전보호유지',
                            '전체QG2실VLAN/DROP/ICMP차단·다중NIC/VPN미검증',
                            'GUI/QG3/제품명시진단시작경로/TXT·CSV/Release/PE·CRT·서명/VM·일반사용자/성능미완료']
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
section=f'''\n## 동일 TCP 원시 replay 후보: 실제 private/보호 경계로 차단 확정 — {now}
- 독립읽기전용검토 deleg_7532729a 결과와부모실제source를대조했다. Quick tcp_to_quick_result는public이지만Inspector apply_tcp_result는engine.rs:452의private이고engine.rs는보호61파일에포함된다. public run_profile은raw/backend주입경로가없고정상TCP선택시실제runtime/socket을사용한다. crates전체추가참조/인자검색에서도별도public Inspector replay진입점을찾지못했다.
- CONNECTED/REFUSED/RESET/TIMED_OUT/UNREACHABLE의상태·근거표현은일치하나CANCELLED/LOCAL_ERROR/DNS_ERROR/미인식outcome은현제품별표현이다르다. frozen Quick계약과Inspector현동작을임의통일/정규화하거나차이를새결함으로단정하지않았다. 비교축과허용차이의사전계약이필요하다.
- 보호소스변경0/판정기복제0/runtime·network0을모두유지하면양제품실제projector replay는현재진행불가. 손으로만든Inspector기대DTO/소스include우회/기존Quick단독시험반복을공백해소로위장하지않는다. 새제품코드/시험0·시험실행0·네트워크/runtime실행0. 최소공개접근점변경을별도승인받기전에는보호를유지한다.
- Inspector61SHA와기존worker수용source6SHA불변을부모가실제재계산했다. 기존root427/native23/CLI38/경계14+6수용은이전실행근거로유지되며이번검토의새실행수치가아니다. 전체QG2/GUI/QG3/배포인증미완료. 상세 artifacts/qg2g-tcp-equivalence-review.json.
\n'''
for name in ['PROGRESS.md','RESUME.md']:
    path=R/name
    first,rest=path.read_text(encoding='utf-8').split('\n',1)
    path.write_text(first+'\n'+section+rest,encoding='utf-8',newline='\n')
path=R/'작업내용/NPI_2026-10-22_001.md'
path.write_text(path.read_text(encoding='utf-8')+section,encoding='utf-8',newline='\n')
print(json.dumps({'status':record['status'],'implementation_started':False,'new_tests_executed':0,
                  'protected_inspector_unchanged':len(protected),'worker_accepted_source_unchanged':6},ensure_ascii=False))
