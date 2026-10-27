"""부모의 test-only 보정 및 1000ms/기존기본3000ms 특성규명을 분리해 보존한다."""
import datetime
import hashlib
import json
import pathlib

R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgtcpnative'
TEST='crates/network-core/tests/tcp_product_native_equivalence.rs'
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
commands={}
for key,name,code,summary in [
    ('first_native','qg2h-tcp-native-first-owned',101,'0 passed; 4 failed;'),
    ('value_only_1000ms','qg2h-tcp-native-value-only-owned',101,'2 passed; 2 failed;'),
    ('prd_default_3000ms','qg2h-tcp-native-prd-default-owned',0,'4 passed; 0 failed;'),
]:
    item=load('artifacts/commands/'+name+'.json')
    assert item['exit_code']==code and not item['partial']
    assert summary in pathlib.Path(item['log']).read_text(encoding='utf-8')
    commands[key]=item
contract=load('artifacts/qg2h-tcp-native-actor-prepared.json')
assert all(sha(W/path)==value and sha(R/path)==value for path,value in contract['immutable_source_sha256'].items())
body=(W/TEST).read_text(encoding='utf-8')
assert body.count('let timeout_ms = DEFAULT_TCP_TIMEOUT_MS;')==4
assert 'pub const DEFAULT_TCP_TIMEOUT_MS: u64 = 3000;' in (W/'crates/network-core/src/targets.rs').read_text(encoding='utf-8')
assert 'raw_roundtrip_bytes, original_bytes' not in body
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),
        'version':'qg2h-owned-native-tcp-products-parent-delta-0.2',
        'status':'PARENT_TEST_ONLY_REPAIR_SOURCE_FIXED_EXECUTION_AND_REVIEW_PENDING',
        'source_sha256':{TEST:sha(W/TEST)},'based_on':'tcp-product-native-contract.json',
        'input_timeout_delta':{'old_initial_test_input_ms':1000,'new_test_input_ms':3000,
            'source':'network_core::targets::DEFAULT_TCP_TIMEOUT_MS·기존PRD20.1의기존입력',
            'production_constant_changed':False,'product_performance_threshold_changed':False,
            'expected_refused_outcome_unchanged':'REFUSED/10061','failure_evidence_preserved':True,
            'old_contract_1000ms_superseded_only_for_native_input':True},
        'controlled_characterization':commands,
        'characterization_limits':'3000ms4PASS는추가F2-F4강화전source·현재source통과증거로전용하지않음',
        'parent_repairs':['F1/TCP-NATIVE-001: 전체JSON값정확동등·동일표현전후byte보존을분리',
            'F2: InspectorEnvelope.target을입력전체와비교·양raw.target/Quick resolved_ip Some을소유IP와정확대조',
            'F3: native/replay각자outcome/limitations/raw전체·상태/근거/metadata/오류메시지독립assert',
            'F4: nullable필수키를get=SomeNull로구분·raw/Envelope/report전후byte보존',
            'Clippy: QuickResult타입새helper사용·nestedif제거·noopWaker불필요borrow제거',
            '예약socket설명을close-gap제거로제한·독점/모든race방지라고표현하지않음'],
        'production_changes':0,'existing_tests_changed':0,'manifest_or_lock_changed':False,
        'native_matrix_count':4,'pure_test_count':1,'latest_source_execution_received':False,
        'root_integrated':False,'accepted':False,'full_qg2_accepted':False}
out=R/'artifacts/qg2h-tcp-native-parent-repair.json'
ref=W/'.harness/references/tcp-product-native-parent-delta.json'
assert not out.exists() and not ref.exists()
for path in [out,ref]:
    path.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':record['status'],'source_sha256':record['source_sha256'],
    'input_timeout_ms':3000,'production_changes':0,'latest_source_execution_received':False},ensure_ascii=False))
