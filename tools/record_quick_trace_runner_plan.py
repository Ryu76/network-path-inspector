"""Trace 실행기 계약 초안을 보존하고 DNS/Trace 추가 검증 상태를 분리 기록한다."""
import datetime
import hashlib
import json
import pathlib

R = pathlib.Path(__file__).resolve().parents[1]
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))
now = datetime.datetime.now().astimezone().isoformat()
dns = load('artifacts/qg2d-dns-runner-repair-pipeline.json')
assert dns['status'] == 'EXECUTION_PASS_INDEPENDENT_REVIEW_PENDING'
assert all(hashlib.sha256((R / '.worktrees/qg2runner' / path).read_bytes()).hexdigest() == expected
           for path, expected in dns['canonical_source_sha256'].items())
trace = load('artifacts/qg2c-trace-os-code-repair.json')
assert all(hashlib.sha256((R / path).read_bytes()).hexdigest() == expected
           for path, expected in trace['source_sha256'].items())
protected = load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(hashlib.sha256((R / path).read_bytes()).hexdigest() == expected for path, expected in protected.items())
plan = {
    'recorded_at': now, 'status': '설계 초안·미구현·미시험', 'design_review': 'deleg_8a9e5c57',
    'provenance': '읽기전용 설계 검토의 제안과 부모가 확인한 실제 소스/스키마를 합친 후속 계약 초안. 수용 기록 아님.',
    'scope': ['crates/network-core/src/runner.rs', 'crates/network-core/tests/runner.rs'],
    'prerequisites': ['DNS 연결 raw/취소 2결함 최종 재QA·root 수용', 'Trace exit_code/OS코드 구분 보정의 최종 검증·재QA'],
    'proposed_api': "QuickProbeBackend에 본문 있는 fn trace<'a>(&'a self,ctx:QuickContext,target:IpAddr,options:crate::traceroute::TraceOptions,cancel:Arc<AtomicBool>)->ProbeFuture<'a> 추가",
    'preserve': ['기존 모든 DTO 필드', 'run_quick 및 기존 backend 메서드', 'NativeProbeBackend unit struct',
                 'NativeDnsProbeBackend 생성자/helper/resolve', '기본선택 TCP+Ping', 'TraceOptions::default() 기존값'],
    'default_method': 'I/O 없이 UNKNOWN/UNKNOWN+UNAVAILABLE. 사전취소면 CANCELLED 우선, 미측정raw 빈 객체. 기존 trait 구현 source호환.',
    'native_delegation': 'NativeProbeBackend::trace는 spawn_blocking으로 기존 trace_once 호출 후 trace_to_quick_result. NativeDnsProbeBackend는 동일 메서드 위임. 프로브복제/새helper/엔진수정 금지.',
    'execution': [
        '명시선택만 trace 호출. IP는 추가DNS0; domain은수용DNS정책의첫검증주소만사용. 다른IP fallback/fanout0.',
        '카운터는 실제 backend trace 메서드 호출횟수이며 프로세스/패킷 수가 아님.',
        'ctx target_host/port/session/source는원문유지. 실제측정 raw.target과resolved_ip는선택IP와일치.',
        '완료DNS는모든feature순서/취소에서도보존. 미시작Trace는호출0; 실행중동일cancel전달후기존엔진정리await.',
        'details는정확3키. DNS전체raw는수용된limitations JSON위치만사용, Trace raw_measurement를덮지않음.',
        '한도는보관결과 JSONbytes. 대상전체완료후감지라는기존한계를instant RSS/기능별즉시차단으로과장하지않음.',
    ],
    'required_trace_result_guard': [
        '현재generic verifier의null resolved_ip허용만으로실제Trace행을수용하지않음.',
        'raw가있으면기존Deserialize 가능한TraceMeasurement로재구성하고trace_to_quick_result로재검증하여위조PASS·다른target·동일metadata오염을거부.',
        'raw/어댑터의outcome·상태·근거·IP·경과·OS코드의일치를확인한뒤필수DNS원문을첨부. 실측원문을수리하지않음.',
        'default 미측정 UNAVAILABLE/CANCELLED와실제측정행을구분하여미측정만nullableIP/빈raw허용.',
    ],
    'tests_proposed': ['기존trait default source호환·미선택0', 'IP단독/혼합선택과정확한카운터',
                       'domain필수DNS1/상세DNS행0·해석실패뒤Trace0', '역순취소/실행중협력취소·완료원문보존',
                       '위조PASS/다른IP/null실측IP/raw불일치거부', 'REACHED/INCOMPLETE/오류원문·정확3details키',
                       '최대100/동시4/바이트/정렬·미시작중단', '부모명시소유127.0.0.1/::1 실제기능위임'],
    'separate_confirmed_issue': {'id': 'TRACE-EXIT-AS-OS-ERROR', 'severity': 'P2',
                                'before': '부모실제1pass2fail', 'repair': '부모가한필드None+raw종료코드보존으로교정,별도감독기로실제검증중',
                                'artifact': 'artifacts/qg2c-trace-os-code-repair.json'},
    'not_accepted': ['Trace 실행기 연결 구현', 'GUI/제품EXE/helper dispatch/서명/VM/일반사용자/성능',
                     '운영망/VLAN/차단시험', '전체QG2/제품완료'],
}
out = R / 'artifacts/qg2e-trace-runner-proposed-contract.json'
assert not out.exists()
out.write_text(json.dumps(plan, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
state = load('artifacts/quick-check-progress.json')
state['recorded_at'] = now
runner = state['qg2_dns_runner']
runner['historical_before_fix'] = runner.get('parent_boundary_tests')
runner.update(status='REPAIRED_EXECUTION_PASS_FINAL_STATIC_RECHECK_PENDING', latest_execution=dns,
              actor_alive_at_checkpoint=False, active_stage=None, accepted=False, root_integrated=False,
              parent_boundary_tests={'evidence': 'qg2d-dns-runner-repair-witnesses', **dns['test_counts']['qg2d-dns-runner-repair-witnesses']},
              review_pending='deleg_40886ced/tasks-0-1')
state['qg2_trace'].update(status='OS_CODE_PROJECTION_REPAIR_RECHECK_PENDING', accepted=False,
                         latest_projection_repair=trace, review_pending='deleg_40886ced/task-2',
                         pipeline_session='proc_7fc15c511820')
state['trace_runner_contract_review'] = {'status': plan['status'], 'review': 'deleg_8a9e5c57',
                                         'proposed_contract': str(out.relative_to(R)), 'implementation_started': False}
state['remaining_blockers'] = ['DNS 실행기 최종원문/취소 재QA deleg_40886ced/tasks0-1 및 root통합 전',
                               'Trace exit/OS code 별도보정의전체실제검증·재QA task2 전',
                               'Trace 선택실행기 연결·GUI/EXE/일반사용자/VM/실VLAN·성능·전체QG2 미완료']
(R / 'artifacts/quick-check-progress.json').write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
section = f'''\n## DNS 실행기 보정 시험 통과 / Trace 코드 의미 추가 검증 — {now}
- qg2dnswirefix 실제FILEONLY/경로감사통과후부모회귀11PASS(이전3PASS5FAIL),별도Core125PASS/0FAIL,명시소유native3PASS,Clippy/whitespace0. 앞선11·125·3은각기다른시험범위이며합산제품인증수가아님. 독립최종QA deleg_40886ced/tasks0-1 요청. 아직root미통합/미수용.
- 다음Trace실행기연결설계 deleg_8a9e5c57 회수. 기본default메서드로source호환·기존엔진위임·도메인DNS선행·Trace실측raw/IP/재어댑터검증을제안. artifacts/qg2e-trace-runner-proposed-contract.json은미구현초안이며선행DNS보정수용전구현하지않음.
- 설계검토가발견한기존Trace의exit_code를os_error_code에복사하는의미오류는부모1PASS2FAIL로재현했다. 기존수용상태를이작은필드에대해재개방하고,부모가OS코드None·원시exit_code그대로보존으로교정했다. 실제root workspace/native/경계/Clippy/fmt 유한감독 proc_7fc15c511820 상태={trace['status']}. 별도독립정적QA task2요청,새수용을미리주장하지않음.
- Trace projection은부모의명시기여이며Flash DNS수정과분리. Inspector보호{len(protected)}파일SHA불변·OS정책/운영망/DB/원격push변경없음. GUI/EXE·전체QG2미완료.
\n'''
for filename in ['PROGRESS.md', 'RESUME.md']:
    path = R / filename
    original = path.read_text(encoding='utf-8')
    first, rest = original.split('\n', 1)
    path.write_text(first + '\n' + section + rest, encoding='utf-8', newline='\n')
path = R / '작업내용/NPI_2026-10-22_001.md'
path.write_text(path.read_text(encoding='utf-8') + section, encoding='utf-8', newline='\n')
print(json.dumps({'dns_runner_counts': dns['test_counts'], 'dns_final_static_review': 'deleg_40886ced/tasks-0-1',
                  'trace_projection_status': trace['status'], 'trace_projection_static_review': 'deleg_40886ced/task-2',
                  'trace_runner_plan': plan['status'], 'inspector_unchanged': len(protected)}, ensure_ascii=False))
