"""Trace 필드 보정 수용 후 최종 DNS 실행기 두 파일만 회귀용 선택 통합한다."""
import datetime
import hashlib
import json
import pathlib
import re
import shutil

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qg2runner'
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
now = datetime.datetime.now().astimezone().isoformat()
projection = load('artifacts/qg2c-trace-os-code-repair.json')
assert projection['status'] == 'EXECUTION_PASS_INDEPENDENT_REVIEW_PENDING'
assert all(step['exit_code'] == 0 and not step['partial'] for step in projection['steps'])
trace_previous = load('artifacts/qg2c-trace-acceptance.json')
trace_sha = {**trace_previous['source_sha256'], **projection['source_sha256']}
assert all(sha(R / path) == expected for path, expected in trace_sha.items())
protected = load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(sha(R / path) == expected for path, expected in protected.items())
trace_accept = {
    'recorded_at': now, 'decision': 'ACCEPTED_STANDALONE_TRACE_WITH_EXIT_OS_CODE_SEMANTIC_REPAIR',
    'previous_acceptance': 'artifacts/qg2c-trace-acceptance.json',
    'superseded_fields': ['두 Trace source/tests SHA', '프로세스 종료코드의 top OS오류 투영'],
    'independent_review': 'deleg_40886ced/task-2', 'findings': [],
    'review_limitations': '정적 검토이며 실제Win32오류주입아님. reviewer의 tests/traceroute.rs 상대경로는root로해석되어실제core시험파일을읽지않았으나 부모는실제core파일을all-targets로실행했고독립경계3assertion도검토됨.',
    'execution': projection['steps'], 'source_sha256': trace_sha,
    'parent_adjustment': projection['source_change'], 'finding_resolved': 'TRACE-EXIT-AS-OS-ERROR',
    'accepted': True, 'root_integrated': True, 'runner_connected': False,
    'full_qg2_accepted': False, 'product_accepted': False,
}
trace_path = R / 'artifacts/qg2c-trace-os-code-acceptance.json'
assert not trace_path.exists()
trace_path.write_text(json.dumps(trace_accept, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
dns = load('artifacts/qg2d-dns-runner-repair-pipeline.json')
assert dns['status'] == 'EXECUTION_PASS_INDEPENDENT_REVIEW_PENDING'
assert all(step['exit_code'] == 0 for step in dns['steps'])
assert load('artifacts/qg2dnswirefix-actor-policy-audit.json')['all_actor_policy_checks_passed']
for path, expected in dns['canonical_source_sha256'].items():
    assert sha(W / path) == expected, path
old_runner = load('artifacts/qg2b-runner-acceptance.json')
for path in dns['canonical_source_sha256']:
    assert sha(R / path) == old_runner['source_sha256'][path], '기존root IP실행기 미승인 변경은 덮지 않음'
shared = load('artifacts/qg2c-dns-acceptance.json')['source_sha256']
for path, expected in shared.items():
    if path.endswith(('/dns.rs', '/network-resolver/src/lib.rs', '/network-resolver/tests/dns.rs')):
        assert sha(R / path) == expected and sha(W / path) == expected, path
for suffix in ['workspace', 'native', 'clippy', 'fmt', 'trace-boundaries', 'dns-boundaries']:
    assert not (R / 'artifacts/commands' / ('qg2d-dns-runner-root-' + suffix + '.json')).exists()
meta = ['Cargo.toml', 'Cargo.lock', 'crates/network-core/Cargo.toml', 'crates/network-core/src/lib.rs']
before = {path: sha(R / path) for path in [*dns['canonical_source_sha256'], *meta]}
record = {'recorded_at': now, 'state': 'PREPARING', 'before_sha256': before,
          'source_evidence': 'artifacts/qg2d-dns-runner-repair-pipeline.json',
          'independent_review': 'deleg_40886ced/tasks-0-1', 'findings': [],
          'resolved_findings': ['DNS-RUNNER-002', 'CANCEL-DNS-ORDER-01'],
          'rejected_policy_change': 'DNS-RUNNER-001: IP독립정책은기존승인prompt/positivecontrols로유지',
          'accepted': False, 'full_qg2_accepted': False}
out = R / 'artifacts/qg2d-dns-runner-integration.json'
assert not out.exists()
out.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
for path in dns['canonical_source_sha256']:
    shutil.copyfile(W / path, R / path)
assert all(sha(R / path) == expected for path, expected in dns['canonical_source_sha256'].items())
assert all(sha(R / path) == before[path] for path in meta), 'manifest/lib/lock 변경 금지'
assert all(sha(R / path) == expected for path, expected in protected.items())
assert all(sha(R / path) == expected for path, expected in trace_sha.items())
record.update(state='INTEGRATED_FOR_ROOT_REGRESSION_NOT_ACCEPTED',
              source_sha256={path: sha(R / path) for path in [*dns['canonical_source_sha256'], *meta]},
              inspector_changed=0, dependency_change='없음; 수용된기존DNS/Trace 의존성 그대로,runner두파일만교체')
out.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
state = load('artifacts/quick-check-progress.json')
state['recorded_at'] = now
state['qg2_trace'].update(status=trace_accept['decision'], accepted=True, root_integrated=True,
                         latest_projection_repair=projection, final_review='deleg_40886ced/task-2',
                         acceptance_artifact=str(trace_path.relative_to(R)))
state['qg2_trace'].pop('review_pending', None)
state['qg2_dns_runner'].update(status=record['state'], accepted=False, root_integrated=True,
                               final_static_review='deleg_40886ced/tasks-0-1', integration_artifact=str(out.relative_to(R)))
state['qg2_dns_runner'].pop('review_pending', None)
state['remaining_blockers'] = ['DNS 실행기 root 조합회귀/실제native/Clippy/fmt·최종수용 전',
                               'Trace 실제선택실행기 연결 미구현', 'GUI/EXE/일반사용자/VM/실VLAN·성능·전체QG2 미완료']
(R / 'artifacts/quick-check-progress.json').write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
section = f'''\n## DNS 실행기 root 회귀용 통합 / Trace OS코드 보정 재수용 — {now}
- deleg_40886ced 세검토자 모두확정추가차단0. DNS 숨은원문/역순취소2결함정적해소·IP독립정책보존확인. actor감사·Core125/parent회귀11/native3/Clippy·whitespace0 canonical runner두파일만root에선택반영. 아직root조합시험·최종수용전이며manifest/lib/lock/공유프로브를교체하지않음.
- Trace EXIT-AS-OS-ERROR는부모추가보정및root전체364/native19/경계14/Clippy·fmt0과좁은독립정적QA를확인해단독모듈범위재수용. 원시exit0/1/None은raw에유지하고top OS코드는null. 실제Win32오류주입/Trace실행기/GUI/전체QG2수용아님. 이전수용artifact를덮지않고별도superseding수용record보존.
- Inspector보호{len(protected)}파일SHA변경0·원격push/운영망/OS정책/DB변경없음. root제품앱은아직GUI/단일EXE가없고새DNS backend는명시helper경로설정이필요하다.
\n'''
for filename in ['PROGRESS.md', 'RESUME.md']:
    path = R / filename
    text = path.read_text(encoding='utf-8')
    first, rest = text.split('\n', 1)
    path.write_text(first + '\n' + section + rest, encoding='utf-8', newline='\n')
path = R / '작업내용/NPI_2026-10-22_001.md'
path.write_text(path.read_text(encoding='utf-8') + section, encoding='utf-8', newline='\n')
print(json.dumps({'trace_decision': trace_accept['decision'], 'dns_runner_state': record['state'],
                  'dns_runner_files_integrated': len(dns['canonical_source_sha256']),
                  'manifest_lib_lock_changed': False, 'inspector_unchanged': len(protected)}, ensure_ascii=False))
