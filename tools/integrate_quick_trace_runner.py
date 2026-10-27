"""최종 재QA·동일 소스 실행을 확인해 Trace 실행기 두 파일만 root 회귀용으로 통합한다."""
import datetime
import hashlib
import json
import pathlib
import shutil
import subprocess

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qg2runner'
PATHS = ['crates/network-core/src/runner.rs', 'crates/network-core/tests/runner.rs']
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
now = datetime.datetime.now().astimezone().isoformat()
run = load('artifacts/qg2e-trace-runner-final-guard-execution.json')
assert run['status'] == 'PURE_AND_OWNED_NATIVE_PASS_FINAL_REVIEW_PENDING'
assert all(sha(W / path) == expected for path, expected in run['source_sha256'].items())
assert all(step['exit_code'] == 0 and not step['partial'] for step in run['steps'])
assert load('artifacts/qg2tracewirefix-actor-policy-audit.json')['all_actor_policy_checks_passed']
previous = load('artifacts/qg2d-dns-runner-acceptance.json')
assert previous['accepted']
assert all(sha(R / path) == previous['source_sha256'][path] for path in PATHS), '미승인 root 변경 덮지 않음'
protected = load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(sha(R / path) == expected for path, expected in protected.items())
frozen = load('artifacts/qg2e-trace-runner-prepared.json')['dependency_source_sha256']
assert all(sha(R / path) == expected and sha(W / path) == expected for path, expected in frozen.items() if path not in PATHS)
trace = load('artifacts/qg2c-trace-os-code-acceptance.json')
assert all(sha(R / path) == expected for path, expected in trace['source_sha256'].items())
status = subprocess.run(['git', '-C', str(W), 'status', '--porcelain'], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30)
assert status.returncode == 0 and not status.stdout.rstrip('\r\n')
transcripts = {}
for index in [0, 1]:
    path = pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/delegation/live/deleg_45855748') / f'task-{index}.log'
    text = path.read_text(encoding='utf-8')
    assert 'delegation: deleg_45855748' in text and 'end status=completed' in text
    assert any('assistant|' in line and '"findings": []' in line for line in text.splitlines())
    transcripts[f'task-{index}'] = {'path': str(path), 'sha256': sha(path), 'findings': []}
review = {
    'recorded_at': now, 'review': 'deleg_45855748', 'source_sha256': run['source_sha256'],
    'transcripts': transcripts, 'findings': [],
    'resolved_findings': ['TRACE-QA-001', 'TRACE-QA-002', 'TRACE-QA-03', 'TRACE-TEST-BUDGET-01', 'TRACE-TEST-BUDGET-02', 'TRACE-TEST-CANCEL-02', 'TRACE-GUARD-PORT-02', 'TRACE-TEST-GUARD-02', 'TRACE-TEST-COUNTER-01'],
    'parent_confirmation': '최종sourceSHA재계산·순수217/native5·strictClippy/fmt·직접guard4실패전후근거별도검증',
    'limitations': ['정적reviewer는코드실행/해시재계산없음. 부모실행증거와분리', '루프백native성공은OS/운영망/실제OS취소인증아님'],
    'accepted': False,
}
out_review = R / 'artifacts/qg2e-trace-runner-final-independent-review.json'
assert not out_review.exists()
meta = ['Cargo.toml', 'Cargo.lock', 'crates/network-core/Cargo.toml', 'crates/network-core/src/lib.rs']
record = {'recorded_at': now, 'state': 'PREPARING', 'before_sha256': {path: sha(R / path) for path in [*PATHS, *meta]},
          'source_evidence': 'artifacts/qg2e-trace-runner-final-guard-execution.json',
          'independent_review': str(out_review.relative_to(R)), 'findings': [], 'accepted': False,
          'root_integrated': False, 'full_qg2_accepted': False}
out = R / 'artifacts/qg2e-trace-runner-integration.json'
assert not out.exists()
for suffix in ['workspace', 'native', 'trace-boundaries', 'dns-boundaries', 'clippy', 'fmt']:
    assert not (R / 'artifacts/commands' / ('qg2e-trace-runner-root-' + suffix + '.json')).exists()
out_review.write_text(json.dumps(review, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
out.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
for path in PATHS:
    shutil.copyfile(W / path, R / path)
assert all(sha(R / path) == expected for path, expected in run['source_sha256'].items())
assert all(sha(R / path) == record['before_sha256'][path] for path in meta)
assert all(sha(R / path) == expected for path, expected in protected.items())
record.update(state='INTEGRATED_FOR_ROOT_REGRESSION_NOT_ACCEPTED', root_integrated=True,
              source_sha256={path: sha(R / path) for path in [*PATHS, *meta]}, inspector_changed=0,
              dependency_change='없음; 수용기존DNS/Trace와manifest/lock/lib 그대로,runner source/tests만교체')
out.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
state = load('artifacts/quick-check-progress.json')
state['recorded_at'] = now
state['qg2_trace_runner'].update(status=record['state'], accepted=False, root_integrated=True,
    independent_review='deleg_45855748_COMPLETE_FINDINGS_EMPTY', integration_artifact=str(out.relative_to(R)))
state['remaining_blockers'] = ['Trace 실행기 root조합workspace/native/경계/Clippy/fmt 및제한수용 기록전', '제품helper dispatch/GUI/EXE/VM/성능/실VLAN·전체QG2미완료']
(R / 'artifacts/quick-check-progress.json').write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'state':record['state'], 'files_integrated':len(PATHS), 'manifest_lib_lock_changed':False,
                  'independent_findings':0, 'inspector_unchanged':len(protected), 'accepted':False}, ensure_ascii=False))
