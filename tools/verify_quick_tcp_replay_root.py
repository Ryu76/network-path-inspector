"""승인된 TCP 공개가시성 및 순수 replay를 Inspector/Quick 전체와 root 조합 검증한다."""
import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import time

R = pathlib.Path(__file__).resolve().parents[1]
OUT = R / 'artifacts/qg2g-tcp-replay-root-validation.json'
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
assert not OUT.exists()
proof = load('artifacts/qg2g-tcp-replay-integration.json')
assert proof['state'] == 'INTEGRATED_FOR_ROOT_REGRESSION_NOT_ACCEPTED'
assert all(sha(R / path) == expected for path, expected in proof['source_sha256'].items())
for suffix in ['workspace','native','trace-boundaries','dns-boundaries','clippy','fmt','commandline']:
    assert not (R / 'artifacts/commands' / ('qg2g-tcp-replay-root-' + suffix + '.json')).exists()
spec = importlib.util.spec_from_file_location('npi_redact', R / 'tools/ai_pro_harness.py')
redaction = importlib.util.module_from_spec(spec)
spec.loader.exec_module(redaction)
state = {'started_at': datetime.datetime.now().astimezone().isoformat(), 'status': 'RUNNING',
         'source_sha256': proof['source_sha256'], 'steps': [], 'accepted': False,
         'independent_review_complete': True, 'independent_review': 'deleg_fa9790f8/tasks-0-1'}
def save():
    temporary = OUT.with_suffix('.json.tmp')
    temporary.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    temporary.replace(OUT)
save()
# 새로운 runtime/native 시험은 없다. 기존23 native를 승인된 pub-only delta와 조합 회귀한다.
review = load('artifacts/qg2g-tcp-replay-final-independent-review.json')
assert review['findings'] == [] and len(review['transcripts']) == 2 and review['safe_to_execute_default_tests']
assert load('artifacts/qg2g-tcp-replay-explicit-approval.json')['authorization_granted']
run = load('artifacts/qg2g-tcp-replay-parent-execution.json')
assert run['new_replay_tests_passed'] == 6 and run['workspace_counts']['passed'] == 433
assert all(sha(R / path) == value for path, value in run['source_sha256'].items())
frozen = load('artifacts/qg2g-tcp-replay-actor-prepared.json')['immutable_source_sha256']
assert all(sha(R / path) == value for path, value in frozen.items())
engine = 'crates/npi-probes/src/engine.rs'
original_engine = R / '.harness/baselines/qg2g-tcp-replay-root/engine.rs'
assert (R / engine).read_bytes().replace(b'pub fn apply_tcp_result(', b'fn apply_tcp_result(', 1) == original_engine.read_bytes()
previous = load('artifacts/qg2f-app-entry-root-validation.json')
expected_native = next(step['passed'] for step in previous['steps'] if step['name'].endswith('-native'))
assert expected_native == 23
assert not re.search(r'#\[\s*ignore', (R / 'crates/network-core/tests/tcp_product_projection_replay.rs').read_text(encoding='utf-8'))
state['native_scope'] = {'previous_root_native': expected_native, 'new_native_tests': 0,
                         'expected_native': expected_native, 'approved_visibility_only_delta': True}
save()
env = os.environ.copy()
env['CARGO_TARGET_DIR'] = str(R / '.harness/targets/qg2g-tcp-replay-root-shared')
helper = R / '.harness/targets/qg2c-resolver-isolated-pure/debug/quick-resolver-qa.exe'
assert helper.is_file()
assert sha(helper) == 'f9d32baf6861fb2a8442a5c2b759b0d2ac68520ae13343e575fc2b8781d4a959'
env['NPI_TEST_HELPER_EXE'] = str(helper.resolve())
scratch = pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/scratch/npi-tcp-replay-root')
scratch.mkdir(parents=True, exist_ok=True)
env.update(TMP=str(scratch), TEMP=str(scratch), TMPDIR=str(scratch))
gates = [
    ('workspace', R, ['cargo', 'test', '--offline', '--locked', '--workspace', '--all-targets']),
    ('native', R, ['cargo', 'test', '--offline', '--locked', '--workspace', '--all-targets', '--', '--ignored', '--test-threads=1']),
    ('trace-boundaries', R / '.harness/qa/quick-trace-boundaries', ['cargo', 'test', '--offline', '--all-targets']),
    ('dns-boundaries', R / '.harness/qa/quick-dns-boundaries', ['cargo', 'test', '--offline', '--all-targets']),
    ('clippy', R, ['cargo', 'clippy', '--offline', '--locked', '--workspace', '--all-targets', '--', '-D', 'warnings']),
    ('fmt', R, ['cargo', 'fmt', '--all', '--check']),
    ('commandline', R, [sys.executable, 'tools/verify_quick_app_entry_owned_native.py', '--root', '--cli-only', '--tcp-replay']),
]
try:
    for suffix, cwd, argv in gates:
        name = 'qg2g-tcp-replay-root-' + suffix
        state['current_step'] = name
        save()
        print('STEP ' + name, flush=True)
        started = datetime.datetime.now().astimezone().isoformat()
        begin = time.monotonic()
        if suffix == 'native':
            product = R / '.harness/targets/qg2g-tcp-replay-root-shared/debug/NetworkQuickCheck.exe'
            native_bins = list((product.parent / 'deps').glob('resolver_dispatch-*.exe'))
            assert product.is_file() and len(native_bins) == 1
            state['product_binary_before_native_sha256'] = {str(path): sha(path) for path in [product, native_bins[0]]}
            save()
        p = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        partial = False
        try:
            stdout, stderr = p.communicate(timeout=240)
        except subprocess.TimeoutExpired:
            partial = True
            subprocess.run(['taskkill.exe', '/PID', str(p.pid), '/T', '/F'], capture_output=True, timeout=20)
            stdout, stderr = p.communicate(timeout=20)
        log = redaction.clean(stdout.decode('utf-8', 'replace') + '\n' + stderr.decode('utf-8', 'replace'))
        stem = R / 'artifacts/commands' / name
        stem.with_suffix('.log').write_text(log, encoding='utf-8')
        metadata = {'command': argv, 'cwd': str(cwd), 'started_at': started, 'exit_code': p.returncode, 'partial': partial,
                    'elapsed_seconds': round(time.monotonic() - begin, 3), 'log': str(stem.with_suffix('.log'))}
        stem.with_suffix('.json').write_text(json.dumps(metadata, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        rows = re.findall(r'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', log)
        entry = {'name': name, 'exit_code': p.returncode, 'partial': partial}
        if rows:
            entry.update({key: sum(int(row[i]) for row in rows) for i, key in enumerate(['passed', 'failed', 'ignored'])})
        state['steps'].append(entry)
        save()
        print(json.dumps(entry, ensure_ascii=False), flush=True)
        assert p.returncode == 0 and not partial, name
        if suffix == 'workspace':
            assert entry['passed'] == 433 and entry['ignored'] == 23
        if suffix == 'native':
            assert all(sha(pathlib.Path(path)) == value for path, value in state['product_binary_before_native_sha256'].items())
        if suffix == 'commandline':
            cli = load('artifacts/qg2g-tcp-replay-root-commandline.json')
            assert cli['status'] == 'ROOT_COMMANDLINE_PASS_NOT_ACCEPTED'
            assert cli['commandline_case_count'] == 38 and cli['supervisor_self_test_count'] == 6
            assert cli['native_harness'] is None
            state['commandline_cases_passed'] = 38
            state['supervisor_self_tests_passed'] = 6
        if 'test' in argv:
            assert rows and entry['passed'] > 0 and entry['failed'] == 0, '시험0/실패는 성공 아님'
            if suffix == 'native':
                assert entry['passed'] == expected_native and entry['ignored'] == 0, '승인한 native 범위/수 일치 필요'
    assert all(sha(R / path) == expected for path, expected in state['source_sha256'].items())
    protected = load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
    assert all(sha(R / path) == expected for path, expected in protected.items() if path != engine)
    assert sha(original_engine) == protected[engine]
    assert (R / engine).read_bytes().replace(b'pub fn apply_tcp_result(', b'fn apply_tcp_result(', 1) == original_engine.read_bytes()
    state['inspector_protected_unchanged'] = len(protected) - 1
    state['approved_visibility_change_files'] = 1
    state['function_body_unchanged'] = True
    state['status'] = 'ROOT_EXECUTION_PASS_ACCEPTANCE_RECORD_PENDING'
except Exception as error:
    state['status'] = 'BLOCKED_PRESERVED_FOR_REVIEW'
    state['error'] = str(error)
finally:
    state['finished_at'] = datetime.datetime.now().astimezone().isoformat()
    save()
print(json.dumps(state, ensure_ascii=False), flush=True)
sys.exit(0 if state['status'] == 'ROOT_EXECUTION_PASS_ACCEPTANCE_RECORD_PENDING' else 1)
