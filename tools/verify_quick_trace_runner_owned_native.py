"""검토된 runner 5개 ignored 시험만 정확한 소유 helper와 루프백에서 명시 실행한다."""
import datetime
import hashlib
import json
import os
import pathlib
import platform
import re
import subprocess
import sys

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qg2runner'
OUT = R / 'artifacts/qg2e-trace-runner-final-guard-execution.json'
PATHS = ['crates/network-core/src/runner.rs', 'crates/network-core/tests/runner.rs']
EXPECTED = {
    PATHS[0]: '68e1b3b0c07cb9e990822fd23f7ca8a7c61dc0b126d30af4a21ccfaf7f25b1da',
    PATHS[1]: '186f345e3f8863d58b0db01f5cc5cee81b23532289a3ed040b7d27cd71121739',
}
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
assert not OUT.exists()
state = {'started_at': datetime.datetime.now().astimezone().isoformat(), 'status': 'RUNNING',
         'source_sha256': EXPECTED, 'root_integrated': False, 'accepted': False,
         'independent_review': 'deleg_45855748', 'steps': [], 'test_counts': {}}

def save():
    temp = OUT.with_suffix('.json.tmp')
    temp.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    temp.replace(OUT)

def evidence(name, command, timeout=180):
    p = subprocess.run([sys.executable, 'tools/run_command_evidence.py', '--cwd', str(W),
                        '--name', name, '--timeout', str(timeout), '--', *command], cwd=R, timeout=timeout+30)
    meta = load('artifacts/commands/' + name + '.json')
    state['steps'].append(meta)
    save()
    assert p.returncode == 0 and meta['exit_code'] == 0 and not meta['partial']
    text = pathlib.Path(meta['log']).read_text(encoding='utf-8')
    if 'test' in command:
        rows = re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
        assert rows
        state['test_counts'][name] = {key: sum(int(row[i]) for row in rows)
                                     for i, key in enumerate(['passed', 'failed', 'ignored'])}
    save()

save()
try:
    assert platform.system() == 'Windows'
    state['platform'] = platform.platform()
    assert all(sha(W / path) == value for path, value in EXPECTED.items())
    frozen = load('artifacts/qg2e-trace-runner-prepared.json')['dependency_source_sha256']
    assert all(sha(W / path) == value for path, value in frozen.items() if path not in PATHS)
    source = (W / PATHS[1]).read_text(encoding='utf-8')
    ignored = re.findall(r'#\[ignore[^\n]*\]\s*async fn (\w+)', source)
    allowed = [
        'test_16_live_loopback_ipv4_tcp_connect_and_ping',
        'test_17_live_loopback_ipv6_tcp_connect_and_ping',
        'test_18_live_native_dns_and_domain_tcp_localhost',
        'test_19_live_loopback_ipv4_and_ipv6_native_trace',
        'test_20_live_native_dns_and_domain_trace_localhost',
    ]
    assert sorted(ignored) == sorted(allowed) and len(ignored) == len(allowed)
    state['reviewed_native_tests'] = allowed
    state['native_safety_basis'] = 'deleg_cfe9fa59 task1 현재5시험 조건부 목적지안전 판정+부모검토. 이후변경은testguard ctxport/실제DNSDTO검사 강화와pure회귀뿐이며 대상/위임native경로는확대없음'
    state['parent_approved_scope'] = '소유127.0.0.1/::1·test18/20동일port양쪽listener생존·고정5시험만 단일스레드 명시실행'
    helper = R / '.harness/targets/qg2c-resolver-isolated-pure/debug/quick-resolver-qa.exe'
    assert helper.is_file()
    assert sha(helper) == 'f9d32baf6861fb2a8442a5c2b759b0d2ac68520ae13343e575fc2b8781d4a959'
    os.environ['NPI_TEST_HELPER_EXE'] = str(helper.resolve())
    state['owned_helper'] = str(helper.resolve())
    state['owned_helper_sha256'] = sha(helper)
    core = load('artifacts/commands/qg2e-trace-runner-final-guard-all-targets.json')
    clippy = load('artifacts/commands/qg2e-trace-runner-final-guard-clippy.json')
    assert all(data['exit_code'] == 0 and not data['partial'] for data in [core, clippy])
    rows = re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', pathlib.Path(core['log']).read_text(encoding='utf-8'))
    assert len(rows) == 7
    state['core_counts'] = {key: sum(int(row[i]) for row in rows)
                            for i, key in enumerate(['passed', 'failed', 'ignored'])}
    state['core_evidence'] = core
    state['clippy_evidence'] = clippy
    evidence('qg2e-trace-runner-final-guard-fmt', ['cargo', 'fmt', '--all', '--', '--check'], 60)
    evidence('qg2e-trace-runner-final-guard-native', ['cargo', 'test', '--offline', '--locked', '-p', 'network-core', '--test', 'runner', '--', '--ignored', '--test-threads=1'], 180)
    assert state['test_counts']['qg2e-trace-runner-final-guard-native'] == {'passed': 5, 'failed': 0, 'ignored': 0}
    evidence('qg2e-trace-runner-final-guard-whitespace', ['git', 'diff', '--check'], 30)
    assert all(sha(W / path) == value for path, value in EXPECTED.items())
    protected = load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
    assert all(sha(R / path) == value for path, value in protected.items())
    state['protected_inspector_unchanged'] = len(protected)
    state['status'] = 'PURE_AND_OWNED_NATIVE_PASS_FINAL_REVIEW_PENDING'
except Exception as error:
    state['status'] = 'BLOCKED_PRESERVED_FOR_REVIEW'
    state['error'] = str(error)
finally:
    state['finished_at'] = datetime.datetime.now().astimezone().isoformat()
    save()
print(json.dumps(state, ensure_ascii=False), flush=True)
sys.exit(0 if state['status'] == 'PURE_AND_OWNED_NATIVE_PASS_FINAL_REVIEW_PENDING' else 1)
