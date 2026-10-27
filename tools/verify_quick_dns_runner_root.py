"""선택 통합된 DNS 실행기를 Inspector/Trace와 조합해 실제 root 게이트를 검증한다."""
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
OUT = R / 'artifacts/qg2d-dns-runner-root-validation.json'
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
assert not OUT.exists()
proof = load('artifacts/qg2d-dns-runner-integration.json')
assert proof['state'] == 'INTEGRATED_FOR_ROOT_REGRESSION_NOT_ACCEPTED'
assert all(sha(R / path) == expected for path, expected in proof['source_sha256'].items())
for suffix in ['workspace','native','trace-boundaries','dns-boundaries','clippy','fmt']:
    assert not (R / 'artifacts/commands' / ('qg2d-dns-runner-root-' + suffix + '.json')).exists()
spec = importlib.util.spec_from_file_location('npi_redact', R / 'tools/ai_pro_harness.py')
redaction = importlib.util.module_from_spec(spec)
spec.loader.exec_module(redaction)
state = {'started_at': datetime.datetime.now().astimezone().isoformat(), 'status': 'RUNNING',
         'source_sha256': proof['source_sha256'], 'steps': [], 'accepted': False,
         'independent_review_complete': True, 'independent_review': 'deleg_40886ced/tasks-0-1'}
def save():
    temporary = OUT.with_suffix('.json.tmp')
    temporary.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    temporary.replace(OUT)
save()
env = os.environ.copy()
env['CARGO_TARGET_DIR'] = str(R / '.harness/targets/qg2d-dns-runner-root-shared')
helper = R / '.harness/targets/qg2c-resolver-isolated-pure/debug/quick-resolver-qa.exe'
assert helper.is_file()
env['NPI_TEST_HELPER_EXE'] = str(helper)
scratch = pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/scratch/npi-dns-runner-root')
scratch.mkdir(parents=True, exist_ok=True)
env.update(TMP=str(scratch), TEMP=str(scratch), TMPDIR=str(scratch))
gates = [
    ('workspace', R, ['cargo', 'test', '--offline', '--locked', '--workspace', '--all-targets']),
    ('native', R, ['cargo', 'test', '--offline', '--locked', '--workspace', '--all-targets', '--', '--ignored']),
    ('trace-boundaries', R / '.harness/qa/quick-trace-boundaries', ['cargo', 'test', '--offline', '--all-targets']),
    ('dns-boundaries', R / '.harness/qa/quick-dns-boundaries', ['cargo', 'test', '--offline', '--all-targets']),
    ('clippy', R, ['cargo', 'clippy', '--offline', '--locked', '--workspace', '--all-targets', '--', '-D', 'warnings']),
    ('fmt', R, ['cargo', 'fmt', '--all', '--check']),
]
try:
    for suffix, cwd, argv in gates:
        name = 'qg2d-dns-runner-root-' + suffix
        state['current_step'] = name
        save()
        print('STEP ' + name, flush=True)
        started = datetime.datetime.now().astimezone().isoformat()
        begin = time.monotonic()
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
        if 'test' in argv:
            assert rows and entry['passed'] > 0 and entry['failed'] == 0, '시험0/실패는 성공 아님'
    assert all(sha(R / path) == expected for path, expected in state['source_sha256'].items())
    protected = load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
    assert all(sha(R / path) == expected for path, expected in protected.items())
    state['inspector_protected_unchanged'] = len(protected)
    state['status'] = 'ROOT_EXECUTION_PASS_ACCEPTANCE_RECORD_PENDING'
except Exception as error:
    state['status'] = 'BLOCKED_PRESERVED_FOR_REVIEW'
    state['error'] = str(error)
finally:
    state['finished_at'] = datetime.datetime.now().astimezone().isoformat()
    save()
print(json.dumps(state, ensure_ascii=False), flush=True)
sys.exit(0 if state['status'] == 'ROOT_EXECUTION_PASS_ACCEPTANCE_RECORD_PENDING' else 1)
