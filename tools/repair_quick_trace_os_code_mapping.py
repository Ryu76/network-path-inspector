"""Trace 종료코드와 OS 오류코드 혼동을 별도 보정하고 실제 회귀를 실행한다."""
import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import time

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qgtrace'
OUT = R / 'artifacts/qg2c-trace-os-code-repair.json'
PATHS = ['crates/network-core/src/traceroute.rs', 'crates/network-core/tests/traceroute.rs']
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
spec = importlib.util.spec_from_file_location('npi_redact', R / 'tools/ai_pro_harness.py')
redaction = importlib.util.module_from_spec(spec)
spec.loader.exec_module(redaction)
state = {'started_at': datetime.datetime.now().astimezone().isoformat(), 'status': 'RUNNING',
         'accepted': False, 'independent_review_required': True, 'steps': []}


def save():
    temporary = OUT.with_suffix('.json.tmp')
    temporary.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    temporary.replace(OUT)


def git(*args):
    p = subprocess.run(['git', '-C', str(W), *args], capture_output=True, text=True,
                       encoding='utf-8', errors='replace', timeout=40)
    assert p.returncode == 0, p.stderr
    return p.stdout.rstrip('\r\n')


assert not OUT.exists()
proof = load('artifacts/qg2c-trace-acceptance.json')
assert all(sha(R / relative) == expected for relative, expected in proof['source_sha256'].items())
assert all(sha(W / relative) == proof['source_sha256'][relative] for relative in PATHS)
witness = load('artifacts/commands/qg2c-trace-exit-os-code-before-fix.json')
assert witness['exit_code'] == 101 and not witness['partial']
assert all(line[3:] in PATHS for line in git('status', '--porcelain').splitlines())
for suffix in ['workspace', 'native', 'boundaries', 'clippy', 'fmt']:
    assert not (R / 'artifacts/commands' / ('qg2c-trace-os-code-' + suffix + '.json')).exists()
state['before_sha256'] = {path: sha(R / path) for path in PATHS}
state['finding'] = {'id': 'TRACE-EXIT-AS-OS-ERROR', 'severity': 'P2',
                    'evidence': '1pass/2fail: qg2c-trace-exit-os-code-before-fix',
                    'issue': '프로세스 exit_code를 OS/Winsock 오류코드로 잘못 투영. 원시 종료코드는 raw DTO에 남기고 미관측 OS 오류는 null이어야 함'}
save()
if git('status', '--porcelain'):
    git('add', *PATHS)
    git('-c', 'core.autocrlf=false', 'commit', '-m', 'feat: preserve accepted standalone Trace before OS-code projection repair')
state['preserved_commit'] = git('rev-parse', 'HEAD')
source = W / PATHS[0]
text = source.read_text(encoding='utf-8')
old = '        os_error_code: measurement.exit_code,'
assert text.count(old) == 1
text = text.replace(old, '        // 프로세스 종료코드는 OS 오류코드가 아니다. exit_code 원문은 raw_measurement에 보존한다.\n        // 현재 DTO에 독립적으로 관측된 OS 오류코드 필드가 없으므로 미확인 null을 사용한다.\n        os_error_code: None,')
source.write_text(text, encoding='utf-8', newline='\n')
tests = W / PATHS[1]
text = tests.read_text(encoding='utf-8')
old = '    assert_eq!(result.os_error_code, Some(0));'
assert text.count(old) == 1
text = text.replace(old, '    assert_eq!(result.os_error_code, None);\n    assert_eq!(result.details["raw_measurement"]["exit_code"], 0);')
tests.write_text(text, encoding='utf-8', newline='\n')
for path in PATHS:
    shutil.copyfile(W / path, R / path)
state['source_sha256'] = {path: sha(R / path) for path in PATHS}
state['source_change'] = '부모 production 1필드+설명주석 및 잘못된 테스트 기대값을 계약대로 교정. raw exit_code 보존 assertion 추가. DTO/스키마/성공판정/엔진 변경 없음'
state['current_step'] = 'ROOT_REGRESSION_RUNNING'
save()
progress = load('artifacts/quick-check-progress.json')
progress['recorded_at'] = datetime.datetime.now().astimezone().isoformat()
progress['qg2_trace'].update(status='OS_CODE_PROJECTION_REOPENED_FOR_REGRESSION', accepted=False,
                            finding=state['finding'], latest_repair='artifacts/qg2c-trace-os-code-repair.json')
(R / 'artifacts/quick-check-progress.json').write_text(json.dumps(progress, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
env = os.environ.copy()
env['CARGO_TARGET_DIR'] = str(R / '.harness/targets/qg2c-trace-os-code-shared')
helper = R / '.harness/targets/qg2c-resolver-isolated-pure/debug/quick-resolver-qa.exe'
assert helper.is_file()
env['NPI_TEST_HELPER_EXE'] = str(helper)
scratch = pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/scratch/npi-trace-os-code')
scratch.mkdir(parents=True, exist_ok=True)
env.update(TMP=str(scratch), TEMP=str(scratch), TMPDIR=str(scratch))
gates = [
    ('workspace', R, ['cargo', 'test', '--offline', '--locked', '--workspace', '--all-targets']),
    ('native', R, ['cargo', 'test', '--offline', '--locked', '--workspace', '--all-targets', '--', '--ignored']),
    ('boundaries', R / '.harness/qa/quick-trace-boundaries', ['cargo', 'test', '--offline', '--locked', '--all-targets']),
    ('clippy', R, ['cargo', 'clippy', '--offline', '--locked', '--workspace', '--all-targets', '--', '-D', 'warnings']),
    ('fmt', R, ['cargo', 'fmt', '--all', '--check']),
]
try:
    for suffix, cwd, argv in gates:
        name = 'qg2c-trace-os-code-' + suffix
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
    state['status'] = 'EXECUTION_PASS_INDEPENDENT_REVIEW_PENDING'
except Exception as error:
    state['status'] = 'BLOCKED_PRESERVED_FOR_REVIEW'
    state['error'] = str(error)
finally:
    state['finished_at'] = datetime.datetime.now().astimezone().isoformat()
    save()
print(json.dumps(state, ensure_ascii=False), flush=True)
sys.exit(0 if state['status'] == 'EXECUTION_PASS_INDEPENDENT_REVIEW_PENDING' else 1)
