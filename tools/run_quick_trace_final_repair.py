"""Flash 보정 종료 뒤 감사와 실제 시험까지 이어지는 유한 감독 파이프라인."""
import datetime
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qgtrace'
STAGE = 'qg2tracefinalfix'
ATTEMPT = sys.argv[1] if len(sys.argv) > 1 else ''
assert re.fullmatch(r'[a-z0-9-]*', ATTEMPT), '유효한 증거 재시도 이름 필요'
SUFFIX = '-' + ATTEMPT if ATTEMPT else ''
ARTIFACT = R / ('artifacts/qg2c-trace-final-repair-pipeline' + SUFFIX + '.json')
PATHS = ['crates/network-core/src/traceroute.rs', 'crates/network-core/tests/traceroute.rs']
STATE = {'started_at': datetime.datetime.now().astimezone().isoformat(),
         'status': 'RUNNING', 'stage': STAGE, 'steps': [], 'accepted': False,
         'root_integrated': False, 'independent_final_review_required': True}


def save():
    temporary = ARTIFACT.with_suffix('.json.tmp')
    temporary.write_text(json.dumps(STATE, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    temporary.replace(ARTIFACT)


def step(name, argv, cwd=R, timeout=1100):
    STATE['current_step'] = name
    save()
    print('STEP ' + name, flush=True)
    result = subprocess.run(argv, cwd=cwd, timeout=timeout)
    STATE['steps'].append({'name': name, 'exit_code': result.returncode,
                           'finished_at': datetime.datetime.now().astimezone().isoformat()})
    save()
    if result.returncode:
        raise RuntimeError(f'{name}: exit {result.returncode}')


def evidence(name, cwd, argv, timeout=240):
    step(name, [sys.executable, str(R / 'tools/run_command_evidence.py'), '--cwd', str(cwd),
                '--name', name, '--timeout', str(timeout), '--', *argv], timeout=timeout + 40)
    data = json.loads((R / 'artifacts/commands' / (name + '.json')).read_text(encoding='utf-8'))
    assert data['exit_code'] == 0 and not data['partial'], name
    text = (R / 'artifacts/commands' / (name + '.log')).read_text(encoding='utf-8')
    rows = re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
    if 'test' in argv:
        assert rows and sum(int(row[0]) for row in rows) > 0, '시험 0개를 성공으로 취급하지 않음'
        STATE.setdefault('test_counts', {})[name] = {
            key: sum(int(row[i]) for row in rows)
            for i, key in enumerate(['passed', 'failed', 'ignored'])}
        save()


assert not ARTIFACT.exists(), '기존 파이프라인 증거를 덮어쓰지 않음'
os.environ['NPI_AI_PRO_MODEL'] = 'gemini-3.8-flash-high'
save()
try:
    step('prepare', [sys.executable, 'tools/prepare_quick_trace_final_repair.py'])
    step('flash-file-only', [sys.executable, '-u', 'tools/ai_pro_harness.py', STAGE, 'qgtrace'])
    step('actor-policy-audit', [sys.executable, 'tools/audit_ai_pro_runs.py', STAGE])
    folder = R / '.harness/runs' / (STAGE + '-qgtrace')
    after = json.loads((folder / 'after.json').read_text(encoding='utf-8'))
    for relative in PATHS:
        assert hashlib.sha256((W / relative).read_bytes()).hexdigest() == after[relative], relative
    # 공용 감사의 reference 예외도 허용하지 않고 실제 도구의 모든 파일 경계를 검사한다.
    for line in (folder / 'stdout.jsonl').read_text(encoding='utf-8').splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        update = record.get('step_update', {})
        if update.get('step_type') != 'tool' or update.get('state') != 'ACTIVE':
            continue
        for key, value in update.get('tool_info', {}).get('parameters', {}).items():
            if key.lower() not in ('path', 'absolutepath', 'targetfile', 'file_path', 'directorypath', 'searchdirectory') or not isinstance(value, str):
                continue
            path = pathlib.Path(value)
            assert path.is_absolute(), 'actor의 상대 파일 경로 금지'
            path.resolve().relative_to(W.resolve())
    STATE['actor_after_sha256'] = {p: after[p] for p in PATHS}
    step('parent-rustfmt-only', ['rustfmt', '--edition', '2024', *PATHS], cwd=W, timeout=40)
    STATE['canonical_source_sha256'] = {p: hashlib.sha256((W / p).read_bytes()).hexdigest() for p in PATHS}
    save()
    evidence('qg2c-trace-final-all-targets', W, ['cargo', 'test', '--offline', '-p', 'network-core', '--all-targets'])
    evidence('qg2c-trace-final-boundaries', R / '.harness/qa/quick-trace-boundaries', ['cargo', 'test', '--offline', '--all-targets'])
    evidence('qg2c-trace-final-native', W, ['cargo', 'test', '--offline', '-p', 'network-core', '--test', 'traceroute', '--', '--ignored'], 180)
    evidence('qg2c-trace-final-clippy', W, ['cargo', 'clippy', '--offline', '-p', 'network-core', '--all-targets', '--', '-D', 'warnings'])
    evidence('qg2c-trace-final-whitespace', W, ['git', 'diff', '--check'])
    STATE['status'] = 'EXECUTION_PASS_INDEPENDENT_REVIEW_PENDING'
except Exception as error:
    STATE['status'] = 'BLOCKED_PRESERVED_FOR_REVIEW'
    STATE['error'] = str(error)
finally:
    STATE['finished_at'] = datetime.datetime.now().astimezone().isoformat()
    save()
print(json.dumps(STATE, ensure_ascii=False), flush=True)
sys.exit(0 if STATE['status'] == 'EXECUTION_PASS_INDEPENDENT_REVIEW_PENDING' else 1)
