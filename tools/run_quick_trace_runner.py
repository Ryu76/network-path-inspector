"""Trace 연결 writer 종료 뒤 감사·SHA 고정 후 실제 실행 전 소스 검토로 넘긴다."""
import datetime
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qg2runner'
STAGE = 'qg2tracewire'
OUT = R / 'artifacts/qg2e-trace-runner-pipeline.json'
PATHS = ['crates/network-core/src/runner.rs', 'crates/network-core/tests/runner.rs']
state = {'started_at': datetime.datetime.now().astimezone().isoformat(), 'status': 'RUNNING',
         'stage': STAGE, 'steps': [], 'root_integrated': False, 'accepted': False,
         'independent_review_required': True}


def save():
    temp = OUT.with_suffix('.json.tmp')
    temp.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    temp.replace(OUT)


def call(name, command, cwd=R, timeout=1100):
    state['current_step'] = name
    save()
    print('STEP ' + name, flush=True)
    process = subprocess.run(command, cwd=cwd, timeout=timeout)
    state['steps'].append({'name': name, 'exit_code': process.returncode})
    save()
    assert process.returncode == 0, f'{name}: exit {process.returncode}'


assert not OUT.exists(), '이전 증거 덮어쓰기 금지'
os.environ['NPI_AI_PRO_MODEL'] = 'gemini-3.8-flash-high'
save()
try:
    helper = R / '.harness/targets/qg2c-resolver-isolated-pure/debug/quick-resolver-qa.exe'
    assert helper.is_file(), '정확 소유 helper 없으면 native 시험을 성공으로 처리하지 않음'
    os.environ['NPI_TEST_HELPER_EXE'] = str(helper.resolve())
    state['owned_helper'] = str(helper)
    state['owned_helper_sha256'] = hashlib.sha256(helper.read_bytes()).hexdigest()
    call('prepare', [sys.executable, 'tools/prepare_quick_trace_runner.py'])
    call('flash-file-only', [sys.executable, '-u', 'tools/ai_pro_harness.py', STAGE, 'qg2runner'])
    call('actor-policy-audit', [sys.executable, 'tools/audit_ai_pro_runs.py', STAGE])
    folder = R / '.harness/runs' / (STAGE + '-qg2runner')
    after = json.loads((folder / 'after.json').read_text(encoding='utf-8'))
    assert all(hashlib.sha256((W / path).read_bytes()).hexdigest() == after[path] for path in PATHS)
    for line in (folder / 'stdout.jsonl').read_text(encoding='utf-8').splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        step = event.get('step_update', {})
        if step.get('step_type') != 'tool' or step.get('state') != 'ACTIVE':
            continue
        for key, value in step.get('tool_info', {}).get('parameters', {}).items():
            if key.lower() in ('path', 'absolutepath', 'targetfile', 'file_path', 'directorypath', 'searchdirectory') and isinstance(value, str):
                path = pathlib.Path(value)
                assert path.is_absolute()
                path.resolve().relative_to(W.resolve())
    state['actor_source_sha256'] = {path: after[path] for path in PATHS}
    state['source_sha256'] = state['actor_source_sha256']
    state['formatting_and_execution_deferred'] = True
    state['status'] = 'AUDITED_SOURCE_READY_FOR_PARENT_REVIEW'
except Exception as error:
    state['status'] = 'BLOCKED_PRESERVED_FOR_REVIEW'
    state['error'] = str(error)
finally:
    state['finished_at'] = datetime.datetime.now().astimezone().isoformat()
    save()
print(json.dumps(state, ensure_ascii=False), flush=True)
sys.exit(0 if state['status'] == 'AUDITED_SOURCE_READY_FOR_PARENT_REVIEW' else 1)
