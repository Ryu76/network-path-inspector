"""제품 동일EXE worker 진입점 작성을 감독하고 실행전 소스검토 게이트에서 멈춘다."""
import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import sys

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qgquickapp'
STAGE = 'qg2appentry'
OUT = R / 'artifacts/qg2f-app-entry-pipeline.json'
PATHS = ['apps/network-quick-check/Cargo.toml', 'apps/network-quick-check/src/lib.rs', 'apps/network-quick-check/src/main.rs', 'apps/network-quick-check/tests/resolver_dispatch.rs']
state = {'started_at': datetime.datetime.now().astimezone().isoformat(), 'status': 'RUNNING',
         'stage': STAGE, 'steps': [], 'root_integrated': False, 'accepted': False,
         'independent_review_required': True, 'formatting_and_execution_deferred': True}

def save():
    temp = OUT.with_suffix('.json.tmp')
    temp.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    temp.replace(OUT)

def call(name, command, timeout=1100):
    state['current_step'] = name
    save()
    print('STEP ' + name, flush=True)
    process = subprocess.run(command, cwd=R, timeout=timeout)
    state['steps'].append({'name': name, 'exit_code': process.returncode})
    save()
    assert process.returncode == 0, f'{name}: exit {process.returncode}'

assert not OUT.exists(), '이전 증거 덮어쓰기 금지'
assert not (R / '.harness/runs' / (STAGE + '-qgquickapp')).exists()
assert not (R / '.harness/prompts' / (STAGE + '-qgquickapp.md')).exists()
os.environ['NPI_AI_PRO_MODEL'] = 'gemini-3.8-flash-high'
save()
try:
    call('prepare', [sys.executable, 'tools/prepare_quick_app_entry.py'])
    call('flash-file-only', [sys.executable, '-u', 'tools/ai_pro_harness.py', STAGE, 'qgquickapp'])
    call('actor-policy-audit', [sys.executable, 'tools/audit_ai_pro_runs.py', STAGE])
    folder = R / '.harness/runs' / (STAGE + '-qgquickapp')
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
    protected = json.loads((R / 'artifacts/qg0-inspector-baseline.json').read_text(encoding='utf-8'))['protected_inspector_sha256']
    assert all(hashlib.sha256((R / path).read_bytes()).hexdigest() == expected for path, expected in protected.items())
    state['protected_inspector_unchanged'] = len(protected)
    prepared = json.loads((R / 'artifacts/qg2f-app-entry-prepared.json').read_text(encoding='utf-8'))
    assert all(hashlib.sha256((W / path).read_bytes()).hexdigest() == value for path, value in prepared['source_sha256'].items())
    assert all((W / path).is_file() for path in PATHS)
    state['source_sha256'] = {path: after[path] for path in PATHS}
    state['parent_workspace_lock_update_deferred'] = True
    state['status'] = 'AUDITED_SOURCE_READY_FOR_PARENT_REVIEW'
except Exception as error:
    state['status'] = 'BLOCKED_PRESERVED_FOR_REVIEW'
    state['error'] = str(error)
finally:
    state['finished_at'] = datetime.datetime.now().astimezone().isoformat()
    save()
print(json.dumps(state, ensure_ascii=False), flush=True)
sys.exit(0 if state['status'] == 'AUDITED_SOURCE_READY_FOR_PARENT_REVIEW' else 1)
