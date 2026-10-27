"""Win32 입력·계획 GUI FILE 작성과 엄격 감사까지만 수행하는 소유 감독기."""
import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import sys

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qgguiinputs'
STAGE, ROLE = 'qg3inputs', 'qgguiinputs'
OUT = R / 'artifacts/qg3b-gui-inputs-pipeline.json'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
load = lambda p: json.loads((R / p).read_text(encoding='utf-8'))
p = load('artifacts/qg3b-gui-inputs-actor-prepared.json')
assert not OUT.exists() and not (R / '.harness/runs' / (STAGE + '-' + ROLE)).exists()
assert all(sha(R / path) == h for path, h in p['root_before_sha256'].items())
assert all(sha(W / path) == h for path, h in p['immutable_source_sha256'].items())
assert all(sha(W / path) == h for path, h in p['reference_sha256'].items())
assert sha(W / 'apps/network-quick-check/src/lib.rs') == p['root_before_sha256']['apps/network-quick-check/src/lib.rs']
state = {'started_at': datetime.datetime.now().astimezone().isoformat(),
    'stage': STAGE, 'role': ROLE, 'status': 'RUNNING', 'steps': [], 'root_integrated': False,
    'accepted': False, 'native_executed': False, 'gui_visible_tested': False,
    'network_diagnostics_connected': False, 'independent_review_required': True,
    'formatting_and_execution_deferred': True}


def save():
    temp = OUT.with_suffix('.json.tmp')
    temp.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    temp.replace(OUT)


def call(name, argv):
    state['current_step'] = name
    save()
    result = subprocess.run(argv, cwd=R, timeout=1100)
    state['steps'].append({'name': name, 'exit_code': result.returncode})
    save()
    assert result.returncode == 0, name


os.environ['NPI_AI_PRO_MODEL'] = 'gemini-3.8-flash-high'
save()
try:
    call('flash-file-only', [sys.executable, '-u', 'tools/ai_pro_harness.py', STAGE, ROLE])
    call('actor-policy-audit', [sys.executable, 'tools/audit_ai_pro_runs.py', STAGE])
    folder = R / '.harness/runs' / (STAGE + '-' + ROLE)
    result = json.loads((folder / 'result.json').read_text(encoding='utf-8'))
    after = json.loads((folder / 'after.json').read_text(encoding='utf-8'))
    audit = load('artifacts/' + STAGE + '-actor-policy-audit.json')
    assert result['changed_paths'] == sorted(p['actor_writes'])
    assert result['exit_code'] == 0 and not result['partial'] and audit['all_actor_policy_checks_passed']
    assert result['model'] == p['model'] == 'gemini-3.8-flash-high'
    assert all(sha(W / path) == after[path] for path in p['actor_writes'])
    assert all(sha(W / path) == h for path, h in p['immutable_source_sha256'].items())
    assert all(sha(R / path) == h for path, h in p['root_before_sha256'].items())
    assert all(sha(W / path) == h for path, h in p['reference_sha256'].items())
    assert (W / 'apps/network-quick-check/src/lib.rs').read_bytes() == (W / '.harness/inputs/qg3b-win32/expected-lib.rs').read_bytes()
    checked = 0
    for line in (folder / 'stdout.jsonl').read_text(encoding='utf-8').splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        step = record.get('step_update', {})
        if step.get('step_type') != 'tool' or step.get('state') != 'ACTIVE':
            continue
        for key, value in step.get('tool_info', {}).get('parameters', {}).items():
            if key.lower() not in {'path', 'absolutepath', 'targetfile', 'file_path', 'directorypath', 'searchdirectory'} or not isinstance(value, str):
                continue
            path = pathlib.Path(value)
            assert path.is_absolute() and path.resolve().is_relative_to(W.resolve()), 'strict W-only actor file path required'
            checked += 1
    assert checked > 0
    state.update(status='AUDITED_SOURCE_READY_FOR_PARENT_REVIEW',
        source_sha256={path: sha(W / path) for path in p['actor_writes']},
        parent_metadata_changes=p['parent_metadata_changes'],
        immutable_source_files=len(p['immutable_source_sha256']),
        reference_files_unchanged=len(p['reference_sha256']), strict_in_worktree_path_checks=checked,
        exact_parent_lib_template_verified=True)
except Exception as error:
    state.update(status='BLOCKED_PRESERVED_FOR_REVIEW', error=str(error))
finally:
    state['finished_at'] = datetime.datetime.now().astimezone().isoformat()
    save()
print(json.dumps(state, ensure_ascii=False), flush=True)
sys.exit(0 if state['status'] == 'AUDITED_SOURCE_READY_FOR_PARENT_REVIEW' else 1)
