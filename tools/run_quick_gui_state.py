"""GUI 순수모델 작성과 엄격 파일/도구 감사를 감독한다. 실행·통합은 하지 않는다."""
import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import sys

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qgguistate'
STAGE = 'qg3state'
ROLE = 'qgguistate'
OUT = R / 'artifacts/qg3a-gui-state-pipeline.json'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
state = {'started_at': datetime.datetime.now().astimezone().isoformat(), 'stage': STAGE,
         'role': ROLE, 'status': 'RUNNING', 'steps': [], 'root_integrated': False,
         'accepted': False, 'native_executed': False, 'independent_review_required': True}


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


assert not OUT.exists() and not (R / '.harness/runs' / (STAGE + '-' + ROLE)).exists()
os.environ['NPI_AI_PRO_MODEL'] = 'gemini-3.8-flash-high'
p = json.loads((R / 'artifacts/qg3a-gui-state-prepared.json').read_text(encoding='utf-8'))
assert all(sha(R / path) == h for path, h in p['root_before_sha256'].items())
assert all(sha(W / path) == h for path, h in p['root_before_sha256'].items())
assert sha(pathlib.Path(p['reference_path'])) == p['contract_sha256']
save()
try:
    call('flash-file-only', [sys.executable, '-u', 'tools/ai_pro_harness.py', STAGE, ROLE])
    call('actor-policy-audit', [sys.executable, 'tools/audit_ai_pro_runs.py', STAGE])
    folder = R / '.harness/runs' / (STAGE + '-' + ROLE)
    result = json.loads((folder / 'result.json').read_text(encoding='utf-8'))
    after = json.loads((folder / 'after.json').read_text(encoding='utf-8'))
    audit = json.loads((R / 'artifacts' / (STAGE + '-actor-policy-audit.json')).read_text(encoding='utf-8'))
    assert result['changed_paths'] == sorted(p['actor_writes'])
    assert result['model'] == p['model'] == 'gemini-3.8-flash-high'
    assert result['exit_code'] == 0 and not result['partial'] and audit['all_actor_policy_checks_passed']
    assert all(sha(W / path) == after[path] for path in p['actor_writes'])
    assert all(sha(W / path) == h for path, h in p['immutable_source_sha256'].items())
    assert all(sha(R / path) == h for path, h in p['root_before_sha256'].items())
    assert sha(pathlib.Path(p['reference_path'])) == p['contract_sha256']
    original = (R / 'apps/network-quick-check/src/lib.rs').read_bytes()
    changed = (W / 'apps/network-quick-check/src/lib.rs').read_bytes()
    added = b'pub mod gui_state;\n'
    assert changed.count(added) == 1 and changed.replace(added, b'', 1) == original, 'lib must differ by exactly one module line'
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
            assert path.is_absolute() and path.resolve().is_relative_to(W.resolve()), 'strict in-worktree file scope'
            checked += 1
    assert checked > 0
    state.update(status='AUDITED_SOURCE_READY_FOR_PARENT_REVIEW',
                 source_sha256={path: sha(W / path) for path in p['actor_writes']},
                 immutable_source_files=len(p['immutable_source_sha256']),
                 strict_in_worktree_path_checks=checked, lib_one_line_delta_verified=True)
except Exception as error:
    state.update(status='BLOCKED_PRESERVED_FOR_REVIEW', error=str(error))
finally:
    state['finished_at'] = datetime.datetime.now().astimezone().isoformat()
    save()
print(json.dumps(state, ensure_ascii=False), flush=True)
sys.exit(0 if state['status'] == 'AUDITED_SOURCE_READY_FOR_PARENT_REVIEW' else 1)
