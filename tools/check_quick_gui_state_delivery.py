"""GUI 상태모델 전달의 코드·기록·보호·실행·문서 경계를 최종 대조한다."""
import datetime
import hashlib
import json
import pathlib
import subprocess

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qgguistate'
load = lambda p: json.loads((R / p).read_text(encoding='utf-8'))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
p = load('artifacts/qg3a-gui-state-prepared.json')
a = load('artifacts/qg3a-gui-state-acceptance.json')
assert a['accepted'] and a['root_integrated'] and not a['full_qg2_accepted'] and not a['full_qg3_accepted']
assert not a['native_window_implemented'] and not a['runner_connected_to_gui'] and not a['native_executed_this_slice']
assert all(sha(R / path) == sha(W / path) == h for path, h in a['source_sha256'].items())
assert all(sha(R / path) == h for path, h in p['root_before_sha256'].items() if path != 'apps/network-quick-check/src/lib.rs')
assert all(sha(W / path) == h for path, h in p['immutable_source_sha256'].items())
assert sha(pathlib.Path(p['reference_path'])) == p['contract_sha256']
head = subprocess.check_output(['git', '-C', str(W), 'rev-parse', 'HEAD'], text=True).rstrip('\r\n')
assert head == a['preserved_source_commit']
status = subprocess.check_output(['git', '-C', str(W), 'status', '--porcelain'], text=True).rstrip('\r\n')
assert not status
paths = set(a['changed_source_paths'])
paths.update('tools/' + name for name in [
    'prepare_quick_gui_state.py', 'run_quick_gui_state.py', 'record_quick_gui_state_start.py',
    'record_quick_gui_state_audit.py', 'record_quick_gui_state_repair.py',
    'preserve_quick_gui_state.py', 'integrate_quick_gui_state.py',
    'accept_quick_gui_state.py', 'check_quick_gui_state_delivery.py',
    'ai_pro_harness.py', 'audit_ai_pro_runs.py', 'tests/test_quick_app_actor_scope.py'])
paths.update(['PROGRESS.md', 'RESUME.md', 'apps/network-quick-check/README.md',
    'docs/quick-check/gates.md', 'docs/quick-check/architecture.md',
    'docs/quick-check/requirement-traceability.md',
    'docs/quick-check/development-authorization-2026-10-26.md',
    'docs/quick-check/windows-compatibility-review-2026-10-26.md',
    '작업내용/NPI_2026-10-26_001.md', 'artifacts/quick-check-progress.json',
    'artifacts/qg3-parallel-development-authorization-20261026.json'])
paths.update(path.relative_to(R).as_posix() for path in (R / 'artifacts').glob('qg3a-*.json'))
verified = []
for name in sorted(paths):
    path = R / name
    data = path.read_bytes()
    text = data.decode('utf-8')
    assert data.endswith(b'\n') and all(line == line.rstrip() for line in text.splitlines()), name
    if name.endswith('.json'):
        json.loads(text)
    if name.endswith('.py'):
        compile(text, name, 'exec')
    verified.append({'path': name, 'sha256': sha(path)})
for name in ['PROGRESS.md', 'RESUME.md', 'apps/network-quick-check/README.md', 'docs/quick-check/gates.md']:
    assert 'GUI 순수 입력·실행 상태모델 root 제한 수용' in (R / name).read_text(encoding='utf-8')
traceability = (R / 'docs/quick-check/requirement-traceability.md').read_text(encoding='utf-8')
assert 'QG0 설계 당시의 원본 계획' in traceability and '477' not in traceability
check = subprocess.run(['git', '-C', str(R), 'diff', '--check'], capture_output=True,
                       text=True, encoding='utf-8', errors='replace', timeout=30)
assert check.returncode == 0, check.stdout + check.stderr
progress = load('artifacts/quick-check-progress.json')
assert progress['latest_root_validation']['workspace_counts'] == a['workspace_counts']
assert progress['qg3_gui_state']['accepted'] and progress['qg3_gui_state']['final_review_received']
assert not progress['gui_implemented'] and progress['gui_state_model_accepted'] and progress['qg3_started']
progress['qg3_gui_state']['independent_review_received'] = True
progress['qg3_gui_state']['final_delivery_check'] = 'artifacts/qg3a-gui-state-final-delivery-check.json'
(R / 'artifacts/quick-check-progress.json').write_text(json.dumps(progress, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
# progress의 최종 경로 추가를 반영한 해시로 검증 목록을 갱신한다.
for item in verified:
    if item['path'] == 'artifacts/quick-check-progress.json':
        item['sha256'] = sha(R / item['path'])
state = {'recorded_at': datetime.datetime.now().astimezone().isoformat(),
    'status': 'PASS', 'source_hashes_root_and_worktree_match': True,
    'immutable_source_files_verified': len(p['immutable_source_sha256']),
    'new_and_changed_text_files_checked': len(verified), 'verified_files': verified,
    'json_and_python_syntax_checked': True, 'utf8_final_lf_and_trailing_whitespace_checked': True,
    'root_diff_check_exit': check.returncode, 'worktree_clean': True,
    'preserved_source_commit': head, 'workspace_counts': a['workspace_counts'],
    'accepted_scope': a['scope'], 'full_qg2_accepted': False, 'full_qg3_accepted': False,
    'product_accepted': False, 'remote_push_or_deploy': False}
out = R / 'artifacts/qg3a-gui-state-final-delivery-check.json'
assert not out.exists()
out.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({k: state[k] for k in ['status', 'immutable_source_files_verified',
    'new_and_changed_text_files_checked', 'workspace_counts', 'worktree_clean',
    'full_qg3_accepted']}, ensure_ascii=False))
