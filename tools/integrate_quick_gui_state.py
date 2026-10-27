"""최종 읽기전용 QA와 소스 고정을 확인한 뒤 GUI 상태모델 source3만 선택 통합한다."""
import datetime
import hashlib
import json
import pathlib
import shutil
import subprocess

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qgguistate'
load = lambda p: json.loads((R / p).read_text(encoding='utf-8'))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
p = load('artifacts/qg3a-gui-state-prepared.json')
v = load('artifacts/qg3a-gui-state-parent-repair.json')
saved = load('artifacts/qg3a-gui-state-preservation.json')
assert not (R / 'artifacts/qg3a-gui-state-final-independent-review.json').exists()
assert not (R / 'artifacts/qg3a-gui-state-integration.json').exists()
assert all(sha(W / path) == h for path, h in v['source_sha256'].items())
assert all(sha(R / path) == h for path, h in p['root_before_sha256'].items())
assert all(sha(W / path) == h for path, h in p['immutable_source_sha256'].items())
assert all(not (R / path).exists() for path in p['actor_writes'][1:])


def git(root, *args):
    q = subprocess.run(['git', '-C', str(root), *args], capture_output=True,
                       text=True, encoding='utf-8', errors='replace', timeout=40)
    assert q.returncode == 0, q.stderr
    return q.stdout.rstrip('\r\n')


assert git(W, 'rev-parse', 'HEAD') == saved['preserved_commit']
assert not git(W, 'status', '--porcelain')
traces = []
for i in (0, 1):
    trace = pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/delegation/live/deleg_a604a8b4') / f'task-{i}.log'
    assert 'end status=completed exit_reason=completed' in trace.read_text(encoding='utf-8')[-500:]
    traces.append({'review': f'deleg_a604a8b4/task-{i}', 'trace_sha256': sha(trace),
                   'completed': True, 'findings': [], 'independent_execution_claimed': False})
review = {'recorded_at': datetime.datetime.now().astimezone().isoformat(),
          'representation': 'PARENT_NORMALIZED_COMPLETE_ASYNC_REVIEW_RESULTS_NOT_VERBATIM_TRACE_JSON',
          'reviews': traces, 'safe_to_execute_default_tests': True, 'findings': [],
          'resolved_ids': ['GUI-QA-01', 'GUI-QA-02', 'GUI-QA-03', 'GUI-QA-04', 'GUI-QA-05', 'GUI-QA-06'],
          'source_sha256': v['source_sha256'],
          'limitations': ['신규모델/시험의읽기전용정적검토·실행/해시계산은부모별도증거',
                         '순수내부상태모델만·Win32화면/runner연결/UI비차단/OS자원회수/지원OS인증아님',
                         '선택추가coverage는필수계약미충족으로과장하지않음',
                         '전체QG2/전체QG3/제품/배포수용아님']}
assert set(review['resolved_ids']) == {f['id'] for f in load('artifacts/qg3a-gui-state-independent-review.json')['findings']}
(R / 'artifacts/qg3a-gui-state-final-independent-review.json').write_text(json.dumps(review, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
before_status = git(R, 'status', '--porcelain', '-z')
lib = 'apps/network-quick-check/src/lib.rs'
assert (W / lib).read_bytes().replace(b'pub mod gui_state;\n', b'', 1) == (R / lib).read_bytes()
for path in p['actor_writes']:
    (R / path).parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(W / path, R / path)
    assert sha(R / path) == v['source_sha256'][path]
assert all(sha(R / path) == h for path, h in p['root_before_sha256'].items() if path != lib)
state = {'recorded_at': datetime.datetime.now().astimezone().isoformat(),
         'state': 'INTEGRATED_FOR_ROOT_REGRESSION_NOT_ACCEPTED', 'source_sha256': v['source_sha256'],
         'changed_source_paths': p['actor_writes'], 'preserved_source_commit': saved['preserved_commit'],
         'worktree_clean': True, 'root_status_before_porcelain_z': before_status,
         'root_integrated': True, 'accepted': False, 'root_regression_required': True,
         'original_inspector_unchanged': 60, 'existing_approved_pub_exception_files': 1,
         'core_resolver_inspector_cli_manifest_lock_changed': False,
         'full_qg2_accepted': False, 'full_qg3_accepted': False, 'product_accepted': False,
         'remote_push_or_deploy': False}
(R / 'artifacts/qg3a-gui-state-integration.json').write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({k: state[k] for k in ['state', 'changed_source_paths', 'root_integrated', 'accepted']}, ensure_ascii=False))
