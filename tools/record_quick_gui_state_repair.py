"""독립 QA 반영 시험 보정·생산 rustfmt 동등성 및 실제 회귀 결과를 동결한다."""
import datetime
import hashlib
import json
import pathlib
import re
import shutil
import subprocess

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qgguistate'
load = lambda p: json.loads((R / p).read_text(encoding='utf-8'))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
p = load('artifacts/qg3a-gui-state-prepared.json')
a = load('artifacts/qg3a-gui-state-source-audit.json')
review = load('artifacts/qg3a-gui-state-independent-review.json')
assert review['safe_to_execute_default_tests'] and len(review['findings']) == 6
assert all(sha(W / path) == h for path, h in p['immutable_source_sha256'].items())
assert all(sha(R / path) == h for path, h in p['root_before_sha256'].items())
original = R / '.harness/evidence/qg3a-gui-state-actor-original'
assert all(sha(original / pathlib.Path(path).name) == h for path, h in a['source_sha256'].items())
qa = R / '.harness/qa/qg3a-actor-production-format'
assert not qa.exists()
qa.mkdir(parents=True)
for name in ['gui_state.rs', 'gui_state_tests.rs']:
    shutil.copyfile(original / name, qa / name)
format_result = subprocess.run(['rustfmt', '--edition', '2024', '--config', 'skip_children=true', str(qa / 'gui_state.rs')],
    capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30)
assert format_result.returncode == 0, format_result.stderr
assert (qa / 'gui_state.rs').read_bytes() == (W / 'apps/network-quick-check/src/gui_state.rs').read_bytes(), 'production differs beyond exact rustfmt output'
lib = 'apps/network-quick-check/src/lib.rs'
assert (W / lib).read_bytes().replace(b'pub mod gui_state;\n', b'', 1) == (R / lib).read_bytes()


def command(name):
    record = load('artifacts/commands/' + name + '.json')
    assert record['exit_code'] == 0 and not record['partial'], name
    log = pathlib.Path(record['log']).read_text(encoding='utf-8')
    counts = [tuple(map(int, m)) for m in re.findall(r'test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored', log)]
    if counts:
        record['counts'] = dict(zip(['passed', 'failed', 'ignored'], map(sum, zip(*counts))))
    return record


focused = command('qg3a-gui-state-repaired-focused')
workspace = command('qg3a-gui-state-parent-workspace')
assert focused['counts']['failed'] == 0 and focused['counts']['passed'] > 0
baseline = load('artifacts/qg2j-public-entry-acceptance.json')['workspace_counts']
assert workspace['counts']['passed'] == baseline['passed'] + focused['counts']['passed']
assert workspace['counts']['ignored'] == baseline['ignored'] and workspace['counts']['failed'] == 0
trace = pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/delegation/live/deleg_07610d09/task-0.log')
state = {'recorded_at': datetime.datetime.now().astimezone().isoformat(),
         'status': 'REPAIRED_SOURCE_EXECUTION_PASS_FINAL_REVIEW_PENDING',
         'first_review': review['review'], 'first_review_trace_sha256': sha(trace),
         'initial_findings': review['findings'], 'parent_repaired_finding_ids': [f['id'] for f in review['findings']],
         'parent_change_scope': '신규시험만계약보정/보강·상태모델은정확한rustfmt출력외변경0·lib한줄노출유지',
         'production_exact_actor_rustfmt_equivalence': True,
         'actor_original_sha256': a['source_sha256'],
         'source_sha256': {path: sha(W / path) for path in p['actor_writes']},
         'execution': {'focused': focused, 'workspace': workspace,
             'clippy': command('qg3a-gui-state-parent-clippy'), 'fmt': command('qg3a-gui-state-parent-fmt-check')},
         'first_failed_focused_preserved': a['first_focused'],
         'core_resolver_inspector_cli_manifest_lock_changes': 0,
         'original_inspector_unchanged': 60, 'existing_approved_pub_exception_files': 1,
         'native_executed_this_slice': False, 'root_integrated': False, 'accepted': False,
         'full_qg2_accepted': False, 'full_qg3_accepted': False, 'product_accepted': False,
         'limitations': ['GUI화면/runner연결아님', '실제취소·IO/OS자원회수인증아님', 'Windows2012/R2·배포/성능미수용']}
out = R / 'artifacts/qg3a-gui-state-parent-repair.json'
assert not out.exists()
out.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'status': state['status'], 'focused_counts': focused['counts'],
                  'workspace_counts': workspace['counts'], 'production_exact_actor_rustfmt_equivalence': True,
                  'source_sha256': state['source_sha256']}, ensure_ascii=False))
