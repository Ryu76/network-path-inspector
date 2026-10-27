"""GUI actor 원문·파일 감사 및 첫 focused 실패를 보존한다. 수정·통합은 하지 않는다."""
import datetime
import hashlib
import json
import pathlib
import re
import shutil

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qgguistate'
load = lambda p: json.loads((R / p).read_text(encoding='utf-8'))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
p = load('artifacts/qg3a-gui-state-prepared.json')
a = load('artifacts/qg3a-gui-state-pipeline.json')
assert a['status'] == 'AUDITED_SOURCE_READY_FOR_PARENT_REVIEW'
assert all(sha(W / path) == h for path, h in a['source_sha256'].items())
assert all(sha(R / path) == h for path, h in p['root_before_sha256'].items())
assert all(sha(W / path) == h for path, h in p['immutable_source_sha256'].items())
original = R / '.harness/evidence/qg3a-gui-state-actor-original'
assert not original.exists()
original.mkdir(parents=True)
for path in p['actor_writes']:
    shutil.copyfile(W / path, original / pathlib.Path(path).name)
    assert sha(original / pathlib.Path(path).name) == a['source_sha256'][path]
command = load('artifacts/commands/qg3a-gui-state-first-focused.json')
log = pathlib.Path(command['log']).read_text(encoding='utf-8')
counts = [tuple(map(int, m)) for m in re.findall(r'test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored', log)]
assert len(counts) == 1 and command['exit_code'] == 101 and not command['partial']
state = {'recorded_at': datetime.datetime.now().astimezone().isoformat(),
         'status': 'ACTOR_AUDITED_FIRST_FOCUSED_FAILED_INDEPENDENT_REVIEW_PENDING',
         'actor_completed': True, 'actor_alive_at_checkpoint': False,
         'actor_exit_code': 0, 'actor_partial': False, 'actor_tool_calls': 28,
         'actor_scope_violations': [], 'strict_path_checks': a['strict_in_worktree_path_checks'],
         'source_sha256': a['source_sha256'], 'immutable_source_files': len(p['immutable_source_sha256']),
         'actor_original_directory': str(original), 'lib_one_line_delta_verified': True,
         'first_focused': {**command, 'counts': dict(zip(['passed', 'failed', 'ignored'], counts[0]))},
         'parent_observation': 'Core 목록포트 파서는 선행0을 허용하지만 신규 test가080을거부목록에넣음. source기준정책불일치이며제품파서변경금지. unused QuickContext 경고도있음.',
         'observation_is_not_independent_review_result': True,
         'independent_review': 'deleg_07610d09', 'independent_review_received': False,
         'source_changed_after_review_request': False, 'source_compiled': True,
         'new_gui_tests_all_passed': False, 'native_executed': False,
         'root_integrated': False, 'accepted': False, 'full_qg2_accepted': False,
         'full_qg3_accepted': False, 'product_accepted': False}
out = R / 'artifacts/qg3a-gui-state-source-audit.json'
assert not out.exists()
out.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
progress = load('artifacts/quick-check-progress.json')
progress['recorded_at'] = state['recorded_at']
progress['qg3_gui_state'].update(state)
(R / 'artifacts/quick-check-progress.json').write_text(json.dumps(progress, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
summary = '''
## 2026-10-26 GUI 상태모델 actor 종료·첫 순수시험 실패 보존
- Flash FILE ONLY actor42068/감독proc_9afc8f0e11b9 정상종료 exit0/partialfalse, source3·tool28·strictW path28·정책위반0·공유57SHA불변/lib한줄delta 확인. 아직 구현/GUI수용이 아니다.
- 부모가 원본 source3을 .harness/evidence/qg3a-gui-state-actor-original에 보존하고 같은SHA로 focused순수시험을 실행:16중15PASS/1FAIL, exit101. 실패는 test_invalid_inputs_and_no_repair의unwrap_err가Ok를받은것. Core목록파서는선행0포트를허용하는데 새시험080거부기대와충돌하는것을 source에서확인했다. unusedQuickContext경고도보존. Core를고쳐시험에맞추지않는다.
- 독립정적 QA deleg_07610d09 진행중. 요청이후source/fmt수정0. 부모초기시험실패를QA실행증거로표현하지않는다. root는기존454PASS/31ignored가역사수용근거이며새GUI는미통합/미수용/native실행0이다.
- 다음은독립검토수신후시험계약보정·원자성/완료귀속/전체report보존강화→실제전체회귀/Clippy/fmt→독립재검토→선택통합순서. 전체QG2/전체QG3/GUI화면/OS지원/배포미수용유지.
'''
for name, header in [('PROGRESS.md', '# NPI 진행 기록'), ('RESUME.md', '# NPI 개발 재개 및 승인 경계')]:
    path = R / name
    text = path.read_text(encoding='utf-8')
    assert text.startswith(header + '\n') and 'GUI 상태모델 actor 종료·첫 순수시험 실패 보존' not in text
    path.write_text(text.replace(header + '\n', header + '\n' + summary, 1), encoding='utf-8', newline='\n')
print(json.dumps({'status': state['status'], 'source_compiled': True,
                  'first_focused_counts': state['first_focused']['counts'],
                  'root_integrated': False, 'accepted': False}, ensure_ascii=False))
