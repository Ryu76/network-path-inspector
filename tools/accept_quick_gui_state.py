"""GUI 내부 상태모델의 root 조합 회귀만 제한 수용한다. 화면/OS/제품 수용은 아니다."""
import datetime
import hashlib
import json
import pathlib
import re
import subprocess

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qgguistate'
load = lambda p: json.loads((R / p).read_text(encoding='utf-8'))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
p = load('artifacts/qg3a-gui-state-prepared.json')
v = load('artifacts/qg3a-gui-state-parent-repair.json')
saved = load('artifacts/qg3a-gui-state-preservation.json')
review = load('artifacts/qg3a-gui-state-final-independent-review.json')
integration = load('artifacts/qg3a-gui-state-integration.json')
assert not (R / 'artifacts/qg3a-gui-state-acceptance.json').exists()
assert review['safe_to_execute_default_tests'] and not review['findings']
assert len(review['reviews']) == 2 and all(x['completed'] and not x['findings'] for x in review['reviews'])
assert review['source_sha256'] == v['source_sha256'] == saved['source_sha256'] == integration['source_sha256']
assert all(sha(R / path) == sha(W / path) == h for path, h in v['source_sha256'].items())
lib = 'apps/network-quick-check/src/lib.rs'
assert all(sha(R / path) == h for path, h in p['root_before_sha256'].items() if path != lib)
assert all(sha(W / path) == h for path, h in p['immutable_source_sha256'].items())
assert (R / lib).read_bytes().replace(b'pub mod gui_state;\n', b'', 1) == (R / '.harness/evidence/qg3a-gui-state-actor-original/lib.rs').read_bytes().replace(b'pub mod gui_state;\n', b'', 1)
protected = load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
engine = 'crates/npi-probes/src/engine.rs'
assert all(sha(R / path) == h for path, h in protected.items() if path != engine)
original = R / '.harness/baselines/qg2g-tcp-replay-root/engine.rs'
assert sha(original) == protected[engine]
assert (R / engine).read_bytes() == original.read_bytes().replace(b'fn apply_tcp_result(', b'pub fn apply_tcp_result(', 1)
status = subprocess.run(['git', '-C', str(W), 'status', '--porcelain'], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30)
assert status.returncode == 0 and not status.stdout.rstrip('\r\n')
head = subprocess.check_output(['git', '-C', str(W), 'rev-parse', 'HEAD'], text=True).rstrip('\r\n')
assert head == saved['preserved_commit']


def command(name):
    item = load('artifacts/commands/' + name + '.json')
    assert item['exit_code'] == 0 and not item['partial'], name
    text = pathlib.Path(item['log']).read_text(encoding='utf-8')
    counts = [tuple(map(int, m)) for m in re.findall(r'test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored', text)]
    if counts:
        item['counts'] = dict(zip(['passed', 'failed', 'ignored'], map(sum, zip(*counts))))
    return item


workspace = command('qg3a-gui-state-root-workspace')
assert workspace['counts'] == v['execution']['workspace']['counts']
clippy = command('qg3a-gui-state-root-clippy')
fmt = command('qg3a-gui-state-root-fmt')
harness = command('qg3a-gui-state-delivery-harness')
harness_text = pathlib.Path(harness['log']).read_text(encoding='utf-8')
harness_count = int(re.search(r'Ran (\d+) tests', harness_text).group(1))
assert harness_count == 32 and re.search(r'\bOK\b', harness_text)
for path in p['actor_writes']:
    data = (R / path).read_bytes()
    assert data.endswith(b'\n') and all(line.rstrip() == line for line in data.decode('utf-8').splitlines())
now = datetime.datetime.now().astimezone().isoformat()
state = {'recorded_at': now, 'status': 'ACCEPTED_PURE_GUI_INPUT_AND_RUN_STATE_MODEL_ONLY',
         'accepted': True, 'root_integrated': True, 'scope': '순수 GUI 입력/옵션/실행스냅샷/취소요청/완료귀속 상태모델',
         'source_sha256': v['source_sha256'], 'changed_source_paths': p['actor_writes'],
         'preserved_source_commit': head, 'worktree': str(W), 'worktree_clean': True,
         'actor_model': 'gemini-3.8-flash-high', 'actor_tool_calls': 28, 'actor_scope_violations': [],
         'writer_credit': 'Flash FILE ONLY 상태모델/시험 초안 + 부모 시험계약 보정/보강·format·하네스/검증 공동작성',
         'production_exact_actor_rustfmt_equivalence': True,
         'final_independent_review': 'artifacts/qg3a-gui-state-final-independent-review.json',
         'final_independent_findings': [], 'initial_review_findings_resolved': review['resolved_ids'],
         'focused_counts_in_workspace': v['execution']['focused']['counts'],
         'workspace_counts': workspace['counts'], 'root_execution': {'workspace': workspace, 'clippy': clippy, 'fmt': fmt, 'harness': harness},
         'harness_tests_passed': harness_count, 'core_resolver_inspector_cli_manifest_lock_new_changes': 0,
         'original_inspector_unchanged': len(protected) - 1, 'existing_approved_pub4byte_exception_files': 1,
         'first_failure_preserved': 'artifacts/qg3a-gui-state-source-audit.json',
         'initial_preparation_failure_preserved': 'artifacts/qg3a-gui-state-parent-preflight-failure.json',
         'native_executed_this_slice': False, 'actual_exe_cli_rerun_this_slice': False,
         'historical_native': {'passed': 31, 'artifact': 'artifacts/qg2i-explicit-tcp-acceptance.json', 'rerun_this_slice': False},
         'native_window_implemented': False, 'runner_connected_to_gui': False,
         'full_qg2_accepted': False, 'full_qg3_accepted': False, 'product_accepted': False,
         'remote_push_or_deploy': False,
         'remaining': ['Win32화면/이벤트연결', '백그라운드실행coordinator·bounded완료전달·창종료수명주기',
             '실제Console취소·OS자원회수·domainEXE종단·VLAN/DROP/VPN/다중NIC실환경',
             'GUI필터/TXTCSV/정규metadata·Windows2012이후호환성·Release/서명/VM/일반사용자/성능']}
(R / 'artifacts/qg3a-gui-state-acceptance.json').write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
progress = load('artifacts/quick-check-progress.json')
progress['recorded_at'] = now
progress['qg3_gui_state'].update(state)
progress['qg3_gui_state']['final_review_received'] = True
progress['qg3_gui_state']['acceptance_artifact'] = 'artifacts/qg3a-gui-state-acceptance.json'
progress['latest_root_validation'] = {'recorded_at': now, 'status': state['status'],
    'acceptance_artifact': 'artifacts/qg3a-gui-state-acceptance.json', 'workspace_counts': workspace['counts'],
    'focused_new_tests_in_workspace': v['execution']['focused']['counts']['passed'],
    'clippy_exit': 0, 'fmt_exit': 0, 'native_executed_this_run': False,
    'historical_native_evidence': state['historical_native'], 'full_qg2_accepted': False,
    'full_qg3_accepted': False}
progress['gui_implemented'] = False
progress['gui_state_model_accepted'] = True
progress['qg3_started'] = True
(R / 'artifacts/quick-check-progress.json').write_text(json.dumps(progress, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
summary = f'''
## GUI 순수 입력·실행 상태모델 root 제한 수용 — {now}
- 사용자 GUI 병행 승인 아래 대상목록/옵션/실행스냅샷/취소요청/완료ID귀속 상태모델 source3만 메인에 선택통합했다. 실제Core parser/plan/request/report재사용·기존CLI분기/worker/공유Core/resolver/Inspector/manifest/lock변경0. Win32화면이나runner연결완료가아니다.
- 최종독립QA deleg_a604a8b4 두검토 모두 findings=[]·원본QA01~06해소. root workspace{workspace['counts']['passed']}PASS/0FAIL/{workspace['counts']['ignored']}ignored, 새focused{v['execution']['focused']['counts']['passed']}개는그합계에포함. strictClippy/fmt0·하네스{harness_count}PASS. 초기15PASS1FAIL/unused경고와개행준비차단을보존했다. 실제native/제품EXE CLI는이번재실행0·이전native31은역사근거다.
- Wclean/로컬보존commit {head}. Flash초안+부모시험보강 공동작성·생산은actor원문의정확rustfmt출력과byte동일. Inspector원본60+기승인pub4byte예외1·baseline61원본유지·원격push/배포/전체branch merge0.
- 근거 artifacts/qg3a-gui-state-acceptance.json. 전체QG2/전체QG3/제품수용false. 다음은네이티브Win32화면과별도실행coordinator의bounded전달/창종료수명주기연결이며, GUI스레드IO0·기존CLI계약보존을유지한다. 구형Windows2012/R2/OS별실환경·Release/단일EXE/성능/배포는별도미검증이다.
'''
for name, header in [('PROGRESS.md', '# NPI 진행 기록'), ('RESUME.md', '# NPI 개발 재개 및 승인 경계')]:
    path = R / name
    text = path.read_text(encoding='utf-8')
    assert 'GUI 순수 입력·실행 상태모델 root 제한 수용' not in text
    path.write_text(text.replace(header + '\n', header + '\n' + summary, 1), encoding='utf-8', newline='\n')
for name in ['apps/network-quick-check/README.md', 'docs/quick-check/gates.md']:
    path = R / name
    text = path.read_text(encoding='utf-8')
    assert 'GUI 순수 입력·실행 상태모델 root 제한 수용' not in text
    path.write_text(text.rstrip() + '\n\n' + summary.strip() + '\n', encoding='utf-8', newline='\n')
work = R / '작업내용/NPI_2026-10-26_001.md'
assert not work.exists()
work.write_text('# 2026-10-26 Quick Check GUI 병행 첫 구현 기록\n' + summary +
    '\n## 추가 근거\n- 승인: docs/quick-check/development-authorization-2026-10-26.md\n'
    '- 호환성: docs/quick-check/windows-compatibility-review-2026-10-26.md\n'
    '- 초기/보정/최종QA/원문SHA: artifacts/qg3a-gui-state-{source-audit,parent-repair,final-independent-review,integration,acceptance}.json\n'
    '- PE검사는기존debug산출물만읽은결과·Release/OS기동인증아님. 추가설치/OS정책/운영망변경0.\n', encoding='utf-8')
print(json.dumps({'status': state['status'], 'workspace_counts': state['workspace_counts'],
                  'focused_counts_in_workspace': state['focused_counts_in_workspace'],
                  'harness_tests_passed': harness_count, 'root_integrated': True,
                  'accepted': True, 'full_qg3_accepted': False}, ensure_ascii=False))
