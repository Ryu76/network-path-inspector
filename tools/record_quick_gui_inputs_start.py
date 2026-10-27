"""Win32 입력 GUI FILE writer의 실제 PID·동결 입력과 시작 상태를 기록한다."""
import datetime
import hashlib
import json
import pathlib
import re
import subprocess

R = pathlib.Path(__file__).resolve().parents[1]
load = lambda p: json.loads((R / p).read_text(encoding='utf-8'))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
p = load('artifacts/qg3b-gui-inputs-actor-prepared.json')
started = load('.harness/runs/qg3inputs-qgguiinputs/started.json')
W = pathlib.Path(p['worktree'])
assert started['model'] == p['model'] == 'gemini-3.8-flash-high'
assert pathlib.Path(started['worktree']).resolve() == W.resolve()
assert all(sha(R / path) == h for path, h in p['root_before_sha256'].items())
assert all(sha(W / path) == h for path, h in p['immutable_source_sha256'].items())
assert all(sha(W / path) == h for path, h in p['reference_sha256'].items())
proc = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
    'Get-CimInstance Win32_Process -Filter "ProcessId = ' + str(int(started['pid'])) + '" | Select-Object ProcessId,ParentProcessId,Name | ConvertTo-Json -Compress'],
    capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=25)
assert proc.returncode == 0 and proc.stdout.strip()
row = json.loads(proc.stdout)
assert row['Name'].lower() == 'agy.exe' and row['ProcessId'] == started['pid']
harness = load('artifacts/commands/qg3b-gui-inputs-harness.json')
assert harness['exit_code'] == 0 and not harness['partial']
harness_log = pathlib.Path(harness['log']).read_text(encoding='utf-8')
test_count = int(re.search(r'Ran (\d+) tests', harness_log).group(1))
assert test_count == 35 and re.search(r'\bOK\b', harness_log)
trace = pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/delegation/live/deleg_90377070/task-0.log')
assert 'end status=completed exit_reason=completed' in trace.read_text(encoding='utf-8')[-500:]
now = datetime.datetime.now().astimezone().isoformat()
state = {'recorded_at': now, 'status': 'FLASH_FILE_ONLY_NATIVE_INPUT_GUI_WRITER_RUNNING',
    'worktree': str(W), 'branch': p['branch'], 'baseline_commit': p['baseline_commit'],
    'model': started['model'], 'actor_pid': started['pid'], 'actor_alive_at_checkpoint': True,
    'actor_started_at': started['started_at'], 'process_observation': row,
    'supervisor_session': 'proc_8bf4c7b5679a', 'supervisor_pid': 24052,
    'read_only_design_review_received': True, 'design_review': 'deleg_90377070',
    'design_trace_sha256': sha(trace), 'design_result_is_not_execution_evidence': True,
    'actor_writes': p['actor_writes'], 'source_inputs_frozen': len(p['root_before_sha256']),
    'immutable_actor_inputs': len(p['immutable_source_sha256']), 'binding_references_frozen': len(p['reference_sha256']),
    'parent_metadata_changes': p['parent_metadata_changes'], 'old_registry_identities_checksums_preserved': True,
    'harness_tests_passed': test_count, 'parent_dependency_checks_exit': 0,
    'root_product_source_changed': False, 'root_integrated': False, 'accepted': False,
    'source_compiled': False, 'new_gui_tests_executed': False, 'native_tests_executed': False,
    'visible_gui_verified': False, 'network_diagnostics_connected': False,
    'full_qg2_accepted': False, 'full_qg3_accepted': False, 'product_accepted': False,
    'scope': '명시개발selector만·대상추가/전체교체/선택삭제·5기능/옵션·계획확인·실진단버튼비활성',
    'selected_item_in_place_edit_deferred': True,
    'parent_failures_preserved': ['artifacts/qg3b-gui-parent-lock-preflight-failure.json',
        'artifacts/qg3b-gui-parent-actor-preparation-failure.json']}
out = R / 'artifacts/qg3b-gui-inputs-start.json'
assert not out.exists()
out.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
progress = load('artifacts/quick-check-progress.json')
progress['recorded_at'] = now
progress['qg3_native_gui_inputs'] = state
(R / 'artifacts/quick-check-progress.json').write_text(json.dumps(progress, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
summary = f'''
## QG3B Win32 입력·계획 화면 FILE ONLY 구현 시작 — {now}
- 읽기설계 deleg_90377070 수신뒤 부모가첫범위를선택했다. 실제입력/목록추가·전체교체·선택삭제/5기능·옵션/계획확인GUI이며진단미연결상시표시·시작/중지/저장비활성. 선택항목in-place수정은후속으로분리했다. 새 --dev-gui-inputs-v1 정확1인자만GUI를열게하며기존CLI/main/CUI/worker계약을보존한다.
- 전용 .worktrees/qgguiinputs / ai-pro/qgguiinputs / baseline {p['baseline_commit']}. FlashHigh 실제actorPID {started['pid']} 생존확인, 감독proc_8bf4c7b5679a(PID24052). 허용source6파일만·부모metadata2준비·root제품source변경0. 입력{state['source_inputs_frozen']}개/actor불변{state['immutable_actor_inputs']}개/정확Windows-sys0.61.2바인딩참조{state['binding_references_frozen']}개고정. activeW에서부모Cargo/fmt/metadata금지.
- 하네스{test_count}PASS는별도이며새GUI시험통과주장이아니다. Windows features준비/filteredmetadata/기존앱compile은0이지만새화면생성/Win32시험/시각검증/수용은아직0. unsafe재진입/Box생명주기·제한UTF16입력·루프오류를독립QA한뒤실행한다.
- 최초부모offline lock재생성이미캐시최신libc0.2.191을선택해identityguard가차단했다. 변경lock원문을보존하고기존0.2.189로정확pin후신규metadata/check를재실행·기존packageidentity/checksum전체유지확인. 부모APP변수누락NameError도actor시작전실패로보존·기작성contract정확동등확인후복구했다. actor/제품시험실패로계산하지않는다.
- 현재root는기존477PASS/31ignored·QG3A순수모델수용이최신기능근거다. 이번실제GUI수용/전체QG2/QG3/OS호환/Release/배포는아니다. 근거 artifacts/qg3b-gui-inputs-start.json. actor종료→도구/경로/terminal/partial/SHA감사→독립정적안전QA→실제시험/시각검증→선택통합순서.
'''
for name, header in [('PROGRESS.md', '# NPI 진행 기록'), ('RESUME.md', '# NPI 개발 재개 및 승인 경계')]:
    path = R / name
    text = path.read_text(encoding='utf-8')
    assert 'QG3B Win32 입력·계획 화면 FILE ONLY 구현 시작' not in text
    path.write_text(text.replace(header + '\n', header + '\n' + summary, 1), encoding='utf-8', newline='\n')
print(json.dumps({k: state[k] for k in ['status', 'actor_pid', 'actor_alive_at_checkpoint',
    'source_inputs_frozen', 'immutable_actor_inputs', 'binding_references_frozen', 'harness_tests_passed',
    'root_product_source_changed', 'accepted']}, ensure_ascii=False))
