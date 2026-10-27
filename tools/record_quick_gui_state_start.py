"""실제 FILE actor 시작·소유 PID·기존 보호 SHA를 대조해 현재 진행 기록을 남긴다."""
import datetime
import hashlib
import json
import pathlib
import subprocess

R = pathlib.Path(__file__).resolve().parents[1]
load = lambda p: json.loads((R / p).read_text(encoding='utf-8'))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
p = load('artifacts/qg3a-gui-state-prepared.json')
started = load('.harness/runs/qg3state-qgguistate/started.json')
assert started['model'] == p['model'] == 'gemini-3.8-flash-high'
assert pathlib.Path(started['worktree']).resolve() == pathlib.Path(p['worktree']).resolve()
assert all(sha(R / path) == h for path, h in p['root_before_sha256'].items())
proc = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
    'Get-CimInstance Win32_Process -Filter "ProcessId = ' + str(int(started['pid'])) + '" | Select-Object ProcessId,ParentProcessId,Name | ConvertTo-Json -Compress'],
    capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=25)
assert proc.returncode == 0 and proc.stdout.strip()
row = json.loads(proc.stdout)
assert row['Name'].lower() == 'agy.exe' and row['ProcessId'] == started['pid']
now = datetime.datetime.now().astimezone().isoformat()
state = {'recorded_at': now, 'status': 'FLASH_FILE_ONLY_GUI_STATE_WRITER_RUNNING',
         'model': started['model'], 'actor_pid': started['pid'],
         'actor_alive_at_checkpoint': True, 'process_observation': row,
         'supervisor_session': 'proc_9afc8f0e11b9', 'supervisor_pid': 37924,
         'worktree': p['worktree'], 'branch': p['branch'], 'baseline_commit': p['baseline_commit'],
         'actor_writes': p['actor_writes'], 'source_inputs_frozen': len(p['root_before_sha256']),
         'harness_tests_passed': 32, 'new_scope_tests_included': 3,
         'root_product_source_changed': False, 'source_compiled': False,
         'new_gui_tests_executed': False, 'root_integrated': False, 'accepted': False,
         'full_qg2_accepted': False, 'full_qg3_accepted': False, 'product_accepted': False,
         'compatibility_review': 'docs/quick-check/windows-compatibility-review-2026-10-26.md'}
out = R / 'artifacts/qg3a-gui-state-start.json'
assert not out.exists()
out.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
progress = load('artifacts/quick-check-progress.json')
progress['recorded_at'] = now
progress['qg3_gui_state'] = state
progress['development_authorization_20261026']['implementation_started'] = True
(R / 'artifacts/quick-check-progress.json').write_text(json.dumps(progress, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
summary = '''
## 2026-10-26 QG3 순수 GUI 상태모델 FILE ONLY 구현 시작
- 전용 .worktrees/qgguistate / ai-pro/qgguistate, baseline87d1485b. FlashHigh gemini-3.8-flash-high 실제 actorPID42068/감독proc_9afc8f0e11b9(PID37924) 생존을 확인했다. 시점은 artifacts/qg3a-gui-state-start.json을 따른다.
- 허용은 신규 gui_state.rs/gui_state_tests.rs 및 lib.rs 모듈노출 한줄 정확3파일. 대상목록/옵션/실행스냅샷/취소요청/완료ID귀속을 구현하며 기존parser/plan/request/report를 재사용한다. Win32 창·실제 runner·OS I/O는 이번 단위에 없다.
- 입력58파일SHA동결·root 제품source변경0·actor 활동중 W Cargo/fmt/metadata 금지. 하네스32PASS(신규범위3포함)는 별도이며 새 GUI시험 통과 주장이 아니다. actor종료→정책/도구/경로/terminal/partial/SHA감사→독립QA→부모시험/선택통합 전이다.
- 최초 부모 준비는 AGENTS/contract 두파일의 checkout 개행차이로 차단됐다. 원문과 newline-only 동등성을 확인하고 파생사본만 복원·no-op index라 commit추가0. 실패 artifact를 보존했으며 제품/actor 실패로 계산하지 않는다.
- 별도로 기존debug EXE의 dumpbin imports/headers와 일반 dependency tree를 실제 조사했다. x64 CUI·동적 CRT·API-set imports를 확인했지만 Release/2012호환/단일EXE 지원을 인증하지 않는다. 상세 windows-compatibility-review-2026-10-26.md.
- 기존 root454PASS/31ignored 및 역사native31PASS는 유지하되 이번 재실행 수치가 아니다. 전체QG2/전체QG3/GUI화면/OS호환/배포 미수용.
'''
for name, header in [('PROGRESS.md', '# NPI 진행 기록'), ('RESUME.md', '# NPI 개발 재개 및 승인 경계')]:
    path = R / name
    text = path.read_text(encoding='utf-8')
    assert text.startswith(header + '\n') and 'QG3 순수 GUI 상태모델 FILE ONLY 구현 시작' not in text
    path.write_text(text.replace(header + '\n', header + '\n' + summary, 1), encoding='utf-8', newline='\n')
print(json.dumps(state, ensure_ascii=False))
