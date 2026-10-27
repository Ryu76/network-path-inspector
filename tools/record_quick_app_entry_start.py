"""제품 worker 진입점의 실제 writer 가동과 검증 경계를 한국어 진행 기록에 반영한다."""
import csv
import datetime
import hashlib
import io
import json
import pathlib
import subprocess

R = pathlib.Path(__file__).resolve().parents[1]
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))
started = load('.harness/runs/qg2appentry-qgquickapp/started.json')
prepared = load('artifacts/qg2f-app-entry-prepared.json')
assert started['model'] == 'gemini-3.8-flash-high' and started['stage'] == 'qg2appentry'
p = subprocess.run(['tasklist.exe', '/FI', f"PID eq {started['pid']}", '/FO', 'CSV', '/NH'],
                   capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=20)
assert p.returncode == 0
alive = any(len(row) > 1 and row[1] == str(started['pid']) and row[0].lower() == 'agy.exe'
            for row in csv.reader(io.StringIO(p.stdout)))
accepted = load('artifacts/qg2e-trace-runner-acceptance.json')
assert accepted['accepted']
assert all(hashlib.sha256((R / path).read_bytes()).hexdigest() == value for path, value in accepted['source_sha256'].items())
protected = load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(hashlib.sha256((R / path).read_bytes()).hexdigest() == value for path, value in protected.items())
now = datetime.datetime.now().astimezone().isoformat()
state = load('artifacts/quick-check-progress.json')
state['recorded_at'] = now
state['qg2_app_entry'] = {
    'status': 'FLASH_FILE_ONLY_WRITER_RUNNING', 'stage': started['stage'], 'model': started['model'],
    'actor_pid': started['pid'], 'actor_alive_at_checkpoint': alive,
    'pipeline_session': 'proc_8c40ab0a6549', 'supervisor_pid': 37620,
    'pipeline_artifact': 'artifacts/qg2f-app-entry-pipeline.json',
    'prepared_artifact': 'artifacts/qg2f-app-entry-prepared.json',
    'baseline_commit': prepared['baseline_commit'], 'worktree': started['worktree'],
    'design_review': 'deleg_8af528a1', 'allowed_outputs': prepared['allowed_outputs'],
    'harness_tests_passed': 38, 'new_scope_tests_included': 7,
    'source_review_before_execution': True, 'workspace_lock_parent_only_after_actor': True,
    'accepted': False, 'root_integrated': False, 'product_accepted': False, 'qg3_started': False,
}
state['remaining_blockers'] = ['제품동일EXE DNS worker진입점 Flash초안작성중·감사/소스검토/manifest·lock/실행/독립QA전',
                               'QG2실환경VLAN/DROP/ICMP차단등미검증·전체QG2미수용',
                               'QG3 GUI/진단시작경로/TXT·CSV/PE·CRT·서명/VM/일반사용자/성능미완료']
(R / 'artifacts/quick-check-progress.json').write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
section = f'''\n## 제품 동일 EXE DNS worker 진입점 최소 기반 실제 작성 시작 — {now}
- 읽기전용 설계 deleg_8af528a1을부모실제resolver소스와대조했다. --npi-dns-worker-v1/기존validate_host·parse_helper_port·run_worker_from_args·worker_output_line 재사용. 불량입력은worker전에고정오류로차단하고유효worker stdout정확한줄/16384bytes/write·flush오류를검사한다. noargs/help는진단0·정적stderr안내만. GUI나자동진단/진단CLI를추가하지않음.
- 전용worktree {started['worktree']} / ai-pro/qgquickapp, 기준commit {prepared['baseline_commit']}. 수용Core와PRD원문을부모가{len(prepared['source_sha256'])}파일SHA동결·신규출력4개부재를확인했다. Flash High 실제PID{started['pid']},가동확인={alive},감독proc_8c40ab0a6549. 허용은app manifest/lib/main/native시험4파일만이며shared엔진/rootworkspace/lock/README/AGENTS변경금지.
- 새역할qgquickapp의writer·auditor허용목록을부모가정확4파일로추가했다. 새로운범위7회귀포함하네스38시험을실제실행하여38PASS. 이수치는제품시험이나새app실행증거가아니다. 기존역할범위와권한mode변경없음·FILE ONLY prompt/감사는OS강제격리보장아님.
- Rust ignored시험은기존NativeDnsProbeBackend로정확제품EXE→소유localhost worker IPC만검증하고새Child감독을복제하지않도록범위수정. 실제noargs/help/invalid/literal명령행은부모bounded Python subprocess로별도검증한다. actor종료/감사/소스안전검토전format/Cargo없음. workspace/lock추가는actor감사후부모만진행·기존registry버전/checksum불변검사필수.
- 현재는작성중/미컴파일·미시험·root미통합·미수용. root기존Trace연결415/native22수용과Inspector보호{len(protected)}SHA불변유지. 이번은QG2제품helper보완이며전체QG2/QG3 GUI/배포단계진행승인아님. 실VLAN/DROP등blocked와GUIsubsystem stdout·PE/CRT/서명/VM/일반사용자·성능미검증은그대로남는다.
\n'''
for name in ['PROGRESS.md', 'RESUME.md']:
    path = R / name
    first, rest = path.read_text(encoding='utf-8').split('\n', 1)
    path.write_text(first + '\n' + section + rest, encoding='utf-8', newline='\n')
path = R / '작업내용/NPI_2026-10-22_001.md'
path.write_text(path.read_text(encoding='utf-8') + section, encoding='utf-8', newline='\n')
print(json.dumps({'stage':started['stage'], 'actor_pid':started['pid'], 'actor_alive':alive,
                  'worktree':started['worktree'], 'baseline_commit':prepared['baseline_commit'],
                  'frozen_files':len(prepared['source_sha256']), 'inspector_unchanged':len(protected),
                  'accepted':False, 'qg3_started':False}, ensure_ascii=False))
