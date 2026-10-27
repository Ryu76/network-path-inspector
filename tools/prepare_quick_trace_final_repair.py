"""독립 재검토의 남은 Trace 3건을 보존하고 좁은 Flash 보정을 준비한다."""
import datetime
import hashlib
import json
import pathlib
import shutil
import subprocess

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qgtrace'
STAGE = 'qg2tracefinalfix'
PATHS = ['crates/network-core/src/traceroute.rs', 'crates/network-core/tests/traceroute.rs']

def load(relative):
    return json.loads((R / relative).read_text(encoding='utf-8'))

def git(*args):
    result = subprocess.run(['git', '-C', str(W), *args], capture_output=True, text=True,
                            encoding='utf-8', errors='replace', timeout=40)
    assert result.returncode == 0, result.stderr
    return result.stdout.rstrip('\r\n')

proof = load('artifacts/qg2c-trace-repaired-execution.json')
for relative, expected in proof['source_sha256'].items():
    assert hashlib.sha256((W / relative).read_bytes()).hexdigest() == expected, relative
witness = load('artifacts/commands/qg2c-trace-negative-ttl-before-fix.json')
assert witness['exit_code'] == 101 and not witness['partial']
assert git('branch', '--show-current') == 'ai-pro/qgtrace'
status = git('status', '--porcelain')
assert all(line[3:] in PATHS for line in status.splitlines()), status
assert not (R / '.harness/runs' / (STAGE + '-qgtrace')).exists()
git('add', *PATHS)
git('-c', 'core.autocrlf=false', 'commit', '-m', 'chore: preserve trace before final review corrections')
preserved = git('rev-parse', 'HEAD')
assert not git('status', '--porcelain')
refs = W / '.harness/references'
shutil.copyfile(R / '.harness/qa/quick-trace-boundaries/tests/contracts.rs', refs / 'trace-parent-boundaries.rs')
findings = [
    {'id': 'TRACE-P1-NEGATIVE-TTL', 'severity': 'P1', 'line': 453,
     'issue': '음수 TTL 홉을 안내문으로 무시하여 불량 raw를 REACHED로 승격함',
     'evidence': 'qg2c-trace-negative-ttl-before-fix: 10pass/1fail exit101'},
    {'id': 'P2-terminal-drain-error-not-failclosed', 'severity': 'P2', 'line': 1330,
     'issue': '종료 drain의 Peek/read 오류가 limitations에만 남고 성공 승격을 차단하지 않음',
     'evidence': 'deleg_298cedca/task-1 독립 정적 검토 및 부모 분기 확인'},
    {'id': 'P2-job-assignment-failure-skips-drain', 'severity': 'P2', 'line': 1210,
     'issue': 'spawn 후 Job 할당 실패가 공통 drain을 우회하여 이미 가용한 출력 유실',
     'evidence': 'deleg_298cedca/task-1 독립 정적 검토 및 부모 분기 확인'},
]
prompt = f'''당신은 Network Quick Check의 Trace 최종 3결함 전용 FILE ONLY 보정자다.
worktree={W.as_posix()}. 모든 읽기와 쓰기를 이 worktree의 절대 경로로만 수행한다.
허용: FILE READ/EDIT/CREATE 및 worktree 내부 파일 탐색. 금지: run_command/command/terminal/shell/PowerShell/manage_task/시험/설치/git/네트워크/DB/계정/재위임/에이전트. 읽기 목적 명령도 금지. PRD 링크나 integration root를 따라 읽지 않는다.
허용 수정은 정확히 두 파일: {W.as_posix()}/crates/network-core/src/traceroute.rs 및 {W.as_posix()}/crates/network-core/tests/traceroute.rs.
정확 입력: 위 두 파일, {W.as_posix()}/.harness/references/quick-trace-contract.json, {W.as_posix()}/.harness/references/trace-parent-boundaries.rs, {W.as_posix()}/crates/network-core/src/quick.rs. 나머지 소스와 manifest/lib/runner는 변경하지 않는다.
기존 부모 검증은 전체 network-core124pass, Trace 외부34/내부12, 독립10, 소유 loopback native2였다. 당신이 실행한 결과는 아니다. 독립 재QA에서 아래 3건이 남았다. 음수TTL은 부모가 추가하여 현재 독립10pass/1fail로 실제 재현했다.
1. 음수 TTL처럼 명백한 숫자형 hop 후보를 안내문으로 건너뛰지 말고 Err로 거부한다. '-1'뿐 아니라 범위외 음수·부호 숫자 후보를 정상 도달 행 뒤에 붙인 회귀를 넣는다. 정상 한국어/영어/원본 코드페이지 안내문은 raw 그대로 허용한다. 원문 trim/숫자 보정/불량 행 삭제로 수리하지 않는다.
2. 정상 exit0·유효 도달 raw를 이미 수집했어도 최종 stdout 또는 stderr drain의 Peek/read 오류가 있으면 REACHED/PASS 승격을 금지한다. 실제 코드 Option<i64>, 미확인 None, raw 바이트, limitations를 보존한다. 필요하면 공통 수집/결과 반영 내부 helper를 추출하여 기본 pure 시험에서 실제 native에 연결된 동일 로직의 terminal stdout 오류·stderr 오류·None 코드·이미 수집한 성공 raw 보존을 증명한다. 단지 evaluate에 수동 LOCAL_ERROR를 넣는 연결되지 않은 시험은 불충분하다. 상한 미수집도 성공으로 위장하지 않는다. 취소/timeout을 성공으로 변경하지 않는다.
3. spawn 이후 Job 할당 실패는 기존 fail-closed LOCAL_ERROR와 우회/재시도 금지를 유지하며 자식을 bounded cleanup한 후 양쪽 사용 가능한 파이프의 가용 잔량을 공통 bounded drain으로 보존한다. 파이프 소유권을 Job 할당 이전에 안전하게 확보하거나 정상/실패 공통 종료단계로 합류시킨다. 고정 빈 raw 반환을 제거한다. 다른 spawn 이후 종료경로에도 동일 drain helper를 사용한다. 단일 reader/borrowed HANDLE 수명/RAII/32KiB 각 스트림 cap/반복 상한/절삭표시/고정 System32 shell 없는 실행을 유지한다. 강제 OS 정책 변경·임의 실행파일 public injection·무한 read_to_end/무한 join은 금지한다. 이 경로의 가용 stdout/stderr 보존과 오류 한계를 실제 공통 helper를 쓰는 pure fixture로 추가한다.
생산 API/DTO/public 함수 변경 금지. 기존 기대값/시험을 삭제하거나 성공 단언을 완화하지 말라. 기존 raw OS 오류 None 보존 및 4096chunk 반복 drain fixture 정정을 유지한다. 새 helper 인수 <=7개, Clippy suppression 금지. 한국어 흐름 주석·UTF-8·후행공백 없음·최종개행 1개.
최종 한국어 응답에는 실제 변경 경로·보정 내용·부모 검증 필요사항만 기록한다. 명령/시험 실행 및 통과를 주장하지 말라.
'''
prompt_path = R / '.harness/prompts' / (STAGE + '-qgtrace.md')
assert not prompt_path.exists()
prompt_path.write_text(prompt, encoding='utf-8', newline='\n')
record = {'recorded_at': datetime.datetime.now().astimezone().isoformat(),
          'stage': STAGE, 'preserved_commit': preserved, 'review': 'deleg_298cedca',
          'findings': findings, 'root_integrated': False, 'accepted': False,
          'baseline_sha256': {p: hashlib.sha256((W / p).read_bytes()).hexdigest() for p in PATHS}}
output = R / 'artifacts/qg2c-trace-final-repair-prepared.json'
assert not output.exists()
output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps(record, ensure_ascii=False))
