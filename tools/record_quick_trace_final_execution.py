"""Trace 최신 실행 증거와 별도 DNS 실행기 작업 상태를 분리 기록한다."""
import csv
import datetime
import hashlib
import io
import json
import pathlib
import re
import subprocess

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qgtrace'
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))
pipeline = load('artifacts/qg2c-trace-final-repair-pipeline-preflight-repaired.json')
assert pipeline['status'] == 'BLOCKED_PRESERVED_FOR_REVIEW'
assert pipeline['error'] == 'qg2c-trace-final-clippy: exit 1'
for relative, expected in pipeline['canonical_source_sha256'].items():
    assert hashlib.sha256((W / relative).read_bytes()).hexdigest() == expected
clippy = load('artifacts/commands/qg2c-trace-final-recheck-clippy.json')
assert clippy['exit_code'] == 0 and not clippy['partial']
assert load('artifacts/qg2tracefinalfix-actor-policy-audit.json')['all_actor_policy_checks_passed']
counts = {}
for name in ['qg2c-trace-final-all-targets', 'qg2c-trace-final-boundaries', 'qg2c-trace-final-native']:
    data = load('artifacts/commands/' + name + '.json')
    assert data['exit_code'] == 0 and not data['partial']
    text = (R / 'artifacts/commands' / (name + '.log')).read_text(encoding='utf-8')
    rows = re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
    counts[name] = {key: sum(int(row[i]) for row in rows) for i, key in enumerate(['passed', 'failed', 'ignored'])}
    assert counts[name]['passed'] > 0 and counts[name]['failed'] == 0
now = datetime.datetime.now().astimezone().isoformat()
record = {'recorded_at': now, 'status': 'EXECUTION_PASS_INDEPENDENT_RECHECK_PENDING',
          'actor_stage': 'qg2tracefinalfix', 'source_sha256': pipeline['canonical_source_sha256'],
          'execution': counts, 'strict_clippy': clippy,
          'pipeline_blocker': '과거10월21일19:03 Clippy 증거와 이름충돌하여 supervisor exit1. source/시험 실패가 아니며 원본BLOCKED 기록은 보존하고 새이름 Clippy를 실제재실행해0확인',
          'independent_recheck': 'deleg_7622500b', 'root_integrated': False, 'accepted': False}
out = R / 'artifacts/qg2c-trace-final-repaired-execution.json'
assert not out.exists()
out.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
dns_run = load('.harness/runs/qg2dnswire-qg2runner/started.json')
process = subprocess.run(['tasklist.exe', '/FI', 'PID eq ' + str(dns_run['pid']), '/FO', 'CSV', '/NH'],
                         capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=20)
assert process.returncode == 0
rows = list(csv.reader(io.StringIO(process.stdout)))
alive = any(len(row) > 1 and row[1] == str(dns_run['pid']) and row[0].lower() == 'agy.exe' for row in rows)
dns_pipeline = load('artifacts/qg2d-dns-runner-pipeline.json')
state = load('artifacts/quick-check-progress.json')
state['recorded_at'] = now
state['qg2_trace'].update(status=record['status'], latest_execution=record, accepted=False,
                         recheck_pending='deleg_7622500b', root_integrated=False)
state['qg2_dns_runner'] = {'status': dns_pipeline['status'], 'stage': dns_run['stage'],
                          'actor_pid': dns_run['pid'], 'actor_alive_at_checkpoint': alive,
                          'pipeline_step': dns_pipeline['current_step'],
                          'pipeline_session': 'proc_007052be4b8b',
                          'worktree': dns_run['worktree'], 'accepted': False, 'root_integrated': False,
                          'scope': '필수 도메인해석·선택 상세DNS만 기존 실행기에 연결. Trace/GUI 미포함'}
state['remaining_blockers'] = [
    'Trace 최종 독립재QA deleg_7622500b 및 root 선택통합 전',
    'DNS 실행기 연결 qg2dnswire 실제구현·독립시험·QA·통합 전',
    'Trace 실제선택실행기 연결·GUI/EXE/일반사용자/VM/실VLAN·성능 검증 전',
]
(R / 'artifacts/quick-check-progress.json').write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
section = f'''\n## Trace 마지막 3건 보정 실행 / DNS 실행기 별도 가동 — {now}
- Trace FILE ONLY 보정 actor 종료·실제29도구/경로감사통과. 부모rustfmt만적용후 fullCore{counts['qg2c-trace-final-all-targets']['passed']}PASS/0FAIL, 독립{counts['qg2c-trace-final-boundaries']['passed']}PASS/0FAIL(음수TTL회귀포함), 소유IPv4/IPv6 native2PASS. Clippy는과거증거파일이름충돌로supervisor차단(exit1)을그대로보존하고새이름qg2c-trace-final-recheck-clippy로실제재실행exit0. 의미수정/Clippy suppression없음.
- Trace parser/adapter와native종결/잔량보존을두독립검토자deleg_7622500b에요청. 정적최종해소/수용은아직전,root미통합. 실제실행과정적QA는구분.
- 수용DNS를기존qg2runner worktree에불변기준commit c9bd1f88eaf010ec9322a94675ed19968802f85c로동기화후별도 Flash qg2dnswire actor PID{dns_run['pid']} 시작. 체크포인트실제agy실행여부={alive}. proc_007052be4b8b 감독기는종료후정책감사/순수전체/소유helper localhost native/Clippy를순차실행한다. Trace프로브는이actor범위제외·미지원표시유지. root실행기아직기존IP범위이며제품동작연결을미리주장하지않음.
\n'''
for filename in ['PROGRESS.md', 'RESUME.md']:
    path = R / filename
    text = path.read_text(encoding='utf-8')
    first, rest = text.split('\n', 1)
    path.write_text(first + '\n' + section + rest, encoding='utf-8', newline='\n')
path = R / '작업내용/NPI_2026-10-22_001.md'
path.write_text(path.read_text(encoding='utf-8') + section, encoding='utf-8', newline='\n')
print(json.dumps({'trace_execution': counts, 'trace_clippy_exit': 0, 'trace_recheck': 'deleg_7622500b',
                  'dns_runner_actor_pid': dns_run['pid'], 'dns_runner_actor_alive': alive,
                  'dns_runner_pipeline_status': dns_pipeline['status'], 'accepted_trace': False}, ensure_ascii=False))
