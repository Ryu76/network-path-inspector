"""실제 실행 중인 Trace 보정과 DNS 독립 검토를 재개 기록에 반영한다."""
import csv
import datetime
import hashlib
import io
import json
import pathlib
import subprocess

R = pathlib.Path(__file__).resolve().parents[1]
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))
run = load('.harness/runs/qg2tracefinalfix-qgtrace/started.json')
pipeline = load('artifacts/qg2c-trace-final-repair-pipeline-preflight-repaired.json')
assert pipeline['status'] == 'RUNNING' and pipeline['current_step'] == 'flash-file-only'
assert run['model'] == 'gemini-3.8-flash-high'
process = subprocess.run(['tasklist.exe', '/FI', 'PID eq ' + str(run['pid']), '/FO', 'CSV', '/NH'],
                         capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=20)
assert process.returncode == 0, process.stderr
rows = list(csv.reader(io.StringIO(process.stdout)))
assert any(len(row) > 1 and row[1] == str(run['pid']) and row[0].lower() == 'agy.exe' for row in rows), '실제 agy actor 미실행'
protected = load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(hashlib.sha256((R / path).read_bytes()).hexdigest() == sha for path, sha in protected.items())
now = datetime.datetime.now().astimezone().isoformat()
state = load('artifacts/quick-check-progress.json')
state['recorded_at'] = now
state['qg2_trace'].update(status='FINAL_THREE_FINDINGS_REPAIR_RUNNING', accepted=False, root_integrated=False,
                         active_stage='qg2tracefinalfix', actor_pid=run['pid'],
                         pipeline_session='proc_16cc9fdf0aa8',
                         pipeline_artifact='artifacts/qg2c-trace-final-repair-pipeline-preflight-repaired.json',
                         remaining_findings={'P1': 1, 'P2': 2},
                         parent_boundary_tests={'passed': 10, 'failed': 1, 'exit_code': 101,
                                                'evidence': 'qg2c-trace-negative-ttl-before-fix'},
                         review_received='deleg_298cedca')
state['qg2_dns'].update(status='FINAL_ROOT_STATIC_REVIEW_RUNNING', accepted=False,
                       recheck_pending='deleg_ab58ec3b', previous_recheck_received='deleg_75f42e38')
state['remaining_blockers'] = [
    'Trace 추가 P1 1건/P2 2건 보정·실제 전체 회귀·독립 재QA·선택통합 전',
    'DNS 최종 root 독립 재QA deleg_ab58ec3b 및 작은 범위 수용 전',
    '실행기 도메인/DNS/Trace 연결·GUI/EXE/일반사용자/VM/실VLAN·성능 검증 전',
]
(R / 'artifacts/quick-check-progress.json').write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
section = f'''\n## 실제 개발 재개 — {now}
- 사용자 재개 지시에 따라 Flash High qg2tracefinalfix 전용 FILE ONLY actor PID {run['pid']}의 실제 agy.exe 실행 확인. 부모 감독 파이프라인 proc_16cc9fdf0aa8는 actor 종료 후 정책/실제경로/SHA 감사, rustfmt, 전체 all-targets, 독립 경계, 실제 IPv4/IPv6 loopback, strictClippy, whitespace를 순차 실행한다. 완료/수용을 미리 주장하지 않는다.
- 기존 Trace 4P1은 정적 해소 확인했으나 추가 음수TTL P1과 terminal drain 오류 판정·Job실패 raw유실 P2 두건은 미해결. 부모 새 경계시험10PASS/1FAIL(exit101) 보존 후 3건 보정 시작. root미통합/미수용.
- DNS 기존 독립재검토 deleg_75f42e38의 해소 보고는 회수했다. 부모 정형보정 후 최종root를 독립검토 deleg_ab58ec3b에 재요청. 역사root307/native17/독립6/schema77·Clippy/fmt0 소스SHA일치확인; 새 실행결과를 발명하지 않음.
- 최초 재개 preflight가 Git porcelain 선행공백을 strip해 실패했다. 실제 source 변경 전 실패를 원본 pipeline.json에 보존하고 파서만 rstrip(개행)으로 수정한 뒤 별도 preflight-repaired 증거로 재개. 전역권한/모델 변경·운영망·OS정책/DB/원격push 없음. Inspector 보호 {len(protected)}파일SHA불변.
\n'''
for filename in ['PROGRESS.md', 'RESUME.md']:
    path = R / filename
    original = path.read_text(encoding='utf-8')
    first, rest = original.split('\n', 1)
    path.write_text(first + '\n' + section + rest, encoding='utf-8', newline='\n')
output = R / '작업내용/NPI_2026-10-22_001.md'
assert not output.exists()
output.write_text('# Network Quick Check 재개 기록\n' + section, encoding='utf-8', newline='\n')
print(json.dumps({'recorded_at': now, 'actor_pid': run['pid'], 'model': run['model'],
                  'pipeline_session': 'proc_16cc9fdf0aa8', 'independent_dns_review': 'deleg_ab58ec3b',
                  'inspector_protected_unchanged': len(protected), 'accepted': False}, ensure_ascii=False))
