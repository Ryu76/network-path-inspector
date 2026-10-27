"""DNS 실행기 재QA의 실제 실패와 정책 오탐 분류·보정 실행을 기록한다."""
import csv
import datetime
import hashlib
import io
import json
import pathlib
import subprocess

R = pathlib.Path(__file__).resolve().parents[1]
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))
review = load('artifacts/qg2d-dns-runner-independent-review.json')
run = load('.harness/runs/qg2dnswirefix-qg2runner/started.json')
pipeline = load('artifacts/qg2d-dns-runner-repair-pipeline.json')
assert pipeline['status'] == 'RUNNING' and pipeline['current_step'] == 'flash-file-only'
process = subprocess.run(['tasklist.exe', '/FI', 'PID eq ' + str(run['pid']), '/FO', 'CSV', '/NH'],
                         capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=20)
assert process.returncode == 0
assert any(len(row) > 1 and row[1] == str(run['pid']) and row[0].lower() == 'agy.exe'
           for row in csv.reader(io.StringIO(process.stdout))), '실제 actor가 실행 중이어야 함'
accepted = load('artifacts/qg2c-trace-acceptance.json')
assert all(hashlib.sha256((R / relative).read_bytes()).hexdigest() == expected
           for relative, expected in accepted['source_sha256'].items())
protected = load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(hashlib.sha256((R / relative).read_bytes()).hexdigest() == expected for relative, expected in protected.items())
now = datetime.datetime.now().astimezone().isoformat()
state = load('artifacts/quick-check-progress.json')
state['recorded_at'] = now
runner = state['qg2_dns_runner']
runner.pop('review_pending', None)
runner.update(status='TWO_CONFIRMED_FINDINGS_REPAIR_RUNNING', accepted=False, root_integrated=False,
              independent_review_received='deleg_d3ed5297', confirmed_findings=review['accepted_findings'],
              rejected_findings=review['rejected_findings'],
              parent_boundary_tests={'passed': 3, 'failed': 5, 'exit_code': 101,
                                     'evidence': 'qg2d-dns-runner-review-witnesses-before-fix'},
              active_stage=run['stage'], actor_pid=run['pid'], actor_alive_at_checkpoint=True,
              pipeline_session='proc_ced874d0c623',
              pipeline_artifact='artifacts/qg2d-dns-runner-repair-pipeline.json')
state['trace_runner_contract_review'] = {'status': 'READ_ONLY_DESIGN_REVIEW_RUNNING', 'delegation': 'deleg_8a9e5c57',
                                         'implementation_started': False, 'root_integrated': False}
state['remaining_blockers'] = [
    'DNS 실행기 숨은원문/취소순서 2결함·부모5FAIL 보정 및 재QA·통합 전',
    'Trace 실제선택실행기 연결 전(설계 검토만 병행)',
    'GUI/EXE/일반사용자/VM/실VLAN·차단/성능 미검증·전체QG2수용 전',
]
(R / 'artifacts/quick-check-progress.json').write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
section = f'''\n## DNS 실행기 재검토 실패 보존·2결함 보정 시작 — {now}
- deleg_d3ed5297의3개지적중확정2건을부모가재현했다: 상세DNS미선택시성공/실패DTO원문유실2사례, [TCP/Ping/Host,DNS] 역순선택에서취소가완료DNS를버리는3사례. 새 parent_8시험은3PASS/5FAIL exit101. 이전115/native3/Clippy0은이실패를덮지않는다. root미통합·미수용.
- DNS-RUNNER-001의'IP도선택DNS실패시독립검사를막자'는원래승인prompt의IP독립정책과충돌해수용하지않음. 원본prompt SHA·명시문구·2개실행positive control을reviewartifact에보존. 실제 DNS UNKNOWN/LOCAL_ERROR와별개로기존검증IP의TCP/Ping/Host·원래귀속을유지한다.
- 기준보존commit {review['preserved_commit']} 후 Flash qg2dnswirefix 실제 PID{run['pid']} 실행확인. proc_ced874d0c623 유한감독기는보정종료뒤실제도구/범위/SHA 감사→부모실패회귀→전체시험→소유localhost native→Clippy/whitespace를진행하며기존실패증거는덮지않는다. actor2파일외수정금지. details는3필드계약유지·검증된DNS전체JSON을limitations문자열로보존·불량host/자격증명원문비반사.
- 수용된 root Trace/DNS 모듈과Inspector보호{len(protected)}파일SHA변경0. root364/native19의직전수용범위는유지하되전체QG2/GUI/EXE수용아님. 다음Trace실행기연결의읽기전용계약검토 deleg_8a9e5c57 병행중이며아직구현시작아님.
\n'''
for name in ['PROGRESS.md', 'RESUME.md']:
    path = R / name
    text = path.read_text(encoding='utf-8')
    first, rest = text.split('\n', 1)
    path.write_text(first + '\n' + section + rest, encoding='utf-8', newline='\n')
path = R / '작업내용/NPI_2026-10-22_001.md'
path.write_text(path.read_text(encoding='utf-8') + section, encoding='utf-8', newline='\n')
print(json.dumps({'stage': run['stage'], 'actor_pid': run['pid'], 'confirmed_findings': len(review['accepted_findings']),
                  'rejected_findings': len(review['rejected_findings']), 'parent_passed': 3, 'parent_failed': 5,
                  'root_accepted_source_unchanged': True, 'inspector_unchanged': len(protected),
                  'pipeline_session': 'proc_ced874d0c623'}, ensure_ascii=False))
