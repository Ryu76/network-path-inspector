"""Trace 수정 writer의 실제 가동과 선행 실패를 진행 기록에 반영한다."""
import csv
import datetime
import hashlib
import io
import json
import pathlib
import subprocess

R = pathlib.Path(__file__).resolve().parents[1]
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))
started = load('.harness/runs/qg2tracewirefix-qg2runner/started.json')
review = load('artifacts/qg2e-trace-runner-independent-review.json')
assert started['stage'] == 'qg2tracewirefix' and started['model'] == 'gemini-3.8-flash-high'
p = subprocess.run(['tasklist.exe', '/FI', f"PID eq {started['pid']}", '/FO', 'CSV', '/NH'],
                   capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=20)
assert p.returncode == 0
alive = any(len(row) > 1 and row[1] == str(started['pid']) and row[0].lower() == 'agy.exe'
            for row in csv.reader(io.StringIO(p.stdout)))
protected = load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(hashlib.sha256((R / path).read_bytes()).hexdigest() == expected for path, expected in protected.items())
dns = load('artifacts/qg2d-dns-runner-acceptance.json')
assert dns['accepted']
assert all(hashlib.sha256((R / path).read_bytes()).hexdigest() == expected for path, expected in dns['source_sha256'].items())
now = datetime.datetime.now().astimezone().isoformat()
state = load('artifacts/quick-check-progress.json')
state['recorded_at'] = now
state['qg2_trace_runner'].update(
    status='REVIEW_FINDINGS_CONFIRMED_FLASH_REPAIR_RUNNING', stage=started['stage'],
    model=started['model'], actor_pid=started['pid'], actor_alive_at_checkpoint=alive,
    pipeline_session='proc_cfd14d6867d9', pipeline_artifact='artifacts/qg2e-trace-runner-repair-pipeline.json',
    independent_review='deleg_24f5e52c_COMPLETED_WITH_BLOCKERS',
    findings_artifact='artifacts/qg2e-trace-runner-independent-review.json',
    source_compiled_before_repair=True, baseline_tests=review['parent_test_counts'],
    native_executed=False, accepted=False, root_integrated=False,
    preserved_unaccepted_commit=review['preserved_commit'],
    execution_policy='writer 종료·범위/도구감사·SHA 고정 뒤 native 목적지 guard와 성공증거 단언 재검토 후 부모 실행')
state['remaining_blockers'] = [
    'Trace 오류 원문 반사9회귀실패·native 거짓양성 단언·localhost 목적지 TOCTOU 수정 중',
    'Trace 누적counter 시험오류/실행중취소·예산 회귀 보완 후 순수전체/native/독립재QA/root통합 전',
    '제품helper dispatch/GUI/EXE/VM/일반사용자/실VLAN·성능·전체QG2 미완료']
(R / 'artifacts/quick-check-progress.json').write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
section = f'''\n## Trace 독립 QA 차단 재현·Flash 수정 실제 재개 — {now}
- 독립QA deleg_24f5e52c 두검토자결과를부모소스와대조: 원문반사 P1, native실측성공단언공백 P2, localhost실제재조회목적지검사TOCTOU high 세종류수용. 사전조회검사만요구했던원래부모프롬프트도불충분했으며시험전용위임guard로보정한다. 제품DNS첫후보/IP독립정책은그대로유지.
- 부모합성마커12회귀를새로추가해실제offline/locked 실행: 3PASS/9FAIL(exit101). 기본Core --all-targets도실행중 runner 38PASS/10FAIL/5ignored에서중단; 실행완료바이너리합계는artifact의134PASS/10FAIL/6ignored이고전체suite완주아님. 추가1FAIL은동일mock누적TCP/Ping카운터를0으로잘못기대한시험오류. 원문실패와섞어숨기지않음. native미실행.
- 실패source/tests는전용branch WIP commit {review['preserved_commit']}로보존(미수용·미통합). Flash High qg2tracewirefix 실제PID {started['pid']}, 가동확인={alive}; 감독proc_cfd14d6867d9가두파일만수정하도록실행중. 원문반사고정오류·native실측단언·실제resolve및위임직전소유주소guard·취소await/예산회귀·누적counter를범위로고정.
- 수정감독은FILE ONLY종료→정책/경로감사→SHA고정후검토gate까지만수행. writer실행중부모Cargo/format없음. native목적지guard와성공단언재검토전실행금지. root는기존DNS수용상태유지, Inspector보호{len(protected)}파일SHA불변. GUI/EXE·전체QG2미완료.
\n'''
for filename in ['PROGRESS.md', 'RESUME.md']:
    path = R / filename
    text = path.read_text(encoding='utf-8')
    first, rest = text.split('\n', 1)
    path.write_text(first + '\n' + section + rest, encoding='utf-8', newline='\n')
path = R / '작업내용/NPI_2026-10-22_001.md'
path.write_text(path.read_text(encoding='utf-8') + section, encoding='utf-8', newline='\n')
print(json.dumps({'actor_pid': started['pid'], 'actor_alive': alive, 'stage': started['stage'],
                  'preserved_commit': review['preserved_commit'], 'parent_test_counts': review['parent_test_counts'],
                  'inspector_unchanged': len(protected), 'native_executed': False, 'accepted': False}, ensure_ascii=False))
