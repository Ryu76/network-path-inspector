"""소스 검토 대기 제한 실패를 기록하고 감사 완료 후 재요청한 QA 상태를 보존한다."""
import datetime
import hashlib
import json
import pathlib

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qg2runner'
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))
pipeline = load('artifacts/qg2e-trace-runner-pipeline.json')
assert pipeline['status'] == 'AUDITED_SOURCE_READY_FOR_PARENT_REVIEW'
assert pipeline['formatting_and_execution_deferred']
assert load('artifacts/qg2tracewire-actor-policy-audit.json')['all_actor_policy_checks_passed']
assert all(hashlib.sha256((W / path).read_bytes()).hexdigest() == expected
           for path, expected in pipeline['source_sha256'].items())
now = datetime.datetime.now().astimezone().isoformat()
record = {
    'recorded_at': now, 'old_review': 'deleg_1fd6a188', 'old_review_status': 'REVIEW_BLOCKED_NOT_STARTED',
    'old_review_count': 2, 'findings_meaning': '빈 findings는통과아님·소스검토미실시',
    'control_failure': '명령timeout590/OSWait550으로요청했으나도구전송계층이420초에중단. 명시exit124/review_ready를얻지못하여검토를시작하지않은것은정상failclosed동작',
    'confirmed_transcript': 'C:/Users/HODI/AppData/Local/hermes/cache/delegation/live/deleg_1fd6a188/task-0.log:9-14',
    'correction': '대기기본300·상한360으로낮춤. 부모가짧은OSWait 호출에서실제exit0/review_ready=true와감사·SHA완료를확인한뒤명령없는새독립QA를요청',
    'producer_status': pipeline['status'], 'producer_finished_at': pipeline['finished_at'],
    'source_sha256': pipeline['source_sha256'], 'new_review': 'deleg_24f5e52c',
    'source_formatted': False, 'source_compiled': False, 'default_tests_executed': False,
    'native_tests_executed': False, 'root_integrated': False, 'accepted': False,
}
out = R / 'artifacts/qg2e-trace-runner-review-control.json'
assert not out.exists()
out.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
state = load('artifacts/quick-check-progress.json')
state['recorded_at'] = now
state['qg2_trace_runner'].update(status='AUDITED_SOURCE_READY_STATIC_REVIEW_REDISPATCHED',
                                actor_alive_at_checkpoint=False, latest_source=pipeline,
                                review_control=str(out.relative_to(R)),
                                independent_review='deleg_24f5e52c', accepted=False, root_integrated=False,
                                source_formatted=False, source_compiled=False, native_executed=False)
state['remaining_blockers'] = ['Trace 실행기 소스안전/계약QA deleg_24f5e52c 완료 후 format/컴파일/순수/소유native/Clippy·root통합 전',
                               '제품helper dispatch/GUI/EXE/VM/일반사용자/실VLAN·성능·전체QG2 미완료']
(R / 'artifacts/quick-check-progress.json').write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
section = f'''\n## Trace 소스 작성·감사 완료 / 검토 제어 timeout 복구 — {now}
- qg2tracewire Flash actor작성종료·실제67 FILE READ/EDIT 도구/경로감사통과. source/tests 정확2파일만변경. 부모가실제게이트exit0·review_ready=true·불변SHA를확인했다. 후보SHA는review-control artifact에고정. 아직format/compile/시험/native실행없음·root미통합·미수용.
- 선행QA2건 deleg_1fd6a188는도구전송계층420초timeout으로소스미열람·미검토로끝났다. findings빈배열을통과로해석하지않고control실패로보존. 명령timeout590과OSWait550이실효도구한도보다길었던감독자설계문제이며제품결함/producer실패로꾸미지않음.
- 대기helper기본300/최대360으로축소후부모짧은대기에서게이트완료를실제로확인. 이제대기명령없는독립정적QA2건 deleg_24f5e52c를재요청했다. 기본시험pure격리·native ignore/정확소유대상·Trace raw/IP/기존DNS취소회귀검토가끝나기전코드를실행하지않음.
- root는기존DNS연결수용380/native20범위그대로. Trace는단독모듈+OS코드보정수용과새실행기후보를구분. GUI/EXE·전체QG2미완료.
\n'''
for filename in ['PROGRESS.md', 'RESUME.md']:
    path = R / filename
    text = path.read_text(encoding='utf-8')
    first, rest = text.split('\n', 1)
    path.write_text(first + '\n' + section + rest, encoding='utf-8', newline='\n')
path = R / '작업내용/NPI_2026-10-22_001.md'
path.write_text(path.read_text(encoding='utf-8') + section, encoding='utf-8', newline='\n')
print(json.dumps({'producer_status': pipeline['status'], 'source_sha256': pipeline['source_sha256'],
                  'review': 'deleg_24f5e52c', 'old_review_status': record['old_review_status'],
                  'tests_executed': False, 'accepted': False}, ensure_ascii=False))
