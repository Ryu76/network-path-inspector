"""Trace 수정 후보의 부모 순수 실행·기계 게이트와 잔여 독립 QA 경계를 기록한다."""
import datetime
import hashlib
import json
import pathlib
import re

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qg2runner'
PATHS = ['crates/network-core/src/runner.rs', 'crates/network-core/tests/runner.rs']
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
now = datetime.datetime.now().astimezone().isoformat()
producer = load('artifacts/qg2e-trace-runner-repair-pipeline.json')
assert producer['status'] == 'AUDITED_SOURCE_READY_FOR_PARENT_REVIEW'
assert load('artifacts/qg2tracewirefix-actor-policy-audit.json')['all_actor_policy_checks_passed']
evidence = {}
counts = {}
for suffix in ['all-targets', 'clippy', 'fmt', 'whitespace']:
    name = 'qg2e-trace-runner-parent-final-' + suffix
    data = load('artifacts/commands/' + name + '.json')
    assert data['exit_code'] == 0 and not data['partial']
    evidence[suffix] = data
    if suffix == 'all-targets':
        text = pathlib.Path(data['log']).read_text(encoding='utf-8')
        rows = re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
        assert len(rows) == 7
        counts = {key: sum(int(row[i]) for row in rows)
                  for i, key in enumerate(['passed', 'failed', 'ignored'])}
        assert counts['failed'] == 0 and counts['passed'] > 0
        assert len(re.findall(r'test parent_trace_reject_\S+ \.\.\. ok', text)) == 12
protected = load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(sha(R / path) == expected for path, expected in protected.items())
frozen = load('artifacts/qg2e-trace-runner-prepared.json')['dependency_source_sha256']
assert all(sha(W / path) == expected for path, expected in frozen.items() if path not in PATHS)
canonical = {path: sha(W / path) for path in PATHS}
record = {
    'recorded_at': now, 'status': 'PURE_EXECUTION_PASS_NATIVE_AND_FINAL_REVIEW_PENDING',
    'actor': 'qg2tracewirefix', 'actor_source_sha256': producer['source_sha256'],
    'canonical_source_sha256': canonical, 'independent_review': 'deleg_cfe9fa59',
    'test_counts': counts, 'rejection_witnesses': {'passed': 12, 'failed': 0, 'included_in_full_counts': True},
    'evidence': evidence,
    'preserved_failures': [
        'artifacts/commands/qg2e-trace-runner-rejection-before-fix.json',
        'artifacts/commands/qg2e-trace-runner-default-before-fix.json',
        'artifacts/commands/qg2e-trace-runner-repair-all-targets.json',
        'artifacts/commands/qg2e-trace-runner-repair-clippy.json',
        'artifacts/commands/qg2e-trace-runner-parent-recheck-clippy.json'],
    'parent_changes_after_actor': [],
    'parent_change_summary_ko': 'Clippy 동등정리·잘못 추정한예산fixture 실직렬화교정·순수취소/호출0 단언강화. native guard/성공helper 의미변경없음.',
    'protected_inspector_unchanged': len(protected),
    'native_executed': False, 'root_integrated': False, 'accepted': False,
    'limitations': ['독립QA 완료 결과 수신 전. 최종 부모 동등/fixture 변경까지 재검토 필요',
                    'native runner5개·standalone native2개·DNS native1개는 기본실행에서ignored이며 통과로 산입하지 않음',
                    '실제Trace/localhost소유guard 재QA 후에만 명시native 실행. 전체QG2/GUI/EXE/OS/성능 수용 아님'],
}
# 기록은 한국어로 유지한다.
record['parent_changes_after_actor'] = [
    '정확2파일 rustfmt',
    'production map_or(false,is_empty)→is_some_and(is_empty) 동등 Clippy 정리',
    'native시험guard ASCII 비교를 eq_ignore_ascii_case로 동등 변경',
    '미사용 report2/3/4를 호출0/errors 명시 단언으로 사용·삭제/suppress 없음',
    '예산fixture 추정2500padding을 실제serde길이 예산3/4~7/8 선택으로 교정. 4096상한/보관1/누락2/호출2 유지 및 started/completed2·정확bytes 단언 추가',
    '순수취소future20ms 비동기delay·rawCANCELLED/DNS원문/호출수 단언 강화']
out = R / 'artifacts/qg2e-trace-runner-parent-execution.json'
assert not out.exists()
out.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
state = load('artifacts/quick-check-progress.json')
state['recorded_at'] = now
state['qg2_trace_runner'].update(status=record['status'], actor_alive_at_checkpoint=False,
    pipeline_artifact='artifacts/qg2e-trace-runner-repair-pipeline.json',
    parent_execution=str(out.relative_to(R)), canonical_source_sha256=canonical,
    parent_test_counts=counts, independent_review='deleg_cfe9fa59', source_compiled=True,
    source_formatted=True, native_executed=False, accepted=False, root_integrated=False)
state['remaining_blockers'] = ['Trace 수정 후보 기본순수/Clippy/fmt 통과; 독립재QA·부모동등정리/fixture교정 검토·native안전확인 후 실제native 및 root통합 전',
                               '제품helper dispatch/GUI/EXE/VM/일반사용자/실VLAN·성능·전체QG2 미완료']
(R / 'artifacts/quick-check-progress.json').write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
section = f'''\n## Trace 수정 후보 부모 순수 검증 통과·native/최종 QA 전 — {now}
- Flash qg2tracewirefix exit0·46 FILE READ/EDIT·정확2파일·정책/경로감사통과. 부모작성전SHA재계산일치확인후실행전source를읽어mock기본시험·ignored native 분리·소유주소guard와실측성공helper를검토했다. 추가독립2검토자 deleg_cfe9fa59 회수전이며native미실행.
- 오류원문거부 부모12회귀는실제12PASS/0FAIL. 최초수정후Core실행중 새예산시험1FAIL 및Clippy실패를별도보존했다. limitation이details/raw에두번보관되는데2500padding을단일row약2600B로잘못추정한시험fixture문제: 첫row부터4096초과해보관0. 부모가실제serde길이로한row 예산3/4~7/8을선택해보관1/누락2/호출2·4096상한을그대로검증하도록교정했다. 기준상향/실패삭제없음.
- 부모production은is_some_and 동등1줄·testguard ASCII동등정리만; 미사용report는호출0/errors단언추가, 취소future20ms비동기delay·원시CANCELLED/DNS보존을강화했다. actor독점작성으로표현하지않음.
- 최종동일소스 cargo test --offline --locked -p network-core --all-targets: {counts['passed']}PASS/{counts['failed']}FAIL/{counts['ignored']}ignored, strictClippy/fmt/whitespace exit0. 원문12회귀는이합계내포함(더하지않음). 실제ignored미실행은PASS아님. 상세명령/원래실패/actor·parentSHA는parent-execution artifact에연결.
- root미통합·미수용, Inspector보호{len(protected)}SHA불변·그외동결의존소스불변. native목적지guard 독립확인전실행금지, 독립QA가부모최종교정전소스를읽었을수있으므로차이범위확인도필요. 전체QG2/GUI/EXE/VM·성능미완료.
\n'''
for name in ['PROGRESS.md', 'RESUME.md']:
    path = R / name
    first, rest = path.read_text(encoding='utf-8').split('\n', 1)
    path.write_text(first + '\n' + section + rest, encoding='utf-8', newline='\n')
path = R / '작업내용/NPI_2026-10-22_001.md'
path.write_text(path.read_text(encoding='utf-8') + section, encoding='utf-8', newline='\n')
print(json.dumps({'status':record['status'], 'test_counts': counts, 'canonical_source_sha256':canonical,
                  'protected':len(protected), 'native_executed':False, 'accepted':False}, ensure_ascii=False))
