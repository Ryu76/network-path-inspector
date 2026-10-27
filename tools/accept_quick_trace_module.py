"""최종 root 회귀와 독립 재검토를 근거로 단독 Trace 모듈만 수용한다."""
import datetime
import hashlib
import json
import pathlib
import re

R = pathlib.Path(__file__).resolve().parents[1]
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()


def counts(name):
    data = load('artifacts/commands/' + name + '.json')
    assert data['exit_code'] == 0 and not data['partial'], name
    text = (R / 'artifacts/commands' / (name + '.log')).read_text(encoding='utf-8')
    rows = re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
    result = {key: sum(int(row[i]) for row in rows) for i, key in enumerate(['passed', 'failed', 'ignored'])}
    if rows:
        assert result['passed'] > 0 and result['failed'] == 0
    return {'evidence': name, 'exit_code': 0, 'started_at': data['started_at'], **result}


proof = load('artifacts/qg2c-trace-integration.json')
for relative, expected in proof['source_sha256'].items():
    assert sha(R / relative) == expected, relative
for relative in ['crates/network-core/src/quick.rs', 'schemas/quick-check-result-1.0.schema.json']:
    assert sha(R / relative) == load('artifacts/qg1-acceptance.json')['source_sha256'][relative]
protected = load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(sha(R / relative) == expected for relative, expected in protected.items())
execution = {name: counts(name) for name in [
    'qg2c-trace-integrated-workspace', 'qg2c-trace-integrated-native',
    'qg2c-trace-integrated-clippy', 'qg2c-trace-integrated-fmt', 'qg2c-trace-integrated-boundaries']}
now = datetime.datetime.now().astimezone().isoformat()
record = {
    'recorded_at': now, 'slice': 'QG2-C-TRACE',
    'decision': 'ACCEPTED_STANDALONE_ICMP_TRACE_MODULE_AND_ADAPTER_ONLY',
    'independent_reviews': ['deleg_dcaefab3', 'deleg_298cedca', 'deleg_7622500b'],
    'final_review': {'id': 'deleg_7622500b', 'reviewers': 2, 'findings': [],
                     'scope': ['부호/범위외TTL와parser·adapter성공게이트', '최종drain오류 fail-closed·Job실패 raw보존·공통helper연결'],
                     'limitations': '읽기전용 정적검토. 실제 Win32 오류/Job실패 주입을 실행한 결과는 아님'},
    'execution': execution, 'source_sha256': proof['source_sha256'],
    'root_integrated': True, 'inspector_protected_unchanged': len(protected),
    'full_qg2_accepted': False, 'product_accepted': False,
    'excluded': ['실제선택실행기의 Trace 기능 연결', '제품GUI/단일EXE/PE·서명/일반사용자/VM 인증',
                 '실VLAN/DROP/ICMP차단/다중NIC/VPN/성능 실측', 'OS오류 주입 및 엄격한 OS hard realtime 보장',
                 'Inspector 전체 G2'],
    'preserved_pipeline_failure': 'artifacts/qg2c-trace-final-repair-pipeline-preflight-repaired.json',
    'recovery': '과거증거파일명충돌 차단은 보존하고 새이름Clippy/whitespace를 실제재실행. 본수용은별도fresh root회귀가모두0인근거에의함',
}
out = R / 'artifacts/qg2c-trace-acceptance.json'
assert not out.exists()
out.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
review = load('artifacts/qg2c-trace-independent-review.json')
review.pop('recheck_pending', None)
review.update(final_recheck='deleg_7622500b', remaining_findings=[], accepted=True, root_integrated=True,
              acceptance_artifact=str(out.relative_to(R)))
for item in review['findings']:
    item['status'] = 'RESOLVED'
(R / 'artifacts/qg2c-trace-independent-review.json').write_text(json.dumps(review, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
runner_w = R / '.worktrees/qg2runner'
runner_pipeline = load('artifacts/qg2d-dns-runner-pipeline.json')
assert runner_pipeline['status'] == 'BLOCKED_PRESERVED_FOR_REVIEW'
runner_execution = {name: counts(name) for name in [
    'qg2d-dns-runner-parent-all-targets', 'qg2d-dns-runner-parent-native', 'qg2d-dns-runner-parent-clippy']}
runner_sha = {relative: sha(runner_w / relative) for relative in [
    'crates/network-core/src/runner.rs', 'crates/network-core/tests/runner.rs']}
assert runner_sha['crates/network-core/src/runner.rs'] == runner_pipeline['canonical_source_sha256']['crates/network-core/src/runner.rs']
runner_record = {'recorded_at': now, 'state': 'EXECUTION_PASS_INDEPENDENT_REVIEW_PENDING',
                 'source_sha256': runner_sha, 'execution': runner_execution, 'actor_policy_passed': True,
                 'parent_adjustments': '프로덕션 의미 변경 없음. 기존 TCP 취소 훅을 사용하는 회귀 1개를 추가해 unused Clippy를 해소했다. native fixture의 묵시적 IPv6 .ok와 넓은 loopback 검사를 expect 및 정확한 127.0.0.1/::1·동일 helper 검증으로 교체하고 호출 수/원문/첫 후보 귀속 단언을 강화했다. rustfmt 적용.',
                 'independent_review': 'deleg_d3ed5297', 'root_integrated': False, 'accepted': False}
runner_out = R / 'artifacts/qg2d-dns-runner-parent-execution.json'
assert not runner_out.exists()
runner_out.write_text(json.dumps(runner_record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
state = load('artifacts/quick-check-progress.json')
state['recorded_at'] = now
trace = state['qg2_trace']
trace.pop('recheck_pending', None)
trace.pop('active_stage', None)
trace['last_actor_pid'] = trace.pop('actor_pid', None)
trace.update(status=record['decision'], accepted=True, root_integrated=True, runner_connected=False,
             actor_alive=False, final_review='deleg_7622500b', latest_execution=record,
             acceptance_artifact=str(out.relative_to(R)))
state['qg2_dns_runner'].update(status=runner_record['state'], actor_alive_at_checkpoint=False,
                               latest_execution=runner_record, review_pending='deleg_d3ed5297',
                               accepted=False, root_integrated=False)
state['remaining_blockers'] = [
    'DNS 실행기 연결은 별도worktree 단위/native/Clippy통과, 독립QA deleg_d3ed5297 및 root통합 전',
    'Trace 실제선택실행기 연결 미완료', 'GUI/EXE/일반사용자/VM/실VLAN·차단/성능 미검증·전체QG2수용 전',
]
(R / 'artifacts/quick-check-progress.json').write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
section = f'''\n## 단독 Trace 공유모듈 수용 / DNS 실행기 독립QA — {now}
- Trace 최종독립2검토자 deleg_7622500b: 마지막음수TTL P1·최종drain/Job실패 raw보존 P2두건 정적해소·추가확정차단0. 검토canonical두파일과같은바이트를root선택통합하고이미잠긴windows-sys0.61.2의직접edge/Win32 features만추가. package/version변경0·Inspector보호{len(protected)}파일SHA불변.
- 새 root 전체{execution['qg2c-trace-integrated-workspace']['passed']}PASS/0FAIL, 명시소유native{execution['qg2c-trace-integrated-native']['passed']}PASS/0FAIL, root독립Trace{execution['qg2c-trace-integrated-boundaries']['passed']}PASS/0FAIL, workspace strictClippy/fmt0. 첫감독명령경로quoting오류로Cargo미실행한5개시도는별도실패artifact보존후forward-slash/quote로정정·실제실행한결과다.
- 수용범위는단독ICMP Trace모듈·어댑터만. 실제선택실행기는Trace UNAVAILABLE유지. native2loopback와pure오류fixture는실제Win32 Job실패주입/OS hard realtime/VM인증증거가아니다. 전체QG2/GUI/EXE/실VLAN/성능미수용.
- 별도DNS 실행기 qg2dnswire도actor종료/정책감사통과후Core{runner_execution['qg2d-dns-runner-parent-all-targets']['passed']}PASS/native{runner_execution['qg2d-dns-runner-parent-native']['passed']}PASS/strictClippy0. unused시험hook을삭제/suppress하지않고부모TCP후취소회귀로활용,소유nativefixture와단언강화. production코드의부모의미수정없음. deleg_d3ed5297 두독립QA대기,root미통합/미수용.
\n'''
for name in ['PROGRESS.md', 'RESUME.md']:
    path = R / name
    text = path.read_text(encoding='utf-8')
    first, rest = text.split('\n', 1)
    path.write_text(first + '\n' + section + rest, encoding='utf-8', newline='\n')
path = R / '작업내용/NPI_2026-10-22_001.md'
path.write_text(path.read_text(encoding='utf-8') + section, encoding='utf-8', newline='\n')
print(json.dumps({'decision': record['decision'], 'root_tests': execution['qg2c-trace-integrated-workspace'],
                  'root_native': execution['qg2c-trace-integrated-native'], 'root_boundaries': execution['qg2c-trace-integrated-boundaries'],
                  'dns_runner_execution': runner_execution, 'full_qg2_accepted': False}, ensure_ascii=False))
