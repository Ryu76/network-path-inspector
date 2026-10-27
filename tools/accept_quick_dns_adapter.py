"""최종 root 독립 재검토와 새 실행 증거로 DNS 어댑터 범위만 수용한다."""
import datetime
import hashlib
import json
import pathlib
import re
import shutil

R = pathlib.Path(__file__).resolve().parents[1]
load = lambda relative: json.loads((R / relative).read_text(encoding='utf-8'))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()


def counts(name):
    metadata = load('artifacts/commands/' + name + '.json')
    assert metadata['exit_code'] == 0 and not metadata['partial'], name
    text = (R / 'artifacts/commands' / (name + '.log')).read_text(encoding='utf-8')
    rows = re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
    assert rows and sum(int(row[0]) for row in rows) > 0, name
    result = {key: sum(int(row[i]) for row in rows) for i, key in enumerate(['passed', 'failed', 'ignored'])}
    assert result['failed'] == 0
    return {'evidence': name, 'started_at': metadata['started_at'], 'exit_code': 0, **result}


proof = load('artifacts/qg2c-dns-repaired-execution.json')
for relative, expected in proof['source_sha256'].items():
    assert sha(R / relative) == expected, relative
qg1 = load('artifacts/qg1-acceptance.json')
for relative in ['crates/network-core/src/quick.rs', 'schemas/quick-check-result-1.0.schema.json']:
    assert sha(R / relative) == qg1['source_sha256'][relative], relative
protected = load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(sha(R / relative) == expected for relative, expected in protected.items())
for name in ['qg2c-dns-root-strict-clippy', 'qg2c-dns-root-fmt', 'qg2c-dns-root-native']:
    metadata = load('artifacts/commands/' + name + '.json')
    assert metadata['exit_code'] == 0 and not metadata['partial'], name
assert load('artifacts/qg2c-dns-root-schema.json')['failed'] == 0
fresh_root = counts('qg2c-dns-final-root-recheck')
fresh_independent = counts('qg2c-dns-final-independent-recheck')
assert fresh_independent['passed'] == 6
# 이전 actor 계약의 위치를 바로잡되 원본 바이트를 수정하거나 재작성하지 않는다.
contract_source = R / '.worktrees/qgdns/.harness/references/quick-dns-contract.json'
contract_target = R / '.harness/references/quick-dns-contract.json'
contract = json.loads(contract_source.read_text(encoding='utf-8'))
assert contract['version'] == 'qg2c-dns-0.1'
assert len(contract['requirements']) == 7
if contract_target.exists():
    assert contract_target.read_bytes() == contract_source.read_bytes()
else:
    shutil.copyfile(contract_source, contract_target)
assert sha(contract_source) == sha(contract_target)
now = datetime.datetime.now().astimezone().isoformat()
review = {
    'recorded_at': now, 'delegation': 'deleg_ab58ec3b', 'type': 'INDEPENDENT_STATIC_REVIEW_OF_FINAL_ROOT',
    'findings': [], 'original_categories_resolved': [
        'RESOLVED 및 오류/주소 모순', '불량 host 거부 및 거부 오류 원문 비반사', 'literal 단일 동일 IP/port 귀속'],
    'original_finding_id_mapping_by_parent': ['QG2DNS-01', 'QG2DNS-02', 'QG2DNS-03'],
    'parent_adjustments_reviewed': 'let-chain 3곳과 match guard 1곳에서 의미 변경 발견하지 않음',
    'reviewer_limitations': [
        '정적검토이며 명령/시험/네트워크/수정을 실행하지 않음',
        '리뷰 시 root reference 계약 파일은 없었으며 직접 계약 대조를 수행하지 못함',
        '제품 runner/EXE/OS/전체QG2 수용은 범위 밖'],
    'parent_contract_check': {
        'actual_contract': str(contract_source.relative_to(R)),
        'root_reference_copy': str(contract_target.relative_to(R)),
        'sha256': sha(contract_target),
        'checked': '부모가 실제 계약 7개 요구를 읽고 root API/매핑/검증/시험/원문보존 범위를 대조. 제품 helper dispatch 연결은 수용 제외'},
    'source_sha256_verified_by_parent': proof['source_sha256'],
}
review_path = R / 'artifacts/qg2c-dns-final-static-review.json'
acceptance_path = R / 'artifacts/qg2c-dns-acceptance.json'
assert not review_path.exists() and not acceptance_path.exists()
record = {
    'recorded_at': now, 'slice': 'QG2-C-DNS',
    'decision': 'ACCEPTED_SHARED_RESOLVER_AND_DNS_ADAPTER_ONLY',
    'independent_reviews': ['deleg_59c8e74b', 'deleg_75f42e38', 'deleg_ab58ec3b'],
    'final_static_review': str(review_path.relative_to(R)),
    'new_findings': [], 'root_integrated': True,
    'execution': {'fresh_workspace': fresh_root, 'fresh_independent': fresh_independent},
    'historical_same_source_evidence': {
        'recorded_at': proof['recorded_at'], 'native': proof['root_native'],
        'strict_clippy': proof['strict_clippy'], 'fmt': proof['fmt'], 'schema_checks': proof['schema_checks']},
    'source_sha256': proof['source_sha256'], 'inspector_protected_unchanged': len(protected),
    'full_qg2_accepted': False, 'product_accepted': False,
    'excluded': [
        '도메인 필수해석/상세DNS/Trace의 실제 선택실행기 연결',
        '제품 EXE의 같은실행파일 helper 분기 연결 및 제품 배포',
        'DNS 서버/RR/TTL/패킷 관찰, 실제 접속 IP 선택',
        '극단적 OS kill/wait 실패와 손자stdout상속에 대한 hard realtime 보장',
        'GUI/단일EXE/일반사용자/VM/실VLAN·차단·성능 및 Inspector 전체G2'],
}
review_path.write_text(json.dumps(review, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
acceptance_path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
old_review = load('artifacts/qg2c-dns-independent-review.json')
old_review.pop('recheck_pending', None)
old_review.update(final_recheck='deleg_ab58ec3b', accepted=True, root_integrated=True,
                  remaining_findings=[], acceptance_artifact=str(acceptance_path.relative_to(R)),
                  latest_execution={'root': fresh_root, 'independent': fresh_independent})
for finding in old_review['findings']:
    finding['status'] = 'RESOLVED'
(R / 'artifacts/qg2c-dns-independent-review.json').write_text(json.dumps(old_review, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
state = load('artifacts/quick-check-progress.json')
state['recorded_at'] = now
state['qg2_dns'].pop('recheck_pending', None)
state['qg2_dns'].update(status='ACCEPTED_SHARED_RESOLVER_AND_DNS_ADAPTER_ONLY', accepted=True,
                       final_review='deleg_ab58ec3b', acceptance_artifact=str(acceptance_path.relative_to(R)),
                       latest_execution={'root': fresh_root, 'independent': fresh_independent},
                       root_integrated=True, runner_connected=False, product_accepted=False)
state['remaining_blockers'] = [item for item in state['remaining_blockers'] if 'DNS 최종 root 독립 재QA' not in item]
(R / 'artifacts/quick-check-progress.json').write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
section = f'''\n## DNS 공유모듈·어댑터 작은 범위 수용 — {now}
- 최종root 독립 재검토 deleg_ab58ec3b: 기존3P1 해소·추가확정차단0. 부모 Clippy4곳 동등변환도 검토. root 계약 reference 경로 누락 한계는 숨기지 않고 실제 qgdns 계약 7개 요구를 부모가 대조·원본바이트SHA가 같은 root 참조 사본으로 보완했다.
- 새 offline/locked 전체workspace {fresh_root['passed']}PASS/{fresh_root['failed']}FAIL 및 독립6PASS/0FAIL(exit0). 소스SHA는 기존명시native17/schema77/Clippy/fmt0의 시험본과 일치. native17은10월21일 동일소스의 역사 실행증거이며 오늘 새로실행한 수치가 아니다. Inspector보호{len(protected)}파일SHA불변.
- 수용은 공유resolver/DNS어댑터 API만. 실제도메인/DNS 실행기 연결·제품helper분기·Trace/GUI/EXE/VM/성능 및전체QG2는 미수용. Trace는 별도 Flash 전용 보정·감사/시험 감독 파이프라인 실행 중이며 이 수용으로 성공 처리하지 않는다. 근거 artifacts/qg2c-dns-acceptance.json.
\n'''
for name in ['PROGRESS.md', 'RESUME.md']:
    path = R / name
    text = path.read_text(encoding='utf-8')
    first, rest = text.split('\n', 1)
    path.write_text(first + '\n' + section + rest, encoding='utf-8', newline='\n')
path = R / '작업내용/NPI_2026-10-22_001.md'
path.write_text(path.read_text(encoding='utf-8') + section, encoding='utf-8', newline='\n')
print(json.dumps({'decision': record['decision'], 'fresh_root': fresh_root, 'fresh_independent': fresh_independent,
                  'full_qg2_accepted': False, 'inspector_unchanged': len(protected)}, ensure_ascii=False))
