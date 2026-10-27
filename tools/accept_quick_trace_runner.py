"""최종 재QA와 root 조합 회귀를 근거로 선택 ICMP Trace 실행기 범위만 수용한다."""
import datetime
import hashlib
import json
import pathlib
import subprocess

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qg2runner'
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
proof = load('artifacts/qg2e-trace-runner-root-validation.json')
assert proof['status'] == 'ROOT_EXECUTION_PASS_ACCEPTANCE_RECORD_PENDING'
assert all(step['exit_code'] == 0 and not step['partial'] for step in proof['steps'])
assert len(proof['steps']) == 6
assert all(sha(R / path) == expected for path, expected in proof['source_sha256'].items())
paths = ['crates/network-core/src/runner.rs', 'crates/network-core/tests/runner.rs']
assert all(sha(W / path) == proof['source_sha256'][path] for path in paths)
review = load('artifacts/qg2e-trace-runner-final-independent-review.json')
assert review['review'] == 'deleg_45855748' and review['findings'] == []
assert len(review['transcripts']) == 2
assert all(sha(pathlib.Path(data['path'])) == data['sha256'] for data in review['transcripts'].values())
assert all(sha(R / path) == value for path, value in review['source_sha256'].items())
protected = load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(sha(R / path) == expected for path, expected in protected.items())
trace = load('artifacts/qg2c-trace-os-code-acceptance.json')
assert all(sha(R / path) == expected for path, expected in trace['source_sha256'].items())
frozen = load('artifacts/qg2e-trace-runner-prepared.json')['dependency_source_sha256']
assert all(sha(R / path) == expected for path, expected in frozen.items() if path not in paths)
status = subprocess.run(['git', '-C', str(W), 'status', '--porcelain'], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30)
assert status.returncode == 0 and not status.stdout.rstrip('\r\n')
head = subprocess.run(['git', '-C', str(W), 'rev-parse', 'HEAD'], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30)
assert head.returncode == 0
preserved = head.stdout.rstrip('\r\n')
assert preserved == load('artifacts/qg2e-trace-runner-final-guard-record.json')['preserved_unaccepted_commit']
now = datetime.datetime.now().astimezone().isoformat()
record = {
    'recorded_at': now, 'slice': 'QG2-E-SELECTED-ICMP-TRACE-RUNNER',
    'decision': 'ACCEPTED_SELECTED_ICMP_TRACE_RUNNER_AND_EXISTING_DNS_SCHEDULER_ONLY',
    'independent_reviews': ['deleg_24f5e52c', 'deleg_cfe9fa59', 'deleg_45855748'],
    'final_review': 'artifacts/qg2e-trace-runner-final-independent-review.json',
    'resolved_findings': review['resolved_findings'], 'new_findings': [],
    'execution': proof['steps'], 'source_sha256': proof['source_sha256'],
    'preserved_source_commit': preserved, 'inspector_protected_unchanged': len(protected),
    'parent_adjustments': ['독립비반사12회귀', 'production Clippy 동등정리',
                           '실제serde길이예산fixture·정확byte/누락/시작완료단언',
                           'testguard ctxport/실제DNSDTO·직접/순차주소회귀',
                           'Notify Pending취소·동일Arc·전체raw동등·후속/다음target0'],
    'root_integrated': True, 'accepted': True, 'full_qg2_accepted': False, 'product_accepted': False,
    'scope': ['Trace 명시선택만 backend1·기존 default trait 구현source호환·기본TCP+Ping유지',
              '기존Trace엔진spawn_blocking위임·기존OS오류/exit의미보존',
              'domain필수DNS첫검증IP·IP리터럴선택DNS독립·hiddenDNS전체원문보존',
              '불량metadata/raw/위조PASS/canonical모순거부·거부값비반사',
              '실행중future await/drain·완료DNS보존·한도/누락/정렬'],
    'limits': ['합성Pending취소시험은실제OS프로세스취소완료인증아님',
               '보관JSONbytes상한이며RSS hardcap/대상내즉시중단아님',
               '루프백IPv4/IPv6·localhost helper실측이며운영망/OS전체지원인증아님',
               'runner native5는root native22에포함되므로더하지않음'],
    'excluded': ['실VLAN/DROP/ICMP차단·VPN/다중NIC·실제OS오류/취소주입',
                 '제품동일EXE helper dispatch/Win32 GUI/TXT·CSV/단일EXE/PE·서명/클린VM/일반사용자/성능',
                 '전체Quick QG2~QG7·Inspector전체G2이후'],
    'previous_dns_acceptance': 'artifacts/qg2d-dns-runner-acceptance.json',
    'supersedes_source_for_existing_dns_scheduler': True,
    'review_limitations': '정적QA는실행/해시검증하지않음. 부모가동일SHA·실제모든실행/불변의존/정확helper를별도확인함',
}
out = R / 'artifacts/qg2e-trace-runner-acceptance.json'
assert not out.exists()
out.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
state = load('artifacts/quick-check-progress.json')
state['recorded_at'] = now
state['qg2_trace_runner'].update(status=record['decision'], accepted=True, root_integrated=True,
    acceptance_artifact=str(out.relative_to(R)), preserved_source_commit=preserved,
    final_static_review='deleg_45855748_FINDINGS_EMPTY', latest_execution=proof,
    full_qg2_accepted=False, product_accepted=False)
state['qg2_dns_runner'].update(latest_source_acceptance=str(out.relative_to(R)),
    source_superseded_by='Trace연결후동일DNS정책보존·root조합회귀', latest_combined_execution=proof)
state['remaining_blockers'] = ['QG2실환경VLAN/DROP/ICMP차단·다중NIC/VPN·OS오류주입 미검증·전체QG2미수용',
                               '제품helper dispatch/GUI/TXT·CSV/단일EXE/PE·서명/VM/일반사용자/성능미완료']
(R / 'artifacts/quick-check-progress.json').write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
by_suffix = {step['name'].removeprefix('qg2e-trace-runner-root-'): step for step in proof['steps']}
section = f'''\n## 선택 ICMP Trace 실행기 root 조합회귀·제한 범위 수용 — {now}
- 최종독립재QA deleg_45855748 두검토자 findings=[]·원문/성공단언/실제resolve목적지guard·직접ctxport/순차조회·Notify Pending취소·예산fixture 모두해소확인. 부모동일sourceSHA재계산후runner source/tests 정확2파일만root선택통합했다. manifest/lock/lib·기존DNS/Trace엔진불변.
- root workspace {by_suffix['workspace']['passed']}PASS/0FAIL/{by_suffix['workspace']['ignored']}ignored; 별도명시native {by_suffix['native']['passed']}PASS/0FAIL; 독립Trace경계{by_suffix['trace-boundaries']['passed']}/DNS경계{by_suffix['dns-boundaries']['passed']}PASS; strictClippy/fmt exit0. 22 native에는새runner5가포함되고경계suite도별도이므로합산제품인증률로표현하지않음. Inspector보호{len(protected)}파일SHA불변.
- 수용은선택Trace연결+기존DNS실행정책보존범위만. Trace미선택호출0·domain첫검증IP만·IP상세DNS독립·raw/canonical무보정·실측IPnonnull·OS코드None/원시exit구분·완료DNS와진행중await/drain/보관한도유지. Notify취소는합성future증거이지실제OS프로세스취소인증아님.
- source보존local commit {preserved}, 전용worktree clean. root는기존작업을그대로보존해dirty일수있으며전체branch merge/원격push/배포없음. acceptance artifact: artifacts/qg2e-trace-runner-acceptance.json. 이전DNS수용source는역사로보존하고최신동일DNS정책근거는이수용을참조한다.
- 전체QG2는승인실VLAN/DROP/ICMP차단·다중NIC/VPN등환경검증부재로미수용. 제품동일EXE resolver dispatch/Win32GUI/TXT·CSV/PE·서명/VM·일반사용자/성능과Inspector전체G2미완료.
\n'''
for name in ['PROGRESS.md', 'RESUME.md']:
    path = R / name
    first, rest = path.read_text(encoding='utf-8').split('\n', 1)
    path.write_text(first + '\n' + section + rest, encoding='utf-8', newline='\n')
path = R / '작업내용/NPI_2026-10-22_001.md'
path.write_text(path.read_text(encoding='utf-8') + section, encoding='utf-8', newline='\n')
for name in ['docs/quick-check/gates.md', 'apps/network-quick-check/README.md']:
    path = R / name
    path.write_text(path.read_text(encoding='utf-8') + section, encoding='utf-8', newline='\n')
print(json.dumps({'decision':record['decision'], 'execution':proof['steps'], 'preserved_source_commit':preserved,
                  'inspector_unchanged':len(protected), 'full_qg2_accepted':False, 'product_accepted':False}, ensure_ascii=False))
