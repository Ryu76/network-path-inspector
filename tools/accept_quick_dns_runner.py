"""독립 재QA와 실제 root 조합 회귀를 근거로 DNS 연결 실행기 범위를 수용한다."""
import datetime
import hashlib
import json
import pathlib
import subprocess

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qg2runner'
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
proof = load('artifacts/qg2d-dns-runner-root-validation.json')
assert proof['status'] == 'ROOT_EXECUTION_PASS_ACCEPTANCE_RECORD_PENDING'
assert all(step['exit_code'] == 0 and not step['partial'] for step in proof['steps'])
assert all(sha(R / path) == expected for path, expected in proof['source_sha256'].items())
trace = load('artifacts/qg2c-trace-os-code-acceptance.json')
assert all(sha(R / path) == expected for path, expected in trace['source_sha256'].items())
paths = ['crates/network-core/src/runner.rs', 'crates/network-core/tests/runner.rs']
assert all(sha(W / path) == proof['source_sha256'][path] for path in paths)

def git(*args):
    result = subprocess.run(['git', '-C', str(W), *args], capture_output=True, text=True,
                            encoding='utf-8', errors='replace', timeout=40)
    assert result.returncode == 0, result.stderr
    return result.stdout.rstrip('\r\n')

assert all(line[3:] in paths for line in git('status', '--porcelain').splitlines())
if git('status', '--porcelain'):
    git('add', *paths)
    git('-c', 'core.autocrlf=false', 'commit', '-m', 'feat: verify DNS selection scheduler raw and cancellation preservation')
assert not git('status', '--porcelain')
protected = load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(sha(R / path) == expected for path, expected in protected.items())
now = datetime.datetime.now().astimezone().isoformat()
record = {'recorded_at': now, 'slice': 'QG2-D-DNS-RUNNER',
          'decision': 'ACCEPTED_REQUIRED_RESOLUTION_AND_SELECTED_DETAILED_DNS_RUNNER_ONLY',
          'independent_reviews': ['deleg_d3ed5297', 'deleg_40886ced/tasks-0-1'],
          'resolved_findings': ['DNS-RUNNER-002', 'CANCEL-DNS-ORDER-01'], 'new_findings': [],
          'rejected_policy_change': 'DNS-RUNNER-001는원래명시된IP독립정책에반하여거부,실행positive2보존',
          'execution': proof['steps'], 'source_sha256': proof['source_sha256'],
          'preserved_source_commit': git('rev-parse', 'HEAD'), 'inspector_protected_unchanged': len(protected),
          'root_integrated': True, 'accepted': True, 'full_qg2_accepted': False, 'product_accepted': False,
          'scope': ['도메인필수해석·상세DNS선택분리', '주소첫후보만선택·원래host와실사용IP구분',
                    '검증완료DNS전체DTO·취소순서보존', '기존TCP/Ping/Host실행·기능선택/호출/한도/정렬'],
          'limits': ['보관JSONbytes상한이며RSS hardcap아님', '네이티브확인은소유IPv4/IPv6와localhost helper만',
                     'domain+TCP 실제실행은확인했으나운영망/domainPing·Host 전체환경인증아님'],
          'excluded': ['Trace 선택실행기연결', '제품동일EXE helper dispatch·GUI/단일EXE/PE·서명/VM·일반사용자',
                       '실VLAN/DROP/ICMP차단/다중NIC·VPN/성능·전체QG2/Inspector전체G2'],
          'review_limitations': '정적검토자는실행하지않음. 원시DTO정의의None/null과validate_host 전부는부모기존검증/실행증거로별도보완. 실제OS실패주입아님'}
out = R / 'artifacts/qg2d-dns-runner-acceptance.json'
assert not out.exists()
out.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
review = load('artifacts/qg2d-dns-runner-independent-review.json')
review.update(final_recheck='deleg_40886ced/tasks-0-1', remaining_findings=[], accepted=True,
              root_integrated=True, acceptance_artifact=str(out.relative_to(R)))
for finding in review['accepted_findings']:
    finding['status'] = 'RESOLVED'
(R / 'artifacts/qg2d-dns-runner-independent-review.json').write_text(json.dumps(review, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
state = load('artifacts/quick-check-progress.json')
state['recorded_at'] = now
state['qg2_dns_runner'].update(status=record['decision'], accepted=True, root_integrated=True,
                               latest_execution=proof, acceptance_artifact=str(out.relative_to(R)),
                               preserved_source_commit=record['preserved_source_commit'])
state['remaining_blockers'] = ['Trace 실제선택실행기 연결 미구현', '제품helper dispatch/GUI/EXE/일반사용자/VM/실VLAN·성능·전체QG2 미완료']
(R / 'artifacts/quick-check-progress.json').write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
section = f'''\n## 필수해석·선택상세DNS 실행기 범위 수용 — {now}
- 원문/취소2결함최종독립재QA해소후동일canonical2파일root통합. 새전체workspace380PASS/0FAIL·별도명시native20PASS·독립Trace14/DNS6PASS·strictClippy/fmt0. Inspector보호{len(protected)}파일SHA불변. 해당수치는각독립suite이며제품인증률로합산하지않음.
- 기본TCP+Ping/기존DTO유지,domain필수해석과선택상세DNS분리·최초검증IP만사용·전체DNS원문과역순취소보존. IP원문은선택DNS실패와독립적인기존검사정책유지. 소유localhost helper+domainTCP 실제실행검증과운영환경인증을구분.
- 수용범위는DNS연결실행기만. Trace선택실행기/제품동일EXE helper dispatch/GUI/단일EXE/PE·서명/VM/일반사용자/실VLAN·성능·전체QG2미수용. 소스보존commit {record['preserved_source_commit']}·원격push없음. 근거 artifacts/qg2d-dns-runner-acceptance.json.
\n'''
for name in ['PROGRESS.md', 'RESUME.md']:
    path = R / name
    text = path.read_text(encoding='utf-8')
    first, rest = text.split('\n', 1)
    path.write_text(first + '\n' + section + rest, encoding='utf-8', newline='\n')
path = R / '작업내용/NPI_2026-10-22_001.md'
path.write_text(path.read_text(encoding='utf-8') + section, encoding='utf-8', newline='\n')
print(json.dumps({'decision': record['decision'], 'preserved_source_commit': record['preserved_source_commit'],
                  'execution': proof['steps'], 'full_qg2_accepted': False}, ensure_ascii=False))
