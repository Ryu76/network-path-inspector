"""DNS 실행기 독립 QA를 재현·분류하고 두 확정 결함만 보정 actor에 넘긴다."""
import datetime
import hashlib
import json
import pathlib
import subprocess

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qg2runner'
STAGE = 'qg2dnswirefix'
PATHS = ['crates/network-core/src/runner.rs', 'crates/network-core/tests/runner.rs']
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()

def git(*args):
    process = subprocess.run(['git', '-C', str(W), *args], capture_output=True, text=True,
                             encoding='utf-8', errors='replace', timeout=40)
    assert process.returncode == 0, process.stderr
    return process.stdout.rstrip('\r\n')

assert not (R / '.harness/runs' / (STAGE + '-qg2runner')).exists()
assert git('branch', '--show-current') == 'ai-pro/qg2runner'
assert all(line[3:] in PATHS for line in git('status', '--porcelain').splitlines())
proof = load('artifacts/qg2d-dns-runner-parent-execution.json')
assert sha(W / PATHS[0]) == proof['source_sha256'][PATHS[0]], '부모는 회귀만 추가했고 production은 검토본 그대로여야 함'
witness = load('artifacts/commands/qg2d-dns-runner-review-witnesses-before-fix.json')
assert witness['exit_code'] == 101 and not witness['partial']
text = (R / 'artifacts/commands/qg2d-dns-runner-review-witnesses-before-fix.log').read_text(encoding='utf-8')
assert '3 passed; 5 failed;' in text
original = R / '.harness/prompts/qg2dnswire-qg2runner.md'
policy = 'IP대상은상세DNS실패가필수조건이아니므로독립TCP/Ping/Host를막지않는다.'
assert policy in original.read_text(encoding='utf-8'), '과거정책 근거 없이 QA를 거부하지 않음'
contract_path = W / '.harness/references/quick-dns-runner-contract.json'
contract = json.loads(contract_path.read_text(encoding='utf-8'))
contract_before = sha(contract_path)
contract['parent_clarifications'] = {
    'prior_ip_policy': policy,
    'original_implementation_prompt': '.harness/prompts/qg2dnswire-qg2runner.md (원문은 부모 근거이며 actor가 root경로를 읽으면 안 됨)',
    'raw_contract': 'details는 outcome/limitations/raw_measurement 정확3키. 새필드금지. 검증완료된 필수 DNS DTO 전체를 limitations의 접두문구+완전JSON 문자열로 보존. TCP/Ping/Host raw_measurement는 원형을 덮어쓰지 않음. 검증실패한 불량host/자격증명원문은 반사하지 않음.',
    'cancellation': '선택순서와 무관하게 완료된 선택DNS행은 보존. 취소된 의존검사만 건너뛰고 해당호출0,누락건수정확.',
}
contract_path.write_text(json.dumps(contract, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
git('add', *PATHS)
git('-c', 'core.autocrlf=false', 'commit', '-m', 'chore: preserve DNS runner and failing review witnesses before repair')
assert not git('status', '--porcelain')
review = {
    'recorded_at': datetime.datetime.now().astimezone().isoformat(), 'review': 'deleg_d3ed5297',
    'accepted_findings': [
        {'id': 'DNS-RUNNER-002', 'severity': 'P2', 'issue': '숨은 필수DNS 성공/실패 DTO 전체 원문 유실', 'failed_witnesses': 2},
        {'id': 'CANCEL-DNS-ORDER-01', 'severity': 'high', 'issue': '의존기능이 DNS보다 앞선 순서에서 취소가 완료DNS행을 유실', 'failed_witnesses': 3},
    ],
    'rejected_findings': [{
        'id': 'DNS-RUNNER-001', 'reported_severity': 'P2',
        'reason': '상세DNS 실패가 IP 원문 대상의 독립검사 전제조건이 아니라는 기존 명시정책과 충돌. 형식불량DNS로 실제IP를 바꾸지 않고 독립검사 유지함은 의도한 동작.',
        'original_policy': policy, 'policy_prompt_sha256': sha(original),
        'positive_controls': ['parent_ip_optional_dns_error_does_not_gate_literal_probes',
                              'parent_ip_forged_optional_dns_does_not_change_literal_destination'],
        'positive_control_result': '두 사례 모두 실제 합성시험 통과. DNS행 UNKNOWN·기존IP귀속·독립TCP/Ping/Host호출을 확인',
    }],
    'parent_witnesses': {'passed': 3, 'failed': 5, 'evidence': witness},
    'preserved_commit': git('rev-parse', 'HEAD'),
    'contract_before_sha256': contract_before, 'contract_clarified_sha256': sha(contract_path),
    'root_integrated': False, 'accepted': False,
}
output = R / 'artifacts/qg2d-dns-runner-independent-review.json'
assert not output.exists()
output.write_text(json.dumps(review, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
prompt = f'''당신은 DNS 실행기의 확정2결함만 보정하는 FILE ONLY actor다. worktree={W.as_posix()}.
모든 읽기/쓰기는 이worktree 절대경로만. FILE READ/EDIT/CREATE·내부파일탐색만허용. run_command/command/terminal/shell/PowerShell/manage_task/시험/설치/git/네트워크/운영/DB/계정/에이전트/재위임 절대금지. 읽기용명령도금지. PRD링크나integration root를따라읽지말라.
허용수정은 {W.as_posix()}/crates/network-core/src/runner.rs 와 {W.as_posix()}/crates/network-core/tests/runner.rs 정확2파일뿐.
정확읽기입력: 위2파일, {W.as_posix()}/.harness/references/quick-dns-runner-contract.json, {W.as_posix()}/.harness/references/quick-dns-contract.json, {W.as_posix()}/crates/network-core/src/dns.rs, {W.as_posix()}/crates/network-core/src/quick.rs. 나머지모듈/manifest/lib/lock/Trace/제품GUI는변경금지.
직전부모검증Core115/native3/Clippy0이었으나, 독립QA2개의확정결함을새부모회귀5FAIL로재현했다. parent_순수시험8개중3PASS5FAIL이며통과3개에는기존TCP취소1개와IP정책positive2개가있다. 부모시험을당신실행으로주장하지말라.
1) CANCEL-DNS-ORDER-01: [TcpConnect,DnsLookup], [IcmpPing,DnsLookup], [LocalNetwork,DnsLookup] 선택순서에서 선행resolve완료직후취소가오면첫의존기능의break로뒤쪽완료DNS행을버린다. 취소된의존기능만continue하거나동등한최소보정으로미시작probe호출0·완료DNS원문보존·입력feature순서정렬·omitted정확을유지한다. 기존앞DNS순서및TCP완료후취소보존을깨지말라. 모든선택순서에같은논리적결과를보존한다.
2) DNS-RUNNER-002: 도메인TCP/Ping/Host만선택하면필수DNS행은생성하지않지만필수해석의전체raw DTO(host/port/outcome/addresses/elapsed_ms/error_code/error_message/limitations)를보존해야한다. 현재append_domain_resolution_limitations는주소문자열만남기고, DNS실패의UNAVAILABLE에서는raw가비어있다. details의정확3필드 계약을유지하면서valid하게검증된DNS DTO 전체를 serde_json::to_string한문자열로 limitations에첨부하라(예: '필수 DNS 해석 원문(JSON): ' + JSON). 성공한실제probe와DNS실패로미실행UNAVAILABLE 모두적용. 기존TCP/Ping/Host raw_measurement를덮어쓰거나새details필드를만들지말라. RAW목록순서/필드/오류codeNone을보정하지말고보존. DNS어댑터검증에서거절된불량host/자격증명원문은이경로로새로반사하지말고고정거부사유만남긴다. 전체raw의JSONbytes도기존보관예산에정상산정되어야한다.
3) DNS-RUNNER-001는부모가거부한QA오탐이다: 원래승인prompt에서 'IP대상은상세DNS실패가필수조건이아니므로독립TCP/Ping/Host를막지않는다'고명시했다. IP원문은이미검증되어선택DNS실패/불량typed DNS와무관하게기존검사를실행한다. DNS행자체는UNKNOWN/LOCAL_ERROR로유지하고불량DNS의다른주소를선택하지않는다. 새positive2시험이이정책과실제IP귀속을검증하며이미통과했다. 이시험을역으로바꾸거나IP독립검사를막지말라.
4) parent_dns_fixture/parent_assert_full_dns_preserved 및 reverse_order 회귀/positive2시험의기대값은유지. 기대실패5를삭제/완화하거나성공을UNKNOWN으로수리금지. 기존pure/native3·failclosedhelper/IPv6fixture·hook/첫IP/JSONbyte/카운터/메타데이터·공용resolver재사용을보존. production API/DTO/기능ID변경금지. 한국어흐름주석·UTF8·후행공백없음·최종개행1개·Clippy suppression금지·helper인수<=7개.
최종한국어응답은실제변경경로/보정내용/부모검증필요사항만. 명령실행/시험통과주장금지.
'''
path = R / '.harness/prompts' / (STAGE + '-qg2runner.md')
assert not path.exists()
path.write_text(prompt, encoding='utf-8', newline='\n')
print(json.dumps({'stage': STAGE, 'preserved_commit': review['preserved_commit'],
                  'confirmed_findings': len(review['accepted_findings']), 'rejected_findings': len(review['rejected_findings']),
                  'parent_passed': 3, 'parent_failed': 5, 'accepted': False}, ensure_ascii=False))
