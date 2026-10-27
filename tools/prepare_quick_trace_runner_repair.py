"""정적 QA 세 결함과 부모 순수 회귀 실패를 보존하고 제한된 Flash 보정을 준비한다."""
import datetime
import hashlib
import json
import pathlib
import re
import subprocess

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qg2runner'
STAGE = 'qg2tracewirefix'
PATHS = ['crates/network-core/src/runner.rs', 'crates/network-core/tests/runner.rs']
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()

def git(*args):
    p = subprocess.run(['git', '-C', str(W), *args], capture_output=True, text=True,
                       encoding='utf-8', errors='replace', timeout=40)
    assert p.returncode == 0, p.stderr
    return p.stdout.rstrip('\r\n')

assert not (R / '.harness/runs' / (STAGE + '-qg2runner')).exists()
assert git('branch', '--show-current') == 'ai-pro/qg2runner'
assert all(line[3:] in PATHS for line in git('status', '--porcelain').splitlines())
producer = load('artifacts/qg2e-trace-runner-pipeline.json')
assert producer['status'] == 'AUDITED_SOURCE_READY_FOR_PARENT_REVIEW'
assert sha(W / PATHS[0]) == producer['source_sha256'][PATHS[0]], '부모 production 수정 없음'
assert load('artifacts/qg2tracewire-actor-policy-audit.json')['all_actor_policy_checks_passed']
counts = {}
for name in ['rejection', 'default']:
    stem = 'artifacts/commands/qg2e-trace-runner-' + name + '-before-fix'
    evidence = load(stem + '.json')
    assert evidence['exit_code'] == 101 and not evidence['partial']
    text = (R / (stem + '.log')).read_text(encoding='utf-8')
    rows = re.findall(r'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
    assert rows
    counts[name] = {key: sum(int(row[i]) for row in rows)
                    for i, key in enumerate(['passed', 'failed', 'ignored'])}
assert counts['rejection'] == {'passed': 3, 'failed': 9, 'ignored': 0}
assert counts['default']['failed'] == 10
# 허용 두 파일만 WIP 보존. 실패 시험이 포함되므로 수용/통합 커밋이 아니다.
git('add', *PATHS)
git('-c', 'core.autocrlf=false', 'commit', '-m', 'chore: preserve unaccepted Trace runner and failing boundary witnesses')
assert not git('status', '--porcelain')
review = {
    'recorded_at': datetime.datetime.now().astimezone().isoformat(), 'review': 'deleg_24f5e52c',
    'producer_source_sha256': producer['source_sha256'], 'preserved_commit': git('rev-parse', 'HEAD'),
    'current_source_sha256': {path: sha(W / path) for path in PATHS},
    'findings': [
        {'id': 'TRACE-QA-001', 'aliases': ['TRACE-QA-01'], 'severity': 'P1',
         'issue': '거부된 Trace 메타데이터·adapter/backend 오류 원문 반사', 'parent_failed_witnesses': 9},
        {'id': 'TRACE-QA-002', 'aliases': ['TRACE-QA-02'], 'severity': 'P2',
         'issue': '명시 native 시험이 실측 REACHED 증거 없이 통과 가능', 'evidence': '부모 source tests/runner.rs:2114-2242 직접 대조·native 미실행'},
        {'id': 'TRACE-QA-03', 'severity': 'high',
         'issue': 'localhost 사전조회와 실제조회 간 목적지 허용 검사의 TOCTOU 공백',
         'evidence': '부모 source tests/runner.rs:2013-2041/2182-2210 직접 대조·native 미실행'},
    ],
    'additional_parent_findings': [
        {'id': 'TRACE-TEST-COUNTER-01', 'issue': 'test_trace_02가 동일 mock에 기본 TCP/Ping과 Trace 실행 후 누적 call_counts를 0으로 잘못 기대',
         'evidence': '실제 left=(1,1,0,0), right=(0,0,0,0), 별도 mock 또는 before/after delta 필요·production 기본선택 변경금지'},
        {'id': 'TRACE-TEST-COVERAGE-01', 'issue': 'set_on_trace_call/trace_call_targets unused 경고, 실행중취소·실제Trace예산초과 시험 공백',
         'correction': 'helper 삭제/suppress 대신 실제 pure 호출주소·await 완료·후속중단·예산초과 회귀 추가'},
    ],
    'parent_test_counts': counts, 'safe_default_scope': 'review 범위 pure runner + 변경없는 manifest/lock/의존 source 대조 후 offline 기본시험만 실행',
    'native_executed': False, 'root_integrated': False, 'accepted': False,
}
out = R / 'artifacts/qg2e-trace-runner-independent-review.json'
assert not out.exists()
out.write_text(json.dumps(review, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
refs = W / '.harness/references/quick-trace-runner-repair.json'
assert not refs.exists()
refs.write_text(json.dumps(review, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
prompt = f'''당신은 Trace 실행기 독립QA 확정결함을 보정하는 FILE ONLY writer다. worktree={W.as_posix()}.
모든읽기/쓰기는worktree절대경로만. FILE READ/EDIT/CREATE·내부파일탐색만허용. command/run_command/terminal/shell/PowerShell/manage_task/git/compile/시험/네트워크/설치/계정/DB/운영/에이전트/재위임절대금지. root/타worktree/문서링크따라읽기금지.
허용수정 정확2파일: {W.as_posix()}/crates/network-core/src/runner.rs 및 {W.as_posix()}/crates/network-core/tests/runner.rs.
허용읽기: 위2파일, {W.as_posix()}/.harness/references/quick-trace-runner-repair.json, {W.as_posix()}/.harness/references/quick-trace-runner-contract.json, {W.as_posix()}/.harness/references/quick-trace-contract.json, {W.as_posix()}/.harness/references/quick-dns-runner-contract.json, {W.as_posix()}/crates/network-core/src/traceroute.rs, {W.as_posix()}/crates/network-core/src/quick.rs, {W.as_posix()}/crates/network-core/src/targets.rs, {W.as_posix()}/crates/network-core/src/dns.rs. 다른source/manifest/lock/API/DTO/Trace엔진변경금지.
부모가순수시험을실제실행하여 parent_trace_reject 12중3PASS9FAIL(exit101), 기본Core --all-targets 실행중 runner38PASS10FAIL5ignored로중단을보존했다. 당신실행증거아님. native는아직실행하지않았다. 미수용WIPcommit에원본/실패시험이보존됨. 다음만최소보정:
1) TRACE-QA-001/TRACE-QA-01: verify_trace_backend_result의모든거부경로에서외부출력은고정필드명/사유code/문자열만. 불량metadata/실제값/adapter_errs/backendErr/validate_quick_result 오류문자열/serde오류를직접이어붙이지말라. generic verify_backend_result나공용adapter를바꾸지말고Trace경계에서거절된원문이report.errors/LOCAL_ERROR.details.limitations/직렬화report에없는것을보장. 유효하게검증된Trace raw/stdout/stderr/limitations와hiddenDNS DTO는계약그대로보존하며무차별mask로정상원문을삭제하지말라. 기존부모12회귀기대값삭제/완화금지. validraw전체보존positive도추가해도좋다.
2) TRACE-QA-002/TRACE-QA-02: native test_19의IPv4/IPv6/NativeDns위임과test_20 localhost 모두실측성공을필수로검사. REACHED/PASS/OBSERVED·raw exit_code Some(0)·output_truncated=false·stdout비어있지않음·실제target와최종응답hop일치·숫자RTT·parse_tracert_output과raw hops동등성/roundtrip을검증하는공용test helper를만들어각분기에호출. 미지원/LOCAL_ERROR/timeout은명시native시험실패이지return/skip/PASS아님. localhost rawDNS첫주소==Trace topIP==raw target도검사. helper의UNAVAILABLE거짓양성거부는실제I/O없는순수fixture로회귀검증.
3) TRACE-QA-03: 사전조회후실제재조회가있으므로사전검사만으로안전하지않다. tests/runner.rs안시험전용 위임backend wrapper로 실제resolve가돌려준DTO를매번검사하고정확소유127.0.0.1 또는::1·요청/소유port·localhost외host금지·비어있거나잘못된주소실패를native프로브호출전에차단. NativeDnsProbeBackend의실제resolve를호출한뒤반환DTO를검사해야하며fixture를주입해실제를가짜로대체하지말라. wrapper의tcp/icmp/trace/host 위임직전에도정확소유IP/port검사하여실수로외부실행하지못하게하라. 기존test_18과새test_20에둘다사용. 가능하면 inner Arc<dyn QuickProbeBackend>로실제native와순수mock이동일guard를사용; 사전조회는소유루프백인데실제resolve는다른합성unicast/다른port/empty/잘못된IP/잘못된host로변하는mock회귀에서실제inner tcp/trace호출0을검증. guard는실제소켓/프로세스를시작하지않고거절Err,소유정상IP/포트positive도포함. 제품첫주소/IP독립정책은변경금지.
4) TRACE-TEST-COUNTER-01: test_trace_02는동일mock으로기본TCP/Ping후Trace를실행해서누적값(1,1,0,0)이0이아닌것이정상이다. 새mock또는전후delta로Trace단독호출격리를검증하고기본TCP/Ping실제호출1씩도단언. production기본선택을비우거나기존단언단순삭제금지.
5) TRACE-TEST-COVERAGE-01: unused set_on_trace_call와trace_call_targets는삭제/suppress대신의미있는회귀로사용. Trace호출중cancel을설정하고future가실제완료된후에만run_quick이반환함·후속TCP/Ping0·기존완료DNS보존·원시CANCELLED UNKNOWN/UNKNOWN·omitted정확을pure mock으로검증. 실제OS강제종료시험이라고표현금지. test_trace_08은현재default16MB/작은row로예산초과를전혀시험하지않으므로실제로MIN_RESULT_BYTES한도를넘는유효Trace raw limitations 합성시험을추가하고limit_reached/보관bytes/누락/미시작·drain카운터를기존계약대로검증. 대상완료후한도감지이지RSS hardcap/대상내즉시중단이아님; 기존잘못된주석도최소정정.
기존API필드/4원소call_counts/기본TCP+Ping/TraceOptions30·1000·30000/hiddenDNS전체원문/첫주소/IP독립/역순DNS취소/기존실패시험강도보존. mock기본시험실제Native/네트워크/프로세스/환경접근0. native는ignore. 한국어설명주석·UTF8·최종개행1개·후행공백없음·Clippy suppression금지·helper인수<=7.
최종한국어답변은실제변경경로/보정내용/부모검증필요사항만. 코드실행/시험통과주장금지. 부모는작성종료→정책/경로/SHA감사→실행전소스검토에서멈추며native안전검토후에만시험한다.
'''
path = R / '.harness/prompts' / (STAGE + '-qg2runner.md')
assert not path.exists()
path.write_text(prompt, encoding='utf-8', newline='\n')
print(json.dumps({'stage': STAGE, 'preserved_commit': review['preserved_commit'],
                  'parent_test_counts': counts, 'accepted': False, 'native_executed': False}, ensure_ascii=False))
