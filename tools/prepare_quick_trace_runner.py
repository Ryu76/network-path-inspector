"""수용된 DNS 실행기와 Trace 모듈을 동결하고 선택 Trace 연결 actor를 준비한다."""
import datetime
import hashlib
import json
import pathlib
import shutil
import subprocess

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qg2runner'
STAGE = 'qg2tracewire'
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()

def git(*args):
    p = subprocess.run(['git', '-C', str(W), *args], capture_output=True, text=True,
                       encoding='utf-8', errors='replace', timeout=40)
    assert p.returncode == 0, p.stderr
    return p.stdout.rstrip('\r\n')

assert git('branch', '--show-current') == 'ai-pro/qg2runner'
assert not git('status', '--porcelain'), '기존dirty작업을덮지않음'
assert not (R / '.harness/runs' / (STAGE + '-qg2runner')).exists()
dns = load('artifacts/qg2d-dns-runner-acceptance.json')
trace = load('artifacts/qg2c-trace-os-code-acceptance.json')
assert dns['accepted'] and trace['accepted']
for path, expected in {**dns['source_sha256'], **trace['source_sha256']}.items():
    assert sha(R / path) == expected, path
protected = load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(sha(R / path) == expected for path, expected in protected.items())
paths = ['Cargo.toml', 'Cargo.lock']
for directory in ['crates/network-core', 'crates/network-resolver']:
    paths.extend(p.relative_to(R).as_posix() for p in (R / directory).rglob('*')
                 if p.is_file() and p.suffix in ('.rs', '.toml'))
paths = sorted(set(paths))
for path in paths:
    target = W / path
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(R / path, target)
assert all(sha(W / path) == sha(R / path) for path in paths)
git('add', *paths)
git('-c', 'core.autocrlf=false', 'commit', '-m', 'chore: freeze accepted DNS scheduler and standalone Trace before wiring')
assert not git('status', '--porcelain')
refs = W / '.harness/references'
refs.mkdir(parents=True, exist_ok=True)
shutil.copyfile(R / '.worktrees/qgtrace/.harness/references/quick-trace-contract.json', refs / 'quick-trace-contract.json')
contract = {
    'version': 'qg2e-trace-runner-0.1', 'scope': '수용된 DNS실행기에 선택 ICMP Trace만 연결. 두파일만 수정.',
    'accepted_prerequisites': ['QG2-D DNS 실행기', '단독Trace 모듈+OS코드 의미 보정'],
    'preserve': ['QuickRunRequest/QuickRunReport/ProbeCounts/QuickOptions/QuickPlan/QuickResult 필드',
                 'run_quick API 및 tcp/icmp/host/resolve 시그니처·동작', 'NativeProbeBackend unit struct',
                 'NativeDnsProbeBackend 생성자/helper/resolve', '기본선택TCP+Ping', 'details 정확3키'],
    'additive_api': "QuickProbeBackend에 default body를가진 fn trace<'a>(&'a self,ctx:QuickContext,target:IpAddr,options:crate::traceroute::TraceOptions,cancel:Arc<AtomicBool>)->ProbeFuture<'a> 추가",
    'default': 'I/O0·UNKNOWN/UNKNOWN·UNAVAILABLE,이미취소면CANCELLED. 미측정raw 빈객체·elapsed/OS/IP미확인null.',
    'native': 'NativeProbeBackend: spawn_blocking으로기존trace_once→trace_to_quick_result. NativeDnsProbeBackend: 동일메서드위임. 프로브/파서/프로세스복제금지.',
    'options': {'use': 'TraceOptions::default()', 'max_hops': 30, 'probe_timeout_ms': 1000, 'overall_timeout_ms': 30000},
    'invocations': '실제backend trace메서드호출직전에icmp_traceroute+1. default도호출1이나프로세스/패킷수아님.',
    'dns_policy': 'domain은기존필수DNS해석첫검증주소만사용·실패/취소시Trace0. IP원문엔Trace위한DNS0; 선택상세DNS가실패해도IP독립Trace는막지않음. 선택DNS행자동추가/fallback/fanout금지.',
    'trace_guard': '실제raw는TraceMeasurement Deserialize+serialize roundtrip과기존adapter재검증. raw.target과top resolved_ip는실제선택IP와일치해야하며raw있는실측row의null IP금지. adaptercanonical과top metadata/outcome/status/evidence/elapsed/OS/raw의의미불일치거부. 미측정default만빈raw/nullableIP허용. 거부오류원문반사금지.',
    'raw_policy': 'Trace raw DTO전체그대로. 필수DNS전체raw는기존수용된limitations JSON문자열방식으로검증후첨부. Trace raw덮기/새details키/exitcode를OS오류로되돌리기금지.',
    'cancellation': '미시작Trace는continue하여뒤쪽완료DNS도보존. 실행중동일cancel전달후엔진정리완료await. future drop으로OS종료위장금지.',
    'bounds': {'targets':100,'concurrency':4,'max_rows':500,'max_result_bytes':16777216},
    'budget_limit': '기존대상완료시점한도감지·기존보관상한유지. RSS hardcap/대상내기능별즉시중단보장으로과장금지.',
    'excluded': ['새DTO필드/Trace옵션UI', 'TCP Trace', '도메인재해석/다중IP·자동재시도', 'GUI/제품EXE/helper dispatch/OS정책·운영망/VM/전체QG2수용'],
}
(refs / 'quick-trace-runner-contract.json').write_text(json.dumps(contract, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
prompt = f'''당신은 Network Quick Check의 선택 ICMP Trace 실행기 연결자다. worktree={W.as_posix()}.
허용은FILE READ/EDIT/CREATE 및worktree내부파일탐색만. 모든경로는이worktree절대경로만사용. run_command/command/terminal/shell/PowerShell/manage_task/시험/설치/git/네트워크/운영/DB/계정/에이전트/재위임절대금지. 읽기용명령도금지. 문서링크/integration root를따라읽지말라.
허용수정정확2파일: {W.as_posix()}/crates/network-core/src/runner.rs 와 {W.as_posix()}/crates/network-core/tests/runner.rs.
정확읽기입력: 위2파일, {W.as_posix()}/.harness/references/quick-trace-runner-contract.json, {W.as_posix()}/.harness/references/quick-trace-contract.json, {W.as_posix()}/.harness/references/quick-dns-runner-contract.json, {W.as_posix()}/crates/network-core/src/traceroute.rs, {W.as_posix()}/crates/network-core/src/quick.rs, {W.as_posix()}/crates/network-core/src/targets.rs, {W.as_posix()}/crates/network-core/src/dns.rs. 나머지module/lib/manifest/lock/기존프로브/스키마/GUI변경금지.
선행DNS실행기와단독Trace+OS코드보정은독립재QA·부모root전체380/native20/Trace경계14/DNS6/Clippy·fmt0으로작은범위수용했다. 부모가그소스를기준commit으로동결했다. 당신이실행한증거아님. 이제아래Trace연결만최소구현한다:
1) 계약의default trace메서드만additive추가하여기존trait구현source호환유지. 기본구현은측정/프로세스/네트워크0·UNKNOWN/UNKNOWN UNAVAILABLE(사전취소면CANCELLED),미측정raw{{}}·elapsed/OS/IPnull. 기존NativeProbeBackend unit struct유지. NativeProbeBackend::trace는spawn_blocking안기존trace_once 호출후trace_to_quick_result. NativeDnsProbeBackend::trace는동일NativeProbeBackend메서드위임. JoinError등은기존고정LOCAL_ERROR거부경로이며실측성공위장금지.
2) Trace명시선택에만호출. 타임아웃/홉은TraceOptions::default 그대로(max30/probe1000/overall30000). TCP/Ping timeout을Trace옵션으로재해석하지말라. 카운터는backend.trace호출직전1회증가; default도backend1이며OS생성/패킷수와구분. 기본선택TCP+Ping/미선택Trace호출0유지.
3) IP원문은추가DNS없이실행,선택상세DNS실패도IP독립Trace를막지않는다. domain은기존수용필수DNS첫검증주소1개만사용. 실패/불량주소/취소면Trace호출0·명시UNKNOWN/UNAVAILABLE. DNS선택행자동추가/추가해석/주소순서변경/다음IP fallback/fanout금지. 원래ctx host/port/session/source/timestamp유지,Trace실측target/resolved_ip는실제선택IP귀속. Trace는TCP포트서비스/로그인/패킷SYN차단증거가아님.
4) 현재generic verify_backend_result는실측resolved_ip=null과위조PASS raw를충분히검사하지못한다. runner안Trace전용검증helper로보강: raw_measurement가있는측정row는serde_json::from_value::<TraceMeasurement>→다시serde_json::to_value roundtrip으로정확원시구조일치확인, 무보정target IP파싱·expectedIP일치·top resolved_ip가Some(expected)인지확인, trace_to_quick_result(ctx,m)로기존성공게이트를재사용하고canonical top metadata/outcome/status/evidence/elapsed/OS/raw의일치를검증. generic metadata검증도유지. default 미측정UNAVAILABLE/CANCELLED만빈raw와nullableIP로구분해허용. 위조/불량응답을관측성공으로수리하지말고고정LOCAL_ERROR 경로로거부(원문/자격증명반사금지). parent가원하는것은해킹방어라고주장하는인증이아니라모순DTO거부다.
5) 검증이끝난Trace결과에만기존수용DNS raw/전체주소/첫선택정책을limitations의JSON문자열로첨부한다. details 정확3키와Trace raw전체·exit_code/partialstdout/stderr/truncation/less-than값을보존. OS코드topnull을exitcode0으로되돌리지말라. 기존DNSraw/역순취소/IP독립policy부모11회귀전부그대로유지.
6) Trace호출직전취소면해당기능만continue,뒤쪽완료DNS보존. 실행중은동일cancel을기존trace_once에전달후정리까지await/drain. spawn_blocking drop/timeout으로OS작업종료를꾸미지말라. 원시CANCELLED/TIMED_OUT은기존어댑터UNKNOWN/UNKNOWN 유지. 최대100/동시4/500행/보관JSON상한·안정정렬·누락건수유지. 기존한도는대상작업완료후감지이므로대상내즉시차단·RSS hardcap을발명하지말라.
7) 기본pure mock시험추가: oldtrait미구현trace기존컴파일호환(default UNAVAILABLE/CANCELLED I/O0),선택/미선택/빈/기본선택호출수,IP Trace와domain hiddenresolve1·상세DNS행0,상세DNS+Trace해석1,해석실패/역순취소Trace0·완료DNSraw보존,REACHED/INCOMPLETE/실패매핑·raw일치,wrongIP/metadata/null실측IP/위조PASS·raw target모순거부,기존카운터/정렬/예산회귀. mock은실제native를호출하지않는다. 기존Mock의4원소call_counts API를유지하고Trace전용counter/helper만추가가능. 설명과주석은한국어로작성한다.
8) native ignored시험은부모만명시실행: 소유127.0.0.1/::1만run_quick→NativeProbeBackend Trace로검증하고NativeDnsProbeBackend의IP Trace위임시DNS0확인. 가능하면정확NPI_TEST_HELPER_EXE로소유localhost domain Trace도검증하되fixture를동일helper로사전검증하여정확127.0.0.1/::1외주소거부. env/IPv6/fixture없으면expect실패,침묵return/skip금지. 기본시험native/process/network0. 운영망/외부도메인접속금지. 실제취소구간을관찰못하면취소실측통과라하지말라.
기존시험을삭제/약화하지말라. 과거'선택Trace미지원'시험만새계약의default미지원/native연결로강화대체가능. 새DTO필드/추가미승인API/manifest변경·Clippy suppression금지. 한국어흐름주석·UTF8·최종개행1개·후행공백없음·helper인수<=7개.
최종한국어응답은실제변경경로·구현내용·부모검증필요사항만. 명령실행/시험통과주장금지.
'''
path = R / '.harness/prompts' / (STAGE + '-qg2runner.md')
assert not path.exists()
path.write_text(prompt, encoding='utf-8', newline='\n')
record = {'recorded_at': datetime.datetime.now().astimezone().isoformat(), 'stage': STAGE,
          'baseline_commit': git('rev-parse', 'HEAD'), 'dependency_source_sha256': {path:sha(W / path) for path in paths},
          'contract': contract, 'accepted': False, 'root_integrated': False}
out = R / 'artifacts/qg2e-trace-runner-prepared.json'
assert not out.exists()
out.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'stage': STAGE, 'baseline_commit': record['baseline_commit'], 'source_files_frozen': len(paths),
                  'allowed_writes': 2, 'accepted': False}, ensure_ascii=False))
