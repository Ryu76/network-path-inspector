"""수용된 DNS를 IP 실행기의 별도 worktree에 동결하고 DNS 연결 actor를 준비한다."""
import datetime
import hashlib
import json
import pathlib
import shutil
import subprocess

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qg2runner'
STAGE = 'qg2dnswire'
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()

def git(*args):
    process = subprocess.run(['git', '-C', str(W), *args], capture_output=True, text=True,
                             encoding='utf-8', errors='replace', timeout=40)
    assert process.returncode == 0, process.stderr
    return process.stdout.rstrip('\r\n')

assert git('branch', '--show-current') == 'ai-pro/qg2runner'
assert not git('status', '--porcelain'), '기존 작업을 덮지 않음'
assert not (R / '.harness/runs' / (STAGE + '-qg2runner')).exists()
acceptance = load('artifacts/qg2c-dns-acceptance.json')
assert acceptance['decision'] == 'ACCEPTED_SHARED_RESOLVER_AND_DNS_ADAPTER_ONLY'
for relative, expected in acceptance['source_sha256'].items():
    assert sha(R / relative) == expected, relative
runner = load('artifacts/qg2b-runner-acceptance.json')
for relative in ['crates/network-core/src/runner.rs', 'crates/network-core/tests/runner.rs']:
    assert sha(R / relative) == runner['source_sha256'][relative]
    assert sha(W / relative) == sha(R / relative), relative
protected = load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(sha(R / relative) == expected for relative, expected in protected.items())
copy_paths = ['Cargo.toml', 'Cargo.lock']
for directory in ['crates/network-core', 'crates/network-resolver']:
    copy_paths.extend(path.relative_to(R).as_posix() for path in (R / directory).rglob('*')
                      if path.is_file() and path.suffix in ('.rs', '.toml'))
copy_paths = sorted(set(copy_paths))
for relative in copy_paths:
    destination = W / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(R / relative, destination)
assert all(sha(W / relative) == sha(R / relative) for relative in copy_paths)
git('add', *copy_paths)
git('-c', 'core.autocrlf=false', 'commit', '-m', 'chore: freeze accepted DNS modules before scheduler wiring')
assert not git('status', '--porcelain')
contract = {
    'version': 'qg2d-dns-runner-0.1',
    'scope': 'DNS 필수이름해석 및 선택 상세DNS를 기존 실행기에 연결. Trace는 여전히 UNAVAILABLE, GUI/제품helper dispatch 제외.',
    'preserve_api': ['QuickRunRequest 필드', 'QuickRunReport 필드', 'ProbeCounts 필드', 'run_quick 인수/반환',
                     'QuickOptions 필드', '기존 NativeProbeBackend 단위struct와 tcp/icmp/host 메서드'],
    'additive_api': [
        "pub type DnsProbeFuture<'a> = Pin<Box<dyn Future<Output=Result<crate::dns::dns_engine::DnsMeasurement,Vec<String>>>+Send+'a>>",
        "QuickProbeBackend에 기본 구현이 있는 fn resolve<'a>(&'a self,ctx:QuickContext,timeout:Duration,cancel:Arc<AtomicBool>)->DnsProbeFuture<'a> 추가. 기본은 미구성 Err로 기존 구현 source호환 유지",
        'pub struct NativeDnsProbeBackend { helper_executable:std::path::PathBuf }',
        'impl NativeDnsProbeBackend { pub fn new(helper_executable:std::path::PathBuf)->Self }',
    ],
    'selection_policy': 'OS반환 첫 SocketAddr만 후보로 사용. 원문 전체 주소목록 보존, 재정렬/추가IP연결/자동fallback 금지. 첫후보가 기존 targets 안전검증을 통과하지 못하면 연결0·명시UNKNOWN.',
    'counters': 'dns_lookup는 resolver backend API 호출 수(리터럴 bypass 포함)이지 DNS 네트워크패킷 수가 아님. 필수 hidden해석도1회계수, 상세DNS선택여부와무관해 중복조회금지.',
    'limits': {'targets': 100, 'concurrency': 4, 'rows': 500, 'result_bytes_max': 16777216},
    'same_exe_limitation': 'NativeDnsProbeBackend는 명시 절대helper 경로를 받는다. 향후제품은같은EXE worker분기로처리. 이번native시험은정확소유 QAhelper를NPI_TEST_HELPER_EXE로명시하고제품배포로주장하지않음.',
}
refs = W / '.harness/references'
refs.mkdir(parents=True, exist_ok=True)
(refs / 'quick-dns-runner-contract.json').write_text(json.dumps(contract, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
shutil.copyfile(R / '.harness/references/quick-dns-contract.json', refs / 'quick-dns-contract.json')
prompt = f'''당신은 Network Quick Check DNS 실행기 연결의 FILE ONLY 구현자다. worktree={W.as_posix()}.
모든 읽기/쓰기는 이worktree 내부 절대경로만. FILE READ/EDIT/CREATE와 내부파일탐색만 허용. run_command/command/terminal/shell/PowerShell/manage_task/시험/설치/git/네트워크/DB/계정/에이전트/재위임은 절대금지. PRD의integration root/문서링크를따라읽지말라.
허용 수정2파일: {W.as_posix()}/crates/network-core/src/runner.rs 및 {W.as_posix()}/crates/network-core/tests/runner.rs.
정확입력: 위2파일, {W.as_posix()}/.harness/references/quick-dns-runner-contract.json, {W.as_posix()}/.harness/references/quick-dns-contract.json, {W.as_posix()}/crates/network-core/src/dns.rs, {W.as_posix()}/crates/network-core/src/targets.rs, {W.as_posix()}/crates/network-core/src/quick.rs, {W.as_posix()}/crates/network-core/src/measurements.rs, {W.as_posix()}/crates/network-resolver/src/lib.rs. 후자6소스는읽기만,모듈/manifest/Cargo.lock수정금지.
선행수용: 입력/ICMP·Host 어댑터, IP실행기, 최종root DNS어댑터/공용resolver. 부모 새root307/독립6pass 및동일소스역사native17/schema77/Clippy0이다. 당신이실행한증거아님. Trace는다른worktree에서보정중이니절대읽거나연결하지말고UNAVAILABLE유지.
계약을 그대로 지키며 다음만 구현:
1) 기존 모든public DTO필드/API/NativeProbeBackend단위struct를보존하고 DnsProbeFuture/기본구현resolve/NativeDnsProbeBackend::new(PathBuf)만추가. 기존trait구현source호환. NativeDnsProbeBackend는tcp/icmp/host를기존NativeProbeBackend에위임,resolve는spawn_blocking으로기존dns_engine::resolve_isolated를호출. 자체ToSocketAddrs/OSresolver/새프로브구현금지. helper경로는명시주입,환경변수를production에서자동해석하거나임의test감지금지. 명시path의기존resolver 검증을유지.
2) build_quick_plan의requires_resolution을더이상전면Err로막지말고 실제선행해석을각target안에서수행. domain은needs_resolution 또는DnsLookup선택시한번만resolve. 리터럴은DnsLookup선택시만backendresolve를1회호출하고엔진이OSlookup/process0으로bypass. 빈선택/invalidrequest/사전취소는resolve포함전체호출0. 동시대상<=4·100targets/500rows/JSONbytes예산/정렬/중지drain을보존. dns_lookup counter는backendresolve호출횟수이며네트워크질의수라고쓰지말라. DNS timeout은기존 tcp_timeout_ms를사용.
3) resolve의typed DnsMeasurement를반드시dns_to_quick_result(ctx,measurement)로재검증한뒤주소선택. 불량host/port/outcome·오류·주소모순은연결승격금지. 유효RESOLVED의첫SocketAddr만기존targets의동일안전검증으로확인하여사용한다. 먼저존재하는공개입력API를읽어재사용. 주소정렬/trim/형태수리/다음IP자동fallback/다중연결금지. 첫주소가unspecified/multicast/broadcast/불허linklocal이면UNKNOWN로차단,후속probe0. 원래host/session/timestamp/source/port는바꾸지말고실제선택IP만각TCP/Ping/Host결과귀속에사용한다.
4) 선택DnsLookup행은원래dns_to_quick_result 전체결과를feature순서위치에그대로배치(resolved_ip=null·전체raw/주소목록유지). 필수이름해석이더라도미선택DNS행은생성하지않는다. 도메인TCP/Ping/Host 결과details에필수해석원문전체와첫후보선택정책/다른주소미시도한계를보존하되기존raw_measurement를덮지말라. 해석실패/불량typed결과/미구성backend시DNS선택행은원래오류판정또는LOCAL_ERROR, 의존검사들은UNKNOWN/UNKNOWN·UNAVAILABLE·resolved_ip=null로기록하고해당backend호출0. IP대상은상세DNS실패가필수조건이아니므로독립TCP/Ping/Host를막지않는다. Trace는실행0/UNAVAILABLE이며과거기능게이트를확대하지말라.
5) 완료된선택DNS결과의raw는중도취소에도가능한보존한다. DNS에서cancel감지되면이후연결0이고cancelled/omitted건수정확. 기존probe결과metadata·IP무결성검사를유지하며조회주소와실제접속주소를혼동하지않는다. 과도한보관결과를RSShardcap으로주장하지말라.
6) 순수mock 기본시험으로domainTCP-only hiddenresolve1/DNS행0,domain DNS+TCP resolve1,상세DNS-only TCP/Ping/Host0,리터럴상세DNS+TCP1(엔진DNS0한계),multiaddr첫IP만사용·전목록raw보존,해석실패/위조typed/불허첫IP후속backend0,pre/midcancel,순서/귀속/source·metadata/JSON예산/동시4를검증. 기존 IP네이티브2개·입력badmeta실패·타기능미선택호출0 단언 유지. 기존 'DNS/도메인미지원' 두시험만 새승인계약대로강화/대체하며삭제로회피하지말라.
7) 선택ignored owned localhost native 시험추가: NPI_TEST_HELPER_EXE 미설정/잘못된path는expect실패(침묵return금지). 정확QAhelper를쓴NativeDnsProbeBackend의localhost상세DNS 및domainTCP흐름검증. 진단전fixture해석으로주소가127.0.0.1/::1만인지확인하고그외면접속전에실패; 소유IPv4/IPv6 loopback listener를같은ephemeral port에bind하여OS의첫주소순서에의존하지않고실제domain연결을증명. 외부domain/운영IP/스캔/응용payload전송금지. 기본시험native/network/process0. 테스트도실행하지말고작성만.
한국어흐름주석·UTF8·최종개행1개·후행공백없음. helpers인수<=7개·Clippy suppression금지. 최종응답실제변경경로/내용/부모시험필요사항,직접시험/통과주장금지.
'''
path = R / '.harness/prompts' / (STAGE + '-qg2runner.md')
assert not path.exists()
path.write_text(prompt, encoding='utf-8', newline='\n')
record = {'recorded_at': datetime.datetime.now().astimezone().isoformat(), 'stage': STAGE,
          'worktree': str(W), 'baseline_commit': git('rev-parse', 'HEAD'),
          'dependency_source_sha256': {relative: sha(W / relative) for relative in copy_paths},
          'scope': contract['scope'], 'accepted': False, 'root_integrated': False}
output = R / 'artifacts/qg2d-dns-runner-prepared.json'
assert not output.exists()
output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'stage': STAGE, 'baseline_commit': record['baseline_commit'],
                  'source_files_frozen': len(copy_paths), 'allowed_writes': 2, 'accepted': False}, ensure_ascii=False))
