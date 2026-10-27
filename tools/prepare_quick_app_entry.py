"""수용 Core를 새 전용 worktree에 동결하고 제품 DNS worker entrypoint 작성을 준비한다."""
import datetime
import hashlib
import json
import pathlib
import re
import shutil
import subprocess

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qgquickapp'
STAGE = 'qg2appentry'
ROLE = 'qgquickapp'
OUTPUTS = ['apps/network-quick-check/Cargo.toml', 'apps/network-quick-check/src/lib.rs',
           'apps/network-quick-check/src/main.rs', 'apps/network-quick-check/tests/resolver_dispatch.rs']
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()

def git(where, *args):
    p = subprocess.run(['git', '-C', str(where), *args], capture_output=True, text=True,
                       encoding='utf-8', errors='replace', timeout=60)
    assert p.returncode == 0, p.stderr
    return p.stdout.rstrip('\r\n')

accepted = load('artifacts/qg2e-trace-runner-acceptance.json')
assert accepted['accepted'] and not accepted['full_qg2_accepted']
assert all(sha(R / path) == value for path, value in accepted['source_sha256'].items())
assert not W.exists(), '기존 worktree/작업을 덮지 않음'
assert all(not (R / path).exists() for path in OUTPUTS), '신규출력 부재를 확인한 뒤만 생성'
assert not (R / '.harness/runs' / (STAGE + '-' + ROLE)).exists()
assert not (R / '.harness/prompts' / (STAGE + '-' + ROLE + '.md')).exists()
harness = load('artifacts/commands/qg2f-app-harness-role-tests.json')
assert harness['exit_code'] == 0 and not harness['partial']
assert re.search(r'Ran 38 tests', pathlib.Path(harness['log']).read_text(encoding='utf-8'))
base = accepted['preserved_source_commit']
git(R, 'worktree', 'add', '-b', 'ai-pro/qgquickapp', str(W), base)
assert git(W, 'branch', '--show-current') == 'ai-pro/qgquickapp'
assert not git(W, 'status', '--porcelain')
# 문서/입력은 writer 시작 전에 부모가 정확한 원본 바이트로 동결한다.
inputs = ['AGENTS.md', '.gitattributes', 'PRD.md',
          'docs/requirements/Network_Path_Inspector_Harness_PRD_v1.2.md',
          'apps/network-quick-check/README.md']
frozen = load('artifacts/qg2e-trace-runner-prepared.json')['dependency_source_sha256']
for path in sorted(set(inputs) | set(frozen)):
    target = W / path
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(R / path, target)
    assert sha(target) == sha(R / path)
assert all(sha(W / path) == value for path, value in accepted['source_sha256'].items())
assert all(not (W / path).exists() for path in OUTPUTS)
git(W, 'add', *sorted(set(inputs) | set(frozen)))
if git(W, 'status', '--porcelain'):
    git(W, '-c', 'core.autocrlf=false', 'commit', '-m', 'chore: freeze accepted shared core before product DNS entrypoint')
assert not git(W, 'status', '--porcelain')
refs = W / '.harness/references'
refs.mkdir(parents=True, exist_ok=True)
contract = {
    'version': 'qg2f-product-worker-entrypoint-0.1', 'slice': 'QG2 보완 제품 동일EXE DNS worker 진입점만',
    'upstream_design_review': 'deleg_8af528a1',
    'parent_clarification': 'Rust native integration은기존NativeDnsProbeBackend로소유localhost→제품EXE IPC만검증. noargs/help/invalid/literal 실제명령행은부모Python bounded subprocess에서별도검증하여Rust에새감독코드를복제하지않음.',
    'outputs': OUTPUTS,
    'manifest': {'package': {'name': 'network-quick-check', 'version.workspace': True, 'edition.workspace': True, 'rust-version.workspace': True, 'publish': False},
                 'dependencies': {'network-core': {'path': '../../crates/network-core'}},
                 'dev-dependencies': {'tokio': {'version': '=1.52.3', 'features': ['rt', 'time']}},
                 'bin': [{'name': 'NetworkQuickCheck', 'path': 'src/main.rs'}]},
    'app_api': ['pub enum EntryMode { Idle, Help, DnsWorker { host:String, port_arg:String } }',
                'pub enum EntryError { InvalidArguments }',
                'pub fn parse_args(args:&[std::ffi::OsString])->Result<EntryMode,EntryError> (argv0제외)',
                'pub fn entry(args:&[std::ffi::OsString],stdout:&mut dyn std::io::Write,stderr:&mut dyn std::io::Write)->u8',
                'pub fn native_backend_for_current_exe()->std::io::Result<network_core::runner::NativeDnsProbeBackend>'],
    'main': 'args_os().skip(1).take(4)만수집→entry→ExitCode. no runtime/GUI/subsystem속성/자동진단',
    'noargs': {'exit': 0, 'stdout': '', 'stderr': 'Network Quick Check: 진단 실행 진입점은 아직 제공하지 않습니다.\n'},
    'help': {'args': ['--help'], 'exit': 0, 'stdout': '', 'stderr': 'Network Quick Check: 현재 진단 실행 기능은 제공하지 않습니다.\n'},
    'invalid': {'exit': 2, 'stdout': '', 'stderr': 'Network Quick Check: 지원하지 않거나 잘못된 인자입니다.\n'},
    'worker': {'flag': '--npi-dns-worker-v1', 'flag_source': 'network_core::dns_engine::WORKER_FLAG', 'arity': 3,
               'validation_before_any_worker': 'OsString to_str비Unicode거부·기존validate_host/parse_helper_port모두먼저성공. trim/lossy/정규화/URI분해없음',
               'execute': '검증성공worker분기에서run_worker_from_args한번→worker_output_line한번. 재귀resolve/factory/자식process/runtime/GUI없음',
               'stdout': '기존payload UTF8 JSON정확한줄최종LF·실제bytes<=MAX_PAYLOAD_BYTES(16384)·banner/log없음',
               'exit': 'success/errorpayload 모두정상출력0,준비/상한/write/flush실패1·입력원문없는고정stderr',
               'failure_message': 'Network Quick Check: 결과 출력에 실패했습니다.\n',
               'no_stdin': True},
    'io_failures': 'noargs/help/invalid 정적stderr write/flush실패는1(정상invalid는2). worker stdout실패는1이며부분출력회수불가한계유지.',
    'factory': 'std::env::current_exe()절대PathBuf만NativeDnsProbeBackend::new에전달. 실패/비절대failclosed. argv0/PATH/CWD/envhelper/QAhelperfallback금지. 생성만하며noargs/help/worker에서호출0.',
    'pure_tests': '기본시험은내부parser/메모리Write/합성payload/worker literal 또는private injectableworker만. domain해석/process/network/runtime/실제파일쓰기없음. 인자별worker호출0/1관찰가능한privatecallback테스트가능.',
    'native_test': 'tests/resolver_dispatch.rs의모든실제행위는#[ignore]·부모명시전용. env!(CARGO_BIN_EXE_NetworkQuickCheck)정확절대경로를NativeDnsProbeBackend::new에설정·current_exe함수는testharness라제품경로증거로사용금지. 소유localhost+동일portIPv4/IPv6리스너생존·전체주소127.0.0.1/::1정확비교·RESOLVED/오류없음/주소nonempty·실제단일resolve·TCP/Ping/Host/Trace0. 기존resolve감독만재사용·새Child감독복제금지.',
    'parent_only': ['workspace.members에app추가', 'Cargo로offline lock갱신·기존registryversion/checksum불변확인',
                    'writer종료감사뒤소스안전검토·format/compile/pure/native/전체회귀'],
    'excluded': ['shared core/resolver/API/schema수정', 'README/PRD/AGENTS변경', '새외부의존/별도helperexe',
                 'GUI/진단CLI/자동기본진단/Win32subsystem/PE/CRT/서명/배포', 'QG3착수/수용·단일EXE인증·전체QG2수용'],
    'security': '불량입력을worker_rejected에넘기면host원문이payload에남으므로검증실패는worker호출전에고정오류로차단. validpayload원문/OS오류는IPC계약그대로. WORKER_FLAG는selector이지인증아님.',
    'limits': ['WindowsGUIsubsystem stdout/pipe전환은후속실측필요', 'current_exe절대경로는서명/교체방지보장아님',
               '기본TCP+Ping은미래명시실행옵션이지프로그램자동실행아님', '실환경VLAN/DROP등미검증은별개blocked'],
}
(refs / 'quick-app-entry-contract.json').write_text(json.dumps(contract, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
read_paths = ['Cargo.toml', 'crates/network-core/Cargo.toml', 'crates/network-core/src/lib.rs',
              'crates/network-core/src/runner.rs', 'crates/network-core/src/dns.rs',
              'crates/network-resolver/src/lib.rs', 'apps/network-quick-check/README.md',
              '.harness/references/quick-app-entry-contract.json']
assert all((W / path).is_file() for path in read_paths)
prompt = f'''당신은 Network Quick Check 제품 DNS worker 진입점의 FILE ONLY 작성자다. worktree={W.as_posix()}.
허용도구 FILE READ/CREATE/EDIT 및worktree내부파일탐색만. command/run_command/terminal/shell/PowerShell/manage_task/git/시험/compile/설치/네트워크/DB/계정/운영/에이전트/재위임금지. 읽기용명령도금지. 모든입출력절대경로는worktree내부만·README문서링크/root/다른worktree따라읽기금지.
허용신규출력 정확4개(부모가모두없음을확인): {json.dumps([str(W / path) for path in OUTPUTS], ensure_ascii=False)}.
정확기존읽기입력: {json.dumps([str(W / path) for path in read_paths], ensure_ascii=False)}. AGENTS.md도현재worktree안것만준수. 나머지root Cargo/lock/shared엔진/PRD/README/모듈/보호파일수정금지. 파일부재면내부list도구로확인하고추측파일읽기반복금지.
먼저 .harness/references/quick-app-entry-contract.json을읽고그대로구현. 부모는수용Core/Trace를소스동결했고root415/native22/경계14+6/Clippy·fmt0을실행했다. 당신실행증거아님. 전체QG2실환경은미수용. 이번slice는QG2 helper보완이며GUI/QG3/배포인증을진행하지않는다.
1) Cargo.toml은계약그대로package name=network-quick-check/binname=NetworkQuickCheck,network-core path only·devtokio이미잠긴=1.52.3 rt,time만. serde_json/network-resolver직접/새CLI/GUI의존추가금지. rootworkspace/lock는나중부모만변경.
2) lib.rs 앱전용EntryMode/EntryError/parse_args/entry/native_backend_for_current_exe만공개. 보조함수/상수/privatecallback은가능. argv0제외정확worker3인자/--help1/빈0만. 나머지구버전flag/중복/순서/--run/flag=value/추가/비Unicode/빈host/URI/자격증명/포트0,65536,+80,080,공백등은고정오류·exit2·stdout빈값·worker0. validate_host/parse_helper_port원본을호출하고실패문자열은외부반사금지. 내부Private worker callback으로분기호출0/1순수검증가능하나기존API/엔진복제금지.
3) 정상worker분기만기존run_worker_from_args(&host,&port_arg)와worker_output_line재사용. worker_rejected가불량host반사하므로반드시양입력사전검증. 실제UTF8 bytes가MAX_PAYLOAD_BYTES이하·정확한줄+LF인지출력전검사. write_all+flush실패는1·정적stderr,부분JSON을성공으로자르지않음. 정상OS해석오류payload도0. stdout에banner/log/QuickResult없음·stdin없음. Worker에서resolve_isolated/backendfactory/자식process/runtime/GUI를재귀호출하지말라. 기존payload/주소32/OS오류512제한·None그대로유지.
4) noargs/help는계약정적stderr한줄/exit0·stdout빈값·해석/프로브/자식/runtime/GUI/factory호출0. 사용자자동진단/미구현GUI성공인척금지. main은args_os skip1 take4→entry→ExitCode만. windows_subsystem속성/build.rs/manifest/CRT/서명없음.
5) factory는current_exe절대경로만NativeDnsProbeBackend::new,실패/비절대failclosed. argv0/PATH/CWD/환경helper/QAhelperfallback금지. noargs/help/worker는factory0. factory시험에서test current_exe를제품EXE증거로오해금지.
6) lib내부순수시험: parser모든경계·비Unicode(Windows OsStringExt from_wide unpaired surrogate)·정적오류비반사·noargs/help/invalid0·유효worker1·메모리writer partialwrite/write/flush실패·합성success/errorpayload·literal IPv4/IPv6정확한줄/최종LF/상한실제바이트·overflow/다중line거부. puredomainworker실제호출0. 도메인문자열은parser또는injectable합성worker까지만. 문자열len/샘플padding만으로budget추정말고실제UTF8bytes를검사. 기존decoder decode_worker_payload로동등성을검증할수있으며새프로토콜파서복제금지.
7) tests/resolver_dispatch.rs는부모명시#[ignore] 실제소유localhost NativeDnsProbeBackend→제품동일EXE worker IPC검증만. env!(CARGO_BIN_EXE_NetworkQuickCheck)정확제품절대경로,부모소유127.0.0.1 port0·동일port::1리스너둘다시험끝까지생존·모두없으면expect실패. Tokio runtime는ignored시험내부만. resolve한번·RESOLVED/nonempty/오류없음·rawhost/port·전체SocketAddr주소정확127.0.0.1/::1+소유port검증·TCP/Ping/Host/Trace호출금지. 새stdprocess child감독/통신복제금지;기존resolve감독만재사용. main의실제noargs/help/invalid/literal subprocess시험은부모가bounded Python으로별도수행하므로당신은Rust에서그감독을중복작성하지않음. 제품에faultflag/slow/overflow/localhost전용제약추가금지.
한국어흐름설명주석·UTF8·최종개행1개·후행공백없음·helper인수<=7·Clippy suppression금지. 작성후부모감사/실행전안전검토까지미검증이며컴파일/시험/수용/제품완료주장금지. 최종한국어변경경로/설명/부모검증필요사항만.
'''
(R / '.harness/prompts' / (STAGE + '-' + ROLE + '.md')).write_text(prompt, encoding='utf-8', newline='\n')
record = {'recorded_at': datetime.datetime.now().astimezone().isoformat(), 'stage': STAGE, 'role': ROLE,
          'model': 'gemini-3.8-flash-high', 'worktree': str(W), 'baseline_commit': git(W, 'rev-parse', 'HEAD'),
          'source_sha256': {path: sha(W / path) for path in sorted(set(inputs) | set(frozen))},
          'contract': contract, 'allowed_outputs': OUTPUTS, 'verified_existing_inputs': read_paths,
          'outputs_absent_at_start': True, 'source_review_required_before_execution': True,
          'accepted': False, 'root_integrated': False}
out = R / 'artifacts/qg2f-app-entry-prepared.json'
assert not out.exists()
out.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'stage':STAGE,'role':ROLE,'baseline_commit':record['baseline_commit'],
                  'frozen_files':len(record['source_sha256']),'allowed_outputs':OUTPUTS,'accepted':False}, ensure_ascii=False))
