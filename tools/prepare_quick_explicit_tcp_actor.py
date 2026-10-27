"""제품 EXE의 명시 TCP 개발보조 진입점에 대한 FILE ONLY 계약을 고정한다."""
import datetime
import hashlib
import json
import pathlib
import shutil
import subprocess

R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgdevtcp'
APP='apps/network-quick-check/'
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
p=load('artifacts/qg2i-explicit-tcp-prepared.json')
assert all(sha(W/path)==value for path,value in p['immutable_source_sha256'].items())
assert all(sha(R/path)==value for path,value in p['root_before_sha256'].items())
status=subprocess.run(['git','-C',str(W),'status','--porcelain'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
assert status.returncode==0 and not status.stdout.rstrip('\r\n')
ref=W/'.harness/references/explicit-tcp-entry-contract.json'
out=R/'artifacts/qg2i-explicit-tcp-actor-prepared.json'
assert not ref.exists() and not out.exists()
ref.parent.mkdir(parents=True,exist_ok=True)
# Tokio 공개 API의 정확한 로컬 원문을 전용 W로 복사하여 외부 vendor 경로를 읽을 이유를 없앤다.
vendor=pathlib.Path('C:/Users/HODI/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tokio-1.52.3/src/signal/windows.rs')
assert vendor.is_file()
shutil.copyfile(vendor,ref.parent/'tokio-1.52.3-signal-windows.rs')
contract={**p,'version':'qg2i-explicit-tcp-entry-0.1','recorded_at':datetime.datetime.now().astimezone().isoformat(),
    'status':'CONTRACT_FROZEN_FOR_FILE_WRITER','selector':'--dev-tcp-once-v1','args_excluding_argv0':3,
    'options':{'tcp_timeout_ms':3000,'concurrency':1,'selected_features':['TcpConnect'],'max_result_bytes':32768},
    'max_complete_wire_bytes':65536,'exit_codes':{'0':'원문report 전달 완료·TCP PASS 뜻 아님',
        '1':'local/reporterrors/limit/출력오류','2':'인자거부','3':'오류없이취소report전달완료'},
    'worker_unchanged':True,'legacy_public_parser_and_entrymode_unchanged':True,
    'public_new_api_allowed':False,'core_or_inspector_or_resolver_changed':False,
    'new_wire_dto_or_result_reclassification_allowed':False,
    'default_tests':'네트워크/파일/제품프로세스/네이티브factory/신호등록0. 모의run_quick에는I/O·time driver 없는CPU current-thread runtime만허용',
    'noargs_help_invalid_worker_diagnostic_startup':0,
    'native_tests':'Windows ignored4개·CARGO_BIN_EXE_NetworkQuickCheck의실제EXE·127.0.0.1/::1소유singleport·CONNECTED/REFUSED10061·재시도/옵션변경/earlyreturn0',
    'native_signal_preflight':load('artifacts/qg2i-entry-owned-signal-registration.json'),
    'cancellation_limit':'앱소유signal대기task/receiver회수와실제OS신호전달/프로세스전역Tokiohandler등록해제/OS즉시회수인증을구분한다',
    'design_review':'deleg_ed3799ab','design_representation':'실제소스대조후부모가정규화·범위선택한제한구현계약·전체수용아님',
    'accepted':False,'root_integrated':False}
for path in (ref,out):
    path.write_text(json.dumps(contract,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
reads=['AGENTS.md','.harness/references/explicit-tcp-entry-contract.json',
    '.harness/references/tokio-1.52.3-signal-windows.rs','PRD.md',
    'docs/requirements/Network_Path_Inspector_Harness_PRD_v1.2.md','contracts/quick-check-interface-v0.1.json',
    APP+'Cargo.toml',APP+'src/lib.rs',APP+'src/main.rs',APP+'tests/resolver_dispatch.rs',
    'crates/network-core/src/runner.rs','crates/network-core/src/targets.rs','crates/network-core/src/quick.rs',
    'crates/network-core/src/lib.rs','crates/network-core/tests/runner.rs',
    'crates/network-core/tests/tcp_product_native_equivalence.rs','crates/network-resolver/src/lib.rs']
assert all((W/path).is_file() for path in reads)
prompt=f'''당신은QG2 제품EXE의명시개발용TCP단일대상진입점 FILE ONLY 구현자다. 전용worktree={W.as_posix()}.
처음에{ref.as_posix()}를읽어부모동결계약을준수하라. FILE READ/CREATE/EDIT 및내부탐색만허용. command/run_command/terminal/PowerShell/git/test/build/network/install/manage_task/계정/다른agent/재위임은읽기목적도금지. 모든파일경로는이전용worktree내절대경로. root나타worktree나vendor절대경로/문서link를따라읽지말라. 필요한Tokio신호API원문도W내reference로준비했다.
정확히허용된출력3개:{json.dumps([(W/path).as_posix() for path in p['actor_writes']],ensure_ascii=False)}. lib.rs만기존파일이며나머지2개는아직없고새로작성해야한다. 나머지기존시험·manifest·lock·main·문서·Core·Inspector·resolver·계약수정금지. 부모가고정의존성metadata2개만W에미리준비했고현재원본앱소스/95개공유입력을동결했다. Cargo명령은금지다.
검증된입력목록:{json.dumps([(W/path).as_posix() for path in reads],ensure_ascii=False)}. 제공파일이없으면추측파일반복탐색하지말고blocker보고하라.
구현조건:
1. 별도비공개 diagnostic_cli.rs에새기능과단위시험을격리한다. lib.rs변경은비공개 mod diagnostic_cli; 선언, public entry의선행 try_entry분기및그분기의정확한문서주석만최소추가한다. 기존parse_args/EntryMode/entry_with_worker/backend factory·기존unit tests·안내문구·상수/worker구현은그대로보존한다. 공개enum variant/API추가금지. entry는새selector가아닌경우원래entry_with_worker로정확히위임한다. 기존parse_args는legacy parser이므로새selector를계속거부하는것이의도된계약이다. 새로운try_entry는pub(super)이하만허용한다.
2. 새selector정확 --dev-tcp-once-v1 <host> <canonical-decimal-port>, argv0제외정확3개. main.take(4)수정금지:4번째인자는초과인자sentinel로거부되어야한다. 비Unicode/형식불량은고정INVALID_STDERR·stdout0·exit2·원문반사0. host를그대로기존network_core::dns_engine::validate_host, port를parse_helper_port로그대로검증한후targets::parse_target_pair와build_quick_plan을모두I/O전에통과시킨다. trim/대소문자수리/선행0포트수리/주소fallback금지. bareIPv6만·bracket/URI/자격증명/CIDR/목록/제어공백/잘못된숫자IP/금지IP거부. 도메인후행점은두기존validator의교집합에따라거부·기존worker허용문법변경금지.
3. 유효입력만 QuickRunRequest를만든다. 단일target,QuickOptions tcp_timeout_ms=DEFAULT_TCP_TIMEOUT_MS(기존3000),concurrency=1,selected_features=vec![QuickFeature::TcpConnect]를명시. QuickOptions::default()는Ping을켠다·금지. max_result_bytes32768. timestamp_iso8601/source_host는None으로정직하게null,session_id는실제프로세스내비어있지않은로컬ID(현재시각을사용해도측정timestamp를발명하지말라). Request/plan검증이끝난뒤에만I/O가능. 기본모의시험을위해request조립/실행콜백/출력의비공개seam을두되외부public API·새wire DTO는만들지말라.
4. 네이티브진입은유효opt-in에서만current-thread Tokio runtime Builder.enable_all()생성. 기존crate::native_backend_for_current_exe()로기존NativeDnsProbeBackend를만들고실제network_core::runner::run_quick(request,Arc<dyn QuickProbeBackend>,Arc<AtomicBool>)만호출한다. 새로운엔진/측정/projector/DTO매핑복제금지. 같은cancel Arc를신호대기와run_quick에전달한다. 기존Core가IP이면resolve0,TCP1;domain이면필수resolve만1·첫주소만·불량첫주소/해석실패는TCP0/기존UNAVAILABLE·선택DnsLookup0라는동작을그대로보존하라.
5. Windows ctrl_c()와ctrl_break() receiver등록을run_quick시작전에완료하고등록실패는고정local오류exit1(stdout0)로닫는다. production은Windows전용이며타OS에는명시적고정local실패만·검증성공주장0. 신호대기는취소flag만설정하고runner future를drop하거나process::exit/abort하여DNS정리를뛰어넘지않는다. 반드시run_quick반환을기다린뒤소유신호대기task를abort+await하고runtime을해제한다. 신호task joinpanic/error도무시금지. report를이미받았으면원문report를보존해출력하고local오류exit1을우선한다. 내부비직렬화control tuple/struct는가능하지만새JSON wrapper/DTO는금지다. Tokio의전역signal handler등록이receiverdrop으로원복된다고주장하지말라·과장즉시OS회수보장0. mock신호future로취소seam을검증하고기본시험에서실제OS신호등록은절대금지.
6. 기존QuickRunReport 전체를serde_json으로compact1줄+LF출력. report/raw/상태/metadata/errors/nullable를재분류/삭제/보정/추가하지말라. 최대wire65536byte는구두점·UTF8·LF포함한전체상한이고results합serialized_result_bytes와다르다. 상한있는메모리Write에먼저직렬화+LF까지완료한뒤stdout.write_all+flush; 초과/직렬화오류는stdout0·고정오류exit1·잘린JSON생성금지. stdout의partialwrite/WriteZero/flush실패는exit1이고이미기록된partialstdout의원자성은보장하지않는다. stderr오류도성공으로위장금지. exit0=완전report전달이며TCP PASS뜻아님·REFUSED/DNS UNAVAILABLE도원문report. exit1=local/출력오류또는report.errors비어있지않음/limit_reached; exit2=사전인자거부; exit3=오류없고취소report전달완료. 우선순위local/출력1>cancel3>정상0. 새로운오류문구는고정한국어이며불량argv/경로/OS오류문자열반사0. 기존workerwire16384와고정stderr/exit는변경금지.
7. diagnostic_cli.rs의기본#[test]들은파일/제품process/네트워크/nativefactory/실제신호등록0. mockedrun_quick의task스케줄링은Builder.new_current_thread().build()만(I/O/time driver활성화0)사용가능. purecallback으로noargs/help/invalid/worker에서진단start콜백0·고정stderr/exit·유효request단일TCP/options검증. 非Unicode/초과인자/host,port경계/원문sentinel비반사. 실제run_quick+mock backend로IP resolve0 TCP1 others0,domain필수resolve1·TCP최대1(여러주소/불량첫주소/DNS실패는원문보존),pre-cancel호출0확인. backend mock은실제projector사용·생산결과판정복제금지. 실행중취소는firstpoll진입/cleanup해제barrier로동일Arc와drain완료·후속프로브0증명·sleep이나동기메서드진입만으로대체금지. wire전체실제UTF8 MAX-1/MAX/MAX+1·한글/escapedCRLF/quotes·전체JSON roundtrip·partialwrite/WriteZero/flush실패·reporterrors/limit/cancel exit우선순위. wire경계의과대synthetic report는출력guard전용fixture라고명시하라. struct↔Value는전체구조값동등성,같은표현전후bytes보존만검사·map key순서byte직접비교실패반복금지.
8. 새tests/explicit_tcp_entry.rs에는Windows전용실제제품EXE #[ignore="부모 소유 루프백 명시 실행"] 시험4개(native_ipv4_connected/native_ipv4_refused/native_ipv6_connected/native_ipv6_refused). CARGO_BIN_EXE_NetworkQuickCheck 절대파일경로존재필수·부재/IPv6미구성/.ok()/earlyreturn/skip/fallback/재시도는실패. 정확127.0.0.1/::1와소유ephemeral port1개만·domain/localhost/wildcard/외부IP실행0. 직접spawn한Child만RAII로kill/wait,stdout<=65536/stderr고정상한/각stage유한timeout·reader정리. stdout미공백·단일LFJSON으로QuickRunReport역직렬화·exit0·reporterrors0/cancel/limit/omitted0,target1,TCP1/DNSPingTraceHost0,raw전체귀속/정확resolved_ip/포트/outcome/status/evidence/원시OScode/metadata명시null검증. 성공fixture listener는child완료/accept/비어있지않은buffer로EOF까지소유·서버쓰기0·수신applicationbytes0·peer와raw.local_address대조. refusal은살아있는TcpSocket bound/nonlisten을child까지유지·실제REFUSED10061·거부local_address=null을요구한다. OS socket옵션수정0·기대보정0·3000입력실패도그대로실패. bound소켓은전OS독점예약/모든race제거보장아님. TCP접속성공은packet관찰/서비스정상/DB로그인증거가아니다. 부모는기존실제EXE CLI38와native27도다시실행한다·그기존시험기대변경금지.
한국어읽기쉬운흐름주석·UTF8·마지막개행·후행공백0·Clippy suppression금지·함수인자<=7·불필요public API/테스트인식프로덕션분기/환경우회금지. app source는작게시작하되요구한안전·취소·경계단언을빼지말라. 모든실제OS측정은ignored4개만·default의mockruntime은CPU스케줄링만이다.
FILE작성후정확3개변경경로·주요흐름·부모검증필요점만한국어보고. 명령/시험실행/수용/통과주장금지. 부모가종료→terminal SUCCESS/partial/실제tool/path/afterSHA감사→독립정적QA→format/compile/시험→선택통합한다. 전체QG2/GUI/QG3·배포·실도메인TCP·실Windows Console취소/OS회수·성능/정규timestamp요구는미검증으로유지.
'''
path=R/'.harness/prompts'/(p['stage']+'-'+p['role']+'.md')
assert not path.exists()
path.write_text(prompt,encoding='utf-8',newline='\n')
print(json.dumps({'stage':p['stage'],'role':p['role'],'worktree':str(W),'actor_writes':p['actor_writes'],
    'immutable_source_files':len(p['immutable_source_sha256']),'actor_started':False,'root_integrated':False},ensure_ascii=False))
