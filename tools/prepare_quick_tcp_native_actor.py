"""읽기 전용 설계 제안을 실제 API에 대조해 native test-only 작성 계약을 고정한다."""
import datetime
import hashlib
import json
import pathlib
import subprocess

R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgtcpnative'
TEST='crates/network-core/tests/tcp_product_native_equivalence.rs'
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
prepared=load('artifacts/qg2h-tcp-native-prepared.json')
assert not (W/TEST).exists()
assert all(sha(W/path)==value and sha(R/path)==value for path,value in prepared['immutable_source_sha256'].items())
status=subprocess.run(['git','-C',str(W),'status','--porcelain'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
assert status.returncode==0 and not status.stdout.rstrip('\r\n')
source=(W/'crates/network-core/src/runner.rs').read_text(encoding='utf-8')
assert 'pub async fn run_quick(' in source and 'run_quick_with_backend' not in source
transcript=pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/delegation/live/deleg_44dc1296/task-0.log')
text=transcript.read_text(encoding='utf-8')
assert 'end status=completed' in text
now=datetime.datetime.now().astimezone().isoformat()
contract={
    'version':'qg2h-owned-native-tcp-products-0.1','recorded_at':now,'worktree':str(W),
    'stage':prepared['stage'],'role':prepared['role'],'model':prepared['model'],
    'baseline_commit':prepared['baseline_commit'],'actor_writes':[TEST],
    'immutable_source_sha256':prepared['immutable_source_sha256'],
    'design_review':'deleg_44dc1296','design_representation':'완전한async응답을부모가실제소스와대조한정규화계약·live본문잘림가능',
    'design_transcript':{'path':str(transcript),'sha256':sha(transcript)},
    'parent_corrections':['Quick실제공개API는run_quick(request,Arc<dyn QuickProbeBackend>,cancel)·가상with_backend함수생성금지',
        'actor의출력경로는root가아닌전용worktree내1파일·제안의root출력표기는채택하지않음',
        'bound/nonlisten은소유유지에따른close-race감소일뿐독점예약보장아님·OS옵션/결과보정금지',
        '같은실측raw replay와별도시점native측정을분리·elapsed/localport전체동일요구금지',
        'parent범위보강: 잘못된주소/포트/컨텍스트/timeout을실제wrapper가네이티브위임전거부하는순수시험1개권장'],
    'native_matrix':[
        {'name':'native_ipv4_connected','ip':'127.0.0.1','fixture':'소유listener유지·각제품accept/nonemptybuffer EOF관찰','outcome':'CONNECTED','error_code':None},
        {'name':'native_ipv4_refused','ip':'127.0.0.1','fixture':'소유TcpSocket bound/nonlisten유지','outcome':'REFUSED','error_code':10061},
        {'name':'native_ipv6_connected','ip':'::1','fixture':'소유listener유지·각제품accept/nonemptybuffer EOF관찰','outcome':'CONNECTED','error_code':None},
        {'name':'native_ipv6_refused','ip':'::1','fixture':'소유TcpSocket bound/nonlisten유지','outcome':'REFUSED','error_code':10061},
    ],
    'native_policy':'Windows전용4개#[tokio::test]+#[ignore=부모명시실행]·default시험은네트워크/runtime0',
    'allowed_extra_pure_test':'실제wrapper직접호출·부정입력첫poll 즉시Err·Native위임counter0·표준noopWaker만·runtime/socket0',
    'product_selection':'Inspector selected_features tcp_connect만·retries0/concurrency1/capturefalse. Quick TcpConnect만/concurrency1·같은목적지/포트/timeout1000ms',
    'wrapper':'실제QuickProbeBackend::tcp만NativeProbeBackend::tcp에위임·target/ctxhost/ctxport/timeout정확대조·다른4메서드는별도집계후즉시Err·native반환재작성0·반환전serdebytes보관해최종행과비교',
    'inspector':'실제run_profile전체JSON/23FeatureResult·counts tcp1 host0 icmp0·measurements tcp만·미선택SKIPPED_BY_USER·실제TCProw와자기raw대조',
    'quick':'실제run_quick최종1행·counts tcp1 others0·wrapper집계일치·errors0/cancelledfalse/limitfalse/omitted0/targets1/serializedbyte집계대조',
    'same_raw_replay':'Inspector실측raw를정식TcpMeasurement역직렬화후실제tcp_to_quick_result입력·원문JSON/serde bytes전후동일·raw전체동등·row/replay.duration/code무손실',
    'separate_native':'독립적인2native결과는각자기대outcome/OS코드/원문귀속만·elapsed/clientport/raw전체의동일또는다름을요구하지않음',
    'connected_observation':'각제품연결을해당accept peer와raw local_address대조·서버는쓰기0·비어있지않은버퍼로EOF검증·빈버퍼/즉시drop/카운터만으로대체금지',
    'refused_observation':'예약소켓두측정까지유지·실제REFUSED10061/null local/bytes0·OS메시지언어무가정·추가연결/자동retry/다른주소fallback0',
    'cleanup':'prod/accept/EOF모두유한timeout·분리server spawn없이joinfuture우선·오류/timeout도future/socket/stream RAII회수·엄격OS즉시취소보장주장금지',
    'forbidden':['production/기존test/manifest/lock/문서/계약수정','판정/DTO복제·native결과수정·가짜raw/결과대체',
        '운영망/domain/localhost/wildcard/외부주소연결','소켓옵션·방화벽/route/registry/admin/드라이버변경',
        'actor command/test/network/install/git/계정/재위임','환경문제조기return/.ok/skip/fallback·10061보정·성공까지재시도'],
    'limits':['메모리EngineEnvelope/Quickrunner연결증거만·Archive/정규Session아님',
        '명시진단제품EXE경로/GUI/QG3·전체QG2실VLAN/DROP/ICMP차단/VPN/성능/배포/OS인증아님'],
    'accepted':False,'root_integrated':False,
}

ref=W/'.harness/references/tcp-product-native-contract.json'
out=R/'artifacts/qg2h-tcp-native-actor-prepared.json'
assert not ref.exists() and not out.exists()
ref.parent.mkdir(parents=True,exist_ok=True)
for path in [ref,out]:
    path.write_text(json.dumps(contract,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
reads=['AGENTS.md','.harness/references/tcp-product-native-contract.json',
       'crates/network-core/src/runner.rs','crates/network-core/src/quick.rs','crates/network-core/src/targets.rs',
       'crates/network-core/src/lib.rs','crates/network-core/Cargo.toml','crates/network-core/tests/runner.rs',
       'crates/network-core/tests/tcp_product_projection_replay.rs','crates/npi-probes/src/engine.rs',
       'crates/npi-probes/src/tcp.rs','crates/npi-probes/tests/engine.rs','crates/npi-core/src/models.rs',
       'crates/npi-core/src/lib.rs','contracts/quick-check-interface-v0.1.json']
assert all((W/path).is_file() for path in reads)
prompt=f'''당신은QG2의실제양제품소유루프백TCP대조시험FILE ONLY작성자다. 전용worktree={W.as_posix()}.
반드시먼저{ref.as_posix()}를읽고그계약을준수한다. READ/CREATE/EDIT/내부파일탐색만허용. command/run_command/terminal/PowerShell/git/컴파일/시험/network/OS도구/install/manage_task/계정/에이전트/재위임금지·읽기용명령도금지. FILE경로는항상전용worktree내절대경로·root/타worktree/문서link추적금지. AGENTS.md준수.
수정/생성허용은새파일정확1개:{W.as_posix()}/{TEST}. 이는아직없으며당신이새로작성할출력이다. 기존소스/기존시험/manifest/lock/문서/계약변경금지. 입력목록:{json.dumps([(W/path).as_posix() for path in reads],ensure_ascii=False)}.
부모가이미source94개를동결했다. Inspector apply_tcp_result의승인된public4byte변경은이전단계에서수용됐고당신이변경할부분없다. 새코드엔진/projector/DTO/API생성하지말고기존진짜함수를호출하라. 현재core공개API는network_core::runner::run_quick(request,&아닌Arc<dyn QuickProbeBackend>,Arc<AtomicBool>)이다. run_quick_with_backend라는실제함수는없다·가상함수생성금지·원래이름을그대로사용하라.
구현범위:
1) Windows전용모듈에native_ipv4_connected/native_ipv4_refused/native_ipv6_connected/native_ipv6_refused 네개#[tokio::test]를작성하고모두#[ignore="소유 루프백 실제 시험: 부모 명시 실행"]로분리. 기본시험에서fixture/socket/DNS/process/native/runtime시작0. 실제I/O함수는4ignored시험경로에만있어야함. 환경실패시return/.ok/skip/fallback금지.
2) exact127.0.0.1또는::1:OS할당nonzero목적지포트1개만. wildcard/domain/localhost/원격/미소유port/자동retry/포트스캔금지. Inspector실제run_profile과Quick실제run_quick을동일IP/port/timeout1000ms·TCP선택만/concurrency1로각각순차실행. Inspector23행중TCP1개실행/나머지SKIPPED·collectorcounts정확tcp1host0icmp0·measurements키tcp하나. Quick1행/counters tcp1others0·errors/cancel/limit/omitted0·targets1·메타원문귀속및serializedbytes검증. 타임스탬프는None입력으로고정해가짜실측UTC를만들지말라.
3) 시험전용QuickProbeBackend wrapper:tcp에서먼저target주소/IP/port·ctx.target_host/target_port·timeout이소유fixture와정확일치하는지검사하고그후NativeProbeBackend::tcp에1번위임. connect_once직접호출대체금지·동일부모측정DTO를Quicknative에끼워넣지말라. native반환은재작성0·반환직전serde_json::to_vec바이트를Mutex등메모리에보관하여최종보고행전체와비교가능. icmp/host/resolve/trace는명시적으로별도counter후즉시Err·네이티브위임0. 실제4시험에서wrappercounter도확인.
4) 성공fixture는listener를2제품실행/각accept와EOF관찰끝까지소유. 각제품실행future와해당accept/readfuture를함께진행하되이전제품완료뒤다음제품실행. 서버payload쓰기0,nonemptybuffer read EOF로애플리케이션바이트0관찰·acceptpeer와각해당raw.local_address정확대조. tokio features에io-util없으므로AsyncReadExt/새의존성추가금지·TcpStream.readable()/try_read()로WouldBlock반복대기·유한timeout. 빈bufferread/즉시drop/카운터만으로서버관찰대체금지. 분리된spawn서버없이joinfuture우선·각stage유한timeout(예3초,전체10초등hang방지상한이며성능목표아님). 양제품outcome CONNECTED/Noneerrorcode·Noneerrormsg/bytes0·PASS OBSERVED.
5) 거부fixture는TcpSocket::new_v4/v6후정확IP:0 bind만·listen/connect/setsockopt금지. local_addr nonzero 확인후해당socket을두제품실행완료까지유지. 생성후close→미소유port재접속/race금지. 반드시실제REFUSED/10061·raw.local_address None·bytes0·FAIL OBSERVED. 실패를보정하거나다른port재시도하지말라. bound소켓이OS전체독점예약보장이라고주장하지말라.
6) Inspector반환JSON measurements.tcp_connect가진짜원시값이다. 정식TcpMeasurement로serde역직렬화후자기원시값으로실제Inspector TCP행(duration/code/evidence_ids/time/limitations등)을검증. 이같은실측raw로실제tcp_to_quick_result를추가호출해정확raw전체/같은raw의elapsed/errorcode확인·추가소켓0. 원시JSON→serde변환을위한Value.clone은가능하지만합성측정DTO/기대DTO재구성/필드삭제·수정·상태정규화금지. raw/Envelope는호출전후serdebytes로보존확인. Quicknative는자기raw기준으로독립검증하고Inspectorraw로대체금지. 두서로다른native시점의elapsed/localport/raw전체는같거나반드시달라야한다는단언금지.
7) 추가순수#[test]1개로실제wrapper.tcp직접호출시잘못된IP/port/ctxhost/ctxport/timeout을native위임전에거부함을확인하라. syntheticowned주소는이시험에서입력표식일뿐소켓소유주장아님. runtime/socket0·std::task::Waker::noop()로future첫poll즉시Err확인·Native위임counter0. production호출가드와분리된헬퍼만검사하는거짓양성금지. 정상positive경로는4native시험에서실제위임/실제OS결과/서버관찰로검증한다.
한국어흐름설명주석·UTF8·마지막개행·후행공백없음·Clippy suppression금지·도우미args<=7. 모든fixture RAII/futuredrop회수. 단일대상관측을실VLAN/DROP/ICMP차단/packet/service/Archive/Session/전체QG2/GUI/제품EXE/배포/OS/성능인증으로승격금지.
부모가작성이끝난뒤도구/경로/terminal/partial/afterSHA를감사하고독립정적QA뒤에만compile/native실행한다. 당신은명령/시험/실제network를수행하지않는다. 최종한국어변경경로·시험설계·부모미검증사항만반환하고성공/통과/수용주장하지말라.
'''
prompt_path=R/'.harness/prompts/qg2tcpnative-qgtcpnative.md'
assert not prompt_path.exists()
prompt_path.write_text(prompt,encoding='utf-8',newline='\n')
print(json.dumps({'stage':contract['stage'],'role':contract['role'],'worktree':str(W),
    'contract':str(out),'immutable_files':len(contract['immutable_source_sha256']),
    'actual_quick_api_verified':'run_quick','actor_started':False,'native_executed':False},ensure_ascii=False))
