"""검증된 Win32 바인딩을 소비하는 입력·계획 GUI FILE ONLY 계약을 동결한다."""
import datetime
import hashlib
import json
import pathlib
import subprocess

R = pathlib.Path(__file__).resolve().parents[1]
APP = 'apps/network-quick-check/'
load = lambda p: json.loads((R / p).read_text(encoding='utf-8'))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
p = load('artifacts/qg3b-gui-inputs-prepared.json')
W = pathlib.Path(p['worktree'])
ref = pathlib.Path(p['reference_directory'])
contract_path = ref / 'gui-inputs-contract.md'
out = R / 'artifacts/qg3b-gui-inputs-actor-prepared.json'
prompt_path = R / '.harness/prompts' / (p['stage'] + '-' + p['role'] + '.md')
assert not out.exists() and not prompt_path.exists()
assert all(sha(R / path) == h for path, h in p['root_before_sha256'].items())
assert all(sha(W / path) == h for path, h in p['immutable_source_sha256'].items())
assert all(sha(W / path) == h for path, h in p['reference_sha256'].items())
status = subprocess.run(['git', '-C', str(W), 'status', '--porcelain'], capture_output=True, text=True,
                        encoding='utf-8', errors='replace', timeout=30)
assert status.returncode == 0 and not status.stdout.rstrip('\r\n')
contract = '''# QG3B 입력·계획 Win32 GUI 구현 계약 0.1
## 승인·범위
사용자가GUI병행과개발순서부모재량을승인했다. 최신root477PASS/31ignored·GuiState제한수용, 전체QG2/QG3/제품/배포/OS인증은미완료. 이번은실제입력/대상관리/기능선택/계획확인이가능한Win32화면이며실네트워크진단은미연결이다. 새selector는부모선택개발보조경로이지사용자가selector철자를별도승인했다고주장하지않는다.
정확1인자 --dev-gui-inputs-v1 로만연다. noargs/help/worker/기존개발TCP·stdout/stderr문구·exit·자동진단0을유지한다. main.take(4)/CUI subsystem/콘솔표시는유지. 기본실행GUI전환이나콘솔숨김은하지않는다.
첫단위선택항목인-place수정은제외한다. 추가/전체교체/선택삭제로목록관리하며기존100상한과중복제거를제공한다. 편집전용UI임을상시표시한다. 검사시작/중지/TXTCSV저장버튼은비활성·가짜결과/진행률/실측0. 이축소는초기읽기검토제안중부모가선택한범위이며GUI완료아님.

## 파일과정확한진입통합
쓰기정확6: src/lib.rs(기존), 신규src/gui_entry.rs,gui_presenter.rs,gui_presenter_tests.rs,native_gui.rs,native_gui_tests.rs. 접두경로apps/network-quick-check/. 나머지모든파일변경금지. 부모가앱Cargo/lock및windows-sys0.61.2의UI6features만준비했고기존registry package identity/checksum/다른패키지본문을유지했다. manifest/lock/기존gui_state/기존tests/Core/Inspector/resolver/main/diagnostic_cli/PRD/docs불변.
lib.rs의최종byte는옆expected-lib.rs와정확히같게하라. 거기에새private모듈과기존diagnostic_cli분기뒤gui_entry::try_entry(args,stderr)분기및한줄문서만부모가정확히준비했다. 불필요한리팩터링/기존시험수정0.
신규기능은한국어UI/설명주석과한국어최종보고. 다른언어UI라벨금지.

## gui_entry
pub(super)fn try_entry(args:&[OsString],stderr:&mut dyn Write)->Option<u8>는실제/모의가공유하는private launcher dispatcher에위임한다. 정확한첫selector가아니면None·launcher0. 첫selector가맞지만arity가1이아니면기존INVALID_STDERR성공2/write또는flush실패1·launcher0·stdout접근0. Unicode를손실변환하지말라. 정확한1인자만Windows native를열고정상닫힘0/생성·메시지loop·panic실패1고정한국어stderr(원시argv/경로반사0). 비Windows는고정미지원실패1. 새공개API/새wireDTO없음.
같은production dispatcher에FnOnce launcher를주입해기본순수시험:exact1만1회/noargs/help/worker/devTCP/unknown/비Unicode/잘못된arity는0·entry이외OS쿼리0·stderrwrite/flush실패우선순위. 신규selector추가는의도적인확장이지기존모든입력집합완전무변경이아님. legacy parse_args가새selector를계속거부함은의도된정책이다.

## gui_presenter: 순수·기존GuiState소비
GuiPresenter는GuiState와선택인덱스,계획preview와stale표시만소유한다. 기본빈목록/TCP+Ping/3000ms/동시4. GUI상태를복제하지말고기존GuiState메서드로대상추가/전체교체/선택삭제한다. 목록의raw_input을그대로표시·포트080/IPv6bracket/도메인대소문자정책은실제Core그대로. 새중복/주소/포트파서복제0.
선택인덱스범위검증·오류시기존model/선택/preview전체불변,성공한목록변경뒤선택해제·기존preview는변경됨/다시확인표시. 선택없음/잘못된인덱스삭제는명시적오류. 취소/실행중모델상태는기존Busy를존중한다. 모델/plan읽기전용참조만노출·가변참조0.
옵션컨트롤은draft문자열과5기능선택을네이티브측에서읽는다. 순수presenter메서드에서UTF16손실없는decode와ASCII수치parse/overflow를거부한다. 옵션typed값은복제후보GuiState.set_options를거친뒤NoFeatures와실제build_quick_plan으로검증,성공할때만상태/preview확정. timeout/concurrency범위를GUI가복제해정하지말고Core에위임한다. 불량draft는화면에남겨수정가능·모델부분적용0.
계획확인에는begin_run/finish_run/run_quick을절대호출하지않는다. 실행ID/phase/직전완료결과를소비/변경하지않는다. 실제build_quick_plan의전체계획을보존하고대상별원문/기능/필수주소해석여부/TCP와ICMP시간/동시성/limitations를표시한다. 성공한옵션적용과계획확인은원자적으로한다. 이후체크박스/옵션/목록변경은preview stale로표시·이미실행/실측결과인척하지않는다.
입력decode: &[u16]에서잘못된surrogate/명시적으로주어진embeddedNUL/초과UTF16/초과UTF8바이트·truncatedflag를거부,from_utf16_lossy/trim/수리0. Win32텍스트API는NUL로끝나므로OS가전달하지않은NUL뒤원문을검출했다고주장하지말라. Core의32768UTF8byte와EDIT문자수는별개다.
오류/계획표시renderer는UTF8byte65536상한을문자경계에서지켜서만들고생략고지를남긴다. 먼저거대한format String을완성하고나중truncate하지말라. 표시상한은전체프로세스메모리hardcap이나Core원시데이터삭제가아니다. 새의존성없이표준fmt::Write등을사용가능.

## native_gui: 실제창·모든native는명시진입/ignored만
Windows전용private모듈. windows-sys 정확0.61.2의부모제공원문만참조한다. api-index.md에서필요선언과전체원문위치를찾아정확타입/feature를확인하라. EnableWindow/SetFocus는UI/Input/KeyboardAndMouse, EM_SETLIMITTEXT는UI/Controls, WNDCLASSW/RegisterClassW는Gdi gate다. 독자extern FFI/다른버전온라인추정/동적전역설정0.
필수컨트롤:항상보이는'입력·계획 확인 전용 / 네트워크 진단 미연결'라벨;입력안내host:port/[IPv6]:port;여러행EDIT(일반붙여넣기·verticalscroll);raw입력순서LISTBOX(최대100);추가/전체교체/선택삭제/계획확인/닫기버튼;TCP/Ping/Trace/DNS/로컬정보5체크박스(기본TCP/Ping체크);timeout/concurrency EDIT;오류표시영역;read-only다중행스크롤계획표시;비활성검사시작/중지/저장버튼. 예시실제진단/자동조회/합성결과행0. 더블클릭/noargs는기존그대로.
모든대상/옵션작업은production presenter를거쳐서동작하며native에Core판정복제0. 리스트변경후선택해제하고계획stale안내. 버튼/선택/옵션알림source가소유자식HWND와일치하는지도검증한다. 전역데스크톱검색/다른앱조작/공유clipboard API 직접사용금지. 표준EDIT의사용자붙여넣기는허용하지만시험SetWindowText주입을실제clipboard시험이라고하지말라.
GetWindowTextLengthW/GetWindowTextW를확인해상한+terminator범위만할당하고read오류/길이변화를감지한다. EDIT제한은MAX_INPUT_BYTES+1 UTF16단위처럼초과감지여유를둔다. EN_MAXTEXT가오면입력잘림상태를명시하고내용을완전히지운뒤재입력하기전까지추가/교체/계획적용을거부한다. EN_CHANGE만으로잘림을자동해제해조용히잘린입력을정상수용하지말라. options필드에도상한/오버플로검증. 테스트프로그램주입이EDITlimit를우회할수있으므로읽는쪽상한도필수다.
초기창은읽기쉬운크기로만들고최소크기·WM_SIZE레이아웃/버튼Tab순서/스크롤/기본GUI폰트를지원한다. 화면클리핑/125%등은부모실제검증까지미수용. OS전역DPI설정변경·최신OS전용API로구형지원가정금지. Gdi stockfont/공유cursor는소유리소스아니므로DeleteObject/DestroyCursor금지.

## native메모리·재진입·실패
핵심:창상태Box의소유자는create/run guard(메시지loop의Rust호출자)로유지한다. CreateWindowExW의lpParam은빌린안정포인터만전달한다. WndProc에서Box::from_raw로소유권회수/해제하지말라. WM_NCCREATE는userdata등록만,WM_NCDESTROY는userdata0으로해제한다. 생성실패에도외부guard가단한번drop하고정상loop종료전에창파괴/콜백종료를확인한다. 부분자식생성실패도소유parent파괴뒤context해제. guard는panic/error에도자기창만정리한다. DestroyWindow실패를성공으로숨기지말라.
WndProc재진입시동일state의&mut중첩생성금지. userdata로얻은&WindowContext의RefCell<Cell등>에서try_borrow_mut하고순수상태/렌더출력을만드는범위와SetWindowText/SendMessage/컨트롤생성·레이아웃호출범위를분리한다. borrow를놓은뒤native호출한다. 여러nested알림이오면의도한reentrancy상태로무시/지연하고PANIC으로처리하지말라.
외부system FFI콜백에는catch_unwind경계를두고panic이넘어가지않게한다. panic/borrow불변식오류를성공으로삼키지말고fatal표시·안전한창종료경로·launcher실패로전달한다. 손상상태로조작을계속하지말라. GetMessageW==-1은실패,0은정상quit,그외IsDialogMessageW/TranslateMessage/DispatchMessageW. 숨김native시험도동일생산create/dispatch/cleanup사용,동일thread의WM_QUIT가다음시험으로새지않게소유loop를종료한다.
이번에는worker/channel/runtime/신호/실네트워크0. 창종료는UI소유리소스만정리하며프로브취소/OS즉시회수전체인증아님.

## 시험
신규기본시험은gui_presenter_tests.rs와gui_entry.rs내test만. FILE/env/time조회·소켓/DNS/process/thread/runtime/Win32/unsafe실행0. 실제Core/GuiState사용,100/101·합산UTF8/MAX+1·중복/원문/080·UTF16surrogate/NUL/초과/truncatedflag·추가/교체/선택삭제·기능0/유효옵션/범위밖/overflow·실패전체상태보존·계획미리보기로RunId/phase/last_result불변·stale/65536출력한도·공통launcher dispatcher카운터/쓰기사전거부.
native_gui_tests.rs는cfg(windows)+#[ignore="부모 소유 Win32 창 명시 실행"]로정확히4개의native시험을작성하라: (1)필수controls/한국어라벨/기본체크/비활성actions (2)생산handler로추가/전체교체/선택삭제/계획확인·실데이터표시 (3)불량행/초과입력뒤목록보존·stale/시작버튼비활성 (4)소유create/destroy·부분생성실패의단한번drop. 별도native helper defaulttest실행0. 실패주입이필요하면cfg(test) 관측/공유생성경로의한정factory주입으로실제invalid childclass생성실패를유도하고생산cleanup경로를공유한다. production의테스트환경인식/성공우회/earlyreturn skip금지.
시험은자기숨김parent/children만생성·소유·파괴하며FindWindow/EnumWindows/다른앱/clipboard/network/사용자창종료0. native필수환경부재는실패(성공return0아님). actor는시험작성만·부모가정책/unsafe/순수성독립QA후에format/compile/native실행을한다. 각nativecase에유한감독필요:테스트내bounded MessagePump 또는부모소유harnessprocess상한으로시한을집행하고무한루프성공주장0.

## 반환/미완료
새GUI진입점의의도적확장과기존입력회귀보존을구분한다. 부모가실제EXE CLI38/기존dev거부23+새GUI거부를새증거prefix로검증하며기존corpus기대변경0. runtime/GUIsubsystem/도메인제품종단/구형OS/실네트워크/전체QG2/QG3/Release/배포수용은아니다.
한국어UI·주석·보고,UTF8최종LF/후행공백0,lint suppression/todo/unimplemented/빈창가짜완료0. 작은명확한함수,인자<=7원칙은control builder spec struct로지킨다. FILE작성후정확변경경로·실제UI기능·미연결기능·테스트미실행·부모unsafe검증필요점을보고하라. 명령·시험·해시·수용결과를발명하지말라.
'''
if contract_path.exists():
    assert contract_path.read_text(encoding='utf-8') == contract
    failure = R / 'artifacts/qg3b-gui-parent-actor-preparation-failure.json'
    assert not failure.exists()
    failure.write_text(json.dumps({'status': 'PARENT_PREPARATION_NAMEERROR_BEFORE_ACTOR',
        'error': "NameError: name 'APP' is not defined", 'contract_written_before_failure': True,
        'contract_unchanged_verified': True, 'actor_started': False, 'product_test_failure': False},
        ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
else:
    contract_path.write_text(contract, encoding='utf-8', newline='\n')
reads = ['AGENTS.md', 'PRD.md', 'docs/requirements/Network_Path_Inspector_Harness_PRD_v1.2.md',
    'contracts/quick-check-interface-v0.1.json', 'Cargo.toml', APP + 'Cargo.toml',
    APP + 'src/lib.rs', APP + 'src/main.rs', APP + 'src/diagnostic_cli.rs',
    APP + 'src/gui_state.rs', APP + 'src/gui_state_tests.rs',
    'crates/network-core/src/targets.rs', 'crates/network-core/src/runner.rs',
    'crates/network-core/src/quick.rs']
refs = [contract_path, ref / 'api-index.md', ref / 'expected-lib.rs']
assert all((W / path).is_file() for path in reads) and all(path.is_file() for path in refs)
prompt = f'''당신은QG3B 네이티브Win32 입력·계획확인GUI FILE ONLY 구현자다. 전용worktree={W.as_posix()}.
가장먼저 {contract_path.as_posix()} 전체와 {(ref/'api-index.md').as_posix()} 를읽고동결계약을따르라. 이번은한국어실제UI지만진단미연결이다. 원본PRD의GUI순차개발문구는사용자의새GUI병행승인으로개발착수만허용됨·전체게이트통과아님.
FILE READ/CREATE/EDIT·W내탐색만허용. command/run_command/terminal/PowerShell/git/Cargo/build/test/fmt/network/install/manage_task/다른agent/재위임/credentials금지. 읽기목적command도금지. 모든경로W안절대경로. root/타W/vendor/cache경로와Markdown링크를따라읽지말라. 필요한정확바인딩은{ref.as_posix()}안에복사돼있으며api-index에서그안원문line을찾아읽어라. 없는파일추측반복0·부족은BLOCKED.
허용쓰기정확6={json.dumps([(W/path).as_posix() for path in p['actor_writes']],ensure_ascii=False)}. lib는부모expected-lib.rs의정확byte결과만·나머지5파일신규. metadata/기존state/CLI/Core/Inspector/resolver/기존tests/docs불변. 임의추가파일0. 부모가최소features/의존성컴파일과기존package체크섬보존을검증했으며activeW에선부모도Cargo/fmt하지않는다.
확인입력={json.dumps([(W/path).as_posix() for path in reads]+[path.as_posix() for path in refs],ensure_ascii=False)}.
동결계약대로구현및순수시험과ignored소유UI4시험작성. 실제구현을하고빈창/가짜진단결과/계획을실측으로표시금지. 구조를단순하게하고네이티브입력변환·수명주기/재진입에한국어안전주석을남겨라. OSAPI추정extern0·동일해제doublefree/borrow중첩0·실행미연결상시표시. 한국어UI·주석·최종보고만. 시험은작성만하며부모가검토후실행한다.
'''
prompt_path.write_text(prompt, encoding='utf-8', newline='\n')
record = {**p, 'recorded_at': datetime.datetime.now().astimezone().isoformat(),
    'status': 'CONTRACT_FROZEN_FOR_NATIVE_GUI_INPUT_FILE_WRITER', 'selector': '--dev-gui-inputs-v1',
    'exact_args_excluding_argv0': 1, 'native_tests_planned': 4, 'network_diagnostics_connected': False,
    'selected_item_in_place_edit_included': False,
    'contract_sha256': sha(contract_path),
    'reference_sha256': {**p['reference_sha256'], contract_path.relative_to(W).as_posix(): sha(contract_path)},
    'prompt_path': str(prompt_path), 'actor_started': False}
out.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'status': record['status'], 'selector': record['selector'], 'actor_writes': record['actor_writes'],
    'reference_files': len(record['reference_sha256'])}, ensure_ascii=False))
