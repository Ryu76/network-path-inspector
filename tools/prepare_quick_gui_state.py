"""새 GUI 병행 승인 아래 순수 상태모델 FILE ONLY 입력을 동결한다."""
import datetime
import hashlib
import json
import pathlib
import re
import shutil
import subprocess

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qgguistate'
STAGE = 'qg3state'
ROLE = 'qgguistate'
APP = 'apps/network-quick-check/'
WRITES = [APP + 'src/lib.rs', APP + 'src/gui_state.rs', APP + 'src/gui_state_tests.rs']
OUT = R / 'artifacts/qg3a-gui-state-prepared.json'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(root, *args):
    p = subprocess.run(['git', '-C', str(root), *args], capture_output=True,
                       text=True, encoding='utf-8', errors='replace', timeout=60)
    assert p.returncode == 0, p.stderr
    return p.stdout.rstrip('\r\n')


assert not OUT.exists()
assert not (R / '.harness/runs' / (STAGE + '-' + ROLE)).exists()
assert not (R / '.harness/prompts' / (STAGE + '-' + ROLE + '.md')).exists()
assert all(not (R / path).exists() for path in WRITES[1:])
authorization = json.loads((R / 'artifacts/qg3-parallel-development-authorization-20261026.json').read_text(encoding='utf-8'))
assert authorization['gui_parallel_with_unaccepted_qg2_authorized']
previous = json.loads((R / 'artifacts/qg2j-public-entry-acceptance.json').read_text(encoding='utf-8'))
assert previous['accepted_test_slice'] and previous['root_integrated']
assert all(sha(R / p) == h for p, h in previous['source_sha256'].items())
assert not git(pathlib.Path(previous['worktree']), 'status', '--porcelain')
assert git(pathlib.Path(previous['worktree']), 'rev-parse', 'HEAD') == previous['preserved_commit']
proc = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
    '$p=Get-CimInstance Win32_Process | Where-Object { $_.Name -ieq "agy.exe" }; @($p | Select-Object ProcessId,CommandLine) | ConvertTo-Json -Compress'],
    capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30)
assert proc.returncode == 0
rows = json.loads(proc.stdout or '[]')
rows = rows if isinstance(rows, list) else [rows]
assert not [p for p in rows if re.search(r'(?:^|\s)--print(?:=|\s)', p.get('CommandLine') or '')], 'active print writer; preserve and stop'
protected = json.loads((R / 'artifacts/qg0-inspector-baseline.json').read_text(encoding='utf-8'))['protected_inspector_sha256']
engine = 'crates/npi-probes/src/engine.rs'
assert all(sha(R / p) == h for p, h in protected.items() if p != engine)
original = R / '.harness/baselines/qg2g-tcp-replay-root/engine.rs'
assert sha(original) == protected[engine]
assert (R / engine).read_bytes() == original.read_bytes().replace(b'fn apply_tcp_result(', b'pub fn apply_tcp_result(', 1)
paths = {'Cargo.toml', 'Cargo.lock', 'PRD.md', 'AGENTS.md',
         'docs/requirements/Network_Path_Inspector_Harness_PRD_v1.2.md',
         'contracts/quick-check-interface-v0.1.json'}
for base in (R / 'crates', R / 'apps/network-quick-check'):
    paths.update(p.relative_to(R).as_posix() for p in base.rglob('*.rs'))
    paths.update(p.relative_to(R).as_posix() for p in base.rglob('Cargo.toml'))
root_before = {p: sha(R / p) for p in sorted(paths)}
if W.exists():
    assert git(W, 'branch', '--show-current') == 'ai-pro/qgguistate'
    assert git(W, 'rev-parse', 'HEAD') == previous['preserved_commit']
    assert all(sha(W / p) == h for p, h in root_before.items())
else:
    git(R, 'worktree', 'add', '-b', 'ai-pro/qgguistate', str(W), previous['preserved_commit'])
    assert not git(W, 'status', '--porcelain')
# Git checkout의 개행 변환만 파생 사본에서 원문으로 복원한다. 원본은 읽기만 한다.
for p in sorted(paths):
    target = W / p
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(R / p, target)
    assert sha(target) == root_before[p]
status = git(W, 'status', '--porcelain')
if status:
    # 초기 부모 준비의 개행차이 차단은 실패 이력으로 남긴다. 제품/시험 실패가 아니다.
    dirty = [line[3:] for line in status.splitlines()]
    assert sorted(dirty) == ['AGENTS.md', 'contracts/quick-check-interface-v0.1.json'], status
    for path in dirty:
        head = subprocess.check_output(['git', '-C', str(W), 'show', 'HEAD:' + path])
        assert head.replace(b'\r\n', b'\n') == (R / path).read_bytes().replace(b'\r\n', b'\n')
    failure = R / 'artifacts/qg3a-gui-state-parent-preflight-failure.json'
    assert not failure.exists()
    failure.write_text(json.dumps({'status': 'PARENT_PREPARATION_BLOCKED_BEFORE_ACTOR',
        'observed_error': 'baseline source differs from accepted commit',
        'paths': dirty, 'newline_only_verified': True, 'root_bytes_unchanged': True,
        'actor_started': False, 'product_test_failure': False}, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    git(W, 'add', '--', *dirty)
    if subprocess.run(['git', '-C', str(W), 'diff', '--cached', '--quiet']).returncode == 1:
        git(W, '-c', 'core.autocrlf=false', 'commit', '-m', 'chore: preserve authoritative GUI state input bytes')
    assert not git(W, 'status', '--porcelain')
ref = W / '.harness/references/gui-state-contract.md'
ref.parent.mkdir(parents=True, exist_ok=True)
contract = '''# QG3-A 순수 GUI 상태모델 동결 계약 0.1
이 문서는 부모가 deleg_796f094f 두 읽기검토와 실제 API를 대조해 선택한 구현 계약이다. 전체 GUI/OS/제품 수용이 아니다.
사용자 GUI 병행 승인·개발순서 위임. Windows10/11·Server2012이후는 지원 목표, 현재 지원 인증 아님. QG2 실환경 미수용을 유지하며 GUI 개발만 병행한다. 기존 보호 baseline61 원본60+승인pub4byte예외1 유지.

쓰기: src/gui_state.rs 신규, src/gui_state_tests.rs 신규, src/lib.rs 기존 mod diagnostic_cli; 다음에 pub mod gui_state; 한줄추가만. 경로는 apps/network-quick-check/ 기준. 다른 파일 수정 금지.
공개 타입 GuiState, RunId(u64 내부비공개), RunSnapshot(내부필드 비공개), RunPhase(Ready/Running/Cancelling/Finished), GuiStateError.
공개 메서드: new()/Default, replace_targets(&str), append_targets(&str), remove_target(usize), set_options(QuickOptions), begin_run()->Result<RunSnapshot,GuiStateError>, request_cancel()->Option<RunId>, finish_run(RunId,Result<QuickRunReport,Vec<String>>)->Result<(),GuiStateError>, 읽기전용getters. 필요에 맞는 오류변형 Busy/NoFeatures/InvalidInput(Vec<InputError>)/InvalidIndex/IdExhausted/InvalidCompletion 등을 명시. run id/snapshot/request/plan/getters로 값읽기만 노출하고 가변참조는 금지한다.
기존 targets::{parse_target_list,build_quick_plan,QuickTarget,QuickOptions,QuickPlan,InputError,MAX_TARGETS,MAX_INPUT_BYTES}, quick::QuickFeature, runner::{QuickRunRequest,QuickRunReport,DEFAULT_MAX_RESULT_BYTES}를 그대로 재사용한다. 파서/중복제거/계획기/DTO판정을 복제하지 않는다. 실제 공개시그니처를 읽어 맞추고 private pre_validate_request 호출 금지.
기본은 빈대상, QuickOptions::default()(TCP+Ping,3000ms,동시4). 옵션은draft로보관하고begin_run에서계획검증. 기능미선택만앱로컬NoFeatures로거부(Core는빈기능허용). 다른오류는원본계획기오류.
replace는parse_target_list 성공때만교체. append는현재목록 raw_input을 LF로이어신규text를붙인 후보전체를 Core parser로재검증한다. 합산UTF8<=MAX_INPUT_BYTES를 checked_add로먼저검증하고 초과는 상태불변. 대상상한은중복제거후MAX_TARGETS. 기존원문/최초순서유지,trim/소문자화/입력수리0. 별도pair입력API는이번에없음: bareIPv6의pair raw_input을목록으로재사용하지않음. 공백append는Core정책그대로. replace빈문자열은파서오류이며 마지막행삭제로빈목록가능. invalidindex/불량후보는전체상태불변.
begin_run순서:Busy검사→NoFeatures→build_quick_plan→ID checked increment→요청/계획스냅샷확정→Running. 성공한시작만ID소비·단일모델수명내단조증가,재시작전역고유성없음. session_id 비어있지않은결정적 gui-run-N, timestamp_iso8601/source_host=None, max_result_bytes=DEFAULT_MAX_RESULT_BYTES(16MiB;개발CLI32768사용금지). 반환snapshot과내부active는독립소유,각request/plan전체값보존. 실패는상태/ID/이전최종결과불변.
Running/Cancelling동안목록/옵션변경과재시작모두Busy. 최초request_cancel만현재RunId 반환및Cancelling, 반복/비실행시None. cancel은효과데이터이며tokio/AtomicBool/runtime/채널/스레드를소유하지않고끝난척하지않는다.
finish_run은활성ID일때만report또는Vec<String>전체원문저장후Finished,active해제. 별도RunId없으면동일report내세션귀속을추측하지않는다. 다른ID/중복/비활성완료는오류및전체상태불변. 취소뒤정상report(cancelled=false)race허용·report.cancelled를UI요청으로수정금지. Finished는작업반환이지PASS가아님. 새실행시이전완료처리정책을명시하고항상stale완료가현재실행/결과를덮지않도록한다. 결과오류/누락/한도/호출수/QuickResult/raw전체를복제/이동그대로보존·재분류/삭제0.
모델/신규tests는완전순수:파일/환경/시각조회,네트워크/DNS/소켓,프로세스,thread/channel/runtime/sleep,Win32,unsafe,run_quick호출0. 테스트는새gui_state_tests.rs에#[cfg(test)] #[path="gui_state_tests.rs"] mod tests;로연결한다. DTO전체구조동등비교,Source코드복제/expected DTO로실제호출대체0.
시험필수:기본값/빈시작;IPv4/bracketIPv6/domain원문순서;대소문자domain·동치IPv6중복및다른port별개;100허용101원자거부/중복상한;32768byte정확허용·초과거부(실제Core문법유효fixture);불량행/앞뒤공백/포트원문정책;remove인덱스/마지막;NoFeatures/중복기능/timeout/concurrency;실제build_quick_plan전체동등/필수DNSvs선택상세DNS;성공만ID소비·overflow;외부clone수정격리/Busy전체불변;최초반복취소/진행중잠금/취소뒤정상race;stale/중복완료;정상·취소·한도·오류report/Err전체보존(메시지CRLF/한글/중복배열포함).
프로덕션에는테스트인식분기없음. private ID카운터경계는자식test모듈로접근가능하며public테스트전용API추가금지. 한국어설명주석,UTF8최종LF/후행공백0,lint suppression0,todo/unimplemented/panic stub0. 부모가actor종료·범위/도구/terminal/partial/SHA감사→독립QA→fmt/compile/시험한다. 이번단위는Win32화면·실runner연결·UI비차단·자원회수·OS호환인증이아니다.
'''
ref.write_text(contract, encoding='utf-8', newline='\n')
reads = ['AGENTS.md', 'PRD.md',
         '.harness/references/gui-state-contract.md',
         'docs/requirements/Network_Path_Inspector_Harness_PRD_v1.2.md',
         'contracts/quick-check-interface-v0.1.json', 'Cargo.toml', APP + 'Cargo.toml',
         APP + 'src/lib.rs', APP + 'src/main.rs', APP + 'src/diagnostic_cli.rs',
         'crates/network-core/src/lib.rs', 'crates/network-core/src/targets.rs',
         'crates/network-core/src/quick.rs', 'crates/network-core/src/runner.rs']
assert all((W / p).is_file() for p in reads)
prompt = f'''당신은 QG3 GUI 순수 상태모델 FILE ONLY 구현자다. 전용 worktree={W.as_posix()}. 먼저 {(W / '.harness/references/gui-state-contract.md').as_posix()} 전체를 읽고 동결계약을 지켜라.
오직 FILE READ/CREATE/EDIT 및 worktree 내부탐색만허용. command/run_command/terminal/PowerShell/git/Cargo/test/build/fmt/network/install/manage_task/다른agent/재위임/credentials금지. 읽기명령도금지. 모든경로는이W내절대경로. PRD나문서Markdown의root/타W/vendor link를따르지마라.
검증된입력:{json.dumps([(W / p).as_posix() for p in reads], ensure_ascii=False)}
쓰기정확3:{json.dumps([(W / p).as_posix() for p in WRITES], ensure_ascii=False)}. gui_state.rs/gui_state_tests.rs는없는신규파일이다. lib.rs는pub mod gui_state;한줄외완전불변. Core/resolver/Inspector/기존CLI/기존tests/manifest/lock/PRD/docs수정0. 부모가현재수용코드를동결했다. 새파일이예기치않게있으면중단하고보고.
동결계약대로직접구현·충분한순수회귀시험작성.불필요한추상화/기능추가금지. 해당실제API타입/필드를먼저읽고그대로사용. 명령/시험은부모가한다. 결과는정확변경경로/흐름/미해결점/부모검증필요만한국어로보고,실행/통과수치/해시/GUI완료주장발명금지.
'''
(R / '.harness/prompts' / (STAGE + '-' + ROLE + '.md')).write_text(prompt, encoding='utf-8', newline='\n')
record = {'recorded_at': datetime.datetime.now().astimezone().isoformat(),
          'status': 'PREPARED_PURE_GUI_STATE_FILE_ONLY_SCOPE', 'stage': STAGE, 'role': ROLE,
          'worktree': str(W), 'branch': 'ai-pro/qgguistate', 'model': 'gemini-3.8-flash-high',
          'baseline_commit': git(W, 'rev-parse', 'HEAD'), 'actor_writes': WRITES,
          'root_before_sha256': root_before,
          'immutable_source_sha256': {p: h for p, h in root_before.items() if p not in WRITES},
          'contract_sha256': sha(ref), 'reference_path': str(ref),
          'design_review': 'deleg_796f094f', 'review_representation': 'parent_normalized_contract_not_verbatim_child_result',
          'original_inspector_unchanged': len(protected) - 1, 'approved_existing_pub_exception_files': 1,
          'actor_started': False, 'root_integrated': False, 'accepted': False,
          'full_qg2_accepted': False, 'full_qg3_accepted': False, 'product_accepted': False}
OUT.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'status': record['status'], 'worktree': str(W), 'baseline_commit': record['baseline_commit'],
                  'frozen_files': len(root_before), 'actor_writes': WRITES}, ensure_ascii=False))
