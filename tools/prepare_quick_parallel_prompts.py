"""세 독립 Flash writer에게 경로 고정·FILE ONLY 작업 지시를 생성한다."""
import pathlib
R=pathlib.Path(__file__).resolve().parents[1]
for role in ['qg2runner','qgdns','qgtrace']:
 w=R/'.worktrees'/role
 common=f'''당신은 Network Quick Check PRD v1.2의 독립 FILE ONLY 구현자다. 모델 Flash High. 작업 root: {w.as_posix()}.
중요: 파일 READ/CREATE/EDIT와 root 내부 파일 탐색만 허용. run_command/command/terminal/shell/PowerShell/manage_task/에이전트/재위임/네트워크/시험/설치/git/운영/DB/자격증명 접근 절대 금지. 읽기 목적 명령도 금지다. 부모가 모든 compile/시험/감사를 수행한다.
모든 읽기·쓰기 경로는 위 worktree 내부의 절대 경로만. PRD/문서에 있는 integration root E:/harnes/network-path-inspector 경로나 링크를 따라가 읽는 것도 금지. 아래 명시 파일은 존재 확인한 입력이며 output 두 파일 이외 수정 금지. 파일이 없으면 추측 경로 루프를 돌지 말고 내부 디렉터리 탐색 후 blocker를 반환한다.
최종 응답은 한국어, 실제 변경 경로·구현 범위·부모 실행검증 필요사항만. 테스트 성공을 꾸미지 않는다. UTF8·한국어 흐름 주석·후행공백 없음·최종개행1개. 실패 기대값 삭제/Clippy allow/suppression 금지. 기존 Inspector·lib/manifest·계약 변경 금지.
'''
 if role=='qg2runner':
  prompt=common+f'''작업: 독립 정적 QA는 추가 findings[]였고 모의10/명시 IPv4·IPv6 loopback2가 실제 통과한 실행기의 경고만 동등 보정한다. 허용 수정2파일: {w.as_posix()}/crates/network-core/src/runner.rs 및 {w.as_posix()}/crates/network-core/tests/runner.rs.
입력: 위2파일, {w.as_posix()}/.harness/references/qg2b-runner-contract.json.
알려진 strictClippy 생산3건: pre_validate_request source_host nestedif, verify_backend_result resolved_ip/expected_ip nestedif를 Rust2024 let-chain으로 동등 정리. run_single_target 인수10개는 내부 실행컨텍스트 struct를 만들어 인수<=7개로 묶되 public API/필드/trait/직렬화/스케줄·취소·결과의 의미를 바꾸지 않는다. 내부struct는 backend/cancel/session/시각/source/timeouts/counters를 묶을 수 있다. 기존 단일target_idx/planned_target는 별도로 유지해 가독성을 확보하라.
시험 unused import Ipv4Addr/AtomicUsize/QuickRunReport 3개 제거, 미사용 set_icmp_responder 메서드만 제거하거나 실제 필요한 회귀에서 사용. 기존 시험10/ignored2와 IPv6 명시 실패·강화된 단언은 그대로 보존한다. 프로브·새 기능·DNS/Trace/GUI 구현 금지. QuickRunRequest는 내부타입이므로 serde derive 재추가 금지.
'''
 elif role=='qgdns':
  prompt=common+f'''작업: 기존 OS resolver를 재사용하는 Quick DNS adapter와 순수 회귀 시험을 완성한다.
허용 출력2파일(신규): {w.as_posix()}/crates/network-core/src/dns.rs, {w.as_posix()}/crates/network-core/tests/dns.rs.
정확한 입력: {w.as_posix()}/.harness/references/quick-dns-contract.json, {w.as_posix()}/.harness/references/dns-engine-provenance.json, {w.as_posix()}/crates/network-resolver/src/lib.rs, {w.as_posix()}/crates/network-resolver/tests/dns.rs, {w.as_posix()}/crates/network-core/src/quick.rs, {w.as_posix()}/crates/network-core/src/measurements.rs, {w.as_posix()}/crates/network-core/src/lib.rs, {w.as_posix()}/crates/network-core/Cargo.toml.
공통 resolver는 부모가 기존 검증본을 바이트 보존해 준비했고 actor 수정 금지. 실제 함수 signature를 읽어 정확히 호출하라(계약의 resolve_once는 개념명일 수 있으며 실제 API resolve_domain_once 등이면 실제 것을 사용). 네이티브 I/O 재구현/복제/추가 의존성 금지. 모듈의 public API는 계약2함수로 동결한다. ctx 검증은 QG1 validate_quick_result를 재사용할 수 있다.
합성 시험은 정상IPv4/IPv6/다중주소/중복·불량raw주소/ctx host·port불일치/각outcome·미지outcome/nullable필드/불량timestamp·빈session/OS오류코드/raw전체보존·취소를 충분히 검증하라. raw주소목록의 어떤 주소라도 invalid면 수리하지 말고 Err 또는 명시불량UNKNOWN으로 fail-closed 처리. RESOLVED인데 addresses=[]도 정상PASS 금지. DnsMeasurement raw schema필드 변경 금지, 실제연결을 아직 하지 않았으므로lookup resolved_ip는null. DNS 서버·RR·TTL·NXDOMAIN을 관찰했다고 추정 금지.
'''
 else:
  prompt=common+f'''작업: Windows 기본 tracert.exe를 안전하게 소유 실행하는 실제 공통 ICMP Trace 모듈과 parser/adapter/ignored loopback 시험을 완성한다. 스텁/가짜hop/무조건성공 금지.
허용 출력2파일(신규): {w.as_posix()}/crates/network-core/src/traceroute.rs, {w.as_posix()}/crates/network-core/tests/traceroute.rs.
정확한 입력: {w.as_posix()}/.harness/references/quick-trace-contract.json, {w.as_posix()}/crates/network-core/src/quick.rs, {w.as_posix()}/crates/network-core/src/measurements.rs, {w.as_posix()}/crates/network-core/src/lib.rs, {w.as_posix()}/crates/network-core/Cargo.toml. Win32 crate 코드 탐색이 필요해도 worktree 밖 읽기는 금지이므로 이미 알고 있는 API로 구현하고 부모 compile검증에 맡긴다.
계약의 고정 API/DTO/상한과 command/path/job/pipe/timeout/취소/raw 보존 요구를 모두 구현. 네이티브 Windows 코드만 cfg(windows), 다른환경은명시 UNAVAILABLE. 진단 target은 IpAddr라 shell해석 금지, GetSystemDirectoryW의 System32 절대경로만. -d로 reverse DNS호출 방지, -4/-6를 선택하고 OS utility 출력의 로케일과 rawbyte를 구별. 단위fixture는 합성임을 표기한다.
공식 문서 확인사항: PeekNamedPipe는 anonymous read-end에도 쓸 수 있지만 멀티스레드 앱의 동기핸들에서는 block 가능하다. 전용 소유 pipe를 동시에 다른 reader가 만지지 않도록 설계하고 엄격한 OS 하드실시간 보장을 주장하지 말고 limitations에 명시. readerthread 무한join은 쓰지 않는다. Job assign 실패시 해당 소유 child를 정리하고 LOCAL_ERROR, 권한우회/다른launch재시도 금지. 지정시간 지났는데 cleanup무한wait로 성공처럼 숨기지 말라. 모든 Win32 HANDLE에 RAII Drop, creation_flags(CREATE_NO_WINDOW), stderr/stdout 상한과 overflow 기록.
tracert의 스위치는 공식문서 /d /4 /6 /h /w 형태이며 Windows가 지원하는 실제 형태를 사용하라(부모가 real owned loopback으로 확인). packet 캡처 없이 'SYN/RST관찰'·'마지막hop차단장비' 같은 설명을 생성하지 않는다. TCP TTL probe는 이번 범위아니며 method명은 ICMP_TRACERT 등 정확히 기록.
'''
 p=R/'.harness/prompts'/('qg2continue-'+role+'.md');assert not p.exists();p.write_text(prompt,encoding='utf-8',newline='\n')
print('격리3세션의 정확 입력·출력/권한/회귀 계약 prompt 작성 완료')
