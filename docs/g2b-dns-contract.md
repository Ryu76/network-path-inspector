# G2-B DNS 개발 계약 — 작업 중이며 G2 수용 아님

## 목적/범위
도메인 이름 해석의 블로킹 OS 호출을 별도 동일 실행파일 helper 프로세스에 격리해 부모의 timeout/cancel 후 자원 정리를 검증한다. Tokio lookup_host의 차단 스레드를 남겨놓고 취소 성공이라고 주장하지 않는다. 기본 프로필/Session1.1/G1 계약은 불변. 운영망 대상 조회나 전송 시험 금지, 실제 검증은 localhost/IP literals만 부모가 명시 실행. 엔진의 기존 loopback-only 정책은 이번 DNS 모듈만으로 해제되지 않는다.

## 소유 경로
새 writer g2dns: crates/npi-probes/src/dns.rs 및 crates/npi-probes/tests/dns.rs 만. lib.rs/main.rs/engine.rs/Cargo.toml은 부모/다음 별도 writer 소유. FILE READ/EDIT/CREATE만, commands/test/network/installer/agents/git/credentials 금지. AGENTS.md 및 G2-A contract와 아래 DNS interface를 읽는다. 다른 모듈 편집/존재하지 않는 파일 추측 금지.

## 정확한 API
모든 DTO Debug,Clone,Serialize,Deserialize,PartialEq,Eq.
`pub struct DnsWorkerPayload { pub format:String, pub host:String, pub port:u16, pub addresses:Vec<String>, pub truncated:bool, pub error_code:Option<i32>, pub error_message:Option<String> }`
`pub struct DnsMeasurement { pub host:String, pub port:u16, pub outcome:String, pub addresses:Vec<String>, pub elapsed_ms:u64, pub error_code:Option<i32>, pub error_message:Option<String>, pub limitations:Vec<String> }`
`pub fn resolver_worker(host:&str,port:u16)->DnsWorkerPayload`
`pub fn resolve_isolated(executable:&std::path::Path,host:&str,port:u16,timeout:std::time::Duration,cancelled:std::sync::Arc<std::sync::atomic::AtomicBool>)->DnsMeasurement`
추가 pure helpers public 허용. name resolving std::net::ToSocketAddrs는 resolver_worker만에서 사용한다. parent 함수에서 to_socket_addrs/getaddrinfo/Tokio resolver 호출 금지. IPv4/IPv6 literal은 parent에서 파싱하여 socket 주소로 반환하고 helper process 생성0.
worker format `npi-dns-worker-1`. helper invocation fixed direct `executable --npi-dns-worker-v1 <host> <decimal port>`, stdin null, stderr null, stdout piped; shell/cmd/PowerShell/shell metacharacter interpolation 금지. trusted executable은 부모가 현재 제품 binary 경로만 전달한다 (사용자 임의 helper 실행 UI/환경변수 설정 금지). 후속 main.rs가 exact flag를 처리하여 resolver_worker 결과 JSON한줄만 출력하도록 연결할 예정이므로 이번 writer는 main/lib 변경 금지.

## 제한/정확성
- 사전 입력 검증 strict host ASCII label rules 1..253 total, labels1..63, alphanumeric/hyphen only, no leading/trailing hyphen, optional terminal dot policy 명시, valid IPv4/IPv6 literal 허용. IP처럼 보이는 잘못된 숫자형주소/URI/CIDR/credentials/whitespace/control 거부. port1..65535, timeout1..60000ms; validation 실패 LOCAL_ERROR no process.
- worker real OS resolved SocketAddr strings, 최대32개 unique stable-order, truncated bool. 원본 raw OS code/message 보존, 오류 문자열 길이 상한 명시. 주소가 없으면 RESOLVED로 만들지 않는다. fake DNS RR TTL/서버/packet/policy claim 없음. addresses must exact requested port.
- parent pending poll<=10ms, monotonic whole deadline. cancellation wins before spawn/after response; kill+wait owned helper on timeout/cancel/error and join any stdout reader thread. timeout result TIMED_OUT, cancel CANCELLED, spawn/protocol errors LOCAL_ERROR, OS resolver errors DNS_ERROR, success RESOLVED. no lingering child/reader. No detached reader task/hidden resolver thread in parent. Reader must be bounded (<=16KiB +1 sentinel) and drained concurrently while child runs to avoid full stdout deadlock. Drop/RAII must reap helper even on IO/protocol errors/panic where possible. No stdout/stderr credentials logging.
- Protocol decode verify exact format/host/port, every string parses SocketAddr with matching port, unique/max32, maxbytes16KiB. forged mismatched/malformed/empty success -> LOCAL_ERROR, not observed result. child successful exit still not acceptance; real payload required.
- literal bypass outcome RESOLVED marked IP literal no DNS request, not falsely claiming DNS response.
- Cancel elapsed strict3sec target must be measured by parent; no claim100% hard realtime from10ms poll interval. Whole operation including process cleanup may have OS scheduling overhead; preserve actual elapsed.

## 시험 (한국어 설명)
기본 unit/contract tests socket/process/DNS0; payload parse mismatch/max-size/addressport/empty/error, input validation, literal bypass, pre-cancel. Mark any actual subprocess/native DNS tests #[ignore="부모 명시 실행: localhost helper 격리 시험"]. 부모가 최종 제품 helper 연결 후 localhost success/invalid DNS fixture cancellation/timeout/reaping/handle count independently verifies. Worker must not create a separate stub exe or fabricated production resolver outputs. Test fixtures clearly synthetic only within tests. No dependencies beyond existing serde/serde_json/std; package deps/lib/main untouched.
