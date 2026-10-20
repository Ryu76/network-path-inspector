//! G2-B DNS: 도메인 이름 해석을 동일 실행파일 helper 프로세스에 격리한다.
//!
//! 작업 중 결과이며 G2 수용이 아니다. 부모 함수는 이름 해석 API(to_socket_addrs,
//! getaddrinfo, Tokio resolver)를 호출하지 않는다. 블로킹 OS 해석 호출은
//! `resolver_worker`에서만 수행되며, 부모는 helper를 소유하고 시한/취소 시
//! kill+wait 및 stdout 읽기 스레드 join으로 정리한다.
//!
//! 제한사항(명시):
//! - 결과는 OS 해석기(getaddrinfo 계열)가 반환한 주소일 뿐이며 DNS 서버, RR, TTL,
//!   패킷, 정책은 관찰하지 않는다. hosts 파일/캐시 등 해석 경로는 구분하지 않는다.
//! - 취소/시한 폴링 간격은 10ms 목표이며 하드 실시간을 보장하지 않는다.
//!   elapsed_ms는 helper 정리 시간을 포함한 실제 측정값이다.
//! - helper는 후속 통합 writer가 main.rs에 `--npi-dns-worker-v1 <host> <port>`
//!   처리로 연결해야 동작한다. helper는 `worker_output_line` 한 줄만 stdout에 쓰고
//!   RESOLVED/DNS_ERROR 페이로드 모두 종료 코드 0으로 끝나야 한다. 비정상 종료는
//!   LOCAL_ERROR로 분류한다.
//! - helper가 손자 프로세스를 만들어 stdout 핸들을 상속하면 reader join이 시한을
//!   넘길 수 있다. 제품 helper는 손자 프로세스를 만들지 않는다는 전제이다.

use serde::{Deserialize, Serialize};
use std::io::{self, Read};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// helper 페이로드 형식 식별자.
pub const WORKER_FORMAT: &str = "npi-dns-worker-1";
/// helper 진입 플래그(후속 main.rs가 처리 예정).
pub const WORKER_FLAG: &str = "--npi-dns-worker-v1";
/// 고유 주소 최대 개수.
pub const MAX_ADDRESSES: usize = 32;
/// helper stdout 최대 바이트(초과 판정용 sentinel 1바이트는 별도).
pub const MAX_PAYLOAD_BYTES: usize = 16 * 1024;
/// OS 오류 메시지 최대 바이트(UTF-8 문자 경계에서 자름).
pub const MAX_ERROR_MESSAGE_BYTES: usize = 512;
/// 부모 대기 폴링 간격 상한.
pub const POLL_INTERVAL: Duration = Duration::from_millis(10);
/// 허용 시한 최소/최대(ms).
pub const MIN_TIMEOUT_MS: u128 = 1;
pub const MAX_TIMEOUT_MS: u128 = 60_000;
/// helper 입력 거부 페이로드 메시지 접두사(부모는 LOCAL_ERROR로 분류).
pub const WORKER_INPUT_REJECTED_PREFIX: &str = "WORKER_INPUT_REJECTED:";

pub const OUTCOME_RESOLVED: &str = "RESOLVED";
pub const OUTCOME_DNS_ERROR: &str = "DNS_ERROR";
pub const OUTCOME_TIMED_OUT: &str = "TIMED_OUT";
pub const OUTCOME_CANCELLED: &str = "CANCELLED";
pub const OUTCOME_LOCAL_ERROR: &str = "LOCAL_ERROR";

pub const LIMIT_STAGE: &str = "G2-B DNS 작업 중 결과이며 G2 수용 또는 Session1.1 보고가 아님";
pub const LIMIT_OS_RESOLVER: &str = "도메인 결과는 helper 프로세스의 OS 해석기(getaddrinfo 계열) 반환 주소이며 DNS 서버·RR·TTL·패킷·정책은 관찰하지 않음";
pub const LIMIT_SOURCE_UNKNOWN: &str =
    "hosts 파일·캐시 등 OS 해석 경로와 실제 DNS 서버 응답을 구분하지 않음(미확인)";
pub const LIMIT_POLL: &str = "취소/시한 확인 폴링 간격 10ms 목표이며 하드 실시간이 아님; elapsed_ms는 helper 정리(kill/wait/reader join) 포함 실측";
pub const LIMIT_LITERAL: &str = "IP 리터럴을 부모에서 파싱: DNS 요청 없음·helper 프로세스 생성 없음; RESOLVED는 DNS 응답을 뜻하지 않음";
pub const LIMIT_TRUNCATED: &str = "고유 주소 32개 상한으로 잘림: 나머지 주소는 미확인";
pub const LIMIT_TIMEOUT: &str = "시한 초과로 helper를 kill+wait 정리함; 해석 결과 미확인";
pub const LIMIT_CANCEL: &str = "취소 요청으로 helper 미생성 또는 kill+wait 정리함; 해석 결과 미확인";
pub const LIMIT_LOCAL: &str = "로컬 입력 검증/실행/프로토콜 오류이며 이름 해석 결과로 간주하지 않음";
pub const LIMIT_DNS_ERROR: &str = "OS 해석기 오류 원문 코드/메시지 보존(메시지 512바이트 상한); 서버 무응답·NXDOMAIN·정책 등 원인은 추론하지 않음";
pub const LIMIT_NO_PROCESS: &str = "helper 프로세스 생성 전 종료";

/// helper가 stdout에 한 줄 JSON으로 출력하는 페이로드.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DnsWorkerPayload {
    pub format: String,
    pub host: String,
    pub port: u16,
    pub addresses: Vec<String>,
    pub truncated: bool,
    pub error_code: Option<i32>,
    pub error_message: Option<String>,
}

/// 부모가 반환하는 DNS 측정 결과.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsMeasurement {
    pub host: String,
    pub port: u16,
    pub outcome: String,
    pub addresses: Vec<String>,
    pub elapsed_ms: u64,
    pub error_code: Option<i32>,
    pub error_message: Option<String>,
    pub limitations: Vec<String>,
}

/// 사전 검증된 호스트 종류.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKind {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    DomainName,
}

/// 부모의 helper 생성 전 판단 결과.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionPlan {
    /// 프로세스 없이 즉시 반환(취소/검증 실패/IP 리터럴).
    Immediate(DnsMeasurement),
    /// 검증된 도메인 이름: helper 생성 필요.
    SpawnHelper,
}

/// helper 감독 결과.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HelperVerdict {
    Payload(DnsWorkerPayload),
    TimedOut,
    Cancelled,
    LocalError(String),
}

/// 부모가 소유한 helper 추상화. 실제 구현은 자식 프로세스, 시험은 합성 구현.
pub trait HelperHandle {
    /// 종료 여부 확인: Some(true)=성공 종료, Some(false)=비정상 종료, None=실행 중.
    fn poll_exit(&mut self) -> io::Result<Option<bool>>;
    /// stdout이 상한을 넘었는지 여부.
    fn output_overflowed(&self) -> bool;
    /// stdout 읽기가 EOF/오류로 끝났는지 여부.
    fn output_finished(&self) -> bool;
    /// kill+wait 후 reader join. 여러 번 호출해도 안전해야 한다.
    fn terminate(&mut self);
    /// terminate 이후 수집된 stdout 바이트.
    fn take_output(&mut self) -> io::Result<Vec<u8>>;
}

/// UTF-8 문자 경계를 지키며 바이트 상한으로 자른다.
pub fn truncate_utf8(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

/// 10진 점 4개, 선행 0 금지, 각 0..=255 엄격 IPv4 파서.
fn parse_strict_ipv4(text: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = text.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        if part.len() > 1 && part.starts_with('0') {
            return None;
        }
        let value: u16 = part.parse().ok()?;
        if value > 255 {
            return None;
        }
        octets[index] = value as u8;
    }
    Some(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
}

fn is_hex_literal_label(label: &str) -> bool {
    let lower = label.to_ascii_lowercase();
    match lower.strip_prefix("0x") {
        Some(rest) => rest.bytes().all(|b| b.is_ascii_hexdigit()),
        None => false,
    }
}

/// 엄격 호스트 검증.
///
/// 정책: ASCII 영숫자/하이픈 라벨(1..63, 하이픈 시작/끝 금지), 후행 점 1개 허용
/// (점 제외 전체 1..253), 밑줄/와일드카드 금지. 마지막 라벨이 숫자뿐이면 IP처럼
/// 보는 것으로 간주해 엄격 IPv4(후행 점 금지)만 허용한다. 마지막 라벨이 0x 16진
/// 형식이면 거부한다. ':' 포함 시 IPv6 리터럴만 허용하며 대괄호/영역ID/포트/URI는
/// 거부한다. 공백·제어·비ASCII·'@'·'/'·'%' 등은 거부한다.
pub fn validate_host(host: &str) -> Result<HostKind, String> {
    if host.is_empty() {
        return Err("호스트가 비어 있음".to_string());
    }
    if host.len() > 254 {
        return Err("호스트 길이 253자(후행 점 제외) 초과".to_string());
    }
    if host
        .chars()
        .any(|c| !c.is_ascii() || c.is_ascii_control() || c.is_whitespace())
    {
        return Err("공백/제어/비ASCII 문자가 포함된 호스트 거부".to_string());
    }
    if host.contains(':') {
        if !host
            .chars()
            .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '.')
        {
            return Err("URI/포트/대괄호/영역ID가 포함된 주소 거부".to_string());
        }
        return host
            .parse::<Ipv6Addr>()
            .map(HostKind::Ipv6)
            .map_err(|_| "잘못된 IPv6 리터럴".to_string());
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    {
        return Err("허용되지 않는 문자(URI/CIDR/자격증명/와일드카드 등) 거부".to_string());
    }
    let has_terminal_dot = host.ends_with('.');
    let name = host.strip_suffix('.').unwrap_or(host);
    if name.is_empty() {
        return Err("라벨이 없는 호스트 거부".to_string());
    }
    if name.len() > 253 {
        return Err("호스트 길이 253자(후행 점 제외) 초과".to_string());
    }
    let labels: Vec<&str> = name.split('.').collect();
    let last = labels.last().copied().unwrap_or("");
    if !last.is_empty() && last.bytes().all(|b| b.is_ascii_digit()) {
        if has_terminal_dot {
            return Err("후행 점이 있는 숫자형 주소 거부".to_string());
        }
        return parse_strict_ipv4(name)
            .map(HostKind::Ipv4)
            .ok_or_else(|| "잘못된 숫자형 IPv4 주소(10진 점 4개, 선행 0 금지)".to_string());
    }
    if is_hex_literal_label(last) {
        return Err("16진 숫자형 주소처럼 보이는 호스트 거부".to_string());
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return Err("라벨 길이는 1..63이어야 함".to_string());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("라벨은 하이픈으로 시작/끝날 수 없음".to_string());
        }
    }
    Ok(HostKind::DomainName)
}

/// 포트 1..65535 검증.
pub fn validate_port(port: u16) -> Result<(), String> {
    if port == 0 {
        return Err("포트는 1..65535이어야 함".to_string());
    }
    Ok(())
}

/// 시한 1..60000ms 검증(묵시적 보정 없음).
pub fn validate_timeout(timeout: Duration) -> Result<(), String> {
    let millis = timeout.as_millis();
    if !(MIN_TIMEOUT_MS..=MAX_TIMEOUT_MS).contains(&millis) {
        return Err("시한은 1..60000ms이어야 함".to_string());
    }
    Ok(())
}

/// helper 인자의 10진 포트 문자열 엄격 파싱('+'/공백/선행 0 금지).
pub fn parse_helper_port(text: &str) -> Result<u16, String> {
    if text.is_empty() || text.len() > 5 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err("포트 인자는 10진 숫자여야 함".to_string());
    }
    if text.len() > 1 && text.starts_with('0') {
        return Err("포트 인자 선행 0 거부".to_string());
    }
    let port: u32 = text
        .parse()
        .map_err(|_| "포트 인자 파싱 실패".to_string())?;
    if port == 0 || port > 65_535 {
        return Err("포트는 1..65535이어야 함".to_string());
    }
    Ok(port as u16)
}

/// helper 실행 인자(셸 없이 직접 전달): [플래그, 호스트, 10진 포트].
pub fn helper_arguments(host: &str, port: u16) -> [String; 3] {
    [WORKER_FLAG.to_string(), host.to_string(), port.to_string()]
}

/// 요청 포트와 일치하는 주소만 OS 순서대로 고유 최대 32개 수집한다.
/// 반환 bool은 32개 초과 고유 주소가 존재해 잘렸는지 여부이다.
pub fn collect_unique_addresses<I>(addresses: I, port: u16) -> (Vec<String>, bool)
where
    I: IntoIterator<Item = SocketAddr>,
{
    let mut seen: Vec<SocketAddr> = Vec::new();
    let mut truncated = false;
    for address in addresses {
        if address.port() != port || seen.contains(&address) {
            continue;
        }
        if seen.len() >= MAX_ADDRESSES {
            truncated = true;
            break;
        }
        seen.push(address);
    }
    (seen.iter().map(|a| a.to_string()).collect(), truncated)
}

fn worker_rejected(host: &str, port: u16, reason: &str) -> DnsWorkerPayload {
    DnsWorkerPayload {
        format: WORKER_FORMAT.to_string(),
        host: truncate_utf8(host, 254),
        port,
        addresses: Vec::new(),
        truncated: false,
        error_code: None,
        error_message: Some(truncate_utf8(
            &format!("{WORKER_INPUT_REJECTED_PREFIX} {reason}"),
            MAX_ERROR_MESSAGE_BYTES,
        )),
    }
}

/// helper 프로세스 내부에서만 호출하는 실제 OS 이름 해석.
///
/// 부모 프로세스에서 호출하지 않는다(블로킹 호출은 취소 불가). IP 리터럴은
/// 해석기 없이 그대로 반환한다.
pub fn resolver_worker(host: &str, port: u16) -> DnsWorkerPayload {
    if let Err(reason) = validate_port(port) {
        return worker_rejected(host, port, &reason);
    }
    let kind = match validate_host(host) {
        Ok(kind) => kind,
        Err(reason) => return worker_rejected(host, port, &reason),
    };
    let mut payload = DnsWorkerPayload {
        format: WORKER_FORMAT.to_string(),
        host: host.to_string(),
        port,
        addresses: Vec::new(),
        truncated: false,
        error_code: None,
        error_message: None,
    };
    match kind {
        HostKind::Ipv4(ip) => {
            payload.addresses = vec![SocketAddr::new(ip.into(), port).to_string()];
        }
        HostKind::Ipv6(ip) => {
            payload.addresses = vec![SocketAddr::new(ip.into(), port).to_string()];
        }
        HostKind::DomainName => match (host, port).to_socket_addrs() {
            Ok(iter) => {
                let (addresses, truncated) = collect_unique_addresses(iter, port);
                if addresses.is_empty() {
                    // 주소 없는 성공은 RESOLVED로 만들지 않는다.
                    payload.error_message =
                        Some("OS 해석기가 요청 포트의 주소를 0개 반환함".to_string());
                } else {
                    payload.addresses = addresses;
                    payload.truncated = truncated;
                }
            }
            Err(error) => {
                // 원본 OS 코드/메시지 보존(비Windows getaddrinfo 오류는 코드 없음 가능).
                payload.error_code = error.raw_os_error();
                payload.error_message =
                    Some(truncate_utf8(&error.to_string(), MAX_ERROR_MESSAGE_BYTES));
            }
        },
    }
    payload
}

/// helper 인자 문자열로 worker를 실행한다(후속 main.rs 연결용).
pub fn run_worker_from_args(host_arg: &str, port_arg: &str) -> DnsWorkerPayload {
    match parse_helper_port(port_arg) {
        Ok(port) => resolver_worker(host_arg, port),
        Err(reason) => worker_rejected(host_arg, 0, &reason),
    }
}

/// helper stdout에 쓸 한 줄 JSON(마지막 개행 포함).
pub fn worker_output_line(payload: &DnsWorkerPayload) -> String {
    let mut line = serde_json::to_string(payload).unwrap_or_default();
    line.push('\n');
    line
}

/// 페이로드 의미 검증: 형식/호스트/포트 일치, 주소 파싱·포트·고유·상한, 오류 일관성.
pub fn validate_worker_payload(
    payload: &DnsWorkerPayload,
    host: &str,
    port: u16,
) -> Result<(), String> {
    if payload.format != WORKER_FORMAT {
        return Err("helper 페이로드 형식 불일치".to_string());
    }
    if payload.host != host {
        return Err("helper 페이로드 호스트 불일치".to_string());
    }
    if payload.port != port {
        return Err("helper 페이로드 포트 불일치".to_string());
    }
    if payload.addresses.len() > MAX_ADDRESSES {
        return Err("helper 주소 개수 32개 초과".to_string());
    }
    if payload.truncated && payload.addresses.len() != MAX_ADDRESSES {
        return Err("잘림 표시와 주소 개수 불일치".to_string());
    }
    let mut seen: Vec<SocketAddr> = Vec::new();
    for text in &payload.addresses {
        let address: SocketAddr = text
            .parse()
            .map_err(|_| "helper 주소가 SocketAddr 형식이 아님".to_string())?;
        if address.to_string() != *text {
            return Err("helper 주소가 정규 표기가 아님".to_string());
        }
        if address.port() != port {
            return Err("helper 주소 포트가 요청 포트와 다름".to_string());
        }
        if seen.contains(&address) {
            return Err("helper 주소 중복".to_string());
        }
        seen.push(address);
    }
    if let Some(message) = &payload.error_message
        && message.len() > MAX_ERROR_MESSAGE_BYTES
    {
        return Err("helper 오류 메시지 길이 상한 초과".to_string());
    }
    let has_error = payload.error_code.is_some() || payload.error_message.is_some();
    if has_error {
        if !payload.addresses.is_empty() || payload.truncated {
            return Err("오류와 주소가 동시에 존재".to_string());
        }
        if payload.error_message.is_none() {
            return Err("오류 코드만 있고 메시지가 없음".to_string());
        }
    } else if payload.addresses.is_empty() {
        return Err("주소 없는 성공 페이로드 거부".to_string());
    }
    Ok(())
}

/// helper stdout 바이트 디코드: 16KiB 이하 UTF-8, 정확히 한 줄 JSON, 알 수 없는 필드 금지.
pub fn decode_worker_payload(
    bytes: &[u8],
    host: &str,
    port: u16,
) -> Result<DnsWorkerPayload, String> {
    if bytes.is_empty() {
        return Err("helper stdout이 비어 있음".to_string());
    }
    if bytes.len() > MAX_PAYLOAD_BYTES {
        return Err("helper stdout 16KiB 상한 초과".to_string());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "helper stdout이 UTF-8이 아님".to_string())?;
    let line = match text.strip_suffix('\n') {
        Some(rest) => rest.strip_suffix('\r').unwrap_or(rest),
        None => text,
    };
    if line.is_empty() || line.contains('\n') || line.contains('\r') || line.trim() != line {
        return Err("helper stdout이 정확히 한 줄 JSON이 아님".to_string());
    }
    let payload: DnsWorkerPayload = serde_json::from_str(line)
        .map_err(|error| truncate_utf8(&format!("helper JSON 파싱 실패: {error}"), MAX_ERROR_MESSAGE_BYTES))?;
    validate_worker_payload(&payload, host, port)?;
    Ok(payload)
}

/// 상한(16KiB + sentinel 1바이트)까지만 보관하고 나머지는 EOF까지 버리며 읽는다.
/// 상한 초과 시 overflow를 즉시 세워 부모가 helper를 종료하게 한다(교착 방지).
pub fn read_bounded<R: Read>(mut reader: R, overflow: &AtomicBool) -> io::Result<Vec<u8>> {
    let mut kept: Vec<u8> = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                if kept.len() <= MAX_PAYLOAD_BYTES {
                    let room = MAX_PAYLOAD_BYTES + 1 - kept.len();
                    let take = read.min(room);
                    kept.extend_from_slice(&chunk[..take]);
                    if kept.len() > MAX_PAYLOAD_BYTES {
                        overflow.store(true, Ordering::SeqCst);
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(kept)
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

fn base_limitations() -> Vec<String> {
    vec![LIMIT_STAGE.to_string(), LIMIT_POLL.to_string()]
}

fn measurement(
    host: &str,
    port: u16,
    outcome: &str,
    elapsed_ms: u64,
    extra: &[&str],
) -> DnsMeasurement {
    let mut limitations = base_limitations();
    limitations.extend(extra.iter().map(|text| text.to_string()));
    DnsMeasurement {
        host: truncate_utf8(host, 254),
        port,
        outcome: outcome.to_string(),
        addresses: Vec::new(),
        elapsed_ms,
        error_code: None,
        error_message: None,
        limitations,
    }
}

fn local_error(
    host: &str,
    port: u16,
    elapsed_ms: u64,
    message: &str,
    code: Option<i32>,
    extra: &[&str],
) -> DnsMeasurement {
    let mut result = measurement(host, port, OUTCOME_LOCAL_ERROR, elapsed_ms, &[LIMIT_LOCAL]);
    result.limitations.extend(extra.iter().map(|text| text.to_string()));
    result.error_code = code;
    result.error_message = Some(truncate_utf8(message, MAX_ERROR_MESSAGE_BYTES));
    result
}

fn executable_rejection(executable: &Path) -> Option<&'static str> {
    if !executable.is_absolute() {
        return Some("helper 실행파일은 부모가 전달한 절대 경로여야 함");
    }
    let extension = executable
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| value.to_ascii_lowercase());
    if matches!(extension.as_deref(), Some("bat") | Some("cmd")) {
        return Some("배치 스크립트 helper는 셸 해석 위험으로 거부");
    }
    None
}

/// helper 생성 전 판단(프로세스/네트워크/DNS 없음). 취소가 검증보다 우선한다.
pub fn plan_resolution(
    executable: &Path,
    host: &str,
    port: u16,
    timeout: Duration,
    cancelled: &AtomicBool,
    started: Instant,
) -> ResolutionPlan {
    if cancelled.load(Ordering::SeqCst) {
        return ResolutionPlan::Immediate(measurement(
            host,
            port,
            OUTCOME_CANCELLED,
            elapsed_ms(started),
            &[LIMIT_CANCEL, LIMIT_NO_PROCESS],
        ));
    }
    let checks = validate_port(port)
        .and_then(|_| validate_timeout(timeout))
        .and_then(|_| validate_host(host));
    let kind = match checks {
        Ok(kind) => kind,
        Err(reason) => {
            return ResolutionPlan::Immediate(local_error(
                host,
                port,
                elapsed_ms(started),
                &format!("입력 검증 실패: {reason}"),
                None,
                &[LIMIT_NO_PROCESS],
            ));
        }
    };
    let literal = match kind {
        HostKind::Ipv4(ip) => Some(SocketAddr::new(ip.into(), port)),
        HostKind::Ipv6(ip) => Some(SocketAddr::new(ip.into(), port)),
        HostKind::DomainName => None,
    };
    if let Some(address) = literal {
        let mut result = measurement(
            host,
            port,
            OUTCOME_RESOLVED,
            elapsed_ms(started),
            &[LIMIT_LITERAL],
        );
        result.addresses = vec![address.to_string()];
        return ResolutionPlan::Immediate(result);
    }
    if let Some(reason) = executable_rejection(executable) {
        return ResolutionPlan::Immediate(local_error(
            host,
            port,
            elapsed_ms(started),
            reason,
            None,
            &[LIMIT_NO_PROCESS],
        ));
    }
    ResolutionPlan::SpawnHelper
}

/// helper 감독 루프. 반환 전 항상 terminate(kill+wait+reader join)를 호출한다.
/// 취소는 응답 수신 후에도 우선한다. 폴링 간격은 10ms 이하이다.
pub fn supervise_helper<H: HelperHandle>(
    handle: &mut H,
    host: &str,
    port: u16,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> HelperVerdict {
    let mut exited: Option<bool> = None;
    let early = loop {
        if cancelled.load(Ordering::SeqCst) {
            break Some(HelperVerdict::Cancelled);
        }
        if Instant::now() >= deadline {
            break Some(HelperVerdict::TimedOut);
        }
        if handle.output_overflowed() {
            break Some(HelperVerdict::LocalError(
                "helper stdout 16KiB 상한 초과".to_string(),
            ));
        }
        if exited.is_none() {
            match handle.poll_exit() {
                Ok(state) => exited = state,
                Err(error) => {
                    break Some(HelperVerdict::LocalError(truncate_utf8(
                        &format!("helper 상태 확인 실패: {error}"),
                        MAX_ERROR_MESSAGE_BYTES,
                    )));
                }
            }
        }
        if cancelled.load(Ordering::SeqCst) {
            break Some(HelperVerdict::Cancelled);
        }
        if Instant::now() >= deadline {
            break Some(HelperVerdict::TimedOut);
        }
        if handle.output_overflowed() {
            break Some(HelperVerdict::LocalError(
                "helper stdout 16KiB 상한 초과".to_string(),
            ));
        }
        if exited.is_some() && handle.output_finished() {
            break None;
        }
        let now = Instant::now();
        if now >= deadline {
            break Some(HelperVerdict::TimedOut);
        }
        std::thread::sleep((deadline - now).min(POLL_INTERVAL));
    };
    handle.terminate();
    if let Some(verdict) = early {
        return verdict;
    }
    // 응답 수신 및 정리 후에도 취소가 최우선이다.
    if cancelled.load(Ordering::SeqCst) {
        return HelperVerdict::Cancelled;
    }
    // 정리 후 전체 마감시간 만료 확인
    if Instant::now() >= deadline {
        return HelperVerdict::TimedOut;
    }
    if handle.output_overflowed() {
        return HelperVerdict::LocalError("helper stdout 16KiB 상한 초과".to_string());
    }
    let bytes = match handle.take_output() {
        Ok(bytes) => bytes,
        Err(error) => {
            return HelperVerdict::LocalError(truncate_utf8(
                &format!("helper stdout 읽기 실패: {error}"),
                MAX_ERROR_MESSAGE_BYTES,
            ));
        }
    };
    if cancelled.load(Ordering::SeqCst) {
        return HelperVerdict::Cancelled;
    }
    if Instant::now() >= deadline {
        return HelperVerdict::TimedOut;
    }
    if exited != Some(true) {
        return HelperVerdict::LocalError("helper 비정상 종료".to_string());
    }
    match decode_worker_payload(&bytes, host, port) {
        Ok(payload) => HelperVerdict::Payload(payload),
        Err(reason) => HelperVerdict::LocalError(reason),
    }
}

/// 감독 결과를 측정 DTO로 변환한다. elapsed_ms는 정리 이후 측정값을 전달한다.
pub fn measurement_from_verdict(
    host: &str,
    port: u16,
    verdict: HelperVerdict,
    elapsed_ms: u64,
) -> DnsMeasurement {
    match verdict {
        HelperVerdict::TimedOut => {
            measurement(host, port, OUTCOME_TIMED_OUT, elapsed_ms, &[LIMIT_TIMEOUT])
        }
        HelperVerdict::Cancelled => {
            measurement(host, port, OUTCOME_CANCELLED, elapsed_ms, &[LIMIT_CANCEL])
        }
        HelperVerdict::LocalError(message) => {
            local_error(host, port, elapsed_ms, &message, None, &[])
        }
        HelperVerdict::Payload(payload) => {
            if let Some(message) = &payload.error_message
                && message.starts_with(WORKER_INPUT_REJECTED_PREFIX)
            {
                return local_error(host, port, elapsed_ms, message, payload.error_code, &[]);
            }
            if payload.error_code.is_some() || payload.error_message.is_some() {
                let mut result = measurement(
                    host,
                    port,
                    OUTCOME_DNS_ERROR,
                    elapsed_ms,
                    &[LIMIT_OS_RESOLVER, LIMIT_SOURCE_UNKNOWN, LIMIT_DNS_ERROR],
                );
                result.error_code = payload.error_code;
                result.error_message = payload.error_message;
                return result;
            }
            let mut result = measurement(
                host,
                port,
                OUTCOME_RESOLVED,
                elapsed_ms,
                &[LIMIT_OS_RESOLVER, LIMIT_SOURCE_UNKNOWN],
            );
            if payload.truncated {
                result.limitations.push(LIMIT_TRUNCATED.to_string());
            }
            result.addresses = payload.addresses;
            result
        }
    }
}

/// 부모가 소유한 실제 helper 자식 프로세스. Drop에서도 kill+wait+join으로 정리한다.
struct OwnedDnsHelper {
    child: Option<Child>,
    reader: Option<JoinHandle<io::Result<Vec<u8>>>>,
    overflow: Arc<AtomicBool>,
    output: Option<io::Result<Vec<u8>>>,
}

impl OwnedDnsHelper {
    fn spawn(executable: &Path, host: &str, port: u16) -> io::Result<Self> {
        let mut command = Command::new(executable);
        command
            .args(helper_arguments(host, port))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            // CREATE_NO_WINDOW: 콘솔 창 없이 helper 실행.
            command.creation_flags(0x0800_0000);
        }
        let child = command.spawn()?;
        // 이후 실패해도 guard Drop이 kill+wait 한다.
        let mut guard = OwnedDnsHelper {
            child: Some(child),
            reader: None,
            overflow: Arc::new(AtomicBool::new(false)),
            output: None,
        };
        let stdout: ChildStdout = guard
            .child
            .as_mut()
            .and_then(|child| child.stdout.take())
            .ok_or_else(|| io::Error::other("helper stdout 파이프 없음"))?;
        let overflow = Arc::clone(&guard.overflow);
        let reader = std::thread::Builder::new()
            .name("npi-dns-helper-stdout".to_string())
            .stack_size(64 * 1024)
            .spawn(move || read_bounded(stdout, &overflow))?;
        guard.reader = Some(reader);
        Ok(guard)
    }
}

impl HelperHandle for OwnedDnsHelper {
    fn poll_exit(&mut self) -> io::Result<Option<bool>> {
        match self.child.as_mut() {
            Some(child) => Ok(child.try_wait()?.map(|status| status.success())),
            None => Err(io::Error::other("helper가 이미 정리됨")),
        }
    }

    fn output_overflowed(&self) -> bool {
        self.overflow.load(Ordering::SeqCst)
    }

    fn output_finished(&self) -> bool {
        self.reader
            .as_ref()
            .map(|reader| reader.is_finished())
            .unwrap_or(true)
    }

    fn terminate(&mut self) {
        if let Some(mut child) = self.child.take() {
            // 이미 종료된 경우 kill 오류는 무시하고 wait로 회수한다.
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(reader) = self.reader.take() {
            // 자식 종료로 파이프가 닫혀 EOF가 되므로 join은 끝난다.
            let result = reader
                .join()
                .unwrap_or_else(|_| Err(io::Error::other("helper stdout 읽기 스레드 panic")));
            self.output = Some(result);
        }
    }

    fn take_output(&mut self) -> io::Result<Vec<u8>> {
        self.output
            .take()
            .unwrap_or_else(|| Err(io::Error::other("helper stdout 결과 없음")))
    }
}

impl Drop for OwnedDnsHelper {
    fn drop(&mut self) {
        self.terminate();
    }
}

/// 도메인 이름을 helper 프로세스에서 해석하고 부모가 시한/취소/정리를 소유한다.
///
/// `executable`은 부모가 현재 제품 실행파일 경로만 전달한다. IP 리터럴/검증 실패/
/// 사전 취소는 프로세스를 만들지 않는다. 셸을 거치지 않고 인자를 직접 전달한다.
pub fn resolve_isolated(
    executable: &Path,
    host: &str,
    port: u16,
    timeout: Duration,
    cancelled: Arc<AtomicBool>,
) -> DnsMeasurement {
    let started = Instant::now();
    match plan_resolution(executable, host, port, timeout, &cancelled, started) {
        ResolutionPlan::Immediate(result) => return result,
        ResolutionPlan::SpawnHelper => {}
    }
    let deadline = started + timeout;
    if cancelled.load(Ordering::SeqCst) {
        return measurement(
            host,
            port,
            OUTCOME_CANCELLED,
            elapsed_ms(started),
            &[LIMIT_CANCEL, LIMIT_NO_PROCESS],
        );
    }
    let mut helper = match OwnedDnsHelper::spawn(executable, host, port) {
        Ok(helper) => helper,
        Err(error) => {
            return local_error(
                host,
                port,
                elapsed_ms(started),
                &format!("helper 실행 실패: {error}"),
                error.raw_os_error(),
                &[],
            );
        }
    };
    let verdict = supervise_helper(&mut helper, host, port, deadline, &cancelled);
    drop(helper);
    measurement_from_verdict(host, port, verdict, elapsed_ms(started))
}
