//! Windows IP Helper API(`IcmpSendEcho2`, `Icmp6SendEcho2`) 기반 단일 대상 동기 ICMP Echo 측정 모듈.
//!
//! 주의 및 제한사항:
//! - 이 모듈의 결과는 OS IP Helper API 수준 관찰이며 패킷 캡처(PCAP) 근거가 아니다.
//! - ICMP 무응답(`TIMEOUT`) 또는 도달 불가(`UNREACHABLE`)는 TCP 연결 가능 여부나 중간 차단 장비 존재를 증명하지 않는다.
//! - Windows `IcmpSendEcho2`/`Icmp6SendEcho2`를 동기 모드(`Event = NULL`, `ApcRoutine = NULL`)로 호출하므로,
//!   진행 중인 시스템 호출은 허용 타임아웃(1..=2000ms) 상한까지 대기한 뒤 취소가 반영된다.

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};

#[cfg(windows)]
use std::net::Ipv6Addr;

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{GetLastError, HANDLE, INVALID_HANDLE_VALUE},
    NetworkManagement::IpHelper::{
        ICMP_ECHO_REPLY, Icmp6CreateFile, Icmp6SendEcho2, IcmpCloseHandle, IcmpCreateFile,
        IcmpSendEcho2,
    },
    Networking::WinSock::{AF_INET6, SOCKADDR_IN6},
    System::IO::IO_STATUS_BLOCK,
};

/// 허용되는 최소 ICMP 타임아웃(밀리초).
pub const MIN_ICMP_TIMEOUT_MS: u64 = 1;

/// 허용되는 최대 ICMP 타임아웃(밀리초). 동기 블로킹 상한을 2초로 제한한다.
pub const MAX_ICMP_TIMEOUT_MS: u64 = 2000;

/// Windows IP Helper `IP_SUCCESS` 상태 코드.
pub const IP_SUCCESS_CODE: u32 = 0;

/// Windows IP Helper `IP_DEST_NET_UNREACHABLE` / `IP_DEST_NO_ROUTE` 상태 코드.
pub const IP_DEST_NET_UNREACHABLE_CODE: u32 = 11002;

/// Windows IP Helper `IP_DEST_HOST_UNREACHABLE` / `IP_DEST_ADDR_UNREACHABLE` 상태 코드.
pub const IP_DEST_HOST_UNREACHABLE_CODE: u32 = 11003;

/// Windows IP Helper `IP_DEST_PROT_UNREACHABLE` / `IP_DEST_PROHIBITED` 상태 코드.
pub const IP_DEST_PROT_UNREACHABLE_CODE: u32 = 11004;

/// Windows IP Helper `IP_DEST_PORT_UNREACHABLE` 상태 코드.
pub const IP_DEST_PORT_UNREACHABLE_CODE: u32 = 11005;

/// Windows IP Helper `IP_REQ_TIMED_OUT` 상태 코드.
pub const IP_REQ_TIMED_OUT_CODE: u32 = 11010;

/// Windows IP Helper `IP_BAD_ROUTE` 상태 코드.
pub const IP_BAD_ROUTE_CODE: u32 = 11012;

/// Windows IP Helper `IP_BAD_DESTINATION` 상태 코드.
pub const IP_BAD_DESTINATION_CODE: u32 = 11018;

/// Windows IP Helper `IP_DEST_UNREACHABLE` 상태 코드.
pub const IP_DEST_UNREACHABLE_CODE: u32 = 11040;

/// Windows IP Helper `IP_DEST_SCOPE_MISMATCH` 상태 코드.
pub const IP_DEST_SCOPE_MISMATCH_CODE: u32 = 11045;

/// 고정 ICMP Echo 요청 페이로드(응답 버퍼 크기 계산에 반영).
const ICMP_REQUEST_PAYLOAD: &[u8] = b"npi-g2a-icmp";

/// 단일 ICMP Echo 측정 결과 DTO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IcmpMeasurement {
    pub target: String,
    pub outcome: String,
    pub elapsed_ms: u64,
    pub ip_status: Option<u32>,
    pub error_code: Option<u32>,
    pub rtt_ms: Option<u32>,
    pub ttl: Option<u8>,
    pub limitations: Vec<String>,
}

/// Windows `IPV6_ADDRESS_EX`와 동일한 C ABI 레이아웃(1바이트 패킹, 26바이트).
#[repr(C, packed(1))]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct Ipv6AddressExRaw {
    pub sin6_port: u16,
    pub sin6_flowinfo: u32,
    pub sin6_addr: [u16; 8],
    pub sin6_scope_id: u32,
}

/// Windows `ICMPV6_ECHO_REPLY_LH` / `ICMPV6_ECHO_REPLY`와 동일한 C ABI 레이아웃(36바이트).
/// API 구조체에 TTL 필드가 존재하지 않으므로 IPv6 응답에서는 TTL을 산출하지 않는다.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct Icmpv6EchoReplyRaw {
    pub address: Ipv6AddressExRaw,
    pub status: u32,
    pub round_trip_time: u32,
}

/// 응답 버퍼에서 추출한 첫 번째 ICMP 응답 구조체의 핵심 필드.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct RawEchoReplyFields {
    pub status: u32,
    pub rtt_ms: u32,
    pub ttl: Option<u8>,
}

/// 응답 개수, 첫 번째 응답 구조체, 원시 OS 오류 코드, 호출 후 취소 여부를 해석한 결과.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct InterpretedEchoOutcome {
    pub outcome: String,
    pub ip_status: Option<u32>,
    pub error_code: Option<u32>,
    pub rtt_ms: Option<u32>,
    pub ttl: Option<u8>,
    pub detail_limitation: Option<String>,
}

#[cfg(windows)]
trait RawPtrConvert<P> {
    fn into_raw_ptr(self) -> P;
}

#[cfg(windows)]
impl<T, U> RawPtrConvert<*const U> for *mut T {
    fn into_raw_ptr(self) -> *const U {
        self as *const U
    }
}

#[cfg(windows)]
impl<T, U> RawPtrConvert<*mut U> for *mut T {
    fn into_raw_ptr(self) -> *mut U {
        self as *mut U
    }
}

/// Windows ICMP 핸들을 스코프 종료 시 자동으로 닫는 RAII 가드.
#[cfg(windows)]
struct IcmpHandleGuard(HANDLE);

#[cfg(windows)]
impl Drop for IcmpHandleGuard {
    fn drop(&mut self) {
        let null_handle: HANDLE = unsafe { std::mem::zeroed() };
        if self.0 != INVALID_HANDLE_VALUE && self.0 != null_handle {
            unsafe {
                let _ = IcmpCloseHandle(self.0);
            }
        }
    }
}

/// 단일 대상(`IpAddr`)에 대해 1회 동기 ICMP Echo 측정을 수행한다.
///
/// - 호출 전 타임아웃(`1..=2000ms`)과 대상 주소(미지정/멀티캐스트/브로드캐스트/링크로컬 거부)를 검증한다.
/// - 시스템 호출 전후로 취소 플래그(`cancelled`)를 확인하며, 동기 호출 중 대기 한계(최대 2초)를 명시한다.
/// - 실패/취소/시간초과/도달불가 시 가짜 RTT나 TTL을 절대 생성하지 않는다.
pub fn ping_once(target: IpAddr, timeout: Duration, cancelled: Arc<AtomicBool>) -> IcmpMeasurement {
    let started_at = Instant::now();
    let target_str = target.to_string();
    let mut limitations = base_limitations(&target);

    if cancelled.load(Ordering::Acquire) {
        limitations.push(
            "ICMP 호출 전 취소 플래그가 설정되어 시스템 호출을 수행하지 않았습니다.".to_string(),
        );
        return IcmpMeasurement {
            target: target_str,
            outcome: "CANCELLED".to_string(),
            elapsed_ms: elapsed_ms_since(started_at),
            ip_status: None,
            error_code: None,
            rtt_ms: None,
            ttl: None,
            limitations,
        };
    }

    let timeout_ms = match validate_timeout(timeout) {
        Ok(ms) => ms,
        Err(reason) => {
            limitations.push(reason);
            return IcmpMeasurement {
                target: target_str,
                outcome: "LOCAL_ERROR".to_string(),
                elapsed_ms: elapsed_ms_since(started_at),
                ip_status: None,
                error_code: None,
                rtt_ms: None,
                ttl: None,
                limitations,
            };
        }
    };

    if let Err(reason) = validate_target(target) {
        limitations.push(reason);
        return IcmpMeasurement {
            target: target_str,
            outcome: "LOCAL_ERROR".to_string(),
            elapsed_ms: elapsed_ms_since(started_at),
            ip_status: None,
            error_code: None,
            rtt_ms: None,
            ttl: None,
            limitations,
        };
    }

    #[cfg(not(windows))]
    {
        let _ = timeout_ms;
        limitations.push(
            "비 Windows 플랫폼에서는 Windows IP Helper ICMP API를 사용할 수 없습니다.".to_string(),
        );
        IcmpMeasurement {
            target: target_str,
            outcome: "UNAVAILABLE".to_string(),
            elapsed_ms: elapsed_ms_since(started_at),
            ip_status: None,
            error_code: None,
            rtt_ms: None,
            ttl: None,
            limitations,
        }
    }

    #[cfg(windows)]
    {
        match target {
            IpAddr::V4(ipv4) => {
                ping_ipv4_windows(ipv4, timeout_ms, &cancelled, started_at, limitations)
            }
            IpAddr::V6(ipv6) => {
                ping_ipv6_windows(ipv6, timeout_ms, &cancelled, started_at, limitations)
            }
        }
    }
}

/// 공통 한계 및 해석 주의사항 문구를 생성한다.
fn base_limitations(target: &IpAddr) -> Vec<String> {
    let mut items = vec![
        "Windows IcmpSendEcho2/Icmp6SendEcho2 동기 호출(null Event/APC)을 사용하므로 호출 진입 후에는 타임아웃 상한(최대 2000ms)까지 대기한 뒤 취소가 반영됩니다.".to_string(),
        "ICMP Echo 결과는 OS API 수준 관찰이며 패킷 캡처(PCAP) 증거가 아닙니다. ICMP 무응답이나 도달 불가는 TCP 연결 실패 또는 차단 장비 존재를 단정하지 않습니다.".to_string(),
        "elapsed_ms는 Instant 기반 단조 경과 시간이며 실제 UTC 시각이 아닙니다.".to_string(),
    ];
    if target.is_ipv6() {
        items.push(
            "IPv6 SOCKADDR_IN6는 sin6_scope_id=0으로 고정되어 영역 ID(scope)가 필요한 링크 로컬(fe80::/10) 대상을 지원하지 않으며, Icmp6SendEcho2 응답 구조체는 TTL 필드를 제공하지 않아 ttl은 항상 None입니다.".to_string(),
        );
    }
    items
}

/// `Instant`로부터 경과 시간을 밀리초(`u64`)로 변환한다.
fn elapsed_ms_since(started_at: Instant) -> u64 {
    u64::try_from(started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// 타임아웃이 `1..=2000ms` 범위 내에 있는지 클램핑 없이 엄격히 검증한다.
pub(crate) fn validate_timeout(timeout: Duration) -> Result<u32, String> {
    let min_duration = Duration::from_millis(MIN_ICMP_TIMEOUT_MS);
    let max_duration = Duration::from_millis(MAX_ICMP_TIMEOUT_MS);
    if timeout < min_duration || timeout > max_duration {
        return Err(format!(
            "ICMP 타임아웃({}ms)이 허용 범위({}..={}ms)를 벗어났습니다(무음 클램핑 금지).",
            timeout.as_millis(),
            MIN_ICMP_TIMEOUT_MS,
            MAX_ICMP_TIMEOUT_MS
        ));
    }
    Ok(timeout.as_millis() as u32)
}

/// 대상 IP 주소가 단일 유니캐스트(영역 미지정 링크로컬 제외)인지 검증한다.
pub(crate) fn validate_target(target: IpAddr) -> Result<(), String> {
    if target.is_unspecified() {
        return Err(
            "미지정 주소(unspecified, 0.0.0.0 또는 ::)는 유효한 ICMP 측정 대상이 아닙니다."
                .to_string(),
        );
    }
    if target.is_multicast() {
        return Err("멀티캐스트 주소는 유효한 ICMP 단일 측정 대상이 아닙니다.".to_string());
    }
    match target {
        IpAddr::V4(ipv4) => {
            if ipv4.is_broadcast() {
                return Err(
                    "IPv4 브로드캐스트(255.255.255.255) 주소는 유효한 ICMP 단일 대상이 아닙니다."
                        .to_string(),
                );
            }
        }
        IpAddr::V6(ipv6) => {
            if ipv6.is_unicast_link_local() {
                return Err(
                    "IPv6 링크 로컬(fe80::/10) 주소는 IpAddr에 영역 ID(sin6_scope_id)가 없어 지원하지 않습니다(scope 0 제한)."
                        .to_string(),
                );
            }
        }
    }
    Ok(())
}

/// IPv4 주소를 Windows `IPAddr`(`in_addr.S_un.S_addr`, 메모리상 네트워크 바이트 순서) `u32` 값으로 변환한다.
///
/// 호스트 바이트 순서(`u32::from(ipv4)`)를 그대로 전달하면 리틀 엔디언에서 옥텟 순서가 뒤집히므로,
/// 반드시 `ipv4.octets()`의 메모리 바이트 배치가 유지되도록 `u32::from_ne_bytes(octets)`를 사용한다.
pub(crate) fn ipv4_to_windows_ipaddr(ipv4: Ipv4Addr) -> u32 {
    let octets = ipv4.octets();
    let raw = u32::from_ne_bytes(octets);
    debug_assert_eq!(raw.to_ne_bytes(), octets);
    raw
}

/// 정렬된 `Vec<usize>` 응답 버퍼를 위해 필요한 최소 바이트 크기를 계산한다.
/// 계약 요건: `>= reply_struct_size + payload_len + 8 + sizeof(IO_STATUS_BLOCK)` 이상 확보하고 `usize` 단위로 올림.
pub(crate) fn required_reply_buffer_bytes(
    reply_struct_size: usize,
    payload_len: usize,
    io_status_block_size: usize,
) -> usize {
    let min_bytes = reply_struct_size
        .saturating_add(payload_len)
        .saturating_add(8)
        .saturating_add(io_status_block_size);
    let word_size = std::mem::size_of::<usize>();
    min_bytes.div_ceil(word_size) * word_size
}

/// IP 상태 코드(`IP_*`)가 실제 도달 불가(`UNREACHABLE`) 계열인지 판별한다.
pub(crate) fn is_unreachable_ip_status(status: u32) -> bool {
    matches!(
        status,
        IP_DEST_NET_UNREACHABLE_CODE
            | IP_DEST_HOST_UNREACHABLE_CODE
            | IP_DEST_PROT_UNREACHABLE_CODE
            | IP_DEST_PORT_UNREACHABLE_CODE
            | IP_BAD_ROUTE_CODE
            | IP_BAD_DESTINATION_CODE
            | IP_DEST_UNREACHABLE_CODE
            | IP_DEST_SCOPE_MISMATCH_CODE
    )
}

/// 응답 구조체의 `Status` 값을 계약된 결과 문자열(`REPLY`, `TIMEOUT`, `UNREACHABLE`, `LOCAL_ERROR`)로 분류한다.
pub(crate) fn classify_ip_status(status: u32) -> &'static str {
    if status == IP_SUCCESS_CODE {
        "REPLY"
    } else if status == IP_REQ_TIMED_OUT_CODE {
        "TIMEOUT"
    } else if is_unreachable_ip_status(status) {
        "UNREACHABLE"
    } else {
        "LOCAL_ERROR"
    }
}

/// API가 0을 반환했을 때 `GetLastError()` 원시 오류 코드를 분류한다.
/// 반환 개수가 0인 경우 오류 코드가 0이더라도 절대 `REPLY`로 분류하지 않는다.
pub(crate) fn classify_api_error_code(error_code: u32) -> &'static str {
    if error_code == IP_REQ_TIMED_OUT_CODE {
        "TIMEOUT"
    } else if is_unreachable_ip_status(error_code)
        || matches!(error_code, 10051 | 10065 | 1231 | 1232 | 1233 | 1234)
    {
        "UNREACHABLE"
    } else {
        "LOCAL_ERROR"
    }
}

/// API 반환 개수(`returned_count`), 첫 번째 응답 구조체, `GetLastError()`, 호출 후 취소 플래그를 바탕으로
/// 최종 ICMP 측정 결과를 해석한다.
///
/// - 호출 후 취소 플래그가 확인되면 `CANCELLED`로 분류하며 가짜 RTT/TTL을 남기지 않는다.
/// - `returned_count == 0`이면 응답 버퍼를 읽지 않고 `error_code = Some(last_error)`, `ip_status = None`으로 분리한다.
/// - `returned_count > 0`이면 `ip_status = Some(reply.status)`, `error_code = None`으로 분리하며,
///   오직 `reply.status == IP_SUCCESS`일 때만 `rtt_ms`와 `ttl`을 채운다.
pub(crate) fn interpret_echo_result(
    returned_count: u32,
    first_reply: Option<RawEchoReplyFields>,
    last_error: u32,
    cancelled_after_call: bool,
) -> InterpretedEchoOutcome {
    if cancelled_after_call {
        return InterpretedEchoOutcome {
            outcome: "CANCELLED".to_string(),
            ip_status: None,
            error_code: None,
            rtt_ms: None,
            ttl: None,
            detail_limitation: Some(
                "동기 ICMP 시스템 호출 완료 직후 취소 플래그가 확인되어 결과를 CANCELLED로 처리했습니다."
                    .to_string(),
            ),
        };
    }

    if returned_count == 0 {
        let outcome = classify_api_error_code(last_error).to_string();
        return InterpretedEchoOutcome {
            outcome,
            ip_status: None,
            error_code: Some(last_error),
            rtt_ms: None,
            ttl: None,
            detail_limitation: Some(format!(
                "ICMP API가 응답 구조체 0개를 반환했습니다(GetLastError={last_error})."
            )),
        };
    }

    let Some(reply) = first_reply else {
        return InterpretedEchoOutcome {
            outcome: "LOCAL_ERROR".to_string(),
            ip_status: None,
            error_code: Some(last_error),
            rtt_ms: None,
            ttl: None,
            detail_limitation: Some(
                "ICMP 응답 개수가 양수였으나 응답 버퍼에서 구조체를 읽을 수 없었습니다."
                    .to_string(),
            ),
        };
    };

    let outcome = classify_ip_status(reply.status).to_string();
    if reply.status == IP_SUCCESS_CODE {
        InterpretedEchoOutcome {
            outcome,
            ip_status: Some(reply.status),
            error_code: None,
            rtt_ms: Some(reply.rtt_ms),
            ttl: reply.ttl,
            detail_limitation: None,
        }
    } else {
        InterpretedEchoOutcome {
            outcome,
            ip_status: Some(reply.status),
            error_code: None,
            rtt_ms: None,
            ttl: None,
            detail_limitation: Some(format!(
                "ICMP 응답 구조체 Status({})가 IP_SUCCESS(0)가 아니므로 RTT/TTL을 산출하지 않았습니다.",
                reply.status
            )),
        }
    }
}

/// IPv6 `Icmp6SendEcho2`에 전달할 출발지(`::`) 및 목적지 `SOCKADDR_IN6` 쌍을 생성한다.
/// 두 주소 모두 `sin6_family = AF_INET6`, `sin6_scope_id = 0`으로 설정한다.
#[cfg(windows)]
pub(crate) fn build_ipv6_sockaddr_pair(target: Ipv6Addr) -> (SOCKADDR_IN6, SOCKADDR_IN6) {
    let mut src: SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
    src.sin6_family = AF_INET6;
    src.sin6_port = 0;
    src.sin6_flowinfo = 0;
    src.sin6_addr.u.Byte = Ipv6Addr::UNSPECIFIED.octets();
    src.Anonymous.sin6_scope_id = 0;

    let mut dst: SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
    dst.sin6_family = AF_INET6;
    dst.sin6_port = 0;
    dst.sin6_flowinfo = 0;
    dst.sin6_addr.u.Byte = target.octets();
    dst.Anonymous.sin6_scope_id = 0;

    (src, dst)
}

#[cfg(windows)]
fn ping_ipv4_windows(
    target: Ipv4Addr,
    timeout_ms: u32,
    cancelled: &AtomicBool,
    started_at: Instant,
    mut limitations: Vec<String>,
) -> IcmpMeasurement {
    let target_str = IpAddr::V4(target).to_string();

    let handle = unsafe { IcmpCreateFile() };
    let null_handle: HANDLE = unsafe { std::mem::zeroed() };
    if handle == INVALID_HANDLE_VALUE || handle == null_handle {
        let err = unsafe { GetLastError() };
        limitations.push(format!("IcmpCreateFile 실패(GetLastError={err})."));
        return IcmpMeasurement {
            target: target_str,
            outcome: "LOCAL_ERROR".to_string(),
            elapsed_ms: elapsed_ms_since(started_at),
            ip_status: None,
            error_code: Some(err),
            rtt_ms: None,
            ttl: None,
            limitations,
        };
    }
    let _handle_guard = IcmpHandleGuard(handle);

    if cancelled.load(Ordering::Acquire) {
        limitations.push(
            "IcmpCreateFile 이후 IcmpSendEcho2 호출 전 취소 플래그가 감지되어 호출을 중단했습니다."
                .to_string(),
        );
        return IcmpMeasurement {
            target: target_str,
            outcome: "CANCELLED".to_string(),
            elapsed_ms: elapsed_ms_since(started_at),
            ip_status: None,
            error_code: None,
            rtt_ms: None,
            ttl: None,
            limitations,
        };
    }

    let mut request_payload = ICMP_REQUEST_PAYLOAD.to_vec();
    let reply_bytes = required_reply_buffer_bytes(
        std::mem::size_of::<ICMP_ECHO_REPLY>(),
        request_payload.len(),
        std::mem::size_of::<IO_STATUS_BLOCK>(),
    );
    let word_count = reply_bytes / std::mem::size_of::<usize>();
    let mut reply_buf: Vec<usize> = vec![0usize; word_count];
    let reply_size_u32 = (reply_buf.len() * std::mem::size_of::<usize>()) as u32;

    let dest_ip = ipv4_to_windows_ipaddr(target);

    let returned_count = unsafe {
        IcmpSendEcho2(
            handle,
            std::mem::zeroed(),
            std::mem::zeroed(),
            std::mem::zeroed(),
            dest_ip,
            request_payload.as_mut_ptr().into_raw_ptr(),
            request_payload.len() as u16,
            std::mem::zeroed(),
            reply_buf.as_mut_ptr().into_raw_ptr(),
            reply_size_u32,
            timeout_ms,
        )
    };

    let last_error = if returned_count == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    let cancelled_after = cancelled.load(Ordering::Acquire);

    let first_reply = if returned_count > 0
        && (reply_size_u32 as usize) >= std::mem::size_of::<ICMP_ECHO_REPLY>()
    {
        debug_assert!(std::mem::align_of::<usize>() >= std::mem::align_of::<ICMP_ECHO_REPLY>());
        let reply_ref: &ICMP_ECHO_REPLY =
            unsafe { &*(reply_buf.as_ptr() as *const ICMP_ECHO_REPLY) };
        Some(RawEchoReplyFields {
            status: reply_ref.Status,
            rtt_ms: reply_ref.RoundTripTime,
            ttl: Some(reply_ref.Options.Ttl),
        })
    } else {
        None
    };

    let interpreted =
        interpret_echo_result(returned_count, first_reply, last_error, cancelled_after);
    if let Some(detail) = interpreted.detail_limitation {
        limitations.push(detail);
    }

    IcmpMeasurement {
        target: target_str,
        outcome: interpreted.outcome,
        elapsed_ms: elapsed_ms_since(started_at),
        ip_status: interpreted.ip_status,
        error_code: interpreted.error_code,
        rtt_ms: interpreted.rtt_ms,
        ttl: interpreted.ttl,
        limitations,
    }
}

#[cfg(windows)]
fn ping_ipv6_windows(
    target: Ipv6Addr,
    timeout_ms: u32,
    cancelled: &AtomicBool,
    started_at: Instant,
    mut limitations: Vec<String>,
) -> IcmpMeasurement {
    let target_str = IpAddr::V6(target).to_string();

    let handle = unsafe { Icmp6CreateFile() };
    let null_handle: HANDLE = unsafe { std::mem::zeroed() };
    if handle == INVALID_HANDLE_VALUE || handle == null_handle {
        let err = unsafe { GetLastError() };
        limitations.push(format!("Icmp6CreateFile 실패(GetLastError={err})."));
        return IcmpMeasurement {
            target: target_str,
            outcome: "LOCAL_ERROR".to_string(),
            elapsed_ms: elapsed_ms_since(started_at),
            ip_status: None,
            error_code: Some(err),
            rtt_ms: None,
            ttl: None,
            limitations,
        };
    }
    let _handle_guard = IcmpHandleGuard(handle);

    if cancelled.load(Ordering::Acquire) {
        limitations.push(
            "Icmp6CreateFile 이후 Icmp6SendEcho2 호출 전 취소 플래그가 감지되어 호출을 중단했습니다."
                .to_string(),
        );
        return IcmpMeasurement {
            target: target_str,
            outcome: "CANCELLED".to_string(),
            elapsed_ms: elapsed_ms_since(started_at),
            ip_status: None,
            error_code: None,
            rtt_ms: None,
            ttl: None,
            limitations,
        };
    }

    let (mut src_addr, mut dst_addr) = build_ipv6_sockaddr_pair(target);
    let mut request_payload = ICMP_REQUEST_PAYLOAD.to_vec();
    let reply_bytes = required_reply_buffer_bytes(
        std::mem::size_of::<Icmpv6EchoReplyRaw>(),
        request_payload.len(),
        std::mem::size_of::<IO_STATUS_BLOCK>(),
    );
    let word_count = reply_bytes / std::mem::size_of::<usize>();
    let mut reply_buf: Vec<usize> = vec![0usize; word_count];
    let reply_size_u32 = (reply_buf.len() * std::mem::size_of::<usize>()) as u32;

    let returned_count = unsafe {
        Icmp6SendEcho2(
            handle,
            std::mem::zeroed(),
            std::mem::zeroed(),
            std::mem::zeroed(),
            (&raw mut src_addr).into_raw_ptr(),
            (&raw mut dst_addr).into_raw_ptr(),
            request_payload.as_mut_ptr().into_raw_ptr(),
            request_payload.len() as u16,
            std::mem::zeroed(),
            reply_buf.as_mut_ptr().into_raw_ptr(),
            reply_size_u32,
            timeout_ms,
        )
    };

    let last_error = if returned_count == 0 {
        unsafe { GetLastError() }
    } else {
        0
    };
    let cancelled_after = cancelled.load(Ordering::Acquire);

    let first_reply = if returned_count > 0
        && (reply_size_u32 as usize) >= std::mem::size_of::<Icmpv6EchoReplyRaw>()
    {
        debug_assert!(std::mem::align_of::<usize>() >= std::mem::align_of::<Icmpv6EchoReplyRaw>());
        let reply_ref: &Icmpv6EchoReplyRaw =
            unsafe { &*(reply_buf.as_ptr() as *const Icmpv6EchoReplyRaw) };
        Some(RawEchoReplyFields {
            status: reply_ref.status,
            rtt_ms: reply_ref.round_trip_time,
            ttl: None,
        })
    } else {
        None
    };

    let interpreted =
        interpret_echo_result(returned_count, first_reply, last_error, cancelled_after);
    if let Some(detail) = interpreted.detail_limitation {
        limitations.push(detail);
    }

    IcmpMeasurement {
        target: target_str,
        outcome: interpreted.outcome,
        elapsed_ms: elapsed_ms_since(started_at),
        ip_status: interpreted.ip_status,
        error_code: interpreted.error_code,
        rtt_ms: interpreted.rtt_ms,
        ttl: None,
        limitations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[test]
    fn ipv4_byte_order_preserves_network_octets_in_memory() {
        let localhost = Ipv4Addr::new(127, 0, 0, 1);
        let raw = ipv4_to_windows_ipaddr(localhost);
        assert_eq!(raw.to_ne_bytes(), [127, 0, 0, 1]);
        if cfg!(target_endian = "little") {
            assert_eq!(raw, 0x0100_007f);
            assert_ne!(raw, u32::from(localhost));
        }

        let sample = Ipv4Addr::new(10, 20, 30, 40);
        assert_eq!(
            ipv4_to_windows_ipaddr(sample).to_ne_bytes(),
            [10, 20, 30, 40]
        );
    }

    #[test]
    fn reply_buffer_size_meets_contract_and_word_alignment() {
        let reply_size = 40usize;
        let payload_len = ICMP_REQUEST_PAYLOAD.len();
        let iosb_size = 16usize;
        let computed = required_reply_buffer_bytes(reply_size, payload_len, iosb_size);

        assert!(computed >= reply_size + payload_len + 8 + iosb_size);
        assert_eq!(computed % std::mem::size_of::<usize>(), 0);
    }

    #[test]
    fn interpret_echo_result_separates_last_error_and_ip_status() {
        // returned_count == 0인 경우 버퍼의 가짜 IP_SUCCESS(0)를 무시하고 GetLastError만 기록해야 한다.
        let bogus_buffer_reply = Some(RawEchoReplyFields {
            status: IP_SUCCESS_CODE,
            rtt_ms: 1,
            ttl: Some(128),
        });
        let timeout_err =
            interpret_echo_result(0, bogus_buffer_reply, IP_REQ_TIMED_OUT_CODE, false);
        assert_eq!(timeout_err.outcome, "TIMEOUT");
        assert_eq!(timeout_err.ip_status, None);
        assert_eq!(timeout_err.error_code, Some(IP_REQ_TIMED_OUT_CODE));
        assert_eq!(timeout_err.rtt_ms, None);
        assert_eq!(timeout_err.ttl, None);

        // returned_count > 0이지만 Status가 실패인 경우 RTT/TTL을 채우지 않아야 한다.
        let unreach_reply = Some(RawEchoReplyFields {
            status: IP_DEST_HOST_UNREACHABLE_CODE,
            rtt_ms: 42,
            ttl: Some(64),
        });
        let unreach_res = interpret_echo_result(1, unreach_reply, 0, false);
        assert_eq!(unreach_res.outcome, "UNREACHABLE");
        assert_eq!(unreach_res.ip_status, Some(IP_DEST_HOST_UNREACHABLE_CODE));
        assert_eq!(unreach_res.error_code, None);
        assert_eq!(unreach_res.rtt_ms, None);
        assert_eq!(unreach_res.ttl, None);

        // returned_count > 0이고 Status == IP_SUCCESS일 때만 RTT/TTL을 채운다.
        let ok_reply = Some(RawEchoReplyFields {
            status: IP_SUCCESS_CODE,
            rtt_ms: 0,
            ttl: Some(128),
        });
        let ok_res = interpret_echo_result(1, ok_reply, 0, false);
        assert_eq!(ok_res.outcome, "REPLY");
        assert_eq!(ok_res.ip_status, Some(IP_SUCCESS_CODE));
        assert_eq!(ok_res.error_code, None);
        assert_eq!(ok_res.rtt_ms, Some(0));
        assert_eq!(ok_res.ttl, Some(128));

        // 호출 직후 취소 플래그가 확인되면 성공 응답이더라도 CANCELLED로 처리하고 RTT/TTL을 비운다.
        let cancelled_res = interpret_echo_result(1, ok_reply, 0, true);
        assert_eq!(cancelled_res.outcome, "CANCELLED");
        assert_eq!(cancelled_res.ip_status, None);
        assert_eq!(cancelled_res.error_code, None);
        assert_eq!(cancelled_res.rtt_ms, None);
        assert_eq!(cancelled_res.ttl, None);
    }

    #[cfg(windows)]
    #[test]
    fn ipv6_sockaddr_pair_sets_af_inet6_and_zero_scope() {
        let (src, dst) = build_ipv6_sockaddr_pair(Ipv6Addr::LOCALHOST);
        assert_eq!(src.sin6_family, AF_INET6);
        assert_eq!(dst.sin6_family, AF_INET6);
        assert_eq!(src.sin6_port, 0);
        assert_eq!(dst.sin6_port, 0);
        assert_eq!(
            unsafe { src.sin6_addr.u.Byte },
            Ipv6Addr::UNSPECIFIED.octets()
        );
        assert_eq!(
            unsafe { dst.sin6_addr.u.Byte },
            Ipv6Addr::LOCALHOST.octets()
        );
        assert_eq!(unsafe { src.Anonymous.sin6_scope_id }, 0);
        assert_eq!(unsafe { dst.Anonymous.sin6_scope_id }, 0);
    }
}
