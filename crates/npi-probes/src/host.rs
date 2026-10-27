//! Windows 네이티브 읽기 전용 호스트 네트워크 스냅샷 수집기 (`GetAdaptersAddresses`, `GetIpForwardTable2`, `GetBestRoute2`).
//!
//! 주의사항:
//! - 외부 명령(`ipconfig`, `route`, `netsh` 등)이나 서브프로세스를 실행하지 않는다.
//! - 패킷 송수신, 소켓 연결, OS 라우팅/방화벽/레지스트리 변경을 절대 수행하지 않는다.
//! - `selected_route`는 OS 라우팅 테이블 기준 경로/출발지 선택 결과일 뿐이며 원격 호스트 도달 또는 연결 성공의 증거가 아니다.
//! - 패킷 캡처(`capture`) 관련 필드는 절대 생성하지 않는다.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS},
    NetworkManagement::{
        IpHelper::{
            FreeMibTable, GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_INCLUDE_PREFIX, GetAdaptersAddresses,
            GetBestRoute2, GetIpForwardTable2, IP_ADAPTER_ADDRESSES_LH,
            IP_ADAPTER_DNS_SERVER_ADDRESS_XP, IP_ADAPTER_GATEWAY_ADDRESS_LH, IP_ADAPTER_PREFIX_XP,
            IP_ADAPTER_UNICAST_ADDRESS_LH, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2,
        },
        Ndis::{
            IF_OPER_STATUS, IfOperStatusDormant as IF_OPER_STATUS_DORMANT,
            IfOperStatusDown as IF_OPER_STATUS_DOWN,
            IfOperStatusLowerLayerDown as IF_OPER_STATUS_LOWER_LAYER_DOWN,
            IfOperStatusNotPresent as IF_OPER_STATUS_NOT_PRESENT,
            IfOperStatusTesting as IF_OPER_STATUS_TESTING,
            IfOperStatusUnknown as IF_OPER_STATUS_UNKNOWN, IfOperStatusUp as IF_OPER_STATUS_UP,
        },
    },
    Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
        SOCKET_ADDRESS,
    },
};

/// `GetAdaptersAddresses` 초기 버퍼 크기 (32 KiB).
pub const INITIAL_ADAPTER_BUFFER_BYTES: usize = 32 * 1024;

/// `GetAdaptersAddresses` 최대 허용 버퍼 크기 (4 MiB 상한).
pub const MAX_ADAPTER_BUFFER_BYTES: usize = 4 * 1024 * 1024;

/// `ERROR_BUFFER_OVERFLOW` 최대 재시도 횟수.
pub const MAX_BUFFER_OVERFLOW_RETRIES: usize = 4;

/// 연결 리스트 어댑터 순회 최대 노드 수 (무한 루프 방지).
pub const MAX_ADAPTER_NODES: usize = 256;

/// 어댑터 내 하위 연결 리스트(유니캐스트/프리픽스/게이트웨이/DNS) 최대 노드 수.
pub const MAX_SUBLIST_NODES: usize = 512;

/// 라우팅 테이블 최대 읽기 엔트리 수.
pub const MAX_ROUTE_ENTRIES: usize = 4096;

/// C 문자열(`PSTR`) 및 와이드 문자열(`PWSTR`) 최대 읽기 길이(코드 유닛 기준).
pub const MAX_STRING_UNITS: usize = 256;

/// `selected_route` 해석 한계 안내 문구.
pub const SELECTED_ROUTE_LIMITATION: &str = "selected_route는 Windows OS 라우팅 테이블(GetBestRoute2) 기준 출발지/경로 선택 결과일 뿐이며 원격 호스트 연결 또는 도달 가능성의 증거가 아닙니다 (OS route selection only, NOT remote connectivity evidence)";

/// 호스트 스냅샷 읽기 전용 수집 한계 안내 문구.
pub const SNAPSHOT_READONLY_LIMITATION: &str = "호스트 네트워크 스냅샷은 로컬 NIC/라우트/DNS 구성을 읽기 전용으로 조회하며 패킷 캡처나 원격 연결을 수행하지 않습니다";

/// 호스트 네트워크 스냅샷 DTO.
///
/// - `adapters`: 로컬 네트워크 어댑터 목록 JSON 배열 (실패 시 `Value::Null`)
/// - `routes`: 로컬 IPv4/IPv6 라우팅 테이블 목록 JSON 배열 (실패 시 `Value::Null`)
/// - `selected_route`: `GetBestRoute2` 기반 OS 선택 라우트 JSON 객체 (실패 시 `Value::Null`)
/// - `errors`: 개별 수집 단계에서 발생한 오류 목록
/// - `limitations`: 해석상 주의사항 및 한계 목록
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostSnapshot {
    pub adapters: serde_json::Value,
    pub routes: serde_json::Value,
    pub selected_route: serde_json::Value,
    pub errors: Vec<String>,
    pub limitations: Vec<String>,
}

/// 어댑터 유니캐스트 주소 및 온링크 프리픽스 길이 DTO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnicastAddressEntry {
    pub ip: String,
    pub prefix_length: u8,
}

/// 어댑터 프리픽스 항목 DTO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrefixEntry {
    pub prefix: String,
    pub prefix_length: u32,
    pub cidr: String,
}

/// 정규화된 단일 네트워크 어댑터 DTO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterEntry {
    pub interface_index: u32,
    pub ipv6_interface_index: u32,
    pub name: String,
    pub adapter_name: String,
    pub friendly_name: String,
    pub description: String,
    pub dns_suffix: String,
    pub operational_status: String,
    pub oper_status_code: i32,
    pub ips: Vec<String>,
    pub unicast_addresses: Vec<UnicastAddressEntry>,
    pub prefixes: Vec<String>,
    pub prefix_entries: Vec<PrefixEntry>,
    pub gateways: Vec<String>,
    pub dns_servers: Vec<String>,
}

/// 정규화된 단일 라우팅 테이블 엔트리 DTO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteEntry {
    pub destination_prefix: String,
    pub prefix: String,
    pub prefix_ip: String,
    pub prefix_length: u8,
    pub next_hop: String,
    pub metric: u32,
    pub interface_index: u32,
    pub interface_luid: u64,
    pub protocol: i32,
    pub origin: i32,
    pub loopback: bool,
}

/// `GetBestRoute2`로 선택된 OS 라우팅 항목 DTO.
/// 원격 연결성 증거가 아님을 명시적으로 표시한다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectedRouteEntry {
    pub target: String,
    pub source_ip: String,
    pub interface_index: u32,
    pub interface_luid: u64,
    pub destination_prefix: String,
    pub prefix: String,
    pub prefix_ip: String,
    pub prefix_length: u8,
    pub next_hop: String,
    pub metric: u32,
    pub selection_basis: String,
    pub remote_connectivity_evidence: bool,
    pub note: String,
}

/// 바이트 크기를 `usize` 정렬 버퍼의 원소 개수로 변환한다.
pub fn aligned_usize_word_count(byte_len: usize) -> usize {
    let word_size = std::mem::size_of::<usize>();
    byte_len.div_ceil(word_size)
}

/// `ERROR_BUFFER_OVERFLOW` 발생 시 다음 재시도 버퍼 바이트 크기를 검증·계산한다.
/// 재시도 횟수 상한(`MAX_BUFFER_OVERFLOW_RETRIES`) 또는 4 MiB(`MAX_ADAPTER_BUFFER_BYTES`)를 초과하면 오류를 반환한다.
pub fn next_overflow_buffer_size(
    current_bytes: usize,
    requested_bytes: u32,
    retry_index: usize,
) -> Result<usize, String> {
    if retry_index >= MAX_BUFFER_OVERFLOW_RETRIES {
        return Err(format!(
            "GetAdaptersAddresses 버퍼 오버플로 재시도 상한({MAX_BUFFER_OVERFLOW_RETRIES}회) 초과"
        ));
    }
    let req = requested_bytes as usize;
    if req == 0 {
        return Err(
            "GetAdaptersAddresses가 유효하지 않은 버퍼 크기(0 바이트)를 반환했습니다".to_string(),
        );
    }
    if req > MAX_ADAPTER_BUFFER_BYTES {
        return Err(format!(
            "GetAdaptersAddresses 요청 버퍼 크기({req} 바이트)가 상한({MAX_ADAPTER_BUFFER_BYTES} 바이트, 4MiB)을 초과했습니다"
        ));
    }
    let next_size = if req > current_bytes {
        req
    } else {
        current_bytes
            .saturating_mul(2)
            .min(MAX_ADAPTER_BUFFER_BYTES)
    };
    if next_size <= current_bytes {
        return Err(format!(
            "GetAdaptersAddresses 버퍼 크기를 더 이상 확장할 수 없습니다 ({current_bytes} 바이트)"
        ));
    }
    Ok(next_size)
}

/// 버퍼 범위 `[buf_start, buf_start + buf_byte_len)` 내에 구조체 포인터와 길이가 안전하게 포함되는지 검증한다.
pub fn is_range_within_buffer(
    buf_start: usize,
    buf_byte_len: usize,
    ptr_addr: usize,
    struct_len: usize,
    min_len: usize,
) -> bool {
    if ptr_addr == 0 || struct_len < min_len || buf_byte_len == 0 {
        return false;
    }
    let Some(buf_end) = buf_start.checked_add(buf_byte_len) else {
        return false;
    };
    let Some(ptr_end) = ptr_addr.checked_add(struct_len) else {
        return false;
    };
    ptr_addr >= buf_start && ptr_end <= buf_end
}

/// 바이트 슬라이스에서 널 종료 문자 또는 `max_len` 상한까지의 ASCII/UTF-8 문자열을 안전하게 추출한다.
pub fn read_bounded_ascii(bytes: &[u8], max_len: usize) -> String {
    let limit = bytes.len().min(max_len);
    let slice = &bytes[..limit];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(limit);
    String::from_utf8_lossy(&slice[..end]).into_owned()
}

/// `u16` 슬라이스에서 널 종료 문자 또는 `max_units` 상한까지의 UTF-16 문자열을 안전하게 추출한다.
pub fn read_bounded_utf16(units: &[u16], max_units: usize) -> String {
    let limit = units.len().min(max_units);
    let slice = &units[..limit];
    let end = slice.iter().position(|&u| u == 0).unwrap_or(limit);
    String::from_utf16_lossy(&slice[..end])
}

/// Windows `IF_OPER_STATUS` 정수 코드를 표준 대문자 상태 문자열로 변환한다.
pub fn oper_status_label(status: i32) -> &'static str {
    #[cfg(windows)]
    {
        match status as IF_OPER_STATUS {
            IF_OPER_STATUS_UP => "UP",
            IF_OPER_STATUS_DOWN => "DOWN",
            IF_OPER_STATUS_TESTING => "TESTING",
            IF_OPER_STATUS_UNKNOWN => "UNKNOWN",
            IF_OPER_STATUS_DORMANT => "DORMANT",
            IF_OPER_STATUS_NOT_PRESENT => "NOT_PRESENT",
            IF_OPER_STATUS_LOWER_LAYER_DOWN => "LOWER_LAYER_DOWN",
            _ => "OTHER",
        }
    }
    #[cfg(not(windows))]
    {
        match status {
            1 => "UP",
            2 => "DOWN",
            3 => "TESTING",
            4 => "UNKNOWN",
            5 => "DORMANT",
            6 => "NOT_PRESENT",
            7 => "LOWER_LAYER_DOWN",
            _ => "OTHER",
        }
    }
}

/// 네트워크 바이트 순서가 메모리에 배치된 `IN_ADDR.S_un.S_addr`(`u32`) 값을 `Ipv4Addr`로 변환한다.
pub fn ipv4_from_network_u32(s_addr_ne: u32) -> Ipv4Addr {
    Ipv4Addr::from(s_addr_ne.to_ne_bytes())
}

/// `Ipv4Addr`를 `IN_ADDR.S_un.S_addr` 메모리 표현(`u32`)으로 변환한다.
pub fn ipv4_to_network_u32(ip: Ipv4Addr) -> u32 {
    u32::from_ne_bytes(ip.octets())
}

/// IP 주소와 프리픽스 길이를 `"<ip>/<prefix_length>"` CIDR 문자열로 포맷한다.
pub fn format_cidr(ip: IpAddr, prefix_length: u32) -> String {
    format!("{ip}/{prefix_length}")
}

/// `GetBestRoute2` 결과로부터 OS 라우트 선택 객체(`SelectedRouteEntry`)를 생성한다.
/// 원격 연결성 증거가 아님을 필드로 명시한다.
pub fn build_selected_route_entry(
    target: IpAddr,
    source_ip: IpAddr,
    route: &RouteEntry,
) -> SelectedRouteEntry {
    SelectedRouteEntry {
        target: target.to_string(),
        source_ip: source_ip.to_string(),
        interface_index: route.interface_index,
        interface_luid: route.interface_luid,
        destination_prefix: route.destination_prefix.clone(),
        prefix: route.prefix.clone(),
        prefix_ip: route.prefix_ip.clone(),
        prefix_length: route.prefix_length,
        next_hop: route.next_hop.clone(),
        metric: route.metric,
        selection_basis: "OS_ROUTE_SELECTION".to_string(),
        remote_connectivity_evidence: false,
        note: SELECTED_ROUTE_LIMITATION.to_string(),
    }
}

/// `GetBestRoute2` 결과로부터 JSON `Value`를 생성한다.
pub fn build_selected_route_value(target: IpAddr, source_ip: IpAddr, route: &RouteEntry) -> Value {
    let entry = build_selected_route_entry(target, source_ip, route);
    serde_json::to_value(entry).unwrap_or(Value::Null)
}

/// 수집된 개별 컴포넌트 결과(`Option`)와 오류/제한사항으로부터 `HostSnapshot`을 조립한다.
/// 실패한 컴포넌트는 가짜 빈 성공값으로 위장하지 않고 `Value::Null`로 유지한다.
pub fn build_host_snapshot_from_parts(
    adapters: Option<Vec<AdapterEntry>>,
    routes: Option<Vec<RouteEntry>>,
    selected_route: Option<SelectedRouteEntry>,
    errors: Vec<String>,
    mut limitations: Vec<String>,
) -> HostSnapshot {
    if !limitations.iter().any(|l| l == SELECTED_ROUTE_LIMITATION) {
        limitations.push(SELECTED_ROUTE_LIMITATION.to_string());
    }
    if !limitations
        .iter()
        .any(|l| l == SNAPSHOT_READONLY_LIMITATION)
    {
        limitations.push(SNAPSHOT_READONLY_LIMITATION.to_string());
    }

    let adapters_val = match adapters {
        Some(list) => serde_json::to_value(list).unwrap_or(Value::Null),
        None => Value::Null,
    };
    let routes_val = match routes {
        Some(list) => serde_json::to_value(list).unwrap_or(Value::Null),
        None => Value::Null,
    };
    let selected_val = match selected_route {
        Some(sel) => serde_json::to_value(sel).unwrap_or(Value::Null),
        None => Value::Null,
    };

    HostSnapshot {
        adapters: adapters_val,
        routes: routes_val,
        selected_route: selected_val,
        errors,
        limitations,
    }
}

/// `IpAddr`를 Windows `SOCKADDR_INET` 공용체로 변환한다.
#[cfg(windows)]
pub fn sockaddr_inet_from_ip(ip: IpAddr) -> SOCKADDR_INET {
    // SAFETY: SOCKADDR_INET은 POD 공용체이므로 0 초기화가 안전하다.
    let mut inet: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    match ip {
        IpAddr::V4(v4) => {
            let mut sa4: SOCKADDR_IN = unsafe { std::mem::zeroed() };
            sa4.sin_family = AF_INET;
            sa4.sin_addr.S_un.S_addr = ipv4_to_network_u32(v4);
            inet.Ipv4 = sa4;
        }
        IpAddr::V6(v6) => {
            let mut sa6: SOCKADDR_IN6 = unsafe { std::mem::zeroed() };
            sa6.sin6_family = AF_INET6;
            sa6.sin6_addr.u.Byte = v6.octets();
            inet.Ipv6 = sa6;
        }
    }
    inet
}

/// Windows `SOCKADDR_INET` 공용체에서 `IpAddr`를 추출한다.
/// 지원하지 않는 주소 패밀리(`AF_INET`/`AF_INET6` 이외)는 `None`을 반환한다.
#[cfg(windows)]
pub fn ip_from_sockaddr_inet(inet: &SOCKADDR_INET) -> Option<IpAddr> {
    // SAFETY: SOCKADDR_INET의 첫 2바이트(si_family)는 모든 분기에서 동일 오프셋에 위치한다.
    let family = unsafe { inet.si_family };
    if family == AF_INET {
        let s_addr = unsafe { inet.Ipv4.sin_addr.S_un.S_addr };
        Some(IpAddr::V4(ipv4_from_network_u32(s_addr)))
    } else if family == AF_INET6 {
        let bytes = unsafe { inet.Ipv6.sin6_addr.u.Byte };
        Some(IpAddr::V6(Ipv6Addr::from(bytes)))
    } else {
        None
    }
}

/// Windows `MIB_IPFORWARD_ROW2` 구조체를 `RouteEntry` DTO로 변환한다.
#[cfg(windows)]
pub fn route_entry_from_mib_row(row: &MIB_IPFORWARD_ROW2) -> Option<RouteEntry> {
    let prefix_ip = ip_from_sockaddr_inet(&row.DestinationPrefix.Prefix)?;
    let next_hop_ip = ip_from_sockaddr_inet(&row.NextHop).unwrap_or(match prefix_ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    });
    let prefix_length = row.DestinationPrefix.PrefixLength;
    let cidr = format_cidr(prefix_ip, u32::from(prefix_length));
    // SAFETY: NET_LUID_LH 공용체의 64비트 정수 표현(Value)을 읽는다.
    let luid_val = unsafe { row.InterfaceLuid.Value };

    Some(RouteEntry {
        destination_prefix: cidr.clone(),
        prefix: cidr,
        prefix_ip: prefix_ip.to_string(),
        prefix_length,
        next_hop: next_hop_ip.to_string(),
        metric: row.Metric,
        interface_index: row.InterfaceIndex,
        interface_luid: luid_val,
        protocol: row.Protocol,
        origin: row.Origin,
        loopback: row.Loopback,
    })
}

#[cfg(windows)]
struct MibTableGuard(*mut MIB_IPFORWARD_TABLE2);

#[cfg(windows)]
impl Drop for MibTableGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: GetIpForwardTable2가 성공적으로 반환한 MIB 테이블 포인터를 FreeMibTable로 해제한다.
            unsafe {
                FreeMibTable((self.0 as *const MIB_IPFORWARD_TABLE2).cast());
            }
            self.0 = std::ptr::null_mut();
        }
    }
}

/// 버퍼 범위 내에 위치한 `SOCKET_ADDRESS`로부터 `IpAddr`를 안전하게 읽는다.
#[cfg(windows)]
fn read_socket_address_in_buffer(
    sock_addr: SOCKET_ADDRESS,
    buf_start: usize,
    buf_byte_len: usize,
) -> Option<IpAddr> {
    if sock_addr.lpSockaddr.is_null() || sock_addr.iSockaddrLength <= 0 {
        return None;
    }
    let sa_len = sock_addr.iSockaddrLength as usize;
    let sa_addr = sock_addr.lpSockaddr as usize;
    if !is_range_within_buffer(
        buf_start,
        buf_byte_len,
        sa_addr,
        sa_len,
        std::mem::size_of::<SOCKADDR>(),
    ) {
        return None;
    }

    // SAFETY: 버퍼 경계 및 최소 SOCKADDR 크기를 검증한 뒤 비정렬 읽기를 수행한다.
    let base_sa: SOCKADDR = unsafe { sock_addr.lpSockaddr.cast::<SOCKADDR>().read_unaligned() };
    if base_sa.sa_family == AF_INET {
        if sa_len < std::mem::size_of::<SOCKADDR_IN>() {
            return None;
        }
        // SAFETY: SOCKADDR_IN 크기 이상이 버퍼 범위 내에 있음을 확인했다.
        let sin: SOCKADDR_IN =
            unsafe { sock_addr.lpSockaddr.cast::<SOCKADDR_IN>().read_unaligned() };
        let raw_ip = unsafe { sin.sin_addr.S_un.S_addr };
        Some(IpAddr::V4(ipv4_from_network_u32(raw_ip)))
    } else if base_sa.sa_family == AF_INET6 {
        if sa_len < std::mem::size_of::<SOCKADDR_IN6>() {
            return None;
        }
        // SAFETY: SOCKADDR_IN6 크기 이상이 버퍼 범위 내에 있음을 확인했다.
        let sin6: SOCKADDR_IN6 =
            unsafe { sock_addr.lpSockaddr.cast::<SOCKADDR_IN6>().read_unaligned() };
        let bytes = unsafe { sin6.sin6_addr.u.Byte };
        Some(IpAddr::V6(Ipv6Addr::from(bytes)))
    } else {
        None
    }
}

/// 버퍼 범위 내에 위치한 `PSTR`(`*const u8`)로부터 상한이 적용된 문자열을 읽는다.
#[cfg(windows)]
fn read_pstr_in_buffer(ptr: *const u8, buf_start: usize, buf_byte_len: usize) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let addr = ptr as usize;
    let Some(buf_end) = buf_start.checked_add(buf_byte_len) else {
        return String::new();
    };
    if addr < buf_start || addr >= buf_end {
        return String::new();
    }
    let available = (buf_end - addr).min(MAX_STRING_UNITS);
    let mut raw = Vec::with_capacity(available);
    for idx in 0..available {
        // SAFETY: addr + idx < buf_end 임이 보장된다.
        let byte = unsafe { ptr.add(idx).read() };
        if byte == 0 {
            break;
        }
        raw.push(byte);
    }
    read_bounded_ascii(&raw, MAX_STRING_UNITS)
}

/// 버퍼 범위 내에 위치한 `PWSTR`(`*const u16`)로부터 상한이 적용된 UTF-16 문자열을 읽는다.
#[cfg(windows)]
fn read_pwstr_in_buffer(ptr: *const u16, buf_start: usize, buf_byte_len: usize) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let addr = ptr as usize;
    let Some(buf_end) = buf_start.checked_add(buf_byte_len) else {
        return String::new();
    };
    if addr < buf_start || addr.saturating_add(std::mem::size_of::<u16>()) > buf_end {
        return String::new();
    }
    let available_units = ((buf_end - addr) / std::mem::size_of::<u16>()).min(MAX_STRING_UNITS);
    let mut units = Vec::with_capacity(available_units);
    for idx in 0..available_units {
        // SAFETY: addr + (idx + 1) * 2 <= buf_end 임이 보장되므로 비정렬 읽기가 안전하다.
        let unit = unsafe { ptr.add(idx).read_unaligned() };
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    read_bounded_utf16(&units, MAX_STRING_UNITS)
}

/// `usize` 정렬 버퍼에 기록된 `IP_ADAPTER_ADDRESSES_LH` 연결 리스트를 경계·순환 검사와 함께 파싱한다.
#[cfg(windows)]
pub fn parse_adapters_from_aligned_buffer(
    buf: &[usize],
    valid_bytes: usize,
    limitations: &mut Vec<String>,
) -> Vec<AdapterEntry> {
    let max_buf_bytes = buf.len().saturating_mul(std::mem::size_of::<usize>());
    let valid_bytes = valid_bytes.min(max_buf_bytes);
    if buf.is_empty() || valid_bytes == 0 {
        return Vec::new();
    }

    let buf_start = buf.as_ptr() as usize;
    let mut adapters = Vec::new();
    let mut visited_adapters = BTreeSet::new();
    let mut current_ptr = buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();

    while !current_ptr.is_null() {
        if adapters.len() >= MAX_ADAPTER_NODES {
            limitations.push(format!(
                "어댑터 연결 리스트 노드 수가 상한({MAX_ADAPTER_NODES}개)에 도달하여 순회를 중단했습니다"
            ));
            break;
        }
        let ptr_addr = current_ptr as usize;
        if !visited_adapters.insert(ptr_addr) {
            limitations.push(
                "어댑터 연결 리스트에서 순환 포인터가 감지되어 순회를 중단했습니다".to_string(),
            );
            break;
        }
        if !is_range_within_buffer(
            buf_start,
            valid_bytes,
            ptr_addr,
            std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>(),
            std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>(),
        ) {
            limitations.push(
                "어댑터 구조체 포인터가 유효 버퍼 범위를 벗어나 순회를 중단했습니다".to_string(),
            );
            break;
        }

        // SAFETY: current_ptr가 버퍼 범위 내에 있음을 확인했다.
        let node: IP_ADAPTER_ADDRESSES_LH = unsafe { current_ptr.read_unaligned() };
        let declared_len = unsafe { node.Anonymous1.Anonymous.Length } as usize;
        if !is_range_within_buffer(
            buf_start,
            valid_bytes,
            ptr_addr,
            declared_len,
            std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>(),
        ) {
            limitations.push(
                "어댑터 구조체 Length 필드가 버퍼 범위를 초과하여 순회를 중단했습니다".to_string(),
            );
            break;
        }

        let if_index = unsafe { node.Anonymous1.Anonymous.IfIndex };
        let ipv6_if_index = node.Ipv6IfIndex;
        let primary_if_index = if if_index != 0 {
            if_index
        } else {
            ipv6_if_index
        };

        let adapter_name =
            read_pstr_in_buffer(node.AdapterName.cast_const(), buf_start, valid_bytes);
        let friendly_name =
            read_pwstr_in_buffer(node.FriendlyName.cast_const(), buf_start, valid_bytes);
        let description =
            read_pwstr_in_buffer(node.Description.cast_const(), buf_start, valid_bytes);
        let dns_suffix = read_pwstr_in_buffer(node.DnsSuffix.cast_const(), buf_start, valid_bytes);

        let name = if !friendly_name.is_empty() {
            friendly_name.clone()
        } else {
            adapter_name.clone()
        };

        let oper_code = node.OperStatus;
        let oper_label = oper_status_label(oper_code).to_string();

        // 1. 유니캐스트 주소 순회
        let mut ips = Vec::new();
        let mut unicast_addresses = Vec::new();
        let mut visited_unicast = BTreeSet::new();
        let mut uni_ptr = node.FirstUnicastAddress.cast_const();
        while !uni_ptr.is_null() && unicast_addresses.len() < MAX_SUBLIST_NODES {
            let u_addr = uni_ptr as usize;
            if !visited_unicast.insert(u_addr) {
                break;
            }
            if !is_range_within_buffer(
                buf_start,
                valid_bytes,
                u_addr,
                std::mem::size_of::<IP_ADAPTER_UNICAST_ADDRESS_LH>(),
                std::mem::size_of::<IP_ADAPTER_UNICAST_ADDRESS_LH>(),
            ) {
                break;
            }
            // SAFETY: uni_ptr가 버퍼 범위 내에 있음을 확인했다.
            let uni_node: IP_ADAPTER_UNICAST_ADDRESS_LH = unsafe { uni_ptr.read_unaligned() };
            let u_len = unsafe { uni_node.Anonymous.Anonymous.Length } as usize;
            if !is_range_within_buffer(
                buf_start,
                valid_bytes,
                u_addr,
                u_len,
                std::mem::size_of::<IP_ADAPTER_UNICAST_ADDRESS_LH>(),
            ) {
                break;
            }
            if let Some(ip) =
                read_socket_address_in_buffer(uni_node.Address, buf_start, valid_bytes)
            {
                let ip_str = ip.to_string();
                ips.push(ip_str.clone());
                unicast_addresses.push(UnicastAddressEntry {
                    ip: ip_str,
                    prefix_length: uni_node.OnLinkPrefixLength,
                });
            }
            uni_ptr = uni_node.Next.cast_const();
        }

        // 2. 프리픽스 리스트 순회
        let mut prefixes = Vec::new();
        let mut prefix_entries = Vec::new();
        let mut visited_prefix = BTreeSet::new();
        let mut pfx_ptr = node.FirstPrefix.cast_const();
        while !pfx_ptr.is_null() && prefix_entries.len() < MAX_SUBLIST_NODES {
            let p_addr = pfx_ptr as usize;
            if !visited_prefix.insert(p_addr) {
                break;
            }
            if !is_range_within_buffer(
                buf_start,
                valid_bytes,
                p_addr,
                std::mem::size_of::<IP_ADAPTER_PREFIX_XP>(),
                std::mem::size_of::<IP_ADAPTER_PREFIX_XP>(),
            ) {
                break;
            }
            // SAFETY: pfx_ptr가 버퍼 범위 내에 있음을 확인했다.
            let pfx_node: IP_ADAPTER_PREFIX_XP = unsafe { pfx_ptr.read_unaligned() };
            let p_len = unsafe { pfx_node.Anonymous.Anonymous.Length } as usize;
            if !is_range_within_buffer(
                buf_start,
                valid_bytes,
                p_addr,
                p_len,
                std::mem::size_of::<IP_ADAPTER_PREFIX_XP>(),
            ) {
                break;
            }
            if let Some(ip) =
                read_socket_address_in_buffer(pfx_node.Address, buf_start, valid_bytes)
            {
                let cidr = format_cidr(ip, pfx_node.PrefixLength);
                prefixes.push(cidr.clone());
                prefix_entries.push(PrefixEntry {
                    prefix: ip.to_string(),
                    prefix_length: pfx_node.PrefixLength,
                    cidr,
                });
            }
            pfx_ptr = pfx_node.Next.cast_const();
        }

        // FirstPrefix가 비어 있는 경우 유니캐스트 OnLinkPrefixLength로부터 프리픽스를 보강한다.
        if prefixes.is_empty() {
            for u in &unicast_addresses {
                let cidr = format!("{}/{}", u.ip, u.prefix_length);
                prefixes.push(cidr.clone());
                prefix_entries.push(PrefixEntry {
                    prefix: u.ip.clone(),
                    prefix_length: u32::from(u.prefix_length),
                    cidr,
                });
            }
        }

        // 3. 게이트웨이 리스트 순회
        let mut gateways = Vec::new();
        let mut visited_gw = BTreeSet::new();
        let mut gw_ptr = node.FirstGatewayAddress.cast_const();
        while !gw_ptr.is_null() && gateways.len() < MAX_SUBLIST_NODES {
            let g_addr = gw_ptr as usize;
            if !visited_gw.insert(g_addr) {
                break;
            }
            if !is_range_within_buffer(
                buf_start,
                valid_bytes,
                g_addr,
                std::mem::size_of::<IP_ADAPTER_GATEWAY_ADDRESS_LH>(),
                std::mem::size_of::<IP_ADAPTER_GATEWAY_ADDRESS_LH>(),
            ) {
                break;
            }
            // SAFETY: gw_ptr가 버퍼 범위 내에 있음을 확인했다.
            let gw_node: IP_ADAPTER_GATEWAY_ADDRESS_LH = unsafe { gw_ptr.read_unaligned() };
            let g_len = unsafe { gw_node.Anonymous.Anonymous.Length } as usize;
            if !is_range_within_buffer(
                buf_start,
                valid_bytes,
                g_addr,
                g_len,
                std::mem::size_of::<IP_ADAPTER_GATEWAY_ADDRESS_LH>(),
            ) {
                break;
            }
            if let Some(ip) = read_socket_address_in_buffer(gw_node.Address, buf_start, valid_bytes)
            {
                gateways.push(ip.to_string());
            }
            gw_ptr = gw_node.Next.cast_const();
        }

        // 4. DNS 서버 리스트 순회
        let mut dns_servers = Vec::new();
        let mut visited_dns = BTreeSet::new();
        let mut dns_ptr = node.FirstDnsServerAddress.cast_const();
        while !dns_ptr.is_null() && dns_servers.len() < MAX_SUBLIST_NODES {
            let d_addr = dns_ptr as usize;
            if !visited_dns.insert(d_addr) {
                break;
            }
            if !is_range_within_buffer(
                buf_start,
                valid_bytes,
                d_addr,
                std::mem::size_of::<IP_ADAPTER_DNS_SERVER_ADDRESS_XP>(),
                std::mem::size_of::<IP_ADAPTER_DNS_SERVER_ADDRESS_XP>(),
            ) {
                break;
            }
            // SAFETY: dns_ptr가 버퍼 범위 내에 있음을 확인했다.
            let dns_node: IP_ADAPTER_DNS_SERVER_ADDRESS_XP = unsafe { dns_ptr.read_unaligned() };
            let d_len = unsafe { dns_node.Anonymous.Anonymous.Length } as usize;
            if !is_range_within_buffer(
                buf_start,
                valid_bytes,
                d_addr,
                d_len,
                std::mem::size_of::<IP_ADAPTER_DNS_SERVER_ADDRESS_XP>(),
            ) {
                break;
            }
            if let Some(ip) =
                read_socket_address_in_buffer(dns_node.Address, buf_start, valid_bytes)
            {
                dns_servers.push(ip.to_string());
            }
            dns_ptr = dns_node.Next.cast_const();
        }

        adapters.push(AdapterEntry {
            interface_index: primary_if_index,
            ipv6_interface_index: ipv6_if_index,
            name,
            adapter_name,
            friendly_name,
            description,
            dns_suffix,
            operational_status: oper_label,
            oper_status_code: oper_code,
            ips,
            unicast_addresses,
            prefixes,
            prefix_entries,
            gateways,
            dns_servers,
        });

        current_ptr = node.Next.cast_const();
    }

    adapters
}

/// Windows `GetAdaptersAddresses`를 호출하여 로컬 네트워크 어댑터 목록을 수집한다.
#[cfg(windows)]
fn collect_adapters_windows(limitations: &mut Vec<String>) -> Result<Vec<AdapterEntry>, String> {
    assert!(
        std::mem::align_of::<usize>() >= std::mem::align_of::<IP_ADAPTER_ADDRESSES_LH>(),
        "Vec<usize> 정렬은 IP_ADAPTER_ADDRESSES_LH 정렬 이상이어야 합니다"
    );

    let flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS;
    let mut current_bytes = INITIAL_ADAPTER_BUFFER_BYTES;
    let mut retry_index = 0usize;

    let (buf, valid_bytes) = loop {
        let word_count = aligned_usize_word_count(current_bytes);
        let mut buffer = vec![0usize; word_count];
        let alloc_bytes =
            (buffer.len() * std::mem::size_of::<usize>()).min(MAX_ADAPTER_BUFFER_BYTES);
        let mut size_pointer = alloc_bytes as u32;

        // SAFETY: Vec<usize>로 정렬된 가변 버퍼와 유효한 크기 포인터를 전달한다.
        let ret = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_UNSPEC),
                flags,
                std::ptr::null(),
                buffer.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>(),
                &mut size_pointer,
            )
        };

        if ret == ERROR_SUCCESS {
            let effective_bytes = if size_pointer == 0 { 0 } else { alloc_bytes };
            break (buffer, effective_bytes);
        } else if ret == ERROR_BUFFER_OVERFLOW {
            current_bytes = next_overflow_buffer_size(alloc_bytes, size_pointer, retry_index)?;
            retry_index += 1;
        } else {
            return Err(format!(
                "GetAdaptersAddresses 실패 (Win32 오류 코드: {ret})"
            ));
        }
    };

    Ok(parse_adapters_from_aligned_buffer(
        &buf,
        valid_bytes,
        limitations,
    ))
}

/// Windows `GetIpForwardTable2`를 호출하여 로컬 라우팅 테이블을 수집하고 `FreeMibTable`로 해제한다.
#[cfg(windows)]
fn collect_routes_windows(limitations: &mut Vec<String>) -> Result<Vec<RouteEntry>, String> {
    let mut table_ptr: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
    // SAFETY: AF_UNSPEC으로 IPv4/IPv6 통합 라우팅 테이블 포인터를 요청한다.
    let status = unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table_ptr) };
    if status != ERROR_SUCCESS {
        return Err(format!(
            "GetIpForwardTable2 실패 (Win32 오류 코드: {status})"
        ));
    }
    if table_ptr.is_null() {
        return Err("GetIpForwardTable2가 널(null) 테이블 포인터를 반환했습니다".to_string());
    }

    let _guard = MibTableGuard(table_ptr);

    // SAFETY: table_ptr가 널이 아니며 GetIpForwardTable2가 할당한 유효한 헤더를 가리킨다.
    let raw_count = unsafe { std::ptr::addr_of!((*table_ptr).NumEntries).read() } as usize;
    let count = if raw_count > MAX_ROUTE_ENTRIES {
        limitations.push(format!(
            "라우팅 테이블 엔트리 수({raw_count}개)가 상한({MAX_ROUTE_ENTRIES}개)을 초과하여 상한까지만 수집했습니다"
        ));
        MAX_ROUTE_ENTRIES
    } else {
        raw_count
    };

    // SAFETY: 유연 배열 멤버(Table)의 시작 주소를 원시 포인터로 얻어 참조 프로비넌스 축소를 방지한다.
    let rows_base = unsafe { std::ptr::addr_of!((*table_ptr).Table).cast::<MIB_IPFORWARD_ROW2>() };
    let mut routes = Vec::with_capacity(count);
    for idx in 0..count {
        // SAFETY: idx < count <= NumEntries 범위 내의 MIB_IPFORWARD_ROW2 원소를 읽는다.
        let row: MIB_IPFORWARD_ROW2 = unsafe { rows_base.add(idx).read_unaligned() };
        if let Some(entry) = route_entry_from_mib_row(&row) {
            routes.push(entry);
        }
    }

    Ok(routes)
}

/// Windows `GetBestRoute2`를 호출하여 대상 주소에 대한 OS 선택 경로 및 출발지 IP를 조회한다.
#[cfg(windows)]
fn collect_selected_route_windows(target: IpAddr) -> Result<SelectedRouteEntry, String> {
    if target.is_unspecified() {
        return Err(format!(
            "GetBestRoute2 거부: 지정되지 않은 대상 주소({target})는 유효한 목적지가 아닙니다"
        ));
    }
    if target.is_multicast() {
        return Err(format!(
            "GetBestRoute2 거부: 멀티캐스트 대상 주소({target})는 단일 유니캐스트 목적지가 아닙니다"
        ));
    }

    let dest_inet = sockaddr_inet_from_ip(target);
    // SAFETY: MIB_IPFORWARD_ROW2 및 SOCKADDR_INET은 0 초기화가 안전한 C 구조체/공용체이다.
    let mut best_row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
    let mut best_source: SOCKADDR_INET = unsafe { std::mem::zeroed() };

    // SAFETY: 읽기 전용으로 대상 주소에 대한 최적 경로 및 출발지 주소를 OS에 질의한다.
    let status = unsafe {
        GetBestRoute2(
            std::ptr::null(),
            0,
            std::ptr::null(),
            &dest_inet,
            0,
            &mut best_row,
            &mut best_source,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(format!(
            "GetBestRoute2({target}) 실패 (Win32 오류 코드: {status})"
        ));
    }

    let route_entry = route_entry_from_mib_row(&best_row).ok_or_else(|| {
        "GetBestRoute2 결과의 목적지 프리픽스 주소 패밀리를 해석할 수 없습니다".to_string()
    })?;
    let source_ip = ip_from_sockaddr_inet(&best_source).ok_or_else(|| {
        "GetBestRoute2 결과의 출발지 주소(BestSourceAddress)를 해석할 수 없습니다".to_string()
    })?;

    Ok(build_selected_route_entry(target, source_ip, &route_entry))
}

/// 대상 IP에 대한 호스트 네트워크 스냅샷(어댑터/게이트웨이/DNS, 라우팅 테이블, OS 선택 경로)을 수집한다.
///
/// - Windows에서는 `GetAdaptersAddresses`, `GetIpForwardTable2`, `GetBestRoute2`를 읽기 전용으로 호출한다.
/// - 개별 컴포넌트가 실패하면 해당 필드를 `Value::Null`로 두고 `errors`에 원인을 기록하며 가짜 성공값을 생성하지 않는다.
/// - 비-Windows 플랫폼에서는 모든 컴포넌트를 `Value::Null`로 두고 `UNAVAILABLE` 사유를 반환한다.
pub fn collect_host_snapshot(target: IpAddr) -> HostSnapshot {
    #[cfg(windows)]
    {
        let mut errors = Vec::new();
        let mut limitations = vec![
            SELECTED_ROUTE_LIMITATION.to_string(),
            SNAPSHOT_READONLY_LIMITATION.to_string(),
        ];

        let adapters = match collect_adapters_windows(&mut limitations) {
            Ok(list) => Some(list),
            Err(err) => {
                errors.push(err);
                None
            }
        };

        let routes = match collect_routes_windows(&mut limitations) {
            Ok(list) => Some(list),
            Err(err) => {
                errors.push(err);
                None
            }
        };

        let selected_route = match collect_selected_route_windows(target) {
            Ok(sel) => Some(sel),
            Err(err) => {
                errors.push(err);
                None
            }
        };

        build_host_snapshot_from_parts(adapters, routes, selected_route, errors, limitations)
    }

    #[cfg(not(windows))]
    {
        let _ = target;
        HostSnapshot {
            adapters: Value::Null,
            routes: Value::Null,
            selected_route: Value::Null,
            errors: vec![
                "UNAVAILABLE: 호스트 네트워크 스냅샷 수집은 Windows 네이티브 API(IpHelper) 환경에서만 지원됩니다".to_string(),
            ],
            limitations: vec![
                "UNAVAILABLE: 비-Windows 플랫폼에서는 GetAdaptersAddresses/GetIpForwardTable2/GetBestRoute2를 사용할 수 없습니다".to_string(),
                SELECTED_ROUTE_LIMITATION.to_string(),
                SNAPSHOT_READONLY_LIMITATION.to_string(),
            ],
        }
    }
}
