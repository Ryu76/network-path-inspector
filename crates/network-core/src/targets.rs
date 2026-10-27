//! Network Quick Check(Part B)를 위한 순수 진단 대상 입력 분석 및 계획 수립 모듈.
//!
//! ## 설계 및 안전 원칙
//! - **순수 계획 수립(Pure Planning)**: 본 모듈은 사용자로부터 입력된 단일/다중 대상을 정규화하고
//!   검사 계획(`QuickPlan`)을 수립하는 순수 계획 엔진입니다.
//! - **실제 네트워크 I/O 배제**: 본 모듈 및 수립된 계획은 소켓 생성, 연결 시도, DNS 쿼리,
//!   프로세스 실행 또는 파일 쓰기 작업을 일체 수행하지 않습니다.
//! - **단일 진실 공급원 준수**: `qg2a-contract.json` 및 Quick Check PRD v1.2 요구사항을 정확히 따릅니다.
//! - **비파괴·엄격성**: 사용자 입력을 임의로 수리하거나 트림하지 않으며,
//!   유효하지 않거나 안전하지 않은 주소(미지정, 멀티캐스트, 브로드캐스트)는 즉각 거부합니다.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::quick::QuickFeature;

/// 단일 진단 세션에서 허용되는 최대 고유 검사 대상 수 (100개).
pub const MAX_TARGETS: usize = 100;

/// 다중 대상 붙여넣기 입력의 최대 허용 바이트 크기 (32KB = 32768 바이트).
pub const MAX_INPUT_BYTES: usize = 32768;

/// 기본 동시 프로브 실행 수 (4).
pub const DEFAULT_CONCURRENCY: usize = 4;

/// 최대 허용 동시 프로브 실행 수 (4).
pub const MAX_CONCURRENCY: usize = 4;

/// 기본 TCP 연결 타임아웃 (3000ms = 3초).
pub const DEFAULT_TCP_TIMEOUT_MS: u64 = 3000;

/// 최소 TCP 연결 타임아웃 (1ms).
pub const MIN_TCP_TIMEOUT_MS: u64 = 1;

/// 최대 TCP 연결 타임아웃 (60000ms = 60초).
pub const MAX_TCP_TIMEOUT_MS: u64 = 60000;

/// ICMP Ping 타임아웃 최대 상한치 (2000ms = 2초).
pub const MAX_ICMP_TIMEOUT_MS: u64 = 2000;

/// 단일 검사 대상 정보.
///
/// 사용자 입력 원문과 정규화된 호스트명, 포트 번호를 보존합니다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickTarget {
    /// 검사 대상 호스트 (도메인 또는 IP 리터럴).
    pub host: String,
    /// 검사 대상 TCP/UDP 포트 번호 (1..=65535).
    pub port: u16,
    /// 최초 입력된 원문 문자열.
    pub raw_input: String,
}

/// Network Quick Check 진단 옵션.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickOptions {
    /// TCP 연결 타임아웃 (ms 단위, 1..=60000).
    pub tcp_timeout_ms: u64,
    /// 동시 실행 작업 수 (1..=4).
    pub concurrency: usize,
    /// 사용자가 선택한 진단 기능 목록.
    pub selected_features: Vec<QuickFeature>,
}

impl Default for QuickOptions {
    fn default() -> Self {
        Self {
            tcp_timeout_ms: DEFAULT_TCP_TIMEOUT_MS,
            concurrency: DEFAULT_CONCURRENCY,
            selected_features: vec![QuickFeature::TcpConnect, QuickFeature::IcmpPing],
        }
    }
}

/// 계획된 단일 진단 대상 정보.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedTarget {
    /// 정규화된 대상 정보.
    pub target: QuickTarget,
    /// 해당 대상에 대해 실행할 진단 기능 목록.
    pub features: Vec<QuickFeature>,
    /// 해당 대상을 진단하기 위해 선행 OS 도메인 주소 해석이 필요한지 여부.
    pub requires_resolution: bool,
}

/// Network Quick Check 실행 계획.
///
/// 주의: 본 구조체는 순수 정적 진단 계획이며, 본 구조체의 생성이나 유지는
/// 실제 네트워크 패킷 송수신이나 소켓 생성, 시스템 변경을 일체 수반하지 않습니다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickPlan {
    /// 계획된 대상 목록.
    pub targets: Vec<PlannedTarget>,
    /// 적용할 TCP 타임아웃 (ms).
    pub tcp_timeout_ms: u64,
    /// 적용할 ICMP Ping 타임아웃 (ms, Ping 기능 미선택 시 None).
    pub icmp_timeout_ms: Option<u64>,
    /// 동시 실행 수.
    pub concurrency: usize,
    /// 계획 수립 중 발생한 제한 사항 및 안내 목록.
    pub limitations: Vec<String>,
}

/// 입력 검증 및 계획 수립 시 발생하는 오류.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputError {
    /// 발생 라인 번호 (다중 행 입력 시 1-based, 단일 pair 또는 전역 옵션 오류 시 0).
    pub line: usize,
    /// 오류 상세 설명 메시지.
    pub message: String,
}

/// 중복 제거를 위한 내부 대상 키.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum TargetHostKey {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TargetDedupKey {
    host_key: TargetHostKey,
    port: u16,
}

/// 포트 번호 문자열의 유효성을 검증하고 u16으로 변환합니다.
fn validate_port_str(port_str: &str) -> Result<u16, String> {
    if port_str.is_empty() {
        return Err("포트 번호가 비어 있습니다.".to_string());
    }
    if port_str.len() > 5 {
        return Err("포트 번호는 최대 5자리 숫자여야 합니다.".to_string());
    }
    if !port_str.chars().all(|c| c.is_ascii_digit()) {
        return Err(
            "포트 번호는 순수 ASCII 숫자여야 합니다 (부호, 공백, 소수점 불가).".to_string(),
        );
    }
    let port_num: u32 = port_str
        .parse()
        .map_err(|_| "포트 번호 숫자를 파싱할 수 없습니다.".to_string())?;
    if !(1..=65535).contains(&port_num) {
        return Err("포트 번호는 1..=65535 범위여야 합니다 (포트 0 금지).".to_string());
    }
    Ok(port_num as u16)
}

/// 지정되지 않은 주소, 브로드캐스트, 멀티캐스트 등 안전하지 않은 주소를 차단합니다.
fn check_safe_ip(ip: IpAddr) -> Result<(), String> {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() {
                return Err(
                    "지정되지 않은 IPv4 주소(0.0.0.0)는 진단 대상으로 사용할 수 없습니다."
                        .to_string(),
                );
            }
            if v4.is_broadcast() || v4.octets() == [255, 255, 255, 255] {
                return Err(
                    "브로드캐스트 IPv4 주소(255.255.255.255)는 진단 대상으로 사용할 수 없습니다."
                        .to_string(),
                );
            }
            if v4.is_multicast() {
                return Err(
                    "멀티캐스트 IPv4 주소(224.0.0.0/4)는 진단 대상으로 사용할 수 없습니다."
                        .to_string(),
                );
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() {
                return Err(
                    "지정되지 않은 IPv6 주소(::)는 진단 대상으로 사용할 수 없습니다.".to_string(),
                );
            }
            if v6.is_multicast() {
                return Err(
                    "멀티캐스트 IPv6 주소(ff00::/8)는 진단 대상으로 사용할 수 없습니다."
                        .to_string(),
                );
            }

            // IPv4-mapped IPv6 주소 (::ffff:a.b.c.d) 안전 검사
            let seg = v6.segments();
            if seg[0] == 0
                && seg[1] == 0
                && seg[2] == 0
                && seg[3] == 0
                && seg[4] == 0
                && seg[5] == 0xffff
            {
                let mapped_v4 = Ipv4Addr::new(
                    (seg[6] >> 8) as u8,
                    (seg[6] & 0xff) as u8,
                    (seg[7] >> 8) as u8,
                    (seg[7] & 0xff) as u8,
                );
                if mapped_v4.is_unspecified() {
                    return Err("IPv4 매핑된 IPv6의 미지정 주소(::ffff:0.0.0.0)는 진단 대상으로 사용할 수 없습니다.".to_string());
                }
                if mapped_v4.is_broadcast() || mapped_v4.octets() == [255, 255, 255, 255] {
                    return Err("IPv4 매핑된 IPv6의 브로드캐스트 주소(::ffff:255.255.255.255)는 진단 대상으로 사용할 수 없습니다.".to_string());
                }
                if mapped_v4.is_multicast() {
                    return Err("IPv4 매핑된 IPv6의 멀티캐스트 주소(::ffff:224.0.0.0/104)는 진단 대상으로 사용할 수 없습니다.".to_string());
                }
            }
        }
    }
    Ok(())
}

/// 호스트 문자열이 유효한 IP 리터럴 또는 도메인 이름인지 검증합니다.
fn validate_target_host_internal(host: &str) -> Result<(), String> {
    if host.is_empty() {
        return Err("호스트가 비어 있습니다.".to_string());
    }
    if !host.is_ascii() {
        return Err("호스트는 ASCII 문자만 허용됩니다.".to_string());
    }
    if host.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("호스트에 공백이나 제어 문자를 포함할 수 없습니다.".to_string());
    }

    if host.contains("://") {
        return Err("호스트에 URI 스킴(://)을 포함할 수 없습니다.".to_string());
    }
    if host.contains('/') || host.contains('\\') {
        return Err("호스트에 경로 또는 CIDR 표기(/, \\)를 포함할 수 없습니다.".to_string());
    }
    if host.contains('@') {
        // 비밀번호나 토큰 노출 방지를 위해 고정된 메시지 반환
        return Err("호스트에 사용자 자격증명 정보(@)를 포함할 수 없습니다.".to_string());
    }
    if host.contains('*') {
        return Err("호스트에 와일드카드(*)를 포함할 수 없습니다.".to_string());
    }
    if host.contains('%') {
        return Err("호스트에 IPv6 존 스코프(%)를 포함할 수 없습니다.".to_string());
    }
    if host.contains('?') || host.contains('#') || host.contains('&') {
        return Err(
            "호스트에 URL 쿼리 또는 프래그먼트 문자(?, #, &)를 포함할 수 없습니다.".to_string(),
        );
    }
    if host.contains(',') || host.contains(';') {
        return Err("호스트에 목록 구분자(,, ;)를 포함할 수 없습니다.".to_string());
    }
    if host.contains('[') || host.contains(']') {
        return Err("호스트에 허용되지 않는 대괄호('[', ']') 문자가 있습니다.".to_string());
    }

    // IP 리터럴 검사
    if let Ok(ip) = host.parse::<IpAddr>() {
        check_safe_ip(ip)?;
        return Ok(());
    }

    // IP 파싱 실패인데 콜론이 포함되어 있으면 잘못된 IPv6이거나 분리되지 않은 포트임
    if host.contains(':') {
        return Err(
            "유효하지 않은 IPv6 주소이거나 콜론(':') 표기가 올바르지 않습니다.".to_string(),
        );
    }

    // 도메인 이름 검증
    if host.len() > 253 {
        return Err("도메인 전체 길이는 최대 253자여야 합니다.".to_string());
    }
    if host.starts_with('.') {
        return Err("도메인은 마침표('.')로 시작할 수 없습니다.".to_string());
    }
    if host.ends_with('.') {
        return Err(
            "도메인 끝의 마침표('.')는 지원하지 않습니다 (FQDN 마지막 점 제외).".to_string(),
        );
    }

    let labels: Vec<&str> = host.split('.').collect();
    for label in &labels {
        if label.is_empty() {
            return Err("도메인에 빈 라벨이 존재합니다.".to_string());
        }
        if label.len() > 63 {
            return Err("도메인 라벨 길이는 최대 63자여야 합니다.".to_string());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("도메인 라벨은 하이픈('-')으로 시작하거나 끝날 수 없습니다.".to_string());
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err("도메인 라벨은 ASCII 영숫자와 하이픈('-')만 허용됩니다.".to_string());
        }
    }

    // 잘못된 숫자형 IPv4 방지 (도메인으로의 임의 수리 금지)
    let all_numeric = labels.iter().all(|l| l.chars().all(|c| c.is_ascii_digit()));
    let last_starts_with_digit = labels
        .last()
        .is_some_and(|l| l.starts_with(|c: char| c.is_ascii_digit()));

    if all_numeric || (labels.len() > 1 && last_starts_with_digit) {
        return Err("잘못된 숫자형 IPv4 주소는 유효한 도메인으로 허용되지 않습니다.".to_string());
    }

    Ok(())
}

/// 단일 호스트 및 포트 문자열 쌍을 파싱하고 검증합니다.
///
/// 입력 토큰을 수리하거나 트림하지 않으며, 원문 호스트 및 결합된 raw_input을 보존합니다.
/// 오류 발생 시 line은 0으로 설정됩니다.
pub fn parse_target_pair(host: &str, port: &str) -> Result<QuickTarget, Vec<InputError>> {
    let mut errors = Vec::new();

    if host.starts_with(char::is_whitespace) || host.ends_with(char::is_whitespace) {
        errors.push(InputError {
            line: 0,
            message: "호스트 앞뒤에 공백이 포함되어 있습니다 (원문 수리 금지).".to_string(),
        });
    }
    if port.starts_with(char::is_whitespace) || port.ends_with(char::is_whitespace) {
        errors.push(InputError {
            line: 0,
            message: "포트 앞뒤에 공백이 포함되어 있습니다 (원문 수리 금지).".to_string(),
        });
    }

    let parsed_port = match validate_port_str(port) {
        Ok(p) => Some(p),
        Err(e) => {
            errors.push(InputError {
                line: 0,
                message: e,
            });
            None
        }
    };

    if let Err(e) = validate_target_host_internal(host) {
        errors.push(InputError {
            line: 0,
            message: e,
        });
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    let port_num = parsed_port.expect("포트 유효성 검증 완료");
    let raw_input = format!("{host}:{port}");

    Ok(QuickTarget {
        host: host.to_string(),
        port: port_num,
        raw_input,
    })
}

/// 여러 행으로 구성된 다중 대상 문자열(`host:port` 또는 `[IPv6]:port`)을 파싱하고 검증합니다.
///
/// - 전체 입력은 최대 32768 바이트로 제한되며, 초과 시 즉각 오류를 반환합니다.
/// - 빈 행이나 공백만 있는 행은 건너뛰지만, 유효 토큰 앞뒤 공백은 거부합니다.
/// - bare IPv6:port 형태는 콜론 모호성으로 인해 거부되며 오직 `[IPv6]:port`만 허용됩니다.
/// - 도메인 대소문자 무시 및 IP 동치 키를 통해 중복을 제거하며, 첫 등장 원문과 순서를 유지합니다.
/// - 한 행이라도 오류가 있으면 전체가 원자적으로 실패합니다.
pub fn parse_target_list(input: &str) -> Result<Vec<QuickTarget>, Vec<InputError>> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(vec![InputError {
            line: 0,
            message: format!(
                "입력 크기({} 바이트)가 최대 허용 크기({MAX_INPUT_BYTES} 바이트)를 초과했습니다.",
                input.len()
            ),
        }]);
    }

    let mut errors = Vec::new();
    let mut raw_targets = Vec::new();

    for (idx, raw_line) in input.lines().enumerate() {
        let line_no = idx + 1;

        // 공백으로만 구성된 행은 건너뜀
        if raw_line.trim().is_empty() {
            continue;
        }

        // 유효 토큰 앞뒤 공백은 거부 (수리 금지)
        if raw_line.starts_with(char::is_whitespace) || raw_line.ends_with(char::is_whitespace) {
            errors.push(InputError {
                line: line_no,
                message: "입력 행의 앞뒤 공백은 허용되지 않습니다 (원문 수리 금지).".to_string(),
            });
            continue;
        }

        // 자격증명 정보 포함 거부 (시크릿 반사 방지)
        if raw_line.contains('@') {
            errors.push(InputError {
                line: line_no,
                message: "입력 행에 사용자 자격증명 정보(@)가 포함되어 있어 거부되었습니다."
                    .to_string(),
            });
            continue;
        }

        let (extracted_host, port_str) = if raw_line.starts_with('[') {
            let Some(closing_idx) = raw_line.find(']') else {
                errors.push(InputError {
                    line: line_no,
                    message: "IPv6 대괄호 주소의 닫는 대괄호(']')가 없습니다.".to_string(),
                });
                continue;
            };

            let after_bracket = &raw_line[closing_idx + 1..];
            let Some(p_str) = after_bracket.strip_prefix(':') else {
                errors.push(InputError {
                    line: line_no,
                    message: "IPv6 대괄호 주소 뒤에는 ':포트' 구분이 와야 합니다.".to_string(),
                });
                continue;
            };

            let inner_host = &raw_line[1..closing_idx];
            if inner_host.parse::<Ipv6Addr>().is_err() {
                errors.push(InputError {
                    line: line_no,
                    message: "대괄호('[...]') 안은 유효한 IPv6 주소여야 합니다.".to_string(),
                });
                continue;
            }

            (inner_host, p_str)
        } else {
            let colon_count = raw_line.chars().filter(|&c| c == ':').count();
            if colon_count == 0 {
                errors.push(InputError {
                    line: line_no,
                    message: "포트 구분자(':')가 누락되었습니다.".to_string(),
                });
                continue;
            }
            if colon_count > 1 {
                errors.push(InputError {
                    line: line_no,
                    message: "IPv6 주소는 포트 구분과의 모호성을 방지하기 위해 [IPv6]:port 형식이어야 합니다.".to_string(),
                });
                continue;
            }

            let (h, p) = raw_line.split_once(':').expect("콜론 개수 사전 검증 완료");
            (h, p)
        };

        let parsed_port = match validate_port_str(port_str) {
            Ok(p) => p,
            Err(e) => {
                errors.push(InputError {
                    line: line_no,
                    message: e,
                });
                continue;
            }
        };

        if let Err(e) = validate_target_host_internal(extracted_host) {
            errors.push(InputError {
                line: line_no,
                message: e,
            });
            continue;
        }

        raw_targets.push(QuickTarget {
            host: extracted_host.to_string(),
            port: parsed_port,
            raw_input: raw_line.to_string(),
        });
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    if raw_targets.is_empty() {
        return Err(vec![InputError {
            line: 0,
            message: "유효한 진단 대상이 입력되지 않았습니다.".to_string(),
        }]);
    }

    // 중복 제거: 도메인은 case-insensitive, IP는 numeric 동치 키 + 포트
    let mut seen = HashSet::new();
    let mut unique_targets = Vec::new();

    for target in raw_targets {
        let host_key = match target.host.parse::<IpAddr>() {
            Ok(ip) => TargetHostKey::Ip(ip),
            Err(_) => TargetHostKey::Domain(target.host.to_ascii_lowercase()),
        };
        let dedup_key = TargetDedupKey {
            host_key,
            port: target.port,
        };

        if seen.insert(dedup_key) {
            unique_targets.push(target);
        }
    }

    if unique_targets.len() > MAX_TARGETS {
        return Err(vec![InputError {
            line: 0,
            message: format!(
                "중복 제거 후 고유 대상 수({})가 최대 허용 한도({MAX_TARGETS})를 초과했습니다.",
                unique_targets.len()
            ),
        }]);
    }

    Ok(unique_targets)
}

/// 검증된 대상 목록과 옵션을 바탕으로 Network Quick Check 진단 계획을 수립합니다.
///
/// ## 주의
/// - 본 함수는 **실제 네트워크 연결, DNS 쿼리, 프로세스 실행을 일체 수행하지 않는 순수 계획 수립기**입니다.
/// - 수동 생성된 QuickTarget 및 QuickOptions의 필드 변조를 방지하기 위해 엄격한 재검증을 수행합니다.
/// - 도메인 대상의 경우 TCP/Ping/Traceroute/LocalNetwork 선택 시 필수 OS 주소 해석(`requires_resolution = true`)을 요구하며,
///   상세 DNS 기능만 단독 선택된 경우 자체 조회를 수행하므로 선행 해석을 요구하지 않습니다(`requires_resolution = false`).
/// - IP 리터럴 대상은 `requires_resolution = false`입니다.
/// - 선택된 기능 순서는 원본 선택 순서를 유지하며, 미선택 기능은 일체 자동 추가되지 않습니다.
/// - 원본 `targets` 및 `options`는 변경되지 않습니다.
pub fn build_quick_plan(
    targets: &[QuickTarget],
    options: &QuickOptions,
) -> Result<QuickPlan, Vec<InputError>> {
    let mut errors = Vec::new();

    // 1. 대상 목록 재검증
    if targets.is_empty() {
        errors.push(InputError {
            line: 0,
            message: "검사 대상 목록이 비어 있습니다.".to_string(),
        });
    }
    if targets.len() > MAX_TARGETS {
        errors.push(InputError {
            line: 0,
            message: format!(
                "대상 수({})가 최대 허용 한도({MAX_TARGETS})를 초과했습니다.",
                targets.len()
            ),
        });
    }

    for (idx, target) in targets.iter().enumerate() {
        let target_idx = idx + 1;
        if !(1..=65535).contains(&target.port) {
            errors.push(InputError {
                line: 0,
                message: format!(
                    "대상 #{target_idx}의 포트 번호({})가 유효 범위(1..=65535)를 벗어났습니다.",
                    target.port
                ),
            });
        }
        if let Err(e) = validate_target_host_internal(&target.host) {
            errors.push(InputError {
                line: 0,
                message: format!("대상 #{target_idx}의 호스트가 유효하지 않습니다: {e}"),
            });
        }
    }

    // 2. 옵션 재검증
    if !(MIN_TCP_TIMEOUT_MS..=MAX_TCP_TIMEOUT_MS).contains(&options.tcp_timeout_ms) {
        errors.push(InputError {
            line: 0,
            message: format!(
                "TCP 타임아웃({}ms)은 {MIN_TCP_TIMEOUT_MS}..={MAX_TCP_TIMEOUT_MS}ms 범위여야 합니다.",
                options.tcp_timeout_ms
            ),
        });
    }
    if !(1..=MAX_CONCURRENCY).contains(&options.concurrency) {
        errors.push(InputError {
            line: 0,
            message: format!(
                "동시 검사 수({})는 1..={MAX_CONCURRENCY} 범위여야 합니다.",
                options.concurrency
            ),
        });
    }

    // 선택된 기능 중복 검증
    let mut seen_features = HashSet::new();
    for feature in &options.selected_features {
        if !seen_features.insert(feature.as_str()) {
            errors.push(InputError {
                line: 0,
                message: format!("선택된 진단 기능에 중복이 존재합니다: {}", feature.as_str()),
            });
            break;
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    // 3. ICMP 타임아웃 및 제한 사항 계산
    let mut limitations = Vec::new();
    let icmp_timeout_ms = if options.selected_features.contains(&QuickFeature::IcmpPing) {
        let clamped = std::cmp::min(options.tcp_timeout_ms, MAX_ICMP_TIMEOUT_MS);
        if options.tcp_timeout_ms > MAX_ICMP_TIMEOUT_MS {
            limitations.push(format!(
                "ICMP(Ping) 타임아웃은 최대 {}ms로 제한되어 적용됩니다 (요청된 TCP 타임아웃: {}ms).",
                MAX_ICMP_TIMEOUT_MS, options.tcp_timeout_ms
            ));
        }
        Some(clamped)
    } else {
        None
    };

    // 4. 대상별 계획 수립
    let mut planned_targets = Vec::with_capacity(targets.len());
    for target in targets {
        let is_ip = target.host.parse::<IpAddr>().is_ok();
        let requires_resolution = if is_ip {
            false
        } else {
            // 도메인 대상: TCP, Ping, Traceroute, LocalNetwork 중 하나라도 선택 시 선행 해석 필요
            options.selected_features.iter().any(|f| match f {
                QuickFeature::TcpConnect
                | QuickFeature::IcmpPing
                | QuickFeature::IcmpTraceroute
                | QuickFeature::LocalNetwork => true,
                QuickFeature::DnsLookup => false,
            })
        };

        planned_targets.push(PlannedTarget {
            target: target.clone(),
            features: options.selected_features.clone(),
            requires_resolution,
        });
    }

    Ok(QuickPlan {
        targets: planned_targets,
        tcp_timeout_ms: options.tcp_timeout_ms,
        icmp_timeout_ms,
        concurrency: options.concurrency,
        limitations,
    })
}
