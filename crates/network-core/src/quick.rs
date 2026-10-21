//! Network Quick Check 전용 DTO 및 어댑터 모듈.
//!
//! 이 모듈은 Part B(Network Quick Check)의 계약(qg1-contract.json)에 정의된
//! 단일 진단 측정 결과 DTO(`QuickResult`), 컨텍스트(`QuickContext`),
//! 그리고 공통 프로브 결과(`TcpMeasurement`)를 Quick 결과로 변환하는 어댑터를 제공합니다.

use std::net::SocketAddr;

use npi_probes::tcp::TcpMeasurement;
use serde::{Deserialize, Serialize};

/// Quick Check 고정 스키마 버전 ("1.0").
pub const QUICK_SCHEMA_VERSION: &str = "1.0";

/// Quick Check 고정 제품 식별자 ("network-quick-check").
pub const QUICK_PRODUCT_NAME: &str = "network-quick-check";

/// 계약에 정의된 허용 상태 목록.
pub const STATUS_VALUES: [&str; 5] = ["PASS", "FAIL", "WARN", "SKIPPED", "UNKNOWN"];
pub const STATUS_VALUES_COUNT: usize = 5;

/// 계약에 정의된 허용 근거 수준 목록.
pub const EVIDENCE_VALUES: [&str; 3] = ["OBSERVED", "INFERRED", "UNKNOWN"];
pub const EVIDENCE_VALUES_COUNT: usize = 3;

/// 계약에 정의된 허용 기능 식별자 목록.
pub const FEATURE_VALUES: [&str; 5] = [
    "tcp_connect",
    "icmp_ping",
    "icmp_traceroute",
    "dns_lookup",
    "local_network",
];
pub const FEATURE_VALUES_COUNT: usize = 5;

/// Quick Check 진단 결과 상태 열거형.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum QuickStatus {
    PASS,
    FAIL,
    WARN,
    SKIPPED,
    UNKNOWN,
}

impl QuickStatus {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::PASS => "PASS",
            Self::FAIL => "FAIL",
            Self::WARN => "WARN",
            Self::SKIPPED => "SKIPPED",
            Self::UNKNOWN => "UNKNOWN",
        }
    }
}

/// Quick Check 진단 근거 수준 열거형.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum EvidenceLevel {
    OBSERVED,
    INFERRED,
    UNKNOWN,
}

impl EvidenceLevel {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::OBSERVED => "OBSERVED",
            Self::INFERRED => "INFERRED",
            Self::UNKNOWN => "UNKNOWN",
        }
    }
}

/// Quick Check 지원 기능 식별자 열거형.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuickFeature {
    TcpConnect,
    IcmpPing,
    IcmpTraceroute,
    DnsLookup,
    LocalNetwork,
}

impl QuickFeature {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::TcpConnect => "tcp_connect",
            Self::IcmpPing => "icmp_ping",
            Self::IcmpTraceroute => "icmp_traceroute",
            Self::DnsLookup => "dns_lookup",
            Self::LocalNetwork => "local_network",
        }
    }
}

/// Quick Check 진단 실행 컨텍스트.
///
/// 사용자가 입력한 원래의 대상 호스트명(`target_host`)과 포트, 세션 정보 등을 보존합니다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuickContext {
    pub session_id: String,
    pub timestamp_iso8601: Option<String>,
    pub source_host: Option<String>,
    pub target_host: String,
    pub target_port: u16,
}

/// Quick Check 단일 측정 결과 계약 DTO (14개 필드 고정).
///
/// - `schema_version`: 고정 "1.0"
/// - `product`: 고정 "network-quick-check"
/// - 모든 필드는 필수 키로 출력되며, 미확인 nullable 필드는 `null`로 유지됩니다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuickResult {
    pub schema_version: String,
    pub product: String,
    pub session_id: String,
    pub timestamp_iso8601: Option<String>,
    pub source_host: Option<String>,
    pub target_host: String,
    pub resolved_ip: Option<String>,
    pub target_port: u16,
    pub feature: QuickFeature,
    pub status: QuickStatus,
    pub elapsed_ms: Option<u64>,
    pub os_error_code: Option<i32>,
    pub details: serde_json::Value,
    pub evidence_level: EvidenceLevel,
}

/// 공통 TCP 프로브 측정 결과(`TcpMeasurement`)를 Quick Check 계약 결과(`QuickResult`)로 변환하는 어댑터 함수.
///
/// ## 규칙 및 불변식
/// 1. 컨텍스트 검증: 포트 0, 빈 세션 ID, 빈 대상 호스트 등은 거부합니다.
/// 2. 포트 일관성 및 교차 오염 방지: `measurement.target`의 SocketAddr 파싱 성공 시
///    컨텍스트 대상 포트(`ctx.target_port`)와 일치해야 하며, 불일치 시 즉시 거부합니다.
///    파싱에 성공하면 해당 피어 IP를 `resolved_ip`로 유도합니다.
/// 3. 임의 해석 금지: `measurement.target` 파싱 실패 시 `resolved_ip`는 미확인(`None` -> `null`)으로 유지하며
///    임의의 네트워크 조회나 DNS 해석 결과를 발명하지 않습니다.
/// 4. TCP 상태 매핑 (frozen contract 준수):
///    - `CONNECTED` -> `PASS`, `OBSERVED`
///    - `REFUSED` / `RESET` / `TIMED_OUT` / `UNREACHABLE` / `DNS_ERROR` -> `FAIL`, `OBSERVED`
///    - `LOCAL_ERROR` -> `UNKNOWN`, `OBSERVED` (로컬 OS 관찰 결과이나 원격 판정 미확정)
///    - `CANCELLED` -> `UNKNOWN`, `UNKNOWN` (FAIL로 위장 금지!)
///    - 알 수 없는 outcome -> `UNKNOWN`, `UNKNOWN` (절대 PASS로 분류 금지)
/// 5. details 보존: `outcome`, `limitations`, `raw_measurement`를 원형 그대로 보존합니다.
pub fn tcp_to_quick_result(
    ctx: &QuickContext,
    measurement: &TcpMeasurement,
) -> Result<QuickResult, Vec<String>> {
    let mut errors = Vec::new();

    if ctx.session_id.trim().is_empty() {
        errors.push("session_id는 비어있을 수 없습니다.".to_string());
    }
    if ctx.target_host.trim().is_empty() {
        errors.push("target_host는 비어있을 수 없습니다.".to_string());
    }
    if ctx.target_port == 0 {
        errors.push("target_port는 0일 수 없습니다 (유효 범위: 1..=65535).".to_string());
    }
    if let Some(ref ts) = ctx.timestamp_iso8601 {
        if ts.trim().is_empty() {
            errors.push("timestamp_iso8601는 비어있을 수 없습니다.".to_string());
        }
    }
    if let Some(ref sh) = ctx.source_host {
        if sh.trim().is_empty() {
            errors.push("source_host는 비어있을 수 없습니다.".to_string());
        }
    }

    let mut resolved_ip: Option<String> = None;
    if let Ok(socket_addr) = measurement.target.parse::<SocketAddr>() {
        if socket_addr.port() != ctx.target_port {
            errors.push(format!(
                "측정 대상 포트({})가 컨텍스트 대상 포트({})와 일치하지 않습니다 (포트 교차 오염 방지).",
                socket_addr.port(),
                ctx.target_port
            ));
        } else {
            resolved_ip = Some(socket_addr.ip().to_string());
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    let (status, evidence_level) = match measurement.outcome.as_str() {
        "CONNECTED" => (QuickStatus::PASS, EvidenceLevel::OBSERVED),
        "REFUSED" => (QuickStatus::FAIL, EvidenceLevel::OBSERVED),
        "RESET" => (QuickStatus::FAIL, EvidenceLevel::OBSERVED),
        "TIMED_OUT" => (QuickStatus::FAIL, EvidenceLevel::OBSERVED),
        "UNREACHABLE" => (QuickStatus::FAIL, EvidenceLevel::OBSERVED),
        "DNS_ERROR" => (QuickStatus::FAIL, EvidenceLevel::OBSERVED),
        "LOCAL_ERROR" => (QuickStatus::UNKNOWN, EvidenceLevel::OBSERVED),
        "CANCELLED" => (QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN),
        _ => (QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN),
    };

    let raw_measurement_val = serde_json::to_value(measurement)
        .map_err(|err| vec![format!("TcpMeasurement 직렬화 오류: {err}")])?;

    let details = serde_json::json!({
        "outcome": measurement.outcome,
        "limitations": measurement.limitations,
        "raw_measurement": raw_measurement_val,
    });

    Ok(QuickResult {
        schema_version: QUICK_SCHEMA_VERSION.to_string(),
        product: QUICK_PRODUCT_NAME.to_string(),
        session_id: ctx.session_id.clone(),
        timestamp_iso8601: ctx.timestamp_iso8601.clone(),
        source_host: ctx.source_host.clone(),
        target_host: ctx.target_host.clone(),
        resolved_ip,
        target_port: ctx.target_port,
        feature: QuickFeature::TcpConnect,
        status,
        elapsed_ms: Some(measurement.elapsed_ms),
        os_error_code: measurement.error_code,
        details,
        evidence_level,
    })
}
