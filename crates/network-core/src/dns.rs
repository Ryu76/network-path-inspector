//! Network Quick Check(Part B) 전용 DNS 진단 어댑터 모듈.
//!
//! 기존 OS resolver(`dns_engine` / `network-resolver`)의 격리 해석 결과를
//! Quick Check 단일 측정 계약 DTO(`QuickResult`)로 변환하고 실행하는 어댑터를 제공합니다.
//!
//! ## 핵심 안전 및 측정 원칙
//! - **기존 OS resolver 단일 진실 공급원 재사용**: 부모가 준비한 `dns_engine`의
//!   `resolve_isolated` 함수만 사용하며, 네이티브 I/O 재구현, 소켓 직접 바인딩,
//!   `ToSocketAddrs` 또는 타 리졸버 호출을 복제하지 않습니다.
//! - **계약 동결**: 모듈의 public API는 `dns_to_quick_result`와 `resolve_for_quick` 2개로 동결합니다.
//! - **측정 사실과 추론의 엄격한 분리**:
//!   - OS resolver(getaddrinfo 계열)가 반환한 IP 목록일 뿐이며, DNS 서버 주소, RR, TTL,
//!     패킷 교환, NXDOMAIN 원인을 관찰했다고 추정하거나 단정하지 않습니다.
//!   - 실제 연결 대상 IP 선택은 후속 runner(TCP connect 등)의 몫이므로 lookup 결과의 `resolved_ip`는 항상 `null`(`None`)로 유지합니다.
//! - **데이터 무결성 및 Fail-Closed**:
//!   - host 및 port 불일치 시 `Err`를 반환합니다 (raw trim 및 임의 수리 금지).
//!   - measurement.host 및 ctx.target_host는 raw 그대로 `dns_engine::validate_host`로 검증합니다.
//!   - 불량 호스트·자격증명 거부 시 오류 메시지에 민감 원문이 반사되지 않도록 정적 사유를 사용합니다.
//!   - 주소 목록(`addresses`)의 어떤 원소라도 잘못된 형식, 비정규 표기, 포트 불일치, 중복이 존재하면 수리하지 않고 fail-closed `Err` 처리합니다.
//!   - `RESOLVED` outcome은 nonempty addresses와 error_code/error_message가 모두 None이어야 합니다.
//!   - 비성공 outcome(`DNS_ERROR`, `TIMED_OUT`, `CANCELLED`, `LOCAL_ERROR`)은 addresses가 비어 있어야 합니다.
//!   - `DNS_ERROR`는 실제 오류 메시지 근거를 요구하며 code 없는 오류는 허용합니다.
//!   - 검증 host가 IPv4/IPv6 리터럴이고 `RESOLVED`면 addresses가 정확히 하나이며 SocketAddr.ip와 literal이 수치적으로 동일해야 합니다.
//!   - raw DTO 및 전체 주소(최대 32개)를 `details.raw_measurement`에 온전히 보존합니다.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use crate::dns_engine::{
    self, DnsMeasurement, HostKind, MAX_ADDRESSES, OUTCOME_CANCELLED, OUTCOME_DNS_ERROR,
    OUTCOME_LOCAL_ERROR, OUTCOME_RESOLVED, OUTCOME_TIMED_OUT,
};
use crate::quick::{
    EvidenceLevel, QUICK_PRODUCT_NAME, QUICK_SCHEMA_VERSION, QuickContext, QuickFeature,
    QuickResult, QuickStatus, validate_quick_result, validate_rfc3339_timestamp,
};

/// 중복 항목 없이 limitations 목록에 안내 문구를 추가하는 헬퍼 함수.
fn push_unique_limitation(limitations: &mut Vec<String>, msg: String) {
    if !limitations.iter().any(|existing| existing == &msg) {
        limitations.push(msg);
    }
}

/// 컨텍스트의 기본 메타데이터 유효성을 검사합니다.
fn validate_context_metadata(ctx: &QuickContext, errors: &mut Vec<String>) {
    if ctx.session_id.trim().is_empty() {
        errors.push("session_id는 비어있을 수 없습니다.".to_string());
    }
    if ctx.target_host.trim().is_empty() {
        errors.push("target_host는 비어있을 수 없습니다.".to_string());
    }
    if ctx.target_port == 0 {
        errors.push("target_port는 0일 수 없습니다 (유효 범위: 1..=65535).".to_string());
    }
    if let Some(ts) = &ctx.timestamp_iso8601 {
        if ts.trim().is_empty() {
            errors.push("timestamp_iso8601는 비어있을 수 없습니다.".to_string());
        } else if let Err(err) = validate_rfc3339_timestamp(ts) {
            errors.push(format!("timestamp_iso8601 형식 오류: {err}"));
        }
    }
    if let Some(sh) = &ctx.source_host
        && sh.trim().is_empty()
    {
        errors.push("source_host는 비어있을 수 없습니다.".to_string());
    }
}

/// DNS 측정 결과의 주소 목록 유효성을 엄격하게 검증합니다.
///
/// - trim 금지: 공백이 포함된 주소는 거부합니다.
/// - 각 주소는 정규 SocketAddr 표기여야 합니다.
/// - 주소의 포트는 측정 대상 포트와 일치해야 합니다.
/// - 중복 주소는 거부합니다.
/// - 최대 주소 개수(32개)를 초과할 수 없습니다.
/// - 오류 메시지에는 원문 주소 문자열을 반사하지 않고 주소 순번(인덱스)을 사용합니다.
fn validate_measurement_addresses(
    addresses: &[String],
    expected_port: u16,
    errors: &mut Vec<String>,
) {
    if addresses.len() > MAX_ADDRESSES {
        errors.push(format!(
            "주소 개수({})가 최대 상한({MAX_ADDRESSES})을 초과했습니다.",
            addresses.len()
        ));
        return;
    }
    let mut seen: Vec<SocketAddr> = Vec::with_capacity(addresses.len());
    for (index, addr_str) in addresses.iter().enumerate() {
        if addr_str.trim().is_empty() || addr_str.trim() != addr_str.as_str() {
            errors.push(format!(
                "주소[{index}]에 선행/후행 공백이 포함되어 있거나 비어 있습니다."
            ));
            return;
        }
        match addr_str.parse::<SocketAddr>() {
            Ok(sock_addr) => {
                if sock_addr.to_string() != *addr_str {
                    errors.push(format!("주소[{index}]가 정규 SocketAddr 표기가 아닙니다."));
                    return;
                }
                if sock_addr.port() != expected_port {
                    errors.push(format!(
                        "주소[{index}] 포트({})가 측정 대상 포트({})와 일치하지 않습니다.",
                        sock_addr.port(),
                        expected_port
                    ));
                    return;
                }
                if seen.contains(&sock_addr) {
                    errors.push(format!(
                        "주소[{index}] 목록에 중복된 주소가 포함되어 있습니다."
                    ));
                    return;
                }
                seen.push(sock_addr);
            }
            Err(_) => {
                errors.push(format!(
                    "주소[{index}]가 유효한 SocketAddr 형식이 아닙니다."
                ));
                return;
            }
        }
    }
}

/// 기존 DNS 해석 엔진의 측정 결과(`DnsMeasurement`)를 Quick Check 계약 DTO(`QuickResult`)로 변환합니다.
///
/// ## 규칙 및 불변식
/// 1. **컨텍스트 메타데이터 검증**: 세션 ID, 대상 호스트, 포트(1..=65535), 타임스탬프(RFC3339) 검증.
/// 2. **호스트 및 포트 불일치 검증**:
///    - `measurement.host != ctx.target_host` -> `Err` (raw 비교, 민감 정보 반사 방지 고정 문구).
///    - `measurement.port != ctx.target_port` -> `Err`.
/// 3. **호스트 유효성 검증 (`validate_host`)**:
///    - `measurement.host` 및 `ctx.target_host`를 raw 그대로 검증합니다.
///    - 잘못된 URI/경로/자격증명/공백은 `Err`로 거부하며 원문 값을 반사하지 않습니다.
/// 4. **주소 목록 무결성 검증**:
///    - 주소 목록의 어떤 원소라도 잘못되었거나, 포트 불일치, 중복, 비정규 표기가 있으면 fail-closed로 `Err` 반환.
/// 5. **outcome 의미 및 불변식 검증**:
///    - `RESOLVED`: nonempty addresses + error_code/error_message 모두 None이어야 함.
///    - `DNS_ERROR`: addresses는 비어 있어야 하며, 실제 오류 메시지 근거를 요구함 (code 없는 오류는 허용, 빈 메시지/코드만 있는 경우 거부).
///    - `TIMED_OUT`, `CANCELLED`, `LOCAL_ERROR`: addresses는 비어 있어야 함.
/// 6. **IP 리터럴 일관성 검증**:
///    - 호스트가 IPv4/IPv6 리터럴이고 `RESOLVED`인 경우 addresses가 정확히 하나여야 하며 `SocketAddr.ip()`와 literal이 수치적으로 동일해야 함.
/// 7. **상태 및 근거 수준 매핑**:
///    - `RESOLVED` -> `(QuickStatus::PASS, EvidenceLevel::OBSERVED)`
///    - `DNS_ERROR` -> `(QuickStatus::FAIL, EvidenceLevel::OBSERVED)`
///    - `TIMED_OUT` -> `(QuickStatus::FAIL, EvidenceLevel::OBSERVED)`
///    - `CANCELLED` -> `(QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN)`
///    - `LOCAL_ERROR` -> `(QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN)`
///    - 기타 미지 outcome -> `(QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN)`
/// 8. **미접속 resolved_ip 보존**: 실제 연결 대상 선택 전이므로 `resolved_ip`는 항상 `None`(`null`)으로 유지.
/// 9. **details 보존**: `outcome`, `limitations`, `raw_measurement` 3개 필드 구성.
pub fn dns_to_quick_result(
    ctx: &QuickContext,
    measurement: &DnsMeasurement,
) -> Result<QuickResult, Vec<String>> {
    let mut errors = Vec::new();

    // 1. 컨텍스트 메타데이터 기본 검증
    validate_context_metadata(ctx, &mut errors);

    // 2. 호스트 및 포트 불일치 검사 (raw 비교, 원문 반사 금지)
    if measurement.host != ctx.target_host {
        errors.push(
            "측정 대상 호스트가 컨텍스트 대상 호스트와 일치하지 않습니다 (호스트 교차 오염 방지)."
                .to_string(),
        );
    }
    if measurement.port != ctx.target_port {
        errors.push(format!(
            "측정 대상 포트({})가 컨텍스트 대상 포트({})와 일치하지 않습니다 (포트 교차 오염 방지).",
            measurement.port, ctx.target_port
        ));
    }

    // 3. raw 호스트 엄격 검증 (validate_host를 raw 그대로 적용, 원문 반사 방지 고정 문구)
    let validated_host_kind = match dns_engine::validate_host(&measurement.host) {
        Ok(kind) => Some(kind),
        Err(reason) => {
            errors.push(format!("측정 대상 호스트 검증 실패: {reason}"));
            None
        }
    };
    if measurement.host != ctx.target_host
        && let Err(reason) = dns_engine::validate_host(&ctx.target_host)
    {
        errors.push(format!("컨텍스트 대상 호스트 검증 실패: {reason}"));
    }

    // 4. 주소 목록 유효성 검사 (불량 주소 수리 금지, fail-closed)
    validate_measurement_addresses(&measurement.addresses, measurement.port, &mut errors);

    // 5. outcome별 의미 및 불변식 검증
    match measurement.outcome.as_str() {
        OUTCOME_RESOLVED => {
            if measurement.addresses.is_empty() {
                errors.push(
                    "RESOLVED outcome이지만 주소 목록이 비어 있습니다 (빈 주소 정상 PASS 금지)."
                        .to_string(),
                );
            }
            if measurement.error_code.is_some() || measurement.error_message.is_some() {
                errors.push(
                    "RESOLVED outcome에 error_code 또는 error_message가 존재할 수 없습니다."
                        .to_string(),
                );
            }
            // IP 리터럴 호스트 검증: 단일 주소 및 수치적 동일성
            if let Some(kind) = validated_host_kind {
                match kind {
                    HostKind::Ipv4(ip) => {
                        if measurement.addresses.len() != 1 {
                            errors.push(
                                "IP 리터럴 호스트의 RESOLVED 결과는 정확히 1개의 주소만 가질 수 있습니다."
                                    .to_string(),
                            );
                        } else if let Ok(sock) = measurement.addresses[0].parse::<SocketAddr>()
                            && sock.ip() != IpAddr::V4(ip)
                        {
                            errors.push(
                                "IP 리터럴 호스트와 주소 IP가 수치적으로 일치하지 않습니다 (외부 IP 귀속 거부)."
                                    .to_string(),
                            );
                        }
                    }
                    HostKind::Ipv6(ip) => {
                        if measurement.addresses.len() != 1 {
                            errors.push(
                                "IP 리터럴 호스트의 RESOLVED 결과는 정확히 1개의 주소만 가질 수 있습니다."
                                    .to_string(),
                            );
                        } else if let Ok(sock) = measurement.addresses[0].parse::<SocketAddr>()
                            && sock.ip() != IpAddr::V6(ip)
                        {
                            errors.push(
                                "IP 리터럴 호스트와 주소 IP가 수치적으로 일치하지 않습니다 (외부 IP 귀속 거부)."
                                    .to_string(),
                            );
                        }
                    }
                    HostKind::DomainName => {}
                }
            }
        }
        OUTCOME_DNS_ERROR => {
            if !measurement.addresses.is_empty() {
                errors.push(
                    "DNS_ERROR outcome에 주소 목록이 존재할 수 없습니다 (오류와 주소 동시 존재 거부)."
                        .to_string(),
                );
            }
            match &measurement.error_message {
                Some(msg) if !msg.trim().is_empty() => {}
                Some(_) => {
                    errors.push(
                        "DNS_ERROR outcome의 오류 메시지가 비어 있습니다 (빈 메시지 거부)."
                            .to_string(),
                    );
                }
                None => {
                    errors.push(
                        "DNS_ERROR outcome에 오류 메시지가 없습니다 (오류 코드만 있고 메시지가 없음 거부)."
                            .to_string(),
                    );
                }
            }
        }
        OUTCOME_TIMED_OUT | OUTCOME_CANCELLED | OUTCOME_LOCAL_ERROR
            if !measurement.addresses.is_empty() =>
        {
            errors.push(format!(
                "{} outcome에 주소 목록이 존재할 수 없습니다 (비성공 결과 주소 거부).",
                measurement.outcome
            ));
        }
        _ => {
            // 미지 outcome: UNKNOWN/UNKNOWN 정책 보존
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    // 6. Quick 상태 및 근거 수준 매핑
    let (status, evidence_level, is_unknown_outcome) = match measurement.outcome.as_str() {
        OUTCOME_RESOLVED => (QuickStatus::PASS, EvidenceLevel::OBSERVED, false),
        OUTCOME_DNS_ERROR => (QuickStatus::FAIL, EvidenceLevel::OBSERVED, false),
        OUTCOME_TIMED_OUT => (QuickStatus::FAIL, EvidenceLevel::OBSERVED, false),
        OUTCOME_CANCELLED => (QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN, false),
        OUTCOME_LOCAL_ERROR => (QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN, false),
        _ => (QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN, true),
    };

    let mut limitations = measurement.limitations.clone();
    push_unique_limitation(
        &mut limitations,
        "도메인 결과는 helper 프로세스의 OS 해석기(getaddrinfo 계열) 반환 주소이며 DNS 서버·RR·TTL·패킷·정책은 관찰하지 않음".to_string(),
    );
    push_unique_limitation(
        &mut limitations,
        "실제 접속 대상 IP 선택은 후속 연결 단계에서 수행되므로 DNS lookup 결과의 resolved_ip는 null로 유지됩니다.".to_string(),
    );

    if is_unknown_outcome {
        push_unique_limitation(
            &mut limitations,
            format!(
                "알 수 없는 DNS 결과 상태('{}')로 인해 판정을 UNKNOWN/UNKNOWN으로 분류합니다.",
                measurement.outcome
            ),
        );
    }

    let raw_measurement_val = serde_json::to_value(measurement)
        .map_err(|err| vec![format!("DnsMeasurement 직렬화 오류: {err}")])?;

    let details = serde_json::json!({
        "outcome": measurement.outcome,
        "limitations": limitations,
        "raw_measurement": raw_measurement_val,
    });

    let res = QuickResult {
        schema_version: QUICK_SCHEMA_VERSION.to_string(),
        product: QUICK_PRODUCT_NAME.to_string(),
        session_id: ctx.session_id.clone(),
        timestamp_iso8601: ctx.timestamp_iso8601.clone(),
        source_host: ctx.source_host.clone(),
        target_host: ctx.target_host.clone(),
        resolved_ip: None,
        target_port: ctx.target_port,
        feature: QuickFeature::DnsLookup,
        status,
        elapsed_ms: Some(measurement.elapsed_ms),
        os_error_code: measurement.error_code,
        details,
        evidence_level,
    };

    validate_quick_result(&res)?;
    Ok(res)
}

/// Quick Check 컨텍스트와 helper 실행파일을 사용하여 격리된 DNS 해석을 실행하고 `QuickResult`를 반환합니다.
///
/// helper 실행 전 대상 호스트를 순수하게 사전 검증하며, 기존 `dns_engine::resolve_isolated` 함수를 그대로 호출합니다.
pub fn resolve_for_quick(
    ctx: &QuickContext,
    helper_executable: &Path,
    timeout: Duration,
    cancel: Arc<AtomicBool>,
) -> Result<QuickResult, Vec<String>> {
    let mut errors = Vec::new();
    validate_context_metadata(ctx, &mut errors);
    if let Err(reason) = dns_engine::validate_host(&ctx.target_host) {
        errors.push(format!("대상 호스트 검증 실패: {reason}"));
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    let measurement = dns_engine::resolve_isolated(
        helper_executable,
        &ctx.target_host,
        ctx.target_port,
        timeout,
        cancel,
    );

    dns_to_quick_result(ctx, &measurement)
}
