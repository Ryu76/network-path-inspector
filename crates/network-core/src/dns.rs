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
//!   - 주소 목록(`addresses`)의 어떤 원소라도 잘못된 형식, 비정규 표기, 포트 불일치, 중복이 존재하면 수리하지 않고 fail-closed `Err` 처리합니다.
//!   - `RESOLVED` outcome인데 주소 목록이 비어있는 경우 정상 PASS로 분류하지 않고 `Err`로 거부합니다.
//!   - raw DTO 및 전체 주소(최대 32개)를 `details.raw_measurement`에 온전히 보존합니다.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use crate::dns_engine::{
    self, DnsMeasurement, MAX_ADDRESSES, OUTCOME_CANCELLED, OUTCOME_DNS_ERROR, OUTCOME_LOCAL_ERROR,
    OUTCOME_RESOLVED, OUTCOME_TIMED_OUT,
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
    for addr_str in addresses {
        if addr_str.trim().is_empty() || addr_str.trim() != addr_str.as_str() {
            errors.push(format!(
                "주소에 선행/후행 공백이 포함되어 있거나 비어 있습니다: '{addr_str}'"
            ));
            return;
        }
        match addr_str.parse::<SocketAddr>() {
            Ok(sock_addr) => {
                if sock_addr.to_string() != *addr_str {
                    errors.push(format!(
                        "주소가 정규 SocketAddr 표기가 아닙니다: '{addr_str}'"
                    ));
                    return;
                }
                if sock_addr.port() != expected_port {
                    errors.push(format!(
                        "주소 포트({})가 측정 대상 포트({})와 일치하지 않습니다: '{addr_str}'",
                        sock_addr.port(),
                        expected_port
                    ));
                    return;
                }
                if seen.contains(&sock_addr) {
                    errors.push(format!(
                        "주소 목록에 중복된 주소가 포함되어 있습니다: '{addr_str}'"
                    ));
                    return;
                }
                seen.push(sock_addr);
            }
            Err(_) => {
                errors.push(format!(
                    "주소가 유효한 SocketAddr 형식이 아닙니다: '{addr_str}'"
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
///    - `measurement.host != ctx.target_host` -> `Err` (raw trim 금지).
///    - `measurement.port != ctx.target_port` -> `Err`.
/// 3. **주소 목록 무결성 검증**:
///    - 주소 목록의 어떤 원소라도 잘못되었거나, 포트 불일치, 중복, 비정규 표기가 있으면 fail-closed로 `Err` 반환.
///    - `RESOLVED` 결과인데 주소 목록이 비어있으면(`addresses.is_empty()`) 정상 PASS를 금지하고 `Err` 반환.
/// 4. **상태 및 근거 수준 매핑**:
///    - `RESOLVED` -> `(QuickStatus::PASS, EvidenceLevel::OBSERVED)`
///    - `DNS_ERROR` -> `(QuickStatus::FAIL, EvidenceLevel::OBSERVED)`
///    - `TIMED_OUT` -> `(QuickStatus::FAIL, EvidenceLevel::OBSERVED)`
///    - `CANCELLED` -> `(QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN)`
///    - `LOCAL_ERROR` -> `(QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN)`
///    - 기타 미지 outcome -> `(QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN)`
/// 5. **미접속 resolved_ip 보존**: 실제 연결 대상 선택 전이므로 `resolved_ip`는 항상 `None`(`null`)으로 유지.
/// 6. **details 보존**: `outcome`, `limitations`, `raw_measurement` 3개 필드 구성.
pub fn dns_to_quick_result(
    ctx: &QuickContext,
    measurement: &DnsMeasurement,
) -> Result<QuickResult, Vec<String>> {
    let mut errors = Vec::new();

    validate_context_metadata(ctx, &mut errors);

    // 대상 호스트 및 포트 불일치 검사 (raw 비교, trim 금지)
    if measurement.host != ctx.target_host {
        errors.push(format!(
            "측정 대상 호스트('{}')가 컨텍스트 대상 호스트('{}')와 일치하지 않습니다 (호스트 교차 오염 방지).",
            measurement.host, ctx.target_host
        ));
    }
    if measurement.port != ctx.target_port {
        errors.push(format!(
            "측정 대상 포트({})가 컨텍스트 대상 포트({})와 일치하지 않습니다 (포트 교차 오염 방지).",
            measurement.port, ctx.target_port
        ));
    }

    // 주소 목록 유효성 검사 (불량 주소 수리 금지, fail-closed)
    validate_measurement_addresses(&measurement.addresses, measurement.port, &mut errors);

    // RESOLVED 결과에서 주소가 비어있는 비정상 성공 거부
    if measurement.outcome == OUTCOME_RESOLVED && measurement.addresses.is_empty() {
        errors.push(
            "RESOLVED outcome이지만 주소 목록이 비어 있습니다 (빈 주소 정상 PASS 금지)."
                .to_string(),
        );
    }

    if !errors.is_empty() {
        return Err(errors);
    }

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
/// 기존 `dns_engine::resolve_isolated` 함수를 그대로 호출하며, I/O나 리졸버 로직을 재구현하지 않습니다.
pub fn resolve_for_quick(
    ctx: &QuickContext,
    helper_executable: &Path,
    timeout: Duration,
    cancel: Arc<AtomicBool>,
) -> Result<QuickResult, Vec<String>> {
    let mut errors = Vec::new();
    validate_context_metadata(ctx, &mut errors);
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
