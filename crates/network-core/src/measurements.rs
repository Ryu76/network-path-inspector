//! Network Quick Check(Part B) 전용 프로브 측정 결과 변환 어댑터 모듈.
//!
//! 이 모듈은 공통 프로브 결과 DTO인 `IcmpMeasurement` 및 `HostSnapshot`을
//! Quick Check 단일 측정 계약 DTO(`QuickResult`)로 변환하는 순수 어댑터를 제공합니다.
//!
//! ## 핵심 안전 및 측정 원칙
//! - **비파괴·순수 변환**: 실제 네트워크 프로브 호출, 소켓 생성, 시스템 변경을 수행하지 않는 순수 변환기입니다.
//! - **측정 사실과 추론의 엄격한 분리**:
//!   - ICMP 무응답/오류나 로컬 OS 라우팅 관찰 결과로부터 원격 TCP 연결 성공이나 패킷 손실률, 방화벽 차단을 단정하지 않습니다.
//!   - 패킷 캡처(PCAP) 근거 없는 SYN/RST 관찰 주장을 배제합니다.
//! - **임의 데이터 발명 금지**: 타임스탬프, 출발지, IP 주소, 경과 시간 등을 임의로 발명하지 않으며,
//!   미확인 nullable 필드는 명시적 `None`(`null`)으로 유지합니다.
//! - **동결 계약(Frozen Contract) 준수**: 공통 스키마 및 DTO 계약에 정의된 상태 및 근거 수준 매핑을 엄격히 따릅니다.

use std::net::IpAddr;

use crate::host::{AdapterEntry, HostSnapshot, RouteEntry, SelectedRouteEntry};
use crate::icmp::IcmpMeasurement;
use crate::quick::{
    EvidenceLevel, QUICK_PRODUCT_NAME, QUICK_SCHEMA_VERSION, QuickContext, QuickFeature,
    QuickResult, QuickStatus, validate_quick_result, validate_rfc3339_timestamp,
};

/// 중복 항목 없이 제한사항 목록에 안내 문구를 추가하는 헬퍼 함수.
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

/// 공통 ICMP Echo(Ping) 측정 결과(`IcmpMeasurement`)를 Quick Check 계약 결과(`QuickResult`)로 변환하는 어댑터 함수.
///
/// ## 규칙 및 불변식
/// 1. 컨텍스트 검증: 포트 0, 빈 세션 ID, 빈 대상 호스트, 유효하지 않은 타임스탬프 등은 거부합니다.
/// 2. IP 일관성 검증 (교차 오염 방지):
///    - `measurement.target`의 원문(trim 없는) IpAddr 파싱 성공 시:
///      - `ctx.target_host`가 IP 리터럴인 경우 수치 비교하여 불일치 시 거부합니다.
///      - `ctx.target_host`가 도메인인 경우 임의 DNS 조회를 하지 않고 실측 IP를 `resolved_ip`로 유도합니다.
///    - `measurement.target` 파싱 실패 시(공백 포함, 미해석 호스트 등) `resolved_ip`는 `None`(`null`)으로 유지하며 조회를 발명하지 않습니다.
/// 3. ICMP 상태 매핑 (frozen contract 준수):
///    - `REPLY` -> `(QuickStatus::PASS, EvidenceLevel::OBSERVED)`
///    - `TIMEOUT` -> `(QuickStatus::FAIL, EvidenceLevel::OBSERVED)`
///    - `UNREACHABLE` -> `(QuickStatus::FAIL, EvidenceLevel::OBSERVED)`
///    - `LOCAL_ERROR` -> `(QuickStatus::UNKNOWN, EvidenceLevel::OBSERVED)`
///    - `CANCELLED` -> `(QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN)`
///    - `UNAVAILABLE` -> `(QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN)`
///    - 알 수 없는 outcome -> `(QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN)`
/// 4. 오류 코드 변환:
///    - `measurement.error_code`(`Option<u32>`)는 `i32::try_from`으로만 변환하며 오버플로 시 최상위는 `None`(`null`)으로 설정하고
///      limitations에 안내를 추가하며 원본 u32는 `details.raw_measurement`에 보존합니다.
///    - `ip_status`는 OS/Winsock 오류 코드가 아니므로 최상위 `os_error_code`에 절대 주입하지 않습니다.
/// 5. 측정 및 추론 분리:
///    - 단일 ICMP Echo 관찰로부터 TCP 연결 수립이나 패킷 손실률/PCAP 근거를 추론하지 않는 한계를 명시합니다.
/// 6. details 보존: `outcome`, `limitations`, `raw_measurement`의 정확히 3개 필드로 구성합니다.
pub fn icmp_to_quick_result(
    ctx: &QuickContext,
    measurement: &IcmpMeasurement,
) -> Result<QuickResult, Vec<String>> {
    let mut errors = Vec::new();

    validate_context_metadata(ctx, &mut errors);

    let mut resolved_ip: Option<String> = None;
    if let Ok(parsed_ip) = measurement.target.parse::<IpAddr>() {
        resolved_ip = Some(parsed_ip.to_string());

        if let Ok(ctx_ip) = ctx.target_host.trim().parse::<IpAddr>()
            && parsed_ip != ctx_ip
        {
            errors.push(format!(
                "측정 대상 IP({parsed_ip})가 컨텍스트 대상 IP({ctx_ip})와 일치하지 않습니다 (IP 불일치 방지)."
            ));
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    let (status, evidence_level) = match measurement.outcome.as_str() {
        "REPLY" => (QuickStatus::PASS, EvidenceLevel::OBSERVED),
        "TIMEOUT" => (QuickStatus::FAIL, EvidenceLevel::OBSERVED),
        "UNREACHABLE" => (QuickStatus::FAIL, EvidenceLevel::OBSERVED),
        "LOCAL_ERROR" => (QuickStatus::UNKNOWN, EvidenceLevel::OBSERVED),
        "CANCELLED" => (QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN),
        "UNAVAILABLE" => (QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN),
        _ => (QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN),
    };

    let mut limitations = measurement.limitations.clone();
    push_unique_limitation(
        &mut limitations,
        "ICMP Echo 결과는 OS IP Helper 관찰값이며 TCP 연결 가능 여부나 원격 포트 개방 상태를 추론할 수 없습니다.".to_string(),
    );
    push_unique_limitation(
        &mut limitations,
        "단일 Echo 측정 결과이므로 패킷 손실률 통계나 패킷 캡처(PCAP) 근거를 포함하지 않습니다."
            .to_string(),
    );

    let mut os_error_code = None;
    if let Some(code_u32) = measurement.error_code {
        match i32::try_from(code_u32) {
            Ok(code_i32) => {
                os_error_code = Some(code_i32);
            }
            Err(_) => {
                os_error_code = None;
                push_unique_limitation(
                    &mut limitations,
                    format!(
                        "원시 error_code({code_u32})가 32비트 부호 있는 정수(i32) 범위를 초과하여 최상위 os_error_code는 null로 설정되며 원본 값은 details.raw_measurement에 보존됩니다."
                    ),
                );
            }
        }
    }

    let raw_measurement_val = serde_json::to_value(measurement)
        .map_err(|err| vec![format!("IcmpMeasurement 직렬화 오류: {err}")])?;

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
        resolved_ip,
        target_port: ctx.target_port,
        feature: QuickFeature::IcmpPing,
        status,
        elapsed_ms: Some(measurement.elapsed_ms),
        os_error_code,
        details,
        evidence_level,
    };

    validate_quick_result(&res)?;
    Ok(res)
}

/// 공통 호스트 네트워크 스냅샷(`HostSnapshot`)을 Quick Check 계약 결과(`QuickResult`)로 변환하는 어댑터 함수.
///
/// ## 규칙 및 불변식
/// 1. 컨텍스트 검증: 포트 0, 빈 세션 ID, 빈 대상 호스트, 유효하지 않은 타임스탬프 등은 거부합니다.
/// 2. 구성요소(components) 구조 검증:
///    - `adapters`: `Vec<AdapterEntry>` 구조로 검증 (유효한 빈 배열 `[]`는 0건 관찰로 인정).
///    - `routes`: `Vec<RouteEntry>` 구조로 검증 (유효한 빈 배열 `[]`는 0건 관찰로 인정).
///    - `selected_route`: `SelectedRouteEntry` 구조로 검증.
///      단, `remote_connectivity_evidence == true`인 경우 위조 상태로 판정하여 유효한 라우트 컴포넌트로 승인하지 않고 거부/한계 분리.
///      `selected_route.target` 원문(trim 없는)이 유효한 `IpAddr`가 아닌 경우 컴포넌트 불량으로 판정하고
///      limitations에 `target.invalid` 이유를 명시.
/// 3. 상태(status/evidence_level/outcome) 판정 규칙:
///    - 세 구성요소 모두 유효하고 `snapshot.errors`가 비어있음 -> `PASS`, `OBSERVED`, outcome `"COLLECTED"`
///    - 한 개 이상 유효 관찰이 존재하고, `snapshot.errors`가 존재하거나 다른 구성요소가 실패 -> `WARN`, `OBSERVED`, outcome `"PARTIAL"`
///    - 모든 구성요소가 수집 실패/null/불량 -> `UNKNOWN`, `UNKNOWN`, outcome `"UNAVAILABLE"`
///      (최상위 status에 임의의 UNAVAILABLE 추가 금지)
/// 4. 대상 IP 일관성 검증 및 교차 오염 방지:
///    - `selected_route.target` 원문(trim 없는)을 numeric `IpAddr`로 파싱하여 성공 시:
///      - `ctx.target_host`가 IP 리터럴인 경우 수치 비교하여 불일치 시 거부합니다 (`Err`).
///      - 일치하거나 도메인인 경우 해당 실측 주소를 `resolved_ip`로 유도합니다.
///    - `snapshot` 자체에 유효한 대상 IP가 없으면 `resolved_ip`는 `None`(`null`)으로 유지하며 임의 발명하지 않습니다.
/// 5. 경과 시간 및 한계 보존:
///    - 호출자가 전달한 `elapsed_ms`(`Option<u64>`)를 그대로 유지하며 `None`을 0으로 변환하지 않습니다.
///    - OS 라우팅 경로 선택은 원격 연결 성공의 증거가 아니라는 명확한 한계를 첨부합니다.
/// 6. details 보존: `outcome`, `limitations`, `raw_measurement`의 정확히 3개 필드로 구성합니다.
pub fn host_to_quick_result(
    ctx: &QuickContext,
    snapshot: &HostSnapshot,
    elapsed_ms: Option<u64>,
) -> Result<QuickResult, Vec<String>> {
    let mut errors = Vec::new();

    validate_context_metadata(ctx, &mut errors);

    // 1. 컴포넌트 유효성 검사
    let adapters_valid = !snapshot.adapters.is_null()
        && serde_json::from_value::<Vec<AdapterEntry>>(snapshot.adapters.clone()).is_ok();

    let routes_valid = !snapshot.routes.is_null()
        && serde_json::from_value::<Vec<RouteEntry>>(snapshot.routes.clone()).is_ok();

    let mut selected_route_valid = false;
    let mut selected_route_entry: Option<SelectedRouteEntry> = None;
    let mut forged_remote_evidence = false;
    let mut invalid_target_str: Option<String> = None;

    if !snapshot.selected_route.is_null() {
        match serde_json::from_value::<SelectedRouteEntry>(snapshot.selected_route.clone()) {
            Ok(entry) => {
                let target_ip_parsed = entry.target.parse::<IpAddr>();
                if entry.remote_connectivity_evidence {
                    // remote_connectivity_evidence=true 같은 위조 상태는 원격 연결 PASS로 고양하지 않고 유효 라우트 컴포넌트 거부 및 한계로 분리
                    forged_remote_evidence = true;
                }
                if target_ip_parsed.is_err() {
                    // selected_route.target 원문 IpAddr 파싱 성공을 component 유효 조건에 포함
                    invalid_target_str = Some(entry.target.clone());
                }
                if !entry.remote_connectivity_evidence && target_ip_parsed.is_ok() {
                    selected_route_valid = true;
                    selected_route_entry = Some(entry);
                } else {
                    selected_route_valid = false;
                }
            }
            Err(_) => {
                selected_route_valid = false;
                if let Some(target_val) = snapshot
                    .selected_route
                    .as_object()
                    .and_then(|obj| obj.get("target"))
                    .and_then(|v| v.as_str())
                    && target_val.parse::<IpAddr>().is_err()
                {
                    invalid_target_str = Some(target_val.to_string());
                }
            }
        }
    }

    // 2. target 교차 오염 검증 및 resolved_ip 유도
    let candidate_target = selected_route_entry
        .as_ref()
        .map(|e| e.target.as_str())
        .or_else(|| {
            snapshot
                .selected_route
                .as_object()
                .and_then(|obj| obj.get("target"))
                .and_then(|v| v.as_str())
        });

    let mut resolved_ip: Option<String> = None;
    if let Some(target_str) = candidate_target
        && let Ok(route_target_ip) = target_str.parse::<IpAddr>()
    {
        if let Ok(ctx_ip) = ctx.target_host.trim().parse::<IpAddr>()
            && route_target_ip != ctx_ip
        {
            errors.push(format!(
                "선택된 라우트 대상 IP({route_target_ip})가 컨텍스트 대상 IP({ctx_ip})와 일치하지 않습니다 (경로 대상 교차 오염 방지)."
            ));
        }
        // 유효한 selected_route인 경우에만 resolved_ip로 채택
        if selected_route_valid {
            resolved_ip = Some(route_target_ip.to_string());
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    // 3. 상태 판정
    let has_snapshot_errors = !snapshot.errors.is_empty();
    let valid_count = (if adapters_valid { 1 } else { 0 })
        + (if routes_valid { 1 } else { 0 })
        + (if selected_route_valid { 1 } else { 0 });

    let (status, evidence_level, outcome) =
        if adapters_valid && routes_valid && selected_route_valid && !has_snapshot_errors {
            (QuickStatus::PASS, EvidenceLevel::OBSERVED, "COLLECTED")
        } else if valid_count >= 1 {
            (QuickStatus::WARN, EvidenceLevel::OBSERVED, "PARTIAL")
        } else {
            (QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN, "UNAVAILABLE")
        };

    // 4. limitations 처리
    let mut limitations = snapshot.limitations.clone();
    push_unique_limitation(
        &mut limitations,
        "selected_route는 Windows OS 라우팅 테이블(GetBestRoute2) 기준 출발지/경로 선택 결과일 뿐이며 원격 호스트 연결 또는 도달 가능성의 증거가 아닙니다 (OS route selection only, NOT remote connectivity evidence)".to_string(),
    );
    push_unique_limitation(
        &mut limitations,
        "호스트 네트워크 스냅샷 수집 성공은 로컬 OS 구성 및 라우트 선택 관찰일 뿐 원격 연결 수립을 보증하지 않습니다.".to_string(),
    );

    if forged_remote_evidence {
        push_unique_limitation(
            &mut limitations,
            "selected_route에 remote_connectivity_evidence가 참(true)으로 설정되어 있어 위조된 상태로 간주하고 유효한 라우트 컴포넌트로 승인하지 않았습니다 (원격 연결 증거 채택 불가).".to_string(),
        );
    }

    if let Some(bad_target) = invalid_target_str {
        push_unique_limitation(
            &mut limitations,
            format!(
                "selected_route target.invalid: 대상 주소 '{bad_target}'가 유효한 IP 주소(IpAddr) 형식이 아니어서 유효한 라우트 컴포넌트로 승인하지 않았습니다."
            ),
        );
    }

    for err in &snapshot.errors {
        push_unique_limitation(&mut limitations, format!("호스트 스냅샷 수집 오류: {err}"));
    }

    let raw_measurement_val = serde_json::to_value(snapshot)
        .map_err(|err| vec![format!("HostSnapshot 직렬화 오류: {err}")])?;

    let details = serde_json::json!({
        "outcome": outcome,
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
        resolved_ip,
        target_port: ctx.target_port,
        feature: QuickFeature::LocalNetwork,
        status,
        elapsed_ms,
        os_error_code: None,
        details,
        evidence_level,
    };

    validate_quick_result(&res)?;
    Ok(res)
}
