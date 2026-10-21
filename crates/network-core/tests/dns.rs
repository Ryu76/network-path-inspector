//! Network Quick Check DNS 어댑터 및 측정 계약 회귀 테스트.
//!
//! 기본 실행 시 실제 네트워크 소켓/하위 프로세스/외부 DNS 호출을 일절 발생시키지 않는
//! 순수 인메모리 합성 단위 테스트로 구성됩니다.
//! 실제 제품 helper 프로세스를 사용한 격리 실행 검증은 부모가 제품 바이너리 경로를
//! 제공하고 명시적으로 실행하는 `#[ignore]` 테스트로만 격리됩니다.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use network_core::dns::{dns_to_quick_result, resolve_for_quick};
use network_core::dns_engine::{
    DnsMeasurement, MAX_ADDRESSES, OUTCOME_CANCELLED, OUTCOME_DNS_ERROR, OUTCOME_LOCAL_ERROR,
    OUTCOME_RESOLVED, OUTCOME_TIMED_OUT,
};
use network_core::quick::{
    EvidenceLevel, QUICK_PRODUCT_NAME, QUICK_SCHEMA_VERSION, QuickContext, QuickFeature,
    QuickResult, QuickStatus,
};

/// 유효한 기본 테스트 컨텍스트를 생성하는 헬퍼 함수.
fn sample_context(host: &str, port: u16) -> QuickContext {
    QuickContext {
        session_id: "test-dns-session-001".to_string(),
        timestamp_iso8601: Some("2026-10-21T18:00:00Z".to_string()),
        source_host: Some("127.0.0.1".to_string()),
        target_host: host.to_string(),
        target_port: port,
    }
}

/// 기본 정상 DnsMeasurement를 생성하는 헬퍼 함수.
fn sample_measurement(host: &str, port: u16, outcome: &str) -> DnsMeasurement {
    DnsMeasurement {
        host: host.to_string(),
        port,
        outcome: outcome.to_string(),
        addresses: Vec::new(),
        elapsed_ms: 25,
        error_code: None,
        error_message: None,
        limitations: vec!["G2-B DNS 작업 중 결과".to_string()],
    }
}

// ============================================================================
// 1. 정상 IPv4 및 IPv6 단일 주소 해석 변환 검증
// ============================================================================

#[test]
fn test_dns_to_quick_result_ipv4_resolved_success() {
    let ctx = sample_context("example.com", 80);
    let mut measurement = sample_measurement("example.com", 80, OUTCOME_RESOLVED);
    measurement.addresses = vec!["93.184.216.34:80".to_string()];

    let res = dns_to_quick_result(&ctx, &measurement).expect("IPv4 정상 변환 성공");

    assert_eq!(res.schema_version, QUICK_SCHEMA_VERSION);
    assert_eq!(res.product, QUICK_PRODUCT_NAME);
    assert_eq!(res.session_id, ctx.session_id);
    assert_eq!(res.timestamp_iso8601, ctx.timestamp_iso8601);
    assert_eq!(res.source_host, ctx.source_host);
    assert_eq!(res.target_host, "example.com");
    assert_eq!(res.target_port, 80);
    assert_eq!(res.feature, QuickFeature::DnsLookup);
    assert_eq!(res.status, QuickStatus::PASS);
    assert_eq!(res.evidence_level, EvidenceLevel::OBSERVED);
    assert_eq!(res.elapsed_ms, Some(25));
    assert_eq!(res.os_error_code, None);

    // lookup 단계에서는 실제 접속 전이므로 resolved_ip는 항상 null
    assert_eq!(res.resolved_ip, None, "DNS lookup 결과의 resolved_ip는 null이어야 함");

    // details 객체 구조 및 원본 measurement 보존 검증
    let details_obj = res.details.as_object().expect("details는 객체");
    assert_eq!(details_obj["outcome"], OUTCOME_RESOLVED);
    assert!(details_obj.contains_key("limitations"));
    assert!(details_obj.contains_key("raw_measurement"));

    let raw_m = &details_obj["raw_measurement"];
    assert_eq!(raw_m["host"], "example.com");
    assert_eq!(raw_m["port"], 80);
    assert_eq!(raw_m["addresses"][0], "93.184.216.34:80");

    // JSON 역직렬화 라운드트립 검증
    let json_str = serde_json::to_string(&res).expect("JSON 직렬화");
    let deserialized: QuickResult = serde_json::from_str(&json_str).expect("JSON 역직렬화");
    assert_eq!(deserialized, res);
}

#[test]
fn test_dns_to_quick_result_ipv6_resolved_success() {
    let ctx = sample_context("ipv6.example.com", 443);
    let mut measurement = sample_measurement("ipv6.example.com", 443, OUTCOME_RESOLVED);
    measurement.addresses = vec!["[2001:db8::1]:443".to_string()];

    let res = dns_to_quick_result(&ctx, &measurement).expect("IPv6 정상 변환 성공");

    assert_eq!(res.target_host, "ipv6.example.com");
    assert_eq!(res.target_port, 443);
    assert_eq!(res.status, QuickStatus::PASS);
    assert_eq!(res.evidence_level, EvidenceLevel::OBSERVED);
    assert_eq!(res.resolved_ip, None);

    let details_raw = &res.details["raw_measurement"];
    assert_eq!(details_raw["addresses"][0], "[2001:db8::1]:443");
}

// ============================================================================
// 2. 다중 주소 (IPv4 + IPv6 복합) 및 최대 32개 상한 보존 검증
// ============================================================================

#[test]
fn test_dns_to_quick_result_multiple_addresses_and_max_limit() {
    let ctx = sample_context("multi.example.com", 80);
    let mut measurement = sample_measurement("multi.example.com", 80, OUTCOME_RESOLVED);

    // IPv4 16개 + IPv6 16개 = 정확히 32개 주소
    let mut addrs = Vec::new();
    for i in 1..=16 {
        addrs.push(format!("10.0.0.{i}:80"));
    }
    for i in 1..=16 {
        addrs.push(format!("[2001:db8::{i:x}]:80"));
    }
    measurement.addresses = addrs.clone();

    let res = dns_to_quick_result(&ctx, &measurement).expect("32개 주소 변환 성공");

    assert_eq!(res.status, QuickStatus::PASS);
    assert_eq!(res.evidence_level, EvidenceLevel::OBSERVED);
    assert_eq!(res.resolved_ip, None);

    let raw_addrs = res.details["raw_measurement"]["addresses"]
        .as_array()
        .expect("addresses 배열");
    assert_eq!(raw_addrs.len(), MAX_ADDRESSES);
    assert_eq!(raw_addrs[0], "10.0.0.1:80");
    assert_eq!(raw_addrs[31], "[2001:db8::10]:80");
}

// ============================================================================
// 3. 중복 주소 및 불량 raw 주소 포함 시 fail-closed 거부 검증
// ============================================================================

#[test]
fn test_dns_to_quick_result_rejects_duplicate_addresses() {
    let ctx = sample_context("example.com", 80);
    let mut measurement = sample_measurement("example.com", 80, OUTCOME_RESOLVED);
    measurement.addresses = vec![
        "93.184.216.34:80".to_string(),
        "93.184.216.34:80".to_string(), // 중복
    ];

    let err = dns_to_quick_result(&ctx, &measurement).unwrap_err();
    assert!(
        err.iter().any(|msg| msg.contains("중복")),
        "중복 주소 포함 시 fail-closed 거부되어야 함: {err:?}"
    );
}

#[test]
fn test_dns_to_quick_result_rejects_invalid_raw_addresses() {
    let ctx = sample_context("example.com", 80);

    // 1) 포트 누락 주소
    let mut m1 = sample_measurement("example.com", 80, OUTCOME_RESOLVED);
    m1.addresses = vec!["93.184.216.34".to_string()];
    let err1 = dns_to_quick_result(&ctx, &m1).unwrap_err();
    assert!(err1.iter().any(|msg| msg.contains("SocketAddr 형식")));

    // 2) 포트 불일치 주소
    let mut m2 = sample_measurement("example.com", 80, OUTCOME_RESOLVED);
    m2.addresses = vec!["93.184.216.34:8080".to_string()];
    let err2 = dns_to_quick_result(&ctx, &m2).unwrap_err();
    assert!(err2.iter().any(|msg| msg.contains("포트")));

    // 3) 선행/후행 공백 포함 주소 (trim 금지)
    let mut m3 = sample_measurement("example.com", 80, OUTCOME_RESOLVED);
    m3.addresses = vec![" 93.184.216.34:80 ".to_string()];
    let err3 = dns_to_quick_result(&ctx, &m3).unwrap_err();
    assert!(err3.iter().any(|msg| msg.contains("공백")));

    // 4) 비정규 표기 (IPv6 대괄호 누락)
    let mut m4 = sample_measurement("example.com", 80, OUTCOME_RESOLVED);
    m4.addresses = vec!["2001:db8::1:80".to_string()];
    let err4 = dns_to_quick_result(&ctx, &m4).unwrap_err();
    assert!(err4.iter().any(|msg| msg.contains("SocketAddr")));

    // 5) 완전히 잘못된 문자열
    let mut m5 = sample_measurement("example.com", 80, OUTCOME_RESOLVED);
    m5.addresses = vec!["not_an_ip:80".to_string()];
    let err5 = dns_to_quick_result(&ctx, &m5).unwrap_err();
    assert!(err5.iter().any(|msg| msg.contains("SocketAddr")));

    // 6) 32개 상한 초과 (33개)
    let mut m6 = sample_measurement("example.com", 80, OUTCOME_RESOLVED);
    let mut addrs33 = Vec::new();
    for i in 1..=33 {
        addrs33.push(format!("10.0.0.{i}:80"));
    }
    m6.addresses = addrs33;
    let err6 = dns_to_quick_result(&ctx, &m6).unwrap_err();
    assert!(err6.iter().any(|msg| msg.contains("상한")));
}

// ============================================================================
// 4. RESOLVED outcome인데 주소 목록이 빈 경우 정상 PASS 금지 검증
// ============================================================================

#[test]
fn test_dns_to_quick_result_rejects_empty_addresses_on_resolved() {
    let ctx = sample_context("example.com", 80);
    let measurement = sample_measurement("example.com", 80, OUTCOME_RESOLVED);
    assert!(measurement.addresses.is_empty());

    let err = dns_to_quick_result(&ctx, &measurement).unwrap_err();
    assert!(
        err.iter().any(|msg| msg.contains("빈 주소 정상 PASS 금지") || msg.contains("비어 있습니다")),
        "RESOLVED 상태에서 주소가 없으면 정상 PASS로 간주하지 않고 거부해야 함: {err:?}"
    );
}

// ============================================================================
// 5. ctx host 및 port 불일치 시 Err 검증 (raw trim 금지)
// ============================================================================

#[test]
fn test_dns_to_quick_result_rejects_host_mismatch() {
    let ctx = sample_context("example.com", 80);
    let mut measurement = sample_measurement("other.com", 80, OUTCOME_RESOLVED);
    measurement.addresses = vec!["93.184.216.34:80".to_string()];

    let err = dns_to_quick_result(&ctx, &measurement).unwrap_err();
    assert!(
        err.iter().any(|msg| msg.contains("호스트 교차 오염 방지")),
        "호스트 불일치 시 거부: {err:?}"
    );
}

#[test]
fn test_dns_to_quick_result_rejects_host_whitespace_difference_without_trim() {
    let ctx = sample_context("example.com", 80);
    // 공백이 포함된 호스트 (raw trim 금지 검증)
    let mut measurement = sample_measurement("example.com ", 80, OUTCOME_RESOLVED);
    measurement.addresses = vec!["93.184.216.34:80".to_string()];

    let err = dns_to_quick_result(&ctx, &measurement).unwrap_err();
    assert!(
        err.iter().any(|msg| msg.contains("호스트")),
        "공백이 다른 호스트를 임의 trim으로 일치시키지 않고 거부: {err:?}"
    );
}

#[test]
fn test_dns_to_quick_result_rejects_port_mismatch() {
    let ctx = sample_context("example.com", 80);
    let mut measurement = sample_measurement("example.com", 443, OUTCOME_RESOLVED);
    measurement.addresses = vec!["93.184.216.34:443".to_string()];

    let err = dns_to_quick_result(&ctx, &measurement).unwrap_err();
    assert!(
        err.iter().any(|msg| msg.contains("포트 교차 오염 방지")),
        "포트 불일치 시 거부: {err:?}"
    );
}

// ============================================================================
// 6. 각 outcome 및 미지 outcome 매핑 검증
// ============================================================================

#[test]
fn test_dns_to_quick_result_dns_error_mapping() {
    let ctx = sample_context("notfound.example.com", 80);
    let mut measurement = sample_measurement("notfound.example.com", 80, OUTCOME_DNS_ERROR);
    measurement.error_code = Some(11001);
    measurement.error_message = Some("호스트를 찾을 수 없음".to_string());

    let res = dns_to_quick_result(&ctx, &measurement).expect("DNS_ERROR 변환 성공");

    assert_eq!(res.status, QuickStatus::FAIL);
    assert_eq!(res.evidence_level, EvidenceLevel::OBSERVED);
    assert_eq!(res.os_error_code, Some(11001));
    assert_eq!(res.resolved_ip, None);
    assert_eq!(res.details["outcome"], OUTCOME_DNS_ERROR);
}

#[test]
fn test_dns_to_quick_result_timed_out_mapping() {
    let ctx = sample_context("slow.example.com", 80);
    let measurement = sample_measurement("slow.example.com", 80, OUTCOME_TIMED_OUT);

    let res = dns_to_quick_result(&ctx, &measurement).expect("TIMED_OUT 변환 성공");

    assert_eq!(res.status, QuickStatus::FAIL);
    assert_eq!(res.evidence_level, EvidenceLevel::OBSERVED);
    assert_eq!(res.resolved_ip, None);
    assert_eq!(res.details["outcome"], OUTCOME_TIMED_OUT);
}

#[test]
fn test_dns_to_quick_result_cancelled_mapping() {
    let ctx = sample_context("example.com", 80);
    let measurement = sample_measurement("example.com", 80, OUTCOME_CANCELLED);

    let res = dns_to_quick_result(&ctx, &measurement).expect("CANCELLED 변환 성공");

    // CANCELLED는 FAIL로 위장하지 않고 UNKNOWN/UNKNOWN 유지
    assert_eq!(res.status, QuickStatus::UNKNOWN);
    assert_eq!(res.evidence_level, EvidenceLevel::UNKNOWN);
    assert_eq!(res.resolved_ip, None);
    assert_eq!(res.details["outcome"], OUTCOME_CANCELLED);
}

#[test]
fn test_dns_to_quick_result_local_error_mapping() {
    let ctx = sample_context("example.com", 80);
    let mut measurement = sample_measurement("example.com", 80, OUTCOME_LOCAL_ERROR);
    measurement.error_message = Some("helper 실행 실패".to_string());

    let res = dns_to_quick_result(&ctx, &measurement).expect("LOCAL_ERROR 변환 성공");

    // 계약 요구사항: CANCELLED·LOCAL_ERROR UNKNOWN/UNKNOWN
    assert_eq!(res.status, QuickStatus::UNKNOWN);
    assert_eq!(res.evidence_level, EvidenceLevel::UNKNOWN);
    assert_eq!(res.resolved_ip, None);
    assert_eq!(res.details["outcome"], OUTCOME_LOCAL_ERROR);
}

#[test]
fn test_dns_to_quick_result_unknown_outcome_mapping() {
    let ctx = sample_context("example.com", 80);
    let measurement = sample_measurement("example.com", 80, "FUTURE_CUSTOM_OUTCOME");

    let res = dns_to_quick_result(&ctx, &measurement).expect("미지 outcome 변환 성공");

    // 알 수 없는 outcome은 절대 PASS가 되어서는 안 됨
    assert_eq!(res.status, QuickStatus::UNKNOWN);
    assert_eq!(res.evidence_level, EvidenceLevel::UNKNOWN);
    assert_eq!(res.resolved_ip, None);

    let limitations = res.details["limitations"].as_array().expect("limitations 배열");
    assert!(
        limitations
            .iter()
            .any(|l| l.as_str().unwrap().contains("알 수 없는 DNS 결과 상태")),
        "미지 outcome 안내 문구 포함 필수"
    );
}

// ============================================================================
// 7. Nullable 필드 및 QG1 스키마 규격 검증
// ============================================================================

#[test]
fn test_dns_to_quick_result_nullable_fields_handling() {
    // timestamp_iso8601과 source_host가 None인 컨텍스트
    let ctx_none = QuickContext {
        session_id: "test-nullables".to_string(),
        timestamp_iso8601: None,
        source_host: None,
        target_host: "example.com".to_string(),
        target_port: 80,
    };
    let mut measurement = sample_measurement("example.com", 80, OUTCOME_RESOLVED);
    measurement.addresses = vec!["93.184.216.34:80".to_string()];

    let res = dns_to_quick_result(&ctx_none, &measurement).expect("None 필드 허용 성공");

    assert_eq!(res.timestamp_iso8601, None);
    assert_eq!(res.source_host, None);
    assert_eq!(res.resolved_ip, None);

    let json_val = serde_json::to_value(&res).expect("JSON Value 변환");
    assert!(json_val["timestamp_iso8601"].is_null());
    assert!(json_val["source_host"].is_null());
    assert!(json_val["resolved_ip"].is_null());
    assert!(json_val["os_error_code"].is_null());

    // 역직렬화 검증 (필수 null 키 존재 확인)
    let json_str = serde_json::to_string(&res).unwrap();
    let decoded: QuickResult = serde_json::from_str(&json_str).expect("역직렬화 성공");
    assert_eq!(decoded.timestamp_iso8601, None);
    assert_eq!(decoded.source_host, None);
    assert_eq!(decoded.resolved_ip, None);
}

// ============================================================================
// 8. 불량 컨텍스트 데이터 거부 검증 (QG1 유효성 규칙 준수)
// ============================================================================

#[test]
fn test_dns_to_quick_result_rejects_invalid_context_data() {
    let mut measurement = sample_measurement("example.com", 80, OUTCOME_RESOLVED);
    measurement.addresses = vec!["93.184.216.34:80".to_string()];

    // 1) 빈 session_id
    let mut ctx1 = sample_context("example.com", 80);
    ctx1.session_id = "".to_string();
    assert!(dns_to_quick_result(&ctx1, &measurement).is_err());

    // 2) 공백뿐인 session_id
    let mut ctx2 = sample_context("example.com", 80);
    ctx2.session_id = "   ".to_string();
    assert!(dns_to_quick_result(&ctx2, &measurement).is_err());

    // 3) 빈 target_host
    let mut ctx3 = sample_context("", 80);
    assert!(dns_to_quick_result(&ctx3, &measurement).is_err());

    // 4) 포트 0
    let mut ctx4 = sample_context("example.com", 0);
    assert!(dns_to_quick_result(&ctx4, &measurement).is_err());

    // 5) 유효하지 않은 timestamp_iso8601
    let mut ctx5 = sample_context("example.com", 80);
    ctx5.timestamp_iso8601 = Some("invalid-rfc3339-time".to_string());
    assert!(dns_to_quick_result(&ctx5, &measurement).is_err());

    // 6) 빈 문자열 timestamp_iso8601
    let mut ctx6 = sample_context("example.com", 80);
    ctx6.timestamp_iso8601 = Some("".to_string());
    assert!(dns_to_quick_result(&ctx6, &measurement).is_err());

    // 7) 빈 문자열 source_host
    let mut ctx7 = sample_context("example.com", 80);
    ctx7.source_host = Some("   ".to_string());
    assert!(dns_to_quick_result(&ctx7, &measurement).is_err());
}

// ============================================================================
// 9. OS 오류 코드 보존 검증
// ============================================================================

#[test]
fn test_dns_to_quick_result_preserves_os_error_codes() {
    let ctx = sample_context("error.example.com", 80);

    // Some(10060) WSAETIMEDOUT
    let mut m1 = sample_measurement("error.example.com", 80, OUTCOME_DNS_ERROR);
    m1.error_code = Some(10060);
    let res1 = dns_to_quick_result(&ctx, &m1).unwrap();
    assert_eq!(res1.os_error_code, Some(10060));

    // Some(-1) 음수 OS 오류 코드
    let mut m2 = sample_measurement("error.example.com", 80, OUTCOME_DNS_ERROR);
    m2.error_code = Some(-1);
    let res2 = dns_to_quick_result(&ctx, &m2).unwrap();
    assert_eq!(res2.os_error_code, Some(-1));

    // None
    let m3 = sample_measurement("error.example.com", 80, OUTCOME_DNS_ERROR);
    let res3 = dns_to_quick_result(&ctx, &m3).unwrap();
    assert_eq!(res3.os_error_code, None);
}

// ============================================================================
// 10. resolve_for_quick 단위 시험 (IP 리터럴 우회, 사전 취소, 불량 인자)
// ============================================================================

#[test]
fn test_resolve_for_quick_ip_literal_bypasses_process_offline() {
    let ctx = sample_context("127.0.0.1", 8080);
    let dummy_exe = std::env::current_exe().expect("현재 바이너리 경로");
    let cancel = Arc::new(AtomicBool::new(false));

    // 127.0.0.1 같은 IP 리터럴은 dns_engine이 helper 프로세스를 스폰하지 않고 즉시 해석 반환함
    let res = resolve_for_quick(&ctx, &dummy_exe, Duration::from_secs(1), cancel)
        .expect("IP 리터럴 즉시 변환 성공");

    assert_eq!(res.status, QuickStatus::PASS);
    assert_eq!(res.evidence_level, EvidenceLevel::OBSERVED);
    assert_eq!(res.resolved_ip, None, "lookup 결과의 resolved_ip는 null");

    let raw = &res.details["raw_measurement"];
    assert_eq!(raw["addresses"][0], "127.0.0.1:8080");

    let limitations = res.details["limitations"].as_array().unwrap();
    assert!(
        limitations.iter().any(|l| l.as_str().unwrap().contains("IP 리터럴")),
        "IP 리터럴 안내 문구 포함 필수"
    );
}

#[test]
fn test_resolve_for_quick_pre_cancelled_returns_unknown() {
    let ctx = sample_context("example.com", 80);
    let dummy_exe = Path::new("C:/non_existent/helper.exe");
    let cancel = Arc::new(AtomicBool::new(true)); // 사전 취소 플래그

    let res = resolve_for_quick(&ctx, dummy_exe, Duration::from_secs(1), cancel)
        .expect("사전 취소 QuickResult 생성 성공");

    // 사전 취소는 helper 프로세스를 생성하지 않고 즉시 CANCELLED -> UNKNOWN/UNKNOWN으로 반환
    assert_eq!(res.status, QuickStatus::UNKNOWN);
    assert_eq!(res.evidence_level, EvidenceLevel::UNKNOWN);
    assert_eq!(res.details["outcome"], OUTCOME_CANCELLED);
}

#[test]
fn test_resolve_for_quick_rejects_invalid_context_early() {
    let mut ctx = sample_context("example.com", 0); // 잘못된 포트
    ctx.session_id = "".to_string(); // 잘못된 세션
    let dummy_exe = Path::new("C:/target/release/npi.exe");
    let cancel = Arc::new(AtomicBool::new(false));

    let err = resolve_for_quick(&ctx, dummy_exe, Duration::from_secs(1), cancel).unwrap_err();
    assert!(!err.is_empty(), "불량 컨텍스트는 helper 실행 전 조기 거부되어야 함");
}

// ============================================================================
// 11. 부모 명시 실행: localhost helper 격리 시험 (#[ignore])
// ============================================================================

#[test]
#[ignore = "부모 명시 실행: localhost helper 격리 시험"]
fn test_real_localhost_helper_resolve_for_quick() {
    let exe_var = match std::env::var("NPI_TEST_HELPER_EXE") {
        Ok(val) => val,
        Err(_) => {
            eprintln!("NPI_TEST_HELPER_EXE 미설정: 부모가 제품 바이너리 경로를 제공해야 격리 시험 가능");
            return;
        }
    };
    let exe_path = Path::new(&exe_var);
    assert!(exe_path.is_absolute(), "NPI_TEST_HELPER_EXE는 절대 경로여야 함");

    let ctx = sample_context("localhost", 80);
    let cancel = Arc::new(AtomicBool::new(false));

    let res = resolve_for_quick(&ctx, exe_path, Duration::from_secs(3), cancel)
        .expect("localhost 격리 실행 및 QuickResult 변환 성공");

    assert_eq!(res.target_host, "localhost");
    assert_eq!(res.target_port, 80);
    assert!(
        res.status == QuickStatus::PASS || res.status == QuickStatus::FAIL,
        "localhost 해석 결과는 PASS(정상해석) 또는 FAIL(OS 해석 실패)이어야 함"
    );
    assert_eq!(res.resolved_ip, None, "lookup 결과의 resolved_ip는 null");
}
