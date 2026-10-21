//! Network Quick Check 및 network-core 라이브러리 순수 회귀 테스트.
//!
//! 본 테스트 파일의 모든 테스트는 합성(synthetic) 데이터를 사용하며,
//! 실제 소켓 생성, DNS 질의, Windows 네이티브 API 호출, 서브프로세스 생성,
//! 파일 쓰기 등의 네트워크/OS 부수 효과를 발생시키지 않습니다 (부수 효과 0).

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use network_core::{
    classify_tcp_error, collect_host_snapshot, connect_once, ping_once, tcp_to_quick_result,
    validate_quick_result, validate_rfc3339_timestamp, EvidenceLevel, QuickContext, QuickFeature,
    QuickResult, QuickStatus, TcpMeasurement, TcpOutcome,
};
use serde_json::Value;

/// 1. 기존 npi-core의 classify_tcp_error와 동일한 오류 코드 분류 순수 회귀 검증.
#[test]
fn existing_classify_tcp_error_pure_regression() {
    // 10061: REFUSED
    assert_eq!(classify_tcp_error(Some(10061), false, false), "REFUSED");
    // 10060: TIMED_OUT
    assert_eq!(classify_tcp_error(Some(10060), false, false), "TIMED_OUT");
    // 10051, 10065: UNREACHABLE
    assert_eq!(classify_tcp_error(Some(10051), false, false), "UNREACHABLE");
    assert_eq!(classify_tcp_error(Some(10065), false, false), "UNREACHABLE");
    // 10054: RESET
    assert_eq!(classify_tcp_error(Some(10054), false, false), "RESET");
    // 10050, 10013: LOCAL_ERROR
    assert_eq!(classify_tcp_error(Some(10050), false, false), "LOCAL_ERROR");
    assert_eq!(classify_tcp_error(Some(10013), false, false), "LOCAL_ERROR");
    // 11001..=11004: DNS_ERROR
    assert_eq!(classify_tcp_error(Some(11001), false, false), "DNS_ERROR");
    assert_eq!(classify_tcp_error(Some(11002), false, false), "DNS_ERROR");
    assert_eq!(classify_tcp_error(Some(11003), false, false), "DNS_ERROR");
    assert_eq!(classify_tcp_error(Some(11004), false, false), "DNS_ERROR");
    // 미정의 코드, 0, None: 절대 CONNECTED로 분류하지 않고 LOCAL_ERROR로 분류
    assert_eq!(classify_tcp_error(Some(99999), false, false), "LOCAL_ERROR");
    assert_eq!(classify_tcp_error(Some(0), false, false), "LOCAL_ERROR");
    assert_eq!(classify_tcp_error(None, false, false), "LOCAL_ERROR");

    // 취소(cancelled) 최우선권 검증
    assert_eq!(classify_tcp_error(Some(10061), false, true), "CANCELLED");
    assert_eq!(classify_tcp_error(Some(10061), true, true), "CANCELLED");
    assert_eq!(classify_tcp_error(None, false, true), "CANCELLED");

    // 타임아웃(timed_out) 데드라인 우선권 검증 (취소 미설정 시)
    assert_eq!(classify_tcp_error(Some(10061), true, false), "TIMED_OUT");
    assert_eq!(classify_tcp_error(None, true, false), "TIMED_OUT");

    // TcpOutcome 열거형 문자열 일치 검증
    assert_eq!(TcpOutcome::Connected.as_str(), "CONNECTED");
    assert_eq!(TcpOutcome::Refused.as_str(), "REFUSED");
    assert_eq!(TcpOutcome::Reset.as_str(), "RESET");
    assert_eq!(TcpOutcome::TimedOut.as_str(), "TIMED_OUT");
    assert_eq!(TcpOutcome::Unreachable.as_str(), "UNREACHABLE");
    assert_eq!(TcpOutcome::LocalError.as_str(), "LOCAL_ERROR");
    assert_eq!(TcpOutcome::DnsError.as_str(), "DNS_ERROR");
    assert_eq!(TcpOutcome::Cancelled.as_str(), "CANCELLED");
}

/// 2. TCP 어댑터의 모든 outcome 매핑이 고정 계약(frozen contract)과 일치하는지 검증.
#[test]
fn tcp_adapter_all_outcomes_mapped_correctly() {
    let ctx = QuickContext {
        session_id: "synthetic-test-session".to_string(),
        timestamp_iso8601: Some("2026-10-21T02:30:00Z".to_string()),
        source_host: Some("client-node".to_string()),
        target_host: "127.0.0.1".to_string(),
        target_port: 8080,
    };

    let cases = [
        ("CONNECTED", QuickStatus::PASS, EvidenceLevel::OBSERVED),
        ("REFUSED", QuickStatus::FAIL, EvidenceLevel::OBSERVED),
        ("RESET", QuickStatus::FAIL, EvidenceLevel::OBSERVED),
        ("TIMED_OUT", QuickStatus::FAIL, EvidenceLevel::OBSERVED),
        ("UNREACHABLE", QuickStatus::FAIL, EvidenceLevel::OBSERVED),
        ("DNS_ERROR", QuickStatus::FAIL, EvidenceLevel::OBSERVED),
        // LOCAL_ERROR는 로컬 OS 관찰 결과이며 원격 판정 미확정이므로 UNKNOWN / OBSERVED
        ("LOCAL_ERROR", QuickStatus::UNKNOWN, EvidenceLevel::OBSERVED),
        // CANCELLED는 사용자 취소이며 절대 FAIL로 위장하지 않고 UNKNOWN / UNKNOWN
        ("CANCELLED", QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN),
        // 알 수 없는 outcome은 안전하게 UNKNOWN / UNKNOWN (절대 PASS 금지)
        ("STRANGE_OUTCOME", QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN),
        ("", QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN),
    ];

    for (outcome, expected_status, expected_evidence) in cases {
        let measurement = TcpMeasurement {
            target: "127.0.0.1:8080".to_string(),
            outcome: outcome.to_string(),
            local_address: None,
            elapsed_ms: 10,
            error_code: None,
            error_message: None,
            application_bytes_sent: 0,
            limitations: vec!["[합성(synthetic) 픽스처]".to_string()],
        };

        let result = tcp_to_quick_result(&ctx, &measurement)
            .unwrap_or_else(|errs| panic!("outcome '{outcome}' 변환 실패: {errs:?}"));

        assert_eq!(result.status, expected_status, "outcome: {outcome}");
        assert_eq!(result.evidence_level, expected_evidence, "outcome: {outcome}");
        assert_eq!(result.feature, QuickFeature::TcpConnect);
        assert_eq!(result.schema_version, "1.0");
        assert_eq!(result.product, "network-quick-check");
    }
}

/// 3. TCP 어댑터가 원본 측정 데이터(코드, 메시지, 대상, 경과 시간, 원시 DTO, 제한사항)를 온전히 보존하는지 검증.
#[test]
fn tcp_adapter_preserves_raw_data_and_errors() {
    let ctx = QuickContext {
        session_id: "synthetic-session-preserve".to_string(),
        timestamp_iso8601: Some("2026-10-21T02:30:00Z".to_string()),
        source_host: Some("client-node".to_string()),
        target_host: "10.0.0.1".to_string(),
        target_port: 1526,
    };

    let measurement = TcpMeasurement {
        target: "10.0.0.1:1526".to_string(),
        outcome: "REFUSED".to_string(),
        local_address: Some("192.168.1.100:54321".to_string()),
        elapsed_ms: 42,
        error_code: Some(10061),
        error_message: Some("대상 컴퓨터에서 연결을 거부했으므로 연결하지 못했습니다.".to_string()),
        application_bytes_sent: 0,
        limitations: vec![
            "[합성(synthetic) 데이터] 애플리케이션 페이로드 0바이트 전송.".to_string(),
            "SYN/RST 패킷 관찰이나 특정 차단 장비를 단정하지 않습니다.".to_string(),
        ],
    };

    let result = tcp_to_quick_result(&ctx, &measurement).expect("어댑터 변환 성공 기대");

    assert_eq!(result.os_error_code, Some(10061));
    assert_eq!(result.elapsed_ms, Some(42));
    assert_eq!(result.target_host, "10.0.0.1");
    assert_eq!(result.resolved_ip, Some("10.0.0.1".to_string()));
    assert_eq!(result.target_port, 1526);
    assert_eq!(result.status, QuickStatus::FAIL);
    assert_eq!(result.evidence_level, EvidenceLevel::OBSERVED);

    // details 객체 검증
    let details = result.details;
    assert_eq!(details["outcome"], "REFUSED");
    assert!(details["limitations"].is_array());
    assert_eq!(details["limitations"].as_array().unwrap().len(), 2);

    let raw_val = &details["raw_measurement"];
    assert_eq!(raw_val["target"], "10.0.0.1:1526");
    assert_eq!(raw_val["error_code"], 10061);
    assert_eq!(raw_val["application_bytes_sent"], 0);
    assert_eq!(raw_val["local_address"], "192.168.1.100:54321");
    assert_eq!(
        raw_val["error_message"],
        "대상 컴퓨터에서 연결을 거부했으므로 연결하지 못했습니다."
    );
}

/// 4. 유효하지 않은 컨텍스트(포트 0, 빈 세션 ID, 빈 대상 호스트 등)에 대한 안전한 거부 검증.
#[test]
fn tcp_adapter_context_validation_rejects_invalid_inputs() {
    let measurement = TcpMeasurement {
        target: "127.0.0.1:8080".to_string(),
        outcome: "CONNECTED".to_string(),
        local_address: None,
        elapsed_ms: 5,
        error_code: None,
        error_message: None,
        application_bytes_sent: 0,
        limitations: vec![],
    };

    // 포트 0 거부
    let ctx_port_0 = QuickContext {
        session_id: "valid-session".to_string(),
        timestamp_iso8601: None,
        source_host: None,
        target_host: "127.0.0.1".to_string(),
        target_port: 0,
    };
    assert!(tcp_to_quick_result(&ctx_port_0, &measurement).is_err());

    // 빈 session_id 거부
    let ctx_empty_session = QuickContext {
        session_id: "".to_string(),
        timestamp_iso8601: None,
        source_host: None,
        target_host: "127.0.0.1".to_string(),
        target_port: 8080,
    };
    assert!(tcp_to_quick_result(&ctx_empty_session, &measurement).is_err());

    // 공백 session_id 거부
    let ctx_blank_session = QuickContext {
        session_id: "   \t\n ".to_string(),
        timestamp_iso8601: None,
        source_host: None,
        target_host: "127.0.0.1".to_string(),
        target_port: 8080,
    };
    assert!(tcp_to_quick_result(&ctx_blank_session, &measurement).is_err());

    // 빈 target_host 거부
    let ctx_empty_host = QuickContext {
        session_id: "valid-session".to_string(),
        timestamp_iso8601: None,
        source_host: None,
        target_host: "".to_string(),
        target_port: 8080,
    };
    assert!(tcp_to_quick_result(&ctx_empty_host, &measurement).is_err());

    // 공백 target_host 거부
    let ctx_blank_host = QuickContext {
        session_id: "valid-session".to_string(),
        timestamp_iso8601: None,
        source_host: None,
        target_host: "   ".to_string(),
        target_port: 8080,
    };
    assert!(tcp_to_quick_result(&ctx_blank_host, &measurement).is_err());
}

/// 5. 측정 대상 포트와 컨텍스트 포트의 교차 오염 방지 거부 검증.
#[test]
fn tcp_adapter_rejects_port_cross_contamination() {
    let ctx = QuickContext {
        session_id: "cross-contamination-test".to_string(),
        timestamp_iso8601: None,
        source_host: None,
        target_host: "127.0.0.1".to_string(),
        target_port: 8080, // 포트 8080
    };

    let measurement_mismatch = TcpMeasurement {
        target: "127.0.0.1:9090".to_string(), // 불일치 포트 9090
        outcome: "CONNECTED".to_string(),
        local_address: None,
        elapsed_ms: 5,
        error_code: None,
        error_message: None,
        application_bytes_sent: 0,
        limitations: vec![],
    };

    let res = tcp_to_quick_result(&ctx, &measurement_mismatch);
    assert!(res.is_err(), "포트 불일치는 반드시 거부되어야 함");
    let errs = res.unwrap_err();
    assert!(
        errs.iter().any(|e| e.contains("포트 교차 오염 방지")),
        "오류 메시지에 포트 교차 오염 방지 안내가 포함되어야 함"
    );
}

/// 6. target이 SocketAddr 형식이 아니거나 해석 불가일 때 resolved_ip를 임의 발명하지 않고 null로 유지하는지 검증.
#[test]
fn tcp_adapter_resolves_ip_from_peer_or_leaves_null_without_invention() {
    let ctx = QuickContext {
        session_id: "unresolved-test".to_string(),
        timestamp_iso8601: None,
        source_host: None,
        target_host: "unresolved.example.corp".to_string(),
        target_port: 1526,
    };

    // measurement.target이 SocketAddr로 파싱 불가능한 경우 (예: 도메인 형식)
    let measurement = TcpMeasurement {
        target: "unresolved.example.corp".to_string(),
        outcome: "DNS_ERROR".to_string(),
        local_address: None,
        elapsed_ms: 10,
        error_code: Some(11001),
        error_message: Some("호스트를 찾을 수 없습니다.".to_string()),
        application_bytes_sent: 0,
        limitations: vec![],
    };

    let result = tcp_to_quick_result(&ctx, &measurement).expect("변환 자체는 허용");
    assert_eq!(result.resolved_ip, None, "네트워크 해석 결과 발명 금지: resolved_ip는 null이어야 함");
    assert_eq!(result.target_host, "unresolved.example.corp");
    assert_eq!(result.status, QuickStatus::FAIL);
    assert_eq!(result.evidence_level, EvidenceLevel::OBSERVED);
}

/// 7. QuickResult 직렬화 시 14개 명시 필드가 모두 출력되며(null 키 누락 금지), strict unknown fields를 준수하는지 검증.
#[test]
fn quick_result_serialization_preserves_all_14_keys_including_nulls() {
    let result = QuickResult {
        schema_version: "1.0".to_string(),
        product: "network-quick-check".to_string(),
        session_id: "session-null-test".to_string(),
        timestamp_iso8601: None,
        source_host: None,
        target_host: "db.local".to_string(),
        resolved_ip: None,
        target_port: 1521,
        feature: QuickFeature::TcpConnect,
        status: QuickStatus::UNKNOWN,
        elapsed_ms: None,
        os_error_code: None,
        details: serde_json::json!({
            "outcome": "CANCELLED",
            "limitations": ["[합성]"],
            "raw_measurement": {}
        }),
        evidence_level: EvidenceLevel::UNKNOWN,
    };

    let json_str = serde_json::to_string(&result).expect("직렬화 성공 기대");
    let json_val: Value = serde_json::from_str(&json_str).expect("JSON 파싱 기대");
    let obj = json_val.as_object().expect("JSON 객체이어야 함");

    let expected_keys = [
        "schema_version",
        "product",
        "session_id",
        "timestamp_iso8601",
        "source_host",
        "target_host",
        "resolved_ip",
        "target_port",
        "feature",
        "status",
        "elapsed_ms",
        "os_error_code",
        "details",
        "evidence_level",
    ];

    assert_eq!(obj.len(), 14, "정확히 14개의 필드만 존재해야 함");
    for key in expected_keys {
        assert!(obj.contains_key(key), "필수 키 '{key}'가 누락되지 않아야 함");
    }

    // null 필드들이 null 리터럴로 직렬화되었는지 확인
    assert!(obj["timestamp_iso8601"].is_null());
    assert!(obj["source_host"].is_null());
    assert!(obj["resolved_ip"].is_null());
    assert!(obj["elapsed_ms"].is_null());
    assert!(obj["os_error_code"].is_null());

    // 라운드트립 역직렬화 검증
    let parsed: QuickResult = serde_json::from_str(&json_str).expect("역직렬화 성공 기대");
    assert_eq!(parsed, result);
}

/// 8. 알 수 없는 필드(unknown field) 및 유효하지 않은 열거형 값에 대한 역직렬화 안전 거부 검증.
#[test]
fn quick_result_deny_unknown_fields_and_invalid_enums() {
    let valid_base_json = serde_json::json!({
        "schema_version": "1.0",
        "product": "network-quick-check",
        "session_id": "test-session",
        "timestamp_iso8601": null,
        "source_host": null,
        "target_host": "127.0.0.1",
        "resolved_ip": "127.0.0.1",
        "target_port": 80,
        "feature": "tcp_connect",
        "status": "PASS",
        "elapsed_ms": 1,
        "os_error_code": null,
        "details": {
            "outcome": "CONNECTED",
            "limitations": [],
            "raw_measurement": {}
        },
        "evidence_level": "OBSERVED"
    });

    // 1. 유효한 기본 JSON은 역직렬화 성공
    let _: QuickResult = serde_json::from_value(valid_base_json.clone()).unwrap();

    // 2. 알 수 없는 필드 추가 시 거부
    let mut unknown_field_json = valid_base_json.clone();
    unknown_field_json["unexpected_field"] = Value::String("disallowed".to_string());
    assert!(
        serde_json::from_value::<QuickResult>(unknown_field_json).is_err(),
        "unknown field는 deny_unknown_fields에 의해 거부되어야 함"
    );

    // 3. 잘못된 status enum 값 거부
    let mut invalid_status_json = valid_base_json.clone();
    invalid_status_json["status"] = Value::String("NOT_A_VALID_STATUS".to_string());
    assert!(
        serde_json::from_value::<QuickResult>(invalid_status_json).is_err(),
        "정의되지 않은 status는 거부되어야 함"
    );

    // 4. 잘못된 evidence_level enum 값 거부
    let mut invalid_evidence_json = valid_base_json.clone();
    invalid_evidence_json["evidence_level"] = Value::String("INVENTED".to_string());
    assert!(
        serde_json::from_value::<QuickResult>(invalid_evidence_json).is_err(),
        "정의되지 않은 evidence_level은 거부되어야 함"
    );

    // 5. 잘못된 feature enum 값 거부
    let mut invalid_feature_json = valid_base_json.clone();
    invalid_feature_json["feature"] = Value::String("unsupported_probe".to_string());
    assert!(
        serde_json::from_value::<QuickResult>(invalid_feature_json).is_err(),
        "정의되지 않은 feature는 거부되어야 함"
    );
}

/// 9. 작성된 테스트 픽스처 파일들(`fixtures/quick-check/**`)의 정합성 검증.
#[test]
fn fixtures_files_validation_against_models() {
    let valid_connected = include_str!("../../../fixtures/quick-check/synthetic-valid-tcp-connected.json");
    let parsed_connected: QuickResult =
        serde_json::from_str(valid_connected).expect("synthetic-valid-tcp-connected.json 파싱 성공");
    assert_eq!(parsed_connected.status, QuickStatus::PASS);
    assert_eq!(parsed_connected.evidence_level, EvidenceLevel::OBSERVED);

    let valid_cancelled = include_str!("../../../fixtures/quick-check/synthetic-valid-tcp-cancelled-nulls.json");
    let parsed_cancelled: QuickResult =
        serde_json::from_str(valid_cancelled).expect("synthetic-valid-tcp-cancelled-nulls.json 파싱 성공");
    assert_eq!(parsed_cancelled.status, QuickStatus::UNKNOWN);
    assert_eq!(parsed_cancelled.evidence_level, EvidenceLevel::UNKNOWN);
    assert!(parsed_cancelled.timestamp_iso8601.is_none());
    assert!(parsed_cancelled.source_host.is_none());
    assert!(parsed_cancelled.resolved_ip.is_none());
    assert!(parsed_cancelled.elapsed_ms.is_none());
    assert!(parsed_cancelled.os_error_code.is_none());

    // 음성 픽스처 검증
    let invalid_status = include_str!("../../../fixtures/quick-check/synthetic-invalid-status.json");
    assert!(
        serde_json::from_str::<QuickResult>(invalid_status).is_err(),
        "synthetic-invalid-status.json은 역직렬화 실패해야 함"
    );

    let invalid_missing = include_str!("../../../fixtures/quick-check/synthetic-invalid-missing-field.json");
    assert!(
        serde_json::from_str::<QuickResult>(invalid_missing).is_err(),
        "synthetic-invalid-missing-field.json은 필수 필드 누락으로 역직렬화 실패해야 함"
    );

    let invalid_unknown = include_str!("../../../fixtures/quick-check/synthetic-invalid-unknown-field.json");
    assert!(
        serde_json::from_str::<QuickResult>(invalid_unknown).is_err(),
        "synthetic-invalid-unknown-field.json은 미정의 필드로 역직렬화 실패해야 함"
    );

    // [부모 계약 불일치 보정]:
    // 기존 시험은 스키마가 금지한 포트 0을 단순 구조체 타입 수준에서만 확인하던 characterization이었음.
    // 스키마(minimum: 1) 및 DTO 계약에 따라 target_port 0은 역직렬화 단계에서 명시적으로 거부되어야 함.
    let invalid_port_zero = include_str!("../../../fixtures/quick-check/synthetic-invalid-port-zero.json");
    assert!(
        serde_json::from_str::<QuickResult>(invalid_port_zero).is_err(),
        "synthetic-invalid-port-zero.json은 target_port=0 위반으로 역직렬화 실패해야 함"
    );

    // 신규 추가 음성 픽스처 검증
    let invalid_product = include_str!("../../../fixtures/quick-check/synthetic-invalid-product.json");
    assert!(
        serde_json::from_str::<QuickResult>(invalid_product).is_err(),
        "synthetic-invalid-product.json은 product 위반으로 역직렬화 실패해야 함"
    );

    let invalid_timestamp = include_str!("../../../fixtures/quick-check/synthetic-invalid-timestamp.json");
    assert!(
        serde_json::from_str::<QuickResult>(invalid_timestamp).is_err(),
        "synthetic-invalid-timestamp.json은 RFC3339 타임스탬프 위반으로 역직렬화 실패해야 함"
    );

    let invalid_missing_nullable = include_str!("../../../fixtures/quick-check/synthetic-invalid-missing-nullable.json");
    assert!(
        serde_json::from_str::<QuickResult>(invalid_missing_nullable).is_err(),
        "synthetic-invalid-missing-nullable.json은 필수 nullable 키 부재로 역직렬화 실패해야 함"
    );
}

/// 10. 공개 facade API 시그니처 컴파일 계약 정적 검증 (실제 호출 및 I/O 0회).
#[test]
fn public_facade_signatures_compile_contract_no_network_side_effects() {
    // connect_once 시그니처 확인 (함수 포인터 타입 검증, 실제 비동기 실행하지 않음)
    let _connect_fn: fn(std::net::SocketAddr, Duration, Arc<AtomicBool>) -> _ = connect_once;

    // ping_once 시그니처 확인 (함수 포인터 타입 검증, 실제 호출하지 않음)
    let _ping_fn: fn(IpAddr, Duration, Arc<AtomicBool>) -> _ = ping_once;

    // collect_host_snapshot 시그니처 확인
    let _host_fn: fn(IpAddr) -> _ = collect_host_snapshot;

    // tcp_to_quick_result 시그니처 확인
    let _adapter_fn: fn(&QuickContext, &TcpMeasurement) -> Result<QuickResult, Vec<String>> =
        tcp_to_quick_result;

    // classify_tcp_error 시그니처 확인
    let _classify_fn: fn(Option<i32>, bool, bool) -> String = classify_tcp_error;
}

/// 11. [Repro 1] IP literal 대상과 측정 peer 일관성 검증 및 도메인 컨텍스트 보존.
///
/// - `ctx.target_host`가 IP literal일 때 측정 peer IP와 다르면 `Err` 반환.
/// - 일치하는 IP일 때는 정상 변환.
/// - `ctx.target_host`가 도메인 문자열인 경우 임의 DNS 조회를 하지 않고 실측 peer IP를 `resolved_ip`로 유도.
/// - 포트 교차 오염 방지 유지.
#[test]
fn repro_1_ip_literal_target_peer_consistency_and_domain_preservation() {
    // 1. IP literal 불일치 거부
    let ctx_ip = QuickContext {
        session_id: "ip-consistency-test".to_string(),
        timestamp_iso8601: Some("2026-10-21T02:30:00Z".to_string()),
        source_host: None,
        target_host: "127.0.0.1".to_string(),
        target_port: 443,
    };

    let measurement_mismatch = TcpMeasurement {
        target: "127.0.0.2:443".to_string(), // IP 불일치
        outcome: "CONNECTED".to_string(),
        local_address: None,
        elapsed_ms: 5,
        error_code: None,
        error_message: None,
        application_bytes_sent: 0,
        limitations: vec![],
    };

    let res_mismatch = tcp_to_quick_result(&ctx_ip, &measurement_mismatch);
    assert!(res_mismatch.is_err(), "IP literal 불일치는 반드시 거부되어야 함");
    let errs = res_mismatch.unwrap_err();
    assert!(
        errs.iter().any(|e| e.contains("IP 불일치 방지")),
        "에러 메시지에 IP 불일치 방지 안내가 포함되어야 함"
    );

    // 2. IP literal 일치 시 성공 및 resolved_ip 보존
    let measurement_match = TcpMeasurement {
        target: "127.0.0.1:443".to_string(),
        outcome: "CONNECTED".to_string(),
        local_address: None,
        elapsed_ms: 5,
        error_code: None,
        error_message: None,
        application_bytes_sent: 0,
        limitations: vec![],
    };
    let res_match = tcp_to_quick_result(&ctx_ip, &measurement_match).expect("IP 일치 시 성공 기대");
    assert_eq!(res_match.resolved_ip, Some("127.0.0.1".to_string()));
    assert_eq!(res_match.status, QuickStatus::PASS);

    // 3. 도메인 컨텍스트: 임의 DNS 조회 없이 실측 peer를 resolved_ip로 유도하는 동작 유지
    let ctx_domain = QuickContext {
        session_id: "domain-test".to_string(),
        timestamp_iso8601: Some("2026-10-21T02:30:00Z".to_string()),
        source_host: None,
        target_host: "gateway.corp.local".to_string(),
        target_port: 443,
    };
    let res_domain =
        tcp_to_quick_result(&ctx_domain, &measurement_mismatch).expect("도메인 컨텍스트 변환 성공");
    assert_eq!(
        res_domain.resolved_ip,
        Some("127.0.0.2".to_string()),
        "실측 peer IP를 resolved_ip로 유도해야 함"
    );
    assert_eq!(res_domain.target_host, "gateway.corp.local");

    // 4. 포트 교차 오염 거부 유지
    let measurement_port_mismatch = TcpMeasurement {
        target: "127.0.0.1:8443".to_string(),
        outcome: "CONNECTED".to_string(),
        local_address: None,
        elapsed_ms: 5,
        error_code: None,
        error_message: None,
        application_bytes_sent: 0,
        limitations: vec![],
    };
    assert!(
        tcp_to_quick_result(&ctx_ip, &measurement_port_mismatch).is_err(),
        "포트 불일치는 계속 거부되어야 함"
    );
}

/// 12. [Repro 2] RFC3339 호환 ISO8601 엄격한 타임스탬프 검증 행렬.
///
/// 윤년, 월별 일수, 시/분/초, 타임존 오프셋, 분수초, 지원하지 않는 윤초(60) 거부 등을 종합 검증합니다.
#[test]
fn repro_2_timestamp_iso8601_strict_rfc3339_matrix() {
    // 1. 어댑터에서 유효하지 않은 timestamp_iso8601 전달 시 거부
    let ctx_invalid_ts = QuickContext {
        session_id: "invalid-ts-session".to_string(),
        timestamp_iso8601: Some("not-a-timestamp".to_string()),
        source_host: None,
        target_host: "127.0.0.1".to_string(),
        target_port: 80,
    };
    let measurement = TcpMeasurement {
        target: "127.0.0.1:80".to_string(),
        outcome: "CONNECTED".to_string(),
        local_address: None,
        elapsed_ms: 1,
        error_code: None,
        error_message: None,
        application_bytes_sent: 0,
        limitations: vec![],
    };
    let res = tcp_to_quick_result(&ctx_invalid_ts, &measurement);
    assert!(res.is_err(), "'not-a-timestamp'는 어댑터에서 거부되어야 함");

    // 2. 유효한 타임스탬프 행렬
    let valid_cases = [
        "2026-10-21T02:30:00Z",
        "2026-10-21t02:30:00z",
        "2026-10-21T11:28:45+09:00",
        "2026-10-21T00:00:00-05:00",
        "2026-10-21T02:30:00.123Z",
        "2026-10-21T02:30:00.123456789+00:00",
        "2024-02-29T12:00:00Z", // 2024 윤년 2월 29일
        "2000-02-29T12:00:00Z", // 400년 주기 윤년 2월 29일
        "2023-12-31T23:59:59Z", // 연말 경계값
    ];
    for ts in valid_cases {
        assert!(
            validate_rfc3339_timestamp(ts).is_ok(),
            "유효한 타임스탬프는 통과해야 함: '{ts}'"
        );
    }

    // 3. 유효하지 않은 타임스탬프 행렬
    let invalid_cases = [
        ("", "빈 문자열"),
        ("not-a-timestamp", "비날짜 문자열"),
        ("2026-10-21", "시간 누락"),
        ("2026-10-21 02:30:00Z", "'T' 구분자 대신 공백"),
        ("2026-10-21T02:30:00", "시간대 오프셋 누락"),
        ("2026-10-21T02:30:00+0900", "오프셋 콜론 누락"),
        ("2026-10-21T02:30:00+25:00", "오프셋 시 초과"),
        ("2026-10-21T02:30:00+09:65", "오프셋 분 초과"),
        ("2023-02-29T12:00:00Z", "평년 2월 29일"),
        ("1900-02-29T12:00:00Z", "100년 주기 평년 2월 29일"),
        ("2026-04-31T12:00:00Z", "30일까지인 4월의 31일"),
        ("2026-13-01T12:00:00Z", "13월"),
        ("2026-00-01T12:00:00Z", "0월"),
        ("2026-10-00T12:00:00Z", "0일"),
        ("2026-10-21T24:00:00Z", "24시(초과)"),
        ("2026-10-21T12:60:00Z", "60분(초과)"),
        ("2026-10-21T12:00:60Z", "지원하지 않는 윤초(60)"),
        ("2026-10-21T12:00:00.Z", "분수초 뒤 숫자 누락"),
    ];
    for (ts, reason) in invalid_cases {
        assert!(
            validate_rfc3339_timestamp(ts).is_err(),
            "유효하지 않은 타임스탬프는 거부되어야 함 ({reason}): '{ts}'"
        );
    }
}

/// 13. [Repro 3] 고정 스키마 버전, 제품명, 포트 범위 및 details 객체 계약 검증.
#[test]
fn repro_3_product_and_schema_version_fixed_contract_and_details_object() {
    let valid_base_json = serde_json::json!({
        "schema_version": "1.0",
        "product": "network-quick-check",
        "session_id": "test-session",
        "timestamp_iso8601": "2026-10-21T02:30:00Z",
        "source_host": null,
        "target_host": "127.0.0.1",
        "resolved_ip": "127.0.0.1",
        "target_port": 443,
        "feature": "tcp_connect",
        "status": "PASS",
        "elapsed_ms": 10,
        "os_error_code": null,
        "details": {
            "outcome": "CONNECTED",
            "limitations": [],
            "raw_measurement": {}
        },
        "evidence_level": "OBSERVED"
    });

    // 1. 정상 역직렬화
    let _: QuickResult = serde_json::from_value(valid_base_json.clone()).unwrap();

    // 2. product='network-inspector' 거부
    let mut invalid_product = valid_base_json.clone();
    invalid_product["product"] = Value::String("network-inspector".to_string());
    assert!(
        serde_json::from_value::<QuickResult>(invalid_product).is_err(),
        "product='network-inspector'는 거부되어야 함"
    );

    // 3. schema_version='2.0' 거부
    let mut invalid_version = valid_base_json.clone();
    invalid_version["schema_version"] = Value::String("2.0".to_string());
    assert!(
        serde_json::from_value::<QuickResult>(invalid_version).is_err(),
        "schema_version='2.0'은 거부되어야 함"
    );

    // 4. target_port=0 거부
    let mut port_0 = valid_base_json.clone();
    port_0["target_port"] = serde_json::json!(0);
    assert!(
        serde_json::from_value::<QuickResult>(port_0).is_err(),
        "target_port=0은 거부되어야 함"
    );

    // 5. target_port=65536 (범위 초과) 거부
    let mut port_overflow = valid_base_json.clone();
    port_overflow["target_port"] = serde_json::json!(65536);
    assert!(
        serde_json::from_value::<QuickResult>(port_overflow).is_err(),
        "target_port=65536은 거부되어야 함"
    );

    // 6. details 객체에 알 수 없는 필드 존재 시 거부 (additionalProperties: false)
    let mut details_unknown = valid_base_json.clone();
    details_unknown["details"]["extra_unknown_key"] = serde_json::json!("disallowed");
    assert!(
        serde_json::from_value::<QuickResult>(details_unknown).is_err(),
        "details에 추가 필드가 있으면 거부되어야 함"
    );

    // 7. details.outcome 누락 시 거부
    let mut details_missing_outcome = valid_base_json.clone();
    details_missing_outcome["details"]
        .as_object_mut()
        .unwrap()
        .remove("outcome");
    assert!(
        serde_json::from_value::<QuickResult>(details_missing_outcome).is_err(),
        "details.outcome 누락은 거부되어야 함"
    );

    // 8. details.limitations에 비문자열 원소 존재 시 거부
    let mut details_bad_limits = valid_base_json.clone();
    details_bad_limits["details"]["limitations"] = serde_json::json!(["ok", 12345]);
    assert!(
        serde_json::from_value::<QuickResult>(details_bad_limits).is_err(),
        "details.limitations에 정수가 있으면 거부되어야 함"
    );

    // 9. details.raw_measurement가 객체가 아닌 경우 거부
    let mut details_bad_raw = valid_base_json.clone();
    details_bad_raw["details"]["raw_measurement"] = serde_json::json!("not-an-object");
    assert!(
        serde_json::from_value::<QuickResult>(details_bad_raw).is_err(),
        "details.raw_measurement가 문자열이면 거부되어야 함"
    );
}

/// 14. [Repro 4] 필수 nullable 5개 키 누락 거부 행렬 검증.
///
/// explicit `null`은 허용되지만, 키 부재(missing key)는 거부되어야 합니다.
#[test]
fn repro_4_missing_required_nullable_keys_rejected_matrix() {
    let all_nulls_json = serde_json::json!({
        "schema_version": "1.0",
        "product": "network-quick-check",
        "session_id": "session-all-nulls",
        "timestamp_iso8601": null,
        "source_host": null,
        "target_host": "127.0.0.1",
        "resolved_ip": null,
        "target_port": 8080,
        "feature": "tcp_connect",
        "status": "UNKNOWN",
        "elapsed_ms": null,
        "os_error_code": null,
        "details": {
            "outcome": "LOCAL_ERROR",
            "limitations": [],
            "raw_measurement": {}
        },
        "evidence_level": "UNKNOWN"
    });

    // 1. 모든 nullable 필드가 explicit null인 경우 정상 역직렬화
    let parsed_nulls: QuickResult = serde_json::from_value(all_nulls_json.clone())
        .expect("명시적 null 리터럴은 정상적으로 None으로 역직렬화되어야 함");
    assert!(parsed_nulls.timestamp_iso8601.is_none());
    assert!(parsed_nulls.source_host.is_none());
    assert!(parsed_nulls.resolved_ip.is_none());
    assert!(parsed_nulls.elapsed_ms.is_none());
    assert!(parsed_nulls.os_error_code.is_none());

    // 2. 필수 nullable 5개 키 각각 누락 시 거부 검증
    let nullable_keys = [
        "timestamp_iso8601",
        "source_host",
        "resolved_ip",
        "elapsed_ms",
        "os_error_code",
    ];

    for key in nullable_keys {
        let mut missing_json = all_nulls_json.clone();
        missing_json.as_object_mut().unwrap().remove(key);

        let res = serde_json::from_value::<QuickResult>(missing_json);
        assert!(
            res.is_err(),
            "필수 nullable 키 '{key}'가 누락된 경우 반드시 거부되어야 함"
        );
        let err_msg = res.unwrap_err().to_string();
        assert!(
            err_msg.contains(key),
            "에러 메시지에 누락된 키 이름 '{key}'가 명시되어야 함 (현재 메시지: {err_msg})"
        );
    }
}

/// 15. 추가 schema 정합성: resolved_ip 형식 검증, os_error_code i32 범위 및 validate_quick_result 검증.
#[test]
fn schema_additional_ip_and_range_validation() {
    let valid_base_json = serde_json::json!({
        "schema_version": "1.0",
        "product": "network-quick-check",
        "session_id": "test-session",
        "timestamp_iso8601": null,
        "source_host": null,
        "target_host": "127.0.0.1",
        "resolved_ip": "127.0.0.1",
        "target_port": 80,
        "feature": "tcp_connect",
        "status": "PASS",
        "elapsed_ms": 1,
        "os_error_code": 10061,
        "details": {
            "outcome": "REFUSED",
            "limitations": [],
            "raw_measurement": {}
        },
        "evidence_level": "OBSERVED"
    });

    // 1. resolved_ip가 비IP 문자열인 경우 거부
    let mut bad_ip = valid_base_json.clone();
    bad_ip["resolved_ip"] = serde_json::json!("invalid-ip-string");
    assert!(
        serde_json::from_value::<QuickResult>(bad_ip).is_err(),
        "resolved_ip가 유효하지 않은 IP 문자열이면 거부되어야 함"
    );

    // 2. resolved_ip가 IPv6 주소인 경우 정상 승인
    let mut ipv6_json = valid_base_json.clone();
    ipv6_json["resolved_ip"] = serde_json::json!("::1");
    let parsed_ipv6: QuickResult = serde_json::from_value(ipv6_json).unwrap();
    assert_eq!(parsed_ipv6.resolved_ip, Some("::1".to_string()));

    // 3. os_error_code가 i32 범위를 초과하는 경우 거부
    let mut bad_error_code = valid_base_json.clone();
    bad_error_code["os_error_code"] = serde_json::json!(9_999_999_999_i64);
    assert!(
        serde_json::from_value::<QuickResult>(bad_error_code).is_err(),
        "os_error_code가 i32 범위를 초과하면 거부되어야 함"
    );

    // 4. elapsed_ms가 음수인 경우 거부
    let mut bad_elapsed = valid_base_json.clone();
    bad_elapsed["elapsed_ms"] = serde_json::json!(-10);
    assert!(
        serde_json::from_value::<QuickResult>(bad_elapsed).is_err(),
        "elapsed_ms가 음수이면 거부되어야 함"
    );

    // 5. validate_quick_result 수동 DTO 검증 함수 작동 확인
    let valid_dto = QuickResult {
        schema_version: "1.0".to_string(),
        product: "network-quick-check".to_string(),
        session_id: "valid-session".to_string(),
        timestamp_iso8601: Some("2026-10-21T02:30:00Z".to_string()),
        source_host: None,
        target_host: "127.0.0.1".to_string(),
        resolved_ip: Some("127.0.0.1".to_string()),
        target_port: 80,
        feature: QuickFeature::TcpConnect,
        status: QuickStatus::PASS,
        elapsed_ms: Some(10),
        os_error_code: None,
        details: serde_json::json!({
            "outcome": "CONNECTED",
            "limitations": [],
            "raw_measurement": {}
        }),
        evidence_level: EvidenceLevel::OBSERVED,
    };
    assert!(validate_quick_result(&valid_dto).is_ok());

    let mut invalid_dto = valid_dto.clone();
    invalid_dto.product = "network-inspector".to_string();
    assert!(validate_quick_result(&invalid_dto).is_err());
}
