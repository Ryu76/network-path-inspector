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
    EvidenceLevel, QuickContext, QuickFeature, QuickResult, QuickStatus, TcpMeasurement, TcpOutcome,
    classify_tcp_error, collect_host_snapshot, connect_once, ping_once, tcp_to_quick_result,
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

    let invalid_port_zero = include_str!("../../../fixtures/quick-check/synthetic-invalid-port-zero.json");
    let parsed_port_zero: QuickResult =
        serde_json::from_str(invalid_port_zero).expect("DTO 구조 자체는 역직렬화 가능하나 포트 0");
    assert_eq!(parsed_port_zero.target_port, 0, "포트 0 음성 데이터 확인");
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
