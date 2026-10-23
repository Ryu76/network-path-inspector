//! 동일 원시 TCP 측정 DTO(`TcpMeasurement`)에 대한 양 제품 실제 프로젝터
//! (`npi_probes::engine::apply_tcp_result`, `network_core::tcp_to_quick_result`)의
//! 순수 회귀 및 특성 규명(characterization) 테스트.
//!
//! 네트워크 I/O, 소켓 생성, DNS 질의, OS 네이티브 호출, 비동기 런타임, 파일 입출력 등이 일체 없는
//! 순수 동기 단위 테스트로만 구성됩니다 (부수 효과 0).

use std::net::SocketAddr;

use network_core::{
    EvidenceLevel, QuickContext, QuickFeature, QuickResult, QuickStatus, TcpMeasurement,
    tcp_to_quick_result,
};
use npi_core::FeatureResult;
use npi_probes::engine::apply_tcp_result;

/// 부모가 작성한 공개 API 가시성 회귀. 소켓·DNS·runtime·프로세스 호출 없음.
#[test]
fn parent_public_projector_signature_contract() {
    let _projector: fn(&mut npi_core::FeatureResult, &network_core::TcpMeasurement) =
        npi_probes::engine::apply_tcp_result;
}

/// 측정값 생성을 위한 보조 매개변수 구조체 (함수 인수 7개 이하 제약 준수).
struct MeasurementParams<'a> {
    target: &'a str,
    outcome: &'a str,
    local_address: Option<&'a str>,
    elapsed_ms: u64,
    error_code: Option<i32>,
    error_message: Option<&'a str>,
    limitations: Vec<String>,
}

/// 테스트 전용 순수 `TcpMeasurement` 합성 헬퍼. 실제 소켓을 호출하지 않는다.
fn build_measurement(params: MeasurementParams<'_>) -> TcpMeasurement {
    TcpMeasurement {
        target: params.target.to_string(),
        outcome: params.outcome.to_string(),
        local_address: params.local_address.map(ToString::to_string),
        elapsed_ms: params.elapsed_ms,
        error_code: params.error_code,
        error_message: params.error_message.map(ToString::to_string),
        application_bytes_sent: 0,
        limitations: params.limitations,
    }
}

/// 계획 단계에서 생성되는 초기 `FeatureResult` 픽스처 생성 헬퍼.
/// stale 증거 ID, 시각, 지속 시간, 오류 코드 등이 포함되어 있어 프로젝터의 초기화 동작을 검증한다.
fn make_test_feature_result() -> FeatureResult {
    FeatureResult {
        feature_id: "tcp_connect".to_string(),
        group_id: "G-NET".to_string(),
        status: "WARN".to_string(),
        classification: Some("UNKNOWN".to_string()),
        evidence_ids: vec![
            "stale-evidence-id-1".to_string(),
            "stale-evidence-id-2".to_string(),
        ],
        started_at_utc: Some("2026-10-23T00:00:00Z".to_string()),
        ended_at_utc: Some("2026-10-23T00:00:01Z".to_string()),
        duration_ms: Some(9999),
        error_code: Some(777),
        limitations: vec!["기존 계획 단계 한계 고지".to_string()],
        next_checks: vec!["기존 계획 단계 다음 점검".to_string()],
    }
}

/// Quick Check 진단 컨텍스트 생성 헬퍼 (함수 인수 2개).
fn make_test_quick_context(target_host: &str, target_port: u16) -> QuickContext {
    QuickContext {
        session_id: "test-replay-session-001".to_string(),
        timestamp_iso8601: Some("2026-10-23T10:00:00Z".to_string()),
        source_host: Some("client-node".to_string()),
        target_host: target_host.to_string(),
        target_port,
    }
}

/// 두 실제 변환기의 공통 보존 축만 검사한다. 제품별 상태를 정규화하지 않는다.
fn assert_shared_preservation(
    ctx: &QuickContext,
    measurement: &TcpMeasurement,
    row: &FeatureResult,
    quick: &QuickResult,
) {
    assert_eq!(row.feature_id, "tcp_connect");
    assert_eq!(row.group_id, "G-NET");
    assert_eq!(row.duration_ms, Some(measurement.elapsed_ms));
    assert_eq!(row.error_code, measurement.error_code.map(i64::from));
    assert!(row.evidence_ids.is_empty());
    assert_eq!(row.started_at_utc, None);
    assert_eq!(row.ended_at_utc, None);
    assert!(row.limitations.starts_with(&measurement.limitations));
    if let Some(message) = &measurement.error_message {
        assert!(
            row.limitations
                .contains(&format!("OS 소켓 오류 메시지: {message}"))
        );
    }
    assert!(!row.next_checks.is_empty());
    assert!(
        !row.next_checks
            .iter()
            .any(|value| value == "기존 계획 단계 다음 점검")
    );
    assert_eq!(quick.os_error_code, measurement.error_code);
    assert_eq!(quick.elapsed_ms, Some(measurement.elapsed_ms));
    assert_eq!(quick.session_id, ctx.session_id);
    assert_eq!(quick.timestamp_iso8601, ctx.timestamp_iso8601);
    assert_eq!(quick.source_host, ctx.source_host);
    assert_eq!(quick.target_host, ctx.target_host);
    assert_eq!(quick.target_port, ctx.target_port);
    assert_eq!(quick.details.as_object().expect("details 객체").len(), 3);
    assert_eq!(
        quick.details["outcome"],
        serde_json::json!(measurement.outcome)
    );
    assert_eq!(
        quick.details["limitations"],
        serde_json::json!(measurement.limitations)
    );
    assert_eq!(
        quick.details["raw_measurement"],
        serde_json::to_value(measurement).unwrap()
    );
}

/// 1. 원시 공유 타입 `TcpMeasurement`의 단일 타입성(Single Type Identity) 및
///    양 제품 프로젝터 호출 전후 원본 불변성(Immutability) 검증.
#[test]
fn shared_tcp_measurement_type_identity_and_immutability() {
    // network_core re-export 타입과 npi_probes 원본 타입이 컴파일 타임에 완벽히 동일한 단일 타입임을 증명.
    let _inspector_projector: fn(&mut FeatureResult, &npi_probes::tcp::TcpMeasurement) =
        apply_tcp_result;
    let _quick_projector: fn(
        &QuickContext,
        &network_core::TcpMeasurement,
    ) -> Result<QuickResult, Vec<String>> = tcp_to_quick_result;

    let measurement = build_measurement(MeasurementParams {
        target: "127.0.0.1:8080",
        outcome: "CONNECTED",
        local_address: Some("127.0.0.1:52100"),
        elapsed_ms: 12,
        error_code: None,
        error_message: None,
        limitations: vec![
            "OS 소켓 API 수준의 관찰 결과입니다.".to_string(),
            "TCP 핸드셰이크 수립만 확인합니다.".to_string(),
        ],
    });

    // 호출 전 원본의 깊은 복사본 및 직렬화 값 저장
    let measurement_before = measurement.clone();
    let serialized_before = serde_json::to_value(&measurement).expect("직렬화 성공");

    let mut inspector_row = make_test_feature_result();
    let quick_ctx = make_test_quick_context("127.0.0.1", 8080);

    // 동일한 단일 &measurement 참조를 두 제품 실제 프로젝터 함수에 순차 전달
    apply_tcp_result(&mut inspector_row, &measurement);
    let quick_result = tcp_to_quick_result(&quick_ctx, &measurement).expect("Quick 프로젝션 성공");

    // 프로젝터 호출 후에도 원본 measurement가 전후 전체 Eq 및 JSON 직렬화 동등성을 완벽히 보존함을 검증
    assert_eq!(measurement, measurement_before);
    assert_eq!(
        serde_json::to_value(&measurement).expect("직렬화 성공"),
        serialized_before
    );
    // 0바이트 전송 불변성 검증 (정상 연결 시에도 애플리케이션 바이트는 0이어야 함)
    assert_eq!(measurement.application_bytes_sent, 0);

    // 정상 공유 관측의 상태 및 근거 수준 축별 확인 (문자열 DTO 전체 동일 요구 금지)
    assert_eq!(inspector_row.status, "PASS");
    assert_eq!(inspector_row.classification.as_deref(), Some("OBSERVED"));
    assert_eq!(quick_result.status, QuickStatus::PASS);
    assert_eq!(quick_result.evidence_level, EvidenceLevel::OBSERVED);
}

/// 2. Inspector 초기 `FeatureResult` 픽스처 정화 및 프로젝션 불변식 검증.
///
/// 주의: 본 raw 적용은 G1 Session/EngineEnvelope 저장 실행 증거가 아니며,
/// FeatureResult는 원시 target이나 local_address 필드를 갖지 않으므로 임의로 발명하지 않습니다.
/// run_profile EngineEnvelope 저장 경로는 본 replay로 실행 검증되지 않습니다.
#[test]
fn inspector_feature_result_fixture_initialization_and_projection() {
    let mut row = make_test_feature_result();

    let measurement = build_measurement(MeasurementParams {
        target: "127.0.0.1:9090",
        outcome: "REFUSED",
        local_address: None,
        elapsed_ms: 25,
        error_code: Some(10061),
        error_message: Some("대상 컴퓨터에서 연결을 거부했으므로 연결하지 못했습니다."),
        limitations: vec!["사용자 정의 입력 한계 1".to_string()],
    });

    apply_tcp_result(&mut row, &measurement);

    // 식별자 불변 보존
    assert_eq!(row.feature_id, "tcp_connect");
    assert_eq!(row.group_id, "G-NET");

    // stale 필드 정화 검증: 원시 측정값은 아카이브 파일이 아니므로 evidence_ids는 반드시 빈 배열([])이어야 함
    assert!(row.evidence_ids.is_empty());
    // 실제 UTC 시각 통합은 후속 단계 대상이므로 null(None)로 유지
    assert_eq!(row.started_at_utc, None);
    assert_eq!(row.ended_at_utc, None);

    // 측정값 반영 확인
    assert_eq!(row.duration_ms, Some(25));
    // i32 -> i64 무손실 확장 검증
    assert_eq!(row.error_code, Some(10061_i64));
    assert_eq!(row.status, "FAIL");
    assert_eq!(row.classification.as_deref(), Some("OBSERVED"));

    // limitations 보존 및 추가 검증: 원래 한계가 맨 앞에 유지되고 OS 오류 메시지와 고정 문구가 덧붙여짐
    assert_eq!(row.limitations[0], "사용자 정의 입력 한계 1");
    assert!(
        row.limitations.contains(
            &"OS 소켓 오류 메시지: 대상 컴퓨터에서 연결을 거부했으므로 연결하지 못했습니다."
                .to_string()
        )
    );
    assert!(row.limitations.contains(&"소켓 연결 결과는 OS API 수준의 관찰값이며 패킷 캡처 없이는 SYN 또는 RST 패킷 실제 관찰이나 차단 장비를 단정할 수 없습니다".to_string()));
    assert!(row.limitations.contains(&"원시 측정값이 영구 아카이브 파일로 저장되지 않았으므로 evidence_ids는 빈 배열([])입니다".to_string()));
}

/// 행렬 검증용 테스트 케이스 정의 구조체.
struct ReplayMatrixCase {
    name: &'static str,
    outcome: &'static str,
    code: Option<i32>,
    error_message: Option<&'static str>,
    expected_inspector_status: &'static str,
    expected_inspector_classification: &'static str,
    expected_quick_status: QuickStatus,
    expected_quick_evidence: EvidenceLevel,
    note: &'static str,
}

/// 3. 계약(`tcp-product-replay-contract.json`) 기준 양 제품 실제 프로젝션 행렬(Replay Matrix)
///    특성 규명(Characterization) 회귀 검증.
///
/// 주의: TIMED_OUT 코드 Some/None, UNREACHABLE 코드 2개, LOCAL_ERROR 코드 None/0/unknown/i32MIN/MAX,
/// CANCELLED 코드 None/0/known, DNS_ERROR/미인식 None/0/unknown은 타입 DTO replay 경계 검증이며,
/// 실제 `connect_once`가 해당 조합을 생성한다는 증거가 아닙니다 (타입 fixture에 의한 계약 특성 규명).
/// 테스트 정규화(normalizer)로 억지로 결과를 통일하거나 실제 projector match를 복제하지 않고 독립 리터럴로 검증합니다.
#[test]
fn tcp_product_projection_matrix_replay() {
    let cases = [
        // 1. CONNECTED: 정상 연결 매핑 (양쪽 일치)
        ReplayMatrixCase {
            name: "정상_연결_CONNECTED",
            outcome: "CONNECTED",
            code: None,
            error_message: None,
            expected_inspector_status: "PASS",
            expected_inspector_classification: "OBSERVED",
            expected_quick_status: QuickStatus::PASS,
            expected_quick_evidence: EvidenceLevel::OBSERVED,
            note: "양 제품 모두 PASS / OBSERVED 일치",
        },
        // 2. REFUSED: 연결 거부 매핑 (양쪽 일치)
        ReplayMatrixCase {
            name: "연결_거부_REFUSED_10061",
            outcome: "REFUSED",
            code: Some(10061),
            error_message: Some("Connection refused"),
            expected_inspector_status: "FAIL",
            expected_inspector_classification: "OBSERVED",
            expected_quick_status: QuickStatus::FAIL,
            expected_quick_evidence: EvidenceLevel::OBSERVED,
            note: "양 제품 모두 FAIL / OBSERVED 일치",
        },
        // 3. RESET: 연결 재설정 매핑 (양쪽 일치)
        ReplayMatrixCase {
            name: "연결_재설정_RESET_10054",
            outcome: "RESET",
            code: Some(10054),
            error_message: Some("Connection reset by peer"),
            expected_inspector_status: "FAIL",
            expected_inspector_classification: "OBSERVED",
            expected_quick_status: QuickStatus::FAIL,
            expected_quick_evidence: EvidenceLevel::OBSERVED,
            note: "양 제품 모두 FAIL / OBSERVED 일치",
        },
        // 4. TIMED_OUT (code None): 타입 DTO replay 경계
        ReplayMatrixCase {
            name: "타임아웃_TIMED_OUT_코드없음",
            outcome: "TIMED_OUT",
            code: None,
            error_message: None,
            expected_inspector_status: "FAIL",
            expected_inspector_classification: "OBSERVED",
            expected_quick_status: QuickStatus::FAIL,
            expected_quick_evidence: EvidenceLevel::OBSERVED,
            note: "타입 DTO replay 경계 (양쪽 FAIL / OBSERVED)",
        },
        // 5. TIMED_OUT (code 10060): 타입 DTO replay 경계
        ReplayMatrixCase {
            name: "타임아웃_TIMED_OUT_10060",
            outcome: "TIMED_OUT",
            code: Some(10060),
            error_message: Some("Connection timed out"),
            expected_inspector_status: "FAIL",
            expected_inspector_classification: "OBSERVED",
            expected_quick_status: QuickStatus::FAIL,
            expected_quick_evidence: EvidenceLevel::OBSERVED,
            note: "타입 DTO replay 경계 (양쪽 FAIL / OBSERVED)",
        },
        // 6. UNREACHABLE (code 10051): 타입 DTO replay 경계
        ReplayMatrixCase {
            name: "도달불가_UNREACHABLE_10051",
            outcome: "UNREACHABLE",
            code: Some(10051),
            error_message: Some("Network unreachable"),
            expected_inspector_status: "FAIL",
            expected_inspector_classification: "OBSERVED",
            expected_quick_status: QuickStatus::FAIL,
            expected_quick_evidence: EvidenceLevel::OBSERVED,
            note: "타입 DTO replay 경계 (양쪽 FAIL / OBSERVED)",
        },
        // 7. UNREACHABLE (code 10065): 타입 DTO replay 경계
        ReplayMatrixCase {
            name: "도달불가_UNREACHABLE_10065",
            outcome: "UNREACHABLE",
            code: Some(10065),
            error_message: Some("Host unreachable"),
            expected_inspector_status: "FAIL",
            expected_inspector_classification: "OBSERVED",
            expected_quick_status: QuickStatus::FAIL,
            expected_quick_evidence: EvidenceLevel::OBSERVED,
            note: "타입 DTO replay 경계 (양쪽 FAIL / OBSERVED)",
        },
        // 8. LOCAL_ERROR (code None): Inspector ERROR/UNKNOWN vs Quick UNKNOWN/OBSERVED
        ReplayMatrixCase {
            name: "로컬오류_LOCAL_ERROR_코드없음",
            outcome: "LOCAL_ERROR",
            code: None,
            error_message: None,
            expected_inspector_status: "ERROR",
            expected_inspector_classification: "UNKNOWN",
            expected_quick_status: QuickStatus::UNKNOWN,
            expected_quick_evidence: EvidenceLevel::OBSERVED,
            note: "Inspector=ERROR/UNKNOWN vs Quick=UNKNOWN/OBSERVED 특성 유지",
        },
        // 9. LOCAL_ERROR (code Some(0)): Inspector ERROR/OBSERVED vs Quick UNKNOWN/OBSERVED
        ReplayMatrixCase {
            name: "로컬오류_LOCAL_ERROR_코드0",
            outcome: "LOCAL_ERROR",
            code: Some(0),
            error_message: Some("Local socket error 0"),
            expected_inspector_status: "ERROR",
            expected_inspector_classification: "OBSERVED",
            expected_quick_status: QuickStatus::UNKNOWN,
            expected_quick_evidence: EvidenceLevel::OBSERVED,
            note: "code Some(0) 구분: Inspector=ERROR/OBSERVED vs Quick=UNKNOWN/OBSERVED",
        },
        // 10. LOCAL_ERROR (code Some(99999)): 미정의 오류 코드
        ReplayMatrixCase {
            name: "로컬오류_LOCAL_ERROR_미정의코드",
            outcome: "LOCAL_ERROR",
            code: Some(99999),
            error_message: Some("Unknown winsock code"),
            expected_inspector_status: "ERROR",
            expected_inspector_classification: "OBSERVED",
            expected_quick_status: QuickStatus::UNKNOWN,
            expected_quick_evidence: EvidenceLevel::OBSERVED,
            note: "Inspector=ERROR/OBSERVED vs Quick=UNKNOWN/OBSERVED",
        },
        // 11. LOCAL_ERROR (code Some(i32::MIN)): 정수 경계값
        ReplayMatrixCase {
            name: "로컬오류_LOCAL_ERROR_i32MIN",
            outcome: "LOCAL_ERROR",
            code: Some(i32::MIN),
            error_message: Some("i32::MIN error code"),
            expected_inspector_status: "ERROR",
            expected_inspector_classification: "OBSERVED",
            expected_quick_status: QuickStatus::UNKNOWN,
            expected_quick_evidence: EvidenceLevel::OBSERVED,
            note: "i32::MIN 무손실 검증",
        },
        // 12. LOCAL_ERROR (code Some(i32::MAX)): 정수 경계값
        ReplayMatrixCase {
            name: "로컬오류_LOCAL_ERROR_i32MAX",
            outcome: "LOCAL_ERROR",
            code: Some(i32::MAX),
            error_message: Some("i32::MAX error code"),
            expected_inspector_status: "ERROR",
            expected_inspector_classification: "OBSERVED",
            expected_quick_status: QuickStatus::UNKNOWN,
            expected_quick_evidence: EvidenceLevel::OBSERVED,
            note: "i32::MAX 무손실 검증",
        },
        // 13. CANCELLED (code None): 사용자 취소 (Inspector CANCELLED/UNKNOWN vs Quick UNKNOWN/UNKNOWN)
        ReplayMatrixCase {
            name: "취소_CANCELLED_코드없음",
            outcome: "CANCELLED",
            code: None,
            error_message: None,
            expected_inspector_status: "CANCELLED",
            expected_inspector_classification: "UNKNOWN",
            expected_quick_status: QuickStatus::UNKNOWN,
            expected_quick_evidence: EvidenceLevel::UNKNOWN,
            note: "Inspector=CANCELLED/UNKNOWN vs Quick=UNKNOWN/UNKNOWN (절대 FAIL 위장 금지)",
        },
        // 14. CANCELLED (code Some(0)): 취소 시 코드 존재
        ReplayMatrixCase {
            name: "취소_CANCELLED_코드0",
            outcome: "CANCELLED",
            code: Some(0),
            error_message: None,
            expected_inspector_status: "CANCELLED",
            expected_inspector_classification: "UNKNOWN",
            expected_quick_status: QuickStatus::UNKNOWN,
            expected_quick_evidence: EvidenceLevel::UNKNOWN,
            note: "코드 유무 무관하게 취소 우선 처리",
        },
        // 15. CANCELLED (code Some(10061)): 취소 시 소켓 오류 코드 존재
        ReplayMatrixCase {
            name: "취소_CANCELLED_코드10061",
            outcome: "CANCELLED",
            code: Some(10061),
            error_message: Some("Operation cancelled with error"),
            expected_inspector_status: "CANCELLED",
            expected_inspector_classification: "UNKNOWN",
            expected_quick_status: QuickStatus::UNKNOWN,
            expected_quick_evidence: EvidenceLevel::UNKNOWN,
            note: "취소 우선권 보장",
        },
        // 16. DNS_ERROR (code None): Inspector ERROR/UNKNOWN vs Quick FAIL/OBSERVED
        ReplayMatrixCase {
            name: "DNS오류_DNS_ERROR_코드없음",
            outcome: "DNS_ERROR",
            code: None,
            error_message: None,
            expected_inspector_status: "ERROR",
            expected_inspector_classification: "UNKNOWN",
            expected_quick_status: QuickStatus::FAIL,
            expected_quick_evidence: EvidenceLevel::OBSERVED,
            note: "Inspector=ERROR/UNKNOWN vs Quick=FAIL/OBSERVED 특성 유지",
        },
        // 17. DNS_ERROR (code Some(11001)): Inspector ERROR/OBSERVED vs Quick FAIL/OBSERVED
        ReplayMatrixCase {
            name: "DNS오류_DNS_ERROR_11001",
            outcome: "DNS_ERROR",
            code: Some(11001),
            error_message: Some("Host not found (WSAHOST_NOT_FOUND)"),
            expected_inspector_status: "ERROR",
            expected_inspector_classification: "OBSERVED",
            expected_quick_status: QuickStatus::FAIL,
            expected_quick_evidence: EvidenceLevel::OBSERVED,
            note: "Inspector=ERROR/OBSERVED vs Quick=FAIL/OBSERVED 특성 유지",
        },
        // 18. 미인식 outcome (코드 없음): Inspector ERROR/UNKNOWN vs Quick UNKNOWN/UNKNOWN
        ReplayMatrixCase {
            name: "미인식_STRANGE_OUTCOME_코드없음",
            outcome: "STRANGE_OUTCOME",
            code: None,
            error_message: None,
            expected_inspector_status: "ERROR",
            expected_inspector_classification: "UNKNOWN",
            expected_quick_status: QuickStatus::UNKNOWN,
            expected_quick_evidence: EvidenceLevel::UNKNOWN,
            note: "미인식 outcome 안전 처리",
        },
        // 19. 미인식 outcome (code Some(0)): Inspector ERROR/OBSERVED vs Quick UNKNOWN/UNKNOWN
        ReplayMatrixCase {
            name: "미인식_STRANGE_OUTCOME_코드0",
            outcome: "STRANGE_OUTCOME",
            code: Some(0),
            error_message: Some("Unknown outcome with code 0"),
            expected_inspector_status: "ERROR",
            expected_inspector_classification: "OBSERVED",
            expected_quick_status: QuickStatus::UNKNOWN,
            expected_quick_evidence: EvidenceLevel::UNKNOWN,
            note: "미인식 outcome에 code Some(0) 존재 시 Inspector는 OBSERVED 분류",
        },
        // 20. 미인식 outcome (code Some(99999)): Inspector ERROR/OBSERVED vs Quick UNKNOWN/UNKNOWN
        ReplayMatrixCase {
            name: "미인식_STRANGE_OUTCOME_코드99999",
            outcome: "STRANGE_OUTCOME",
            code: Some(99999),
            error_message: Some("Unknown outcome with code 99999"),
            expected_inspector_status: "ERROR",
            expected_inspector_classification: "OBSERVED",
            expected_quick_status: QuickStatus::UNKNOWN,
            expected_quick_evidence: EvidenceLevel::UNKNOWN,
            note: "Inspector=ERROR/OBSERVED vs Quick=UNKNOWN/UNKNOWN",
        },
        // 21. 빈 문자열 outcome: Inspector ERROR/UNKNOWN vs Quick UNKNOWN/UNKNOWN
        ReplayMatrixCase {
            name: "미인식_빈문자열_outcome",
            outcome: "",
            code: None,
            error_message: None,
            expected_inspector_status: "ERROR",
            expected_inspector_classification: "UNKNOWN",
            expected_quick_status: QuickStatus::UNKNOWN,
            expected_quick_evidence: EvidenceLevel::UNKNOWN,
            note: "빈 문자열 outcome 안전 처리",
        },
    ];

    let quick_ctx = make_test_quick_context("127.0.0.1", 8080);

    for case in &cases {
        let measurement = build_measurement(MeasurementParams {
            target: "127.0.0.1:8080",
            outcome: case.outcome,
            local_address: None,
            elapsed_ms: 10,
            error_code: case.code,
            error_message: case.error_message,
            limitations: vec![],
        });

        let before = measurement.clone();
        // 1. Inspector 실제 프로젝터 호출 및 독립 literal 검증
        let mut row = make_test_feature_result();
        apply_tcp_result(&mut row, &measurement);
        assert_eq!(
            row.status, case.expected_inspector_status,
            "case [{}] Inspector status 불일치 ({})",
            case.name, case.note
        );
        assert_eq!(
            row.classification.as_deref(),
            Some(case.expected_inspector_classification),
            "case [{}] Inspector classification 불일치 ({})",
            case.name,
            case.note
        );

        // 2. Quick 실제 어댑터 호출 및 독립 literal 검증
        let quick_res = tcp_to_quick_result(&quick_ctx, &measurement)
            .unwrap_or_else(|err| panic!("case [{}] Quick 프로젝션 실패: {:?}", case.name, err));
        assert_eq!(
            quick_res.status, case.expected_quick_status,
            "case [{}] Quick status 불일치 ({})",
            case.name, case.note
        );
        assert_eq!(
            quick_res.evidence_level, case.expected_quick_evidence,
            "case [{}] Quick evidence_level 불일치 ({})",
            case.name, case.note
        );
        assert_shared_preservation(&quick_ctx, &measurement, &row, &quick_res);
        assert_eq!(measurement, before);
    }
}

/// 4. 측정 입력 차원(IPv4/IPv6, local_address, elapsed_ms, error_message, limitations)
///    행렬 검증 및 Quick details 3키/raw_measurement 직렬화 동등성 보존 검증.
///
/// 조합은 합성 DTO 보존 시험이며 실제 연결·주소 계열 선택·경과시간 관측의 증거가 아니다.
#[test]
fn tcp_replay_input_dimensions_and_preservation() {
    let targets = [
        ("127.0.0.1:8080", "127.0.0.1", 8080_u16),
        ("[::1]:8080", "::1", 8080_u16),
    ];
    let local_addrs = [Some("127.0.0.1:54321"), Some("[::1]:54321"), None];
    let elapsed_values = [0_u64, 1234_u64, u64::MAX];
    let error_messages = [
        None,
        Some("오류 메시지: 한글 및 CRLF\r\n\"따옴표\" \\역슬래시\\ 특수문자 포함"),
    ];
    let limitations_inputs = [
        vec![],
        vec![
            "한계 A: 원래 순서 1".to_string(),
            "한계 B: 원래 순서 2".to_string(),
            "한계 A: 원래 순서 1".to_string(),
        ],
    ];

    for (target_str, ctx_host, port) in targets {
        for local_addr in local_addrs {
            for elapsed in elapsed_values {
                for &err_msg in &error_messages {
                    for lims in &limitations_inputs {
                        let measurement = build_measurement(MeasurementParams {
                            target: target_str,
                            outcome: "CONNECTED",
                            local_address: local_addr,
                            elapsed_ms: elapsed,
                            error_code: None,
                            error_message: err_msg,
                            limitations: lims.clone(),
                        });

                        let before = measurement.clone();
                        let mut ctx = make_test_quick_context(ctx_host, port);
                        // nullable 메타데이터도 그대로 보존하며 값을 합성하지 않아야 한다.
                        if local_addr.is_none() {
                            ctx.source_host = None;
                            ctx.timestamp_iso8601 = None;
                        }
                        let mut row = make_test_feature_result();

                        // 두 실제 함수에 동일 measurement 전달
                        apply_tcp_result(&mut row, &measurement);
                        let quick_res =
                            tcp_to_quick_result(&ctx, &measurement).expect("Quick 프로젝션 성공");
                        assert_shared_preservation(&ctx, &measurement, &row, &quick_res);
                        assert_eq!(measurement, before);

                        // --- Inspector 보존성 검증 ---
                        assert_eq!(row.duration_ms, Some(elapsed));
                        assert_eq!(row.error_code, None);
                        // limitations 원본 순서 및 중복 보존 확인
                        for (idx, orig_lim) in lims.iter().enumerate() {
                            assert_eq!(&row.limitations[idx], orig_lim);
                        }

                        // --- Quick details 정확 3키 및 직렬화 동등성 검증 ---
                        let details_obj = quick_res.details.as_object().expect("details는 객체");
                        assert_eq!(details_obj.len(), 3, "details 키는 정확히 3개여야 함");
                        assert!(details_obj.contains_key("outcome"));
                        assert!(details_obj.contains_key("limitations"));
                        assert!(details_obj.contains_key("raw_measurement"));

                        assert_eq!(details_obj["outcome"].as_str(), Some("CONNECTED"));
                        assert_eq!(
                            details_obj["limitations"],
                            serde_json::to_value(&measurement.limitations).expect("직렬화")
                        );
                        assert_eq!(
                            details_obj["raw_measurement"],
                            serde_json::to_value(&measurement).expect("직렬화")
                        );

                        // Quick 컨텍스트 메타데이터 및 IP 귀속(attribution) 검증
                        assert_eq!(quick_res.schema_version, "1.0");
                        assert_eq!(quick_res.product, "network-quick-check");
                        assert_eq!(quick_res.session_id, "test-replay-session-001");
                        assert_eq!(quick_res.target_host, ctx_host);
                        assert_eq!(quick_res.target_port, port);
                        assert_eq!(quick_res.feature, QuickFeature::TcpConnect);
                        assert_eq!(quick_res.elapsed_ms, Some(elapsed));
                        assert_eq!(quick_res.os_error_code, None);

                        let parsed_sock: SocketAddr = target_str.parse().expect("소켓 파싱");
                        assert_eq!(quick_res.resolved_ip, Some(parsed_sock.ip().to_string()));
                    }
                }
            }
        }
    }
}

/// 5. Quick Check 컨텍스트 교차 오염 방지 및 오류 코드 무손실 변환(i32 -> i64 / i32) 검증.
#[test]
fn quick_context_attribution_and_error_code_preservation() {
    // 1. 포트 불일치 시 교차 오염 방지 거부 검증
    let ctx_port_mismatch = make_test_quick_context("127.0.0.1", 8080);
    let meas_port_mismatch = build_measurement(MeasurementParams {
        target: "127.0.0.1:9090",
        outcome: "CONNECTED",
        local_address: None,
        elapsed_ms: 5,
        error_code: None,
        error_message: None,
        limitations: vec![],
    });
    let err_port = tcp_to_quick_result(&ctx_port_mismatch, &meas_port_mismatch)
        .expect_err("포트 불일치 거부 필수");
    assert!(
        err_port
            .iter()
            .any(|msg| msg.contains("포트 교차 오염 방지")),
        "포트 교차 오염 오류 메시지 포함 확인: {:?}",
        err_port
    );

    // 2. IP 리터럴 불일치 시 거부 검증
    let ctx_ip_mismatch = make_test_quick_context("127.0.0.1", 8080);
    let meas_ip_mismatch = build_measurement(MeasurementParams {
        target: "127.0.0.2:8080",
        outcome: "CONNECTED",
        local_address: None,
        elapsed_ms: 5,
        error_code: None,
        error_message: None,
        limitations: vec![],
    });
    let err_ip =
        tcp_to_quick_result(&ctx_ip_mismatch, &meas_ip_mismatch).expect_err("IP 불일치 거부 필수");
    assert!(
        err_ip.iter().any(|msg| msg.contains("IP 불일치 방지")),
        "IP 불일치 방지 오류 메시지 포함 확인: {:?}",
        err_ip
    );

    // 3. 오류 코드 무손실 보존 검증 (None, Some(0), Some(i32::MIN), Some(i32::MAX))
    let code_cases: [(Option<i32>, Option<i64>); 4] = [
        (None, None),
        (Some(0), Some(0_i64)),
        (Some(i32::MIN), Some(i32::MIN as i64)),
        (Some(i32::MAX), Some(i32::MAX as i64)),
    ];

    let ctx_valid = make_test_quick_context("127.0.0.1", 8080);

    for (raw_code, expected_inspector_code) in code_cases {
        let measurement = build_measurement(MeasurementParams {
            target: "127.0.0.1:8080",
            outcome: "LOCAL_ERROR",
            local_address: None,
            elapsed_ms: 15,
            error_code: raw_code,
            error_message: Some("오류 코드 보존 시험"),
            limitations: vec![],
        });

        let mut row = make_test_feature_result();
        apply_tcp_result(&mut row, &measurement);
        let quick_res = tcp_to_quick_result(&ctx_valid, &measurement).expect("Quick 프로젝션 성공");

        // Inspector는 i64로 무손실 확장 보존
        assert_eq!(
            row.error_code, expected_inspector_code,
            "Inspector error_code 무손실 보존 불일치 (입력: {:?})",
            raw_code
        );
        // Quick은 i32로 원본 그대로 보존
        assert_eq!(
            quick_res.os_error_code, raw_code,
            "Quick os_error_code 원본 보존 불일치 (입력: {:?})",
            raw_code
        );
    }
}
