use serde_json::Value;

// 부모 독립 회귀: 제한사항에 인용된 금지 문구는 긍정 판정이 아니다.
#[test]
fn capture_unavailable_warning_quotes_are_valid_without_packet_evidence() {
    let value: Value = serde_json::from_str(include_str!(
        "../../../fixtures/g1/valid_capture_unavailable.json"
    ))
    .unwrap();
    assert_eq!(npi_core::validate_session(&value), Ok(()));
}

#[test]
fn last_hop_warning_in_limitations_is_not_a_blocking_device_assertion() {
    let value: Value = serde_json::from_str(include_str!(
        "../../../fixtures/g1/valid_timeout_unknown_blocker.json"
    ))
    .unwrap();
    assert_eq!(npi_core::validate_session(&value), Ok(()));
}

#[test]
fn positive_claim_in_statement_is_still_rejected_despite_negative_limitation() {
    let mut value: Value = serde_json::from_str(include_str!(
        "../../../fixtures/g1/valid_socket_connected.json"
    ))
    .unwrap();
    value["findings"][0]["statement"] = "방화벽 차단 확정. 미확인 사항 없음.".into();
    value["limitations"] = serde_json::json!(["차단 장비로 확정하면 안 됨"]);
    assert!(npi_core::validate_session(&value).is_err());
}
