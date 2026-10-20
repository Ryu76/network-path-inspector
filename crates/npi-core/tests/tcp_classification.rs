use std::collections::BTreeSet;

#[test]
fn cancelled_takes_highest_priority_over_timeout_and_code() {
    // 취소 플래그는 시간초과 및 모든 오류 코드보다 우선한다.
    assert_eq!(
        npi_core::classify_tcp_error(Some(10061), true, true),
        "CANCELLED"
    );
    assert_eq!(npi_core::classify_tcp_error(None, false, true), "CANCELLED");
}

#[test]
fn explicit_timeout_takes_priority_over_error_code_when_not_cancelled() {
    // 취소되지 않은 경우 명시적 데드라인 만료(timed_out)가 오류 코드보다 우선한다.
    assert_eq!(
        npi_core::classify_tcp_error(Some(10061), true, false),
        "TIMED_OUT"
    );
    assert_eq!(npi_core::classify_tcp_error(None, true, false), "TIMED_OUT");
}

#[test]
fn code_10061_maps_to_refused_as_os_socket_observation() {
    // Winsock 10061은 OS 소켓 수준의 연결 거부(REFUSED)이며 실제 RST 패킷 캡처 관찰과 동일하지 않다.
    assert_eq!(
        npi_core::classify_tcp_error(Some(10061), false, false),
        "REFUSED"
    );
}

#[test]
fn code_10060_maps_to_timed_out() {
    assert_eq!(
        npi_core::classify_tcp_error(Some(10060), false, false),
        "TIMED_OUT"
    );
}

#[test]
fn code_10051_maps_to_unreachable() {
    assert_eq!(
        npi_core::classify_tcp_error(Some(10051), false, false),
        "UNREACHABLE"
    );
}

#[test]
fn code_10065_maps_to_unreachable() {
    assert_eq!(
        npi_core::classify_tcp_error(Some(10065), false, false),
        "UNREACHABLE"
    );
}

#[test]
fn code_10050_maps_to_local_error() {
    assert_eq!(
        npi_core::classify_tcp_error(Some(10050), false, false),
        "LOCAL_ERROR"
    );
}

#[test]
fn code_10013_maps_to_local_error() {
    assert_eq!(
        npi_core::classify_tcp_error(Some(10013), false, false),
        "LOCAL_ERROR"
    );
}

#[test]
fn code_10054_maps_to_local_error() {
    assert_eq!(
        npi_core::classify_tcp_error(Some(10054), false, false),
        "LOCAL_ERROR"
    );
}

#[test]
fn code_11001_maps_to_dns_error() {
    assert_eq!(
        npi_core::classify_tcp_error(Some(11001), false, false),
        "DNS_ERROR"
    );
}

#[test]
fn code_11004_maps_to_dns_error() {
    assert_eq!(
        npi_core::classify_tcp_error(Some(11004), false, false),
        "DNS_ERROR"
    );
}

#[test]
fn missing_zero_or_unknown_codes_map_to_local_error_never_connected() {
    // 누락(None), 0, 미정의 코드는 모두 LOCAL_ERROR로 처리하며 절대 CONNECTED를 반환하지 않는다.
    for sample in [None, Some(0), Some(-1), Some(99999)] {
        let classified = npi_core::classify_tcp_error(sample, false, false);
        assert_eq!(classified, "LOCAL_ERROR");
        assert_ne!(classified, "CONNECTED");
    }
}

#[test]
fn tcp_outcome_serde_uses_screaming_snake_case() {
    let cases = [
        (npi_core::TcpOutcome::Connected, "CONNECTED"),
        (npi_core::TcpOutcome::Refused, "REFUSED"),
        (npi_core::TcpOutcome::TimedOut, "TIMED_OUT"),
        (npi_core::TcpOutcome::Unreachable, "UNREACHABLE"),
        (npi_core::TcpOutcome::LocalError, "LOCAL_ERROR"),
        (npi_core::TcpOutcome::DnsError, "DNS_ERROR"),
        (npi_core::TcpOutcome::Cancelled, "CANCELLED"),
    ];
    for (variant, expected_str) in cases {
        assert_eq!(variant.as_str(), expected_str);
        let json = serde_json::to_string(&variant).expect("직렬화 성공");
        assert_eq!(json, format!("\"{expected_str}\""));
        let decoded: npi_core::TcpOutcome = serde_json::from_str(&json).expect("역직렬화 성공");
        assert_eq!(decoded, variant);
    }
}

#[test]
fn canonical_registry_has_23_features_and_6_groups() {
    let registry = npi_core::canonical_registry();
    let features = registry
        .as_array()
        .expect("정규 레지스트리는 배열이어야 합니다");
    assert_eq!(features.len(), 23);

    let feature_ids: BTreeSet<&str> = features
        .iter()
        .map(|item| {
            item.get("feature_id")
                .and_then(|v| v.as_str())
                .expect("feature_id 문자열 필수")
        })
        .collect();
    assert_eq!(feature_ids.len(), 23);

    let groups: BTreeSet<&str> = features
        .iter()
        .map(|item| {
            item.get("group_id")
                .and_then(|v| v.as_str())
                .expect("group_id 문자열 필수")
        })
        .collect();
    let expected_groups = BTreeSet::from(["G-NET", "G-PATH", "G-PKT", "G-PAIR", "G-OPS", "G-EVID"]);
    assert_eq!(groups, expected_groups);
}

#[test]
fn canonical_registry_has_5_default_selected_and_packet_capture_unselected() {
    let registry = npi_core::canonical_registry();
    let features = registry
        .as_array()
        .expect("정규 레지스트리는 배열이어야 합니다");

    let default_selected: BTreeSet<&str> = features
        .iter()
        .filter(|item| {
            item.get("default_selected")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        })
        .map(|item| {
            item.get("feature_id")
                .and_then(|v| v.as_str())
                .expect("feature_id 문자열 필수")
        })
        .collect();

    let expected_defaults = BTreeSet::from([
        "tcp_connect",
        "icmp_ping",
        "route_table",
        "nic_inventory",
        "result_json",
    ]);
    assert_eq!(default_selected.len(), 5);
    assert_eq!(default_selected, expected_defaults);
    assert!(!default_selected.contains("packet_capture"));
}
