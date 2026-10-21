//! Network Quick Check(Part B) `measurements` 어댑터 순수 단위 테스트.
//!
//! 모든 테스트 픽스처는 인라인 합성(synthetic) 데이터만을 사용하며,
//! 실제 소켓 통신, DNS 질의, OS API 호출, 서브프로세스 실행, 파일 쓰기 등의
//! 부수 효과를 일체 발생시키지 않습니다 (부수 효과 0).

use network_core::host::{
    AdapterEntry, HostSnapshot, PrefixEntry, RouteEntry, SelectedRouteEntry, UnicastAddressEntry,
};
use network_core::icmp::IcmpMeasurement;
use network_core::measurements::{host_to_quick_result, icmp_to_quick_result};
use network_core::quick::{EvidenceLevel, QuickContext, QuickFeature, QuickResult, QuickStatus};

/// 합성(synthetic) 기본 컨텍스트 생성 헬퍼.
fn create_synthetic_context(target_host: &str, target_port: u16) -> QuickContext {
    QuickContext {
        session_id: "synthetic-session-icmp-001".to_string(),
        timestamp_iso8601: Some("2026-10-21T03:30:00Z".to_string()),
        source_host: Some("synthetic-client-node".to_string()),
        target_host: target_host.to_string(),
        target_port,
    }
}

/// 합성(synthetic) 어댑터 엔트리 생성 헬퍼.
fn create_synthetic_adapter_entry() -> AdapterEntry {
    AdapterEntry {
        interface_index: 12,
        ipv6_interface_index: 12,
        name: "{00000000-0000-0000-0000-000000000001}".to_string(),
        adapter_name: "synthetic-eth0".to_string(),
        friendly_name: "Synthetic Ethernet Adapter".to_string(),
        description: "Synthetic Testing Network Adapter".to_string(),
        dns_suffix: "synthetic.local".to_string(),
        operational_status: "Up".to_string(),
        oper_status_code: 1,
        ips: vec!["192.168.1.50".to_string()],
        unicast_addresses: vec![UnicastAddressEntry {
            ip: "192.168.1.50".to_string(),
            prefix_length: 24,
        }],
        prefixes: vec!["192.168.1.0/24".to_string()],
        prefix_entries: vec![PrefixEntry {
            prefix: "192.168.1.0".to_string(),
            prefix_length: 24,
            cidr: "192.168.1.0/24".to_string(),
        }],
        gateways: vec!["192.168.1.1".to_string()],
        dns_servers: vec!["1.1.1.1".to_string()],
    }
}

/// 합성(synthetic) 라우트 엔트리 생성 헬퍼.
fn create_synthetic_route_entry() -> RouteEntry {
    RouteEntry {
        destination_prefix: "0.0.0.0/0".to_string(),
        prefix: "0.0.0.0".to_string(),
        prefix_ip: "0.0.0.0".to_string(),
        prefix_length: 0,
        next_hop: "192.168.1.1".to_string(),
        metric: 25,
        interface_index: 12,
        interface_luid: 1688849860263936,
        protocol: 3,
        origin: 3,
        loopback: false,
    }
}

/// 합성(synthetic) 선택 라우트 엔트리 생성 헬퍼.
fn create_synthetic_selected_route_entry(
    target: &str,
    remote_connectivity_evidence: bool,
) -> SelectedRouteEntry {
    SelectedRouteEntry {
        target: target.to_string(),
        source_ip: "192.168.1.50".to_string(),
        interface_index: 12,
        interface_luid: 1688849860263936,
        destination_prefix: "0.0.0.0/0".to_string(),
        prefix: "0.0.0.0".to_string(),
        prefix_ip: "0.0.0.0".to_string(),
        prefix_length: 0,
        next_hop: "192.168.1.1".to_string(),
        metric: 25,
        selection_basis: "GetBestRoute2".to_string(),
        remote_connectivity_evidence,
        note: "synthetic test selected route".to_string(),
    }
}

// ----------------------------------------------------------------------------
// ICMP 어댑터 단위 테스트
// ----------------------------------------------------------------------------

/// 1. ICMP 어댑터의 모든 outcome 매핑이 고정 계약(frozen contract)과 일치하는지 검증.
#[test]
fn test_icmp_adapter_all_contract_outcomes_mapped_correctly() {
    let ctx = create_synthetic_context("127.0.0.1", 80);

    let cases = [
        ("REPLY", QuickStatus::PASS, EvidenceLevel::OBSERVED),
        ("TIMEOUT", QuickStatus::FAIL, EvidenceLevel::OBSERVED),
        ("UNREACHABLE", QuickStatus::FAIL, EvidenceLevel::OBSERVED),
        ("LOCAL_ERROR", QuickStatus::UNKNOWN, EvidenceLevel::OBSERVED),
        ("CANCELLED", QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN),
        ("UNAVAILABLE", QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN),
        (
            "SYNTHETIC_UNKNOWN_OUTCOME",
            QuickStatus::UNKNOWN,
            EvidenceLevel::UNKNOWN,
        ),
        ("", QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN),
    ];

    for (outcome, expected_status, expected_evidence) in cases {
        let measurement = IcmpMeasurement {
            target: "127.0.0.1".to_string(),
            outcome: outcome.to_string(),
            elapsed_ms: 5,
            ip_status: None,
            error_code: None,
            rtt_ms: if outcome == "REPLY" { Some(2) } else { None },
            ttl: if outcome == "REPLY" { Some(128) } else { None },
            limitations: vec!["[합성(synthetic) ICMP 측정 데이터]".to_string()],
        };

        let result = icmp_to_quick_result(&ctx, &measurement)
            .unwrap_or_else(|errs| panic!("ICMP outcome '{outcome}' 변환 실패: {errs:?}"));

        assert_eq!(result.status, expected_status, "outcome: {outcome}");
        assert_eq!(
            result.evidence_level, expected_evidence,
            "outcome: {outcome}"
        );
        assert_eq!(result.feature, QuickFeature::IcmpPing);
        assert_eq!(result.schema_version, "1.0");
        assert_eq!(result.product, "network-quick-check");
        assert_eq!(result.elapsed_ms, Some(5));
    }
}

/// 2. ICMP IPv4 및 IPv6 정상 귀속 및 resolved_ip 유도 검증.
#[test]
fn test_icmp_adapter_ipv4_and_ipv6_attribution_and_resolved_ip() {
    // IPv4 케이스
    let ctx_v4 = create_synthetic_context("127.0.0.1", 80);
    let meas_v4 = IcmpMeasurement {
        target: "127.0.0.1".to_string(),
        outcome: "REPLY".to_string(),
        elapsed_ms: 1,
        ip_status: Some(0),
        error_code: None,
        rtt_ms: Some(1),
        ttl: Some(64),
        limitations: vec![],
    };
    let res_v4 = icmp_to_quick_result(&ctx_v4, &meas_v4).expect("IPv4 변환 성공");
    assert_eq!(res_v4.resolved_ip, Some("127.0.0.1".to_string()));
    assert_eq!(res_v4.target_host, "127.0.0.1");

    // IPv6 케이스
    let ctx_v6 = create_synthetic_context("::1", 443);
    let meas_v6 = IcmpMeasurement {
        target: "::1".to_string(),
        outcome: "REPLY".to_string(),
        elapsed_ms: 1,
        ip_status: Some(0),
        error_code: None,
        rtt_ms: Some(1),
        ttl: None,
        limitations: vec![],
    };
    let res_v6 = icmp_to_quick_result(&ctx_v6, &meas_v6).expect("IPv6 변환 성공");
    assert_eq!(res_v6.resolved_ip, Some("::1".to_string()));
    assert_eq!(res_v6.target_host, "::1");
}

/// 3. ICMP 대상 IP 불일치 시 교차 오염 방지 오류 반환 검증.
#[test]
fn test_icmp_adapter_target_ip_mismatch_rejected() {
    let ctx = create_synthetic_context("127.0.0.1", 80);
    let measurement = IcmpMeasurement {
        target: "192.168.1.1".to_string(),
        outcome: "REPLY".to_string(),
        elapsed_ms: 2,
        ip_status: Some(0),
        error_code: None,
        rtt_ms: Some(2),
        ttl: Some(64),
        limitations: vec![],
    };

    let err = icmp_to_quick_result(&ctx, &measurement).expect_err("IP 불일치 거부 기대");
    assert!(
        err.iter().any(|msg| msg.contains("일치하지 않습니다")),
        "오류 메시지에 IP 불일치 내용 포함 확인: {err:?}"
    );
}

/// 4. ICMP 컨텍스트가 도메인인 경우 원본 target_host 보존 및 실측 IP 유도 검증 (DNS 조회 0회).
#[test]
fn test_icmp_adapter_domain_context_keeps_raw_host_and_inferred_resolved_ip() {
    let ctx = create_synthetic_context("synthetic.service.local", 1521);
    let measurement = IcmpMeasurement {
        target: "10.0.0.5".to_string(),
        outcome: "REPLY".to_string(),
        elapsed_ms: 8,
        ip_status: Some(0),
        error_code: None,
        rtt_ms: Some(7),
        ttl: Some(128),
        limitations: vec![],
    };

    let res = icmp_to_quick_result(&ctx, &measurement).expect("도메인 컨텍스트 변환 성공");
    assert_eq!(res.target_host, "synthetic.service.local");
    assert_eq!(res.resolved_ip, Some("10.0.0.5".to_string()));
    assert_eq!(res.status, QuickStatus::PASS);
}

/// 5. ICMP 측정 대상이 IP로 파싱되지 않는 경우 resolved_ip가 null로 유지되며 임의 발명되지 않음을 검증.
#[test]
fn test_icmp_adapter_non_ip_target_keeps_resolved_ip_null() {
    let ctx = create_synthetic_context("unresolved-node", 80);
    let measurement = IcmpMeasurement {
        target: "unresolved-node".to_string(),
        outcome: "LOCAL_ERROR".to_string(),
        elapsed_ms: 0,
        ip_status: None,
        error_code: Some(11001),
        rtt_ms: None,
        ttl: None,
        limitations: vec!["[합성(synthetic) 미해석 타겟]".to_string()],
    };

    let res = icmp_to_quick_result(&ctx, &measurement).expect("미해석 타겟 변환 성공");
    assert_eq!(res.resolved_ip, None);
    assert_eq!(res.target_host, "unresolved-node");
    assert_eq!(res.status, QuickStatus::UNKNOWN);
    assert_eq!(res.evidence_level, EvidenceLevel::OBSERVED);
}

/// 6. ICMP 컨텍스트 메타데이터 유효성 검사 실패 케이스 검증.
#[test]
fn test_icmp_adapter_invalid_context_rejected() {
    let valid_meas = IcmpMeasurement {
        target: "127.0.0.1".to_string(),
        outcome: "REPLY".to_string(),
        elapsed_ms: 2,
        ip_status: Some(0),
        error_code: None,
        rtt_ms: Some(2),
        ttl: Some(64),
        limitations: vec![],
    };

    // 1) 빈 session_id
    let mut ctx = create_synthetic_context("127.0.0.1", 80);
    ctx.session_id = "   ".to_string();
    assert!(icmp_to_quick_result(&ctx, &valid_meas).is_err());

    // 2) 빈 target_host
    let mut ctx = create_synthetic_context("127.0.0.1", 80);
    ctx.target_host = "   ".to_string();
    assert!(icmp_to_quick_result(&ctx, &valid_meas).is_err());

    // 3) 포트 0
    let ctx = create_synthetic_context("127.0.0.1", 0);
    assert!(icmp_to_quick_result(&ctx, &valid_meas).is_err());

    // 4) 빈 source_host (Some인데 공백)
    let mut ctx = create_synthetic_context("127.0.0.1", 80);
    ctx.source_host = Some("  ".to_string());
    assert!(icmp_to_quick_result(&ctx, &valid_meas).is_err());
}

/// 7. ICMP 컨텍스트의 잘못된 타임스탬프 형식 거부 검증.
#[test]
fn test_icmp_adapter_invalid_timestamp_rejected() {
    let valid_meas = IcmpMeasurement {
        target: "127.0.0.1".to_string(),
        outcome: "REPLY".to_string(),
        elapsed_ms: 2,
        ip_status: Some(0),
        error_code: None,
        rtt_ms: Some(2),
        ttl: Some(64),
        limitations: vec![],
    };

    let invalid_ts = [
        "",
        "not-a-date",
        "2026-02-30T10:00:00Z", // 2월 30일
        "2026-10-21 12:00:00",  // T 누락
    ];

    for ts in invalid_ts {
        let mut ctx = create_synthetic_context("127.0.0.1", 80);
        ctx.timestamp_iso8601 = Some(ts.to_string());
        let err = icmp_to_quick_result(&ctx, &valid_meas).expect_err("잘못된 타임스탬프 거부 기대");
        assert!(
            err.iter().any(|msg| msg.contains("timestamp_iso8601")),
            "ts: {ts}, err: {err:?}"
        );
    }
}

/// 8. ICMP error_code u32 오버플로 처리 및 ip_status 분리 검증.
#[test]
fn test_icmp_adapter_os_error_code_u32_overflow_and_ip_status_separation() {
    let ctx = create_synthetic_context("127.0.0.1", 80);

    // 1) u32::MAX (4294967295) 오버플로: 최상위 os_error_code는 null(None), raw_measurement에는 보존
    let overflow_meas = IcmpMeasurement {
        target: "127.0.0.1".to_string(),
        outcome: "LOCAL_ERROR".to_string(),
        elapsed_ms: 10,
        ip_status: None,
        error_code: Some(u32::MAX),
        rtt_ms: None,
        ttl: None,
        limitations: vec![],
    };
    let res_overflow =
        icmp_to_quick_result(&ctx, &overflow_meas).expect("오버플로 에러코드 변환 성공");
    assert_eq!(res_overflow.os_error_code, None);
    let details_lims = res_overflow.details["limitations"]
        .as_array()
        .expect("limitations 배열");
    assert!(
        details_lims
            .iter()
            .any(|v| v.as_str().unwrap_or("").contains("초과")),
        "limitations에 초과 안내 포함 확인"
    );
    assert_eq!(
        res_overflow.details["raw_measurement"]["error_code"],
        serde_json::json!(u32::MAX)
    );

    // 2) 정상 i32 범위 에러코드: Some(10060)
    let normal_meas = IcmpMeasurement {
        target: "127.0.0.1".to_string(),
        outcome: "TIMEOUT".to_string(),
        elapsed_ms: 1000,
        ip_status: Some(11010),
        error_code: Some(10060),
        rtt_ms: None,
        ttl: None,
        limitations: vec![],
    };
    let res_normal = icmp_to_quick_result(&ctx, &normal_meas).expect("정상 에러코드 변환 성공");
    assert_eq!(res_normal.os_error_code, Some(10060));

    // 3) ip_status만 있고 error_code는 None인 경우: 최상위 os_error_code는 null(None)이어야 함 (주입 금지!)
    let ip_status_only_meas = IcmpMeasurement {
        target: "127.0.0.1".to_string(),
        outcome: "TIMEOUT".to_string(),
        elapsed_ms: 1000,
        ip_status: Some(11010),
        error_code: None,
        rtt_ms: None,
        ttl: None,
        limitations: vec![],
    };
    let res_ip_status =
        icmp_to_quick_result(&ctx, &ip_status_only_meas).expect("ip_status 전용 변환 성공");
    assert_eq!(
        res_ip_status.os_error_code, None,
        "ip_status를 os_error_code에 주입하지 않아야 함"
    );
}

/// 9. ICMP 원시 DTO 필드 완전 보존 및 14개 키 직렬화/역직렬화 roundtrip 검증.
#[test]
fn test_icmp_adapter_raw_measurement_preserves_all_fields_and_roundtrip() {
    let ctx = create_synthetic_context("127.0.0.1", 80);
    let measurement = IcmpMeasurement {
        target: "127.0.0.1".to_string(),
        outcome: "REPLY".to_string(),
        elapsed_ms: 12,
        ip_status: Some(0),
        error_code: None,
        rtt_ms: Some(11),
        ttl: Some(64),
        limitations: vec!["[합성(synthetic) 측정 고유 한계]".to_string()],
    };

    let result = icmp_to_quick_result(&ctx, &measurement).expect("어댑터 변환 성공");

    // details.raw_measurement 검증
    let raw = &result.details["raw_measurement"];
    assert_eq!(raw["target"], "127.0.0.1");
    assert_eq!(raw["outcome"], "REPLY");
    assert_eq!(raw["elapsed_ms"], 12);
    assert_eq!(raw["ip_status"], 0);
    assert_eq!(raw["rtt_ms"], 11);
    assert_eq!(raw["ttl"], 64);
    assert_eq!(
        raw["limitations"],
        serde_json::json!(measurement.limitations)
    );

    // QuickResult 14개 키 직렬화 및 역직렬화 roundtrip 검증
    let json_val = serde_json::to_value(&result).expect("QuickResult 직렬화");
    let obj = json_val.as_object().expect("JSON 객체");
    assert_eq!(obj.len(), 14, "정확히 14개 필드여야 함");

    let deserialized: QuickResult = serde_json::from_value(json_val).expect("QuickResult 역직렬화");
    assert_eq!(deserialized, result);
}

/// 10. ICMP details 객체가 정확히 3개 키(`outcome`, `limitations`, `raw_measurement`)만 갖는지 검증.
#[test]
fn test_icmp_adapter_details_has_exact_three_keys() {
    let ctx = create_synthetic_context("127.0.0.1", 80);
    let measurement = IcmpMeasurement {
        target: "127.0.0.1".to_string(),
        outcome: "REPLY".to_string(),
        elapsed_ms: 3,
        ip_status: Some(0),
        error_code: None,
        rtt_ms: Some(3),
        ttl: Some(64),
        limitations: vec![],
    };

    let res = icmp_to_quick_result(&ctx, &measurement).expect("변환 성공");
    let details_obj = res.details.as_object().expect("details 객체");
    let mut keys: Vec<&str> = details_obj.keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(keys, vec!["limitations", "outcome", "raw_measurement"]);
}

// ----------------------------------------------------------------------------
// Host 어댑터 단위 테스트
// ----------------------------------------------------------------------------

/// 11. 호스트 스냅샷 전체 수집 성공 시 PASS / OBSERVED / outcome "COLLECTED" 검증.
#[test]
fn test_host_adapter_full_collection_all_valid_no_errors_yields_pass() {
    let ctx = create_synthetic_context("192.168.1.1", 443);
    let adapters = vec![create_synthetic_adapter_entry()];
    let routes = vec![create_synthetic_route_entry()];
    let selected_route = create_synthetic_selected_route_entry("192.168.1.1", false);

    let snapshot = HostSnapshot {
        adapters: serde_json::to_value(adapters).expect("adapters 직렬화"),
        routes: serde_json::to_value(routes).expect("routes 직렬화"),
        selected_route: serde_json::to_value(selected_route).expect("selected_route 직렬화"),
        errors: vec![],
        limitations: vec!["[합성(synthetic) 호스트 스냅샷]".to_string()],
    };

    let res = host_to_quick_result(&ctx, &snapshot, Some(45)).expect("호스트 어댑터 성공");
    assert_eq!(res.status, QuickStatus::PASS);
    assert_eq!(res.evidence_level, EvidenceLevel::OBSERVED);
    assert_eq!(res.feature, QuickFeature::LocalNetwork);
    assert_eq!(res.details["outcome"], "COLLECTED");
    assert_eq!(res.elapsed_ms, Some(45));
    assert_eq!(res.os_error_code, None);
    assert_eq!(res.resolved_ip, Some("192.168.1.1".to_string()));
}

/// 12. 유효한 빈 배열(`[]`)은 로컬 0건 조회 관찰이며 실패로 위장하지 않고 PASS / OBSERVED / "COLLECTED" 유지 검증.
#[test]
fn test_host_adapter_empty_valid_arrays_observed_not_failed() {
    let ctx = create_synthetic_context("192.168.1.1", 443);
    let empty_adapters: Vec<AdapterEntry> = vec![];
    let empty_routes: Vec<RouteEntry> = vec![];
    let selected_route = create_synthetic_selected_route_entry("192.168.1.1", false);

    let snapshot = HostSnapshot {
        adapters: serde_json::to_value(empty_adapters).expect("empty adapters"),
        routes: serde_json::to_value(empty_routes).expect("empty routes"),
        selected_route: serde_json::to_value(selected_route).expect("selected_route"),
        errors: vec![],
        limitations: vec![],
    };

    let res = host_to_quick_result(&ctx, &snapshot, Some(10)).expect("빈 배열 변환 성공");
    assert_eq!(res.status, QuickStatus::PASS);
    assert_eq!(res.evidence_level, EvidenceLevel::OBSERVED);
    assert_eq!(res.details["outcome"], "COLLECTED");
}

/// 13. 부분 수집 조합 1: adapters/routes 유효하나 selected_route null -> WARN / OBSERVED / "PARTIAL" 검증.
#[test]
fn test_host_adapter_partial_combination_missing_selected_route() {
    let ctx = create_synthetic_context("192.168.1.1", 443);
    let adapters = vec![create_synthetic_adapter_entry()];
    let routes = vec![create_synthetic_route_entry()];

    let snapshot = HostSnapshot {
        adapters: serde_json::to_value(adapters).expect("adapters"),
        routes: serde_json::to_value(routes).expect("routes"),
        selected_route: serde_json::Value::Null,
        errors: vec![],
        limitations: vec![],
    };

    let res = host_to_quick_result(&ctx, &snapshot, Some(15)).expect("부분 수환 성공");
    assert_eq!(res.status, QuickStatus::WARN);
    assert_eq!(res.evidence_level, EvidenceLevel::OBSERVED);
    assert_eq!(res.details["outcome"], "PARTIAL");
    assert_eq!(
        res.resolved_ip, None,
        "selected_route 부재 시 resolved_ip는 null"
    );
}

/// 14. 부분 수집 조합 2: 3개 구성요소 모두 유효하나 errors가 존재 -> WARN / OBSERVED / "PARTIAL" 검증.
#[test]
fn test_host_adapter_partial_combination_with_errors() {
    let ctx = create_synthetic_context("192.168.1.1", 443);
    let adapters = vec![create_synthetic_adapter_entry()];
    let routes = vec![create_synthetic_route_entry()];
    let selected_route = create_synthetic_selected_route_entry("192.168.1.1", false);

    let snapshot = HostSnapshot {
        adapters: serde_json::to_value(adapters).expect("adapters"),
        routes: serde_json::to_value(routes).expect("routes"),
        selected_route: serde_json::to_value(selected_route).expect("selected_route"),
        errors: vec!["GetAdaptersAddresses 버퍼 경고 (부분 수집)".to_string()],
        limitations: vec![],
    };

    let res = host_to_quick_result(&ctx, &snapshot, Some(20)).expect("에러 포함 스냅샷 성공");
    assert_eq!(res.status, QuickStatus::WARN);
    assert_eq!(res.evidence_level, EvidenceLevel::OBSERVED);
    assert_eq!(res.details["outcome"], "PARTIAL");
}

/// 15. 부분 수집 조합 3: adapters만 유효하고 routes/selected_route null -> WARN / OBSERVED / "PARTIAL" 검증.
#[test]
fn test_host_adapter_partial_combination_only_adapters_valid() {
    let ctx = create_synthetic_context("192.168.1.1", 443);
    let adapters = vec![create_synthetic_adapter_entry()];

    let snapshot = HostSnapshot {
        adapters: serde_json::to_value(adapters).expect("adapters"),
        routes: serde_json::Value::Null,
        selected_route: serde_json::Value::Null,
        errors: vec![],
        limitations: vec![],
    };

    let res = host_to_quick_result(&ctx, &snapshot, None).expect("어댑터 단독 성공");
    assert_eq!(res.status, QuickStatus::WARN);
    assert_eq!(res.evidence_level, EvidenceLevel::OBSERVED);
    assert_eq!(res.details["outcome"], "PARTIAL");
}

/// 16. 모든 구성요소가 null인 경우 UNKNOWN / UNKNOWN / "UNAVAILABLE" 검증.
#[test]
fn test_host_adapter_all_components_null_yields_unavailable() {
    let ctx = create_synthetic_context("192.168.1.1", 443);

    let snapshot = HostSnapshot {
        adapters: serde_json::Value::Null,
        routes: serde_json::Value::Null,
        selected_route: serde_json::Value::Null,
        errors: vec!["비 Windows 환경 수집 불가".to_string()],
        limitations: vec!["호스트 스냅샷 수집 불가".to_string()],
    };

    let res = host_to_quick_result(&ctx, &snapshot, None).expect("전체 null 변환 성공");
    assert_eq!(res.status, QuickStatus::UNKNOWN);
    assert_eq!(res.evidence_level, EvidenceLevel::UNKNOWN);
    assert_eq!(res.details["outcome"], "UNAVAILABLE");
    assert_eq!(res.resolved_ip, None);
}

/// 17. 구성요소가 잘못된 JSON 형태(객체/문자열/숫자 등)일 때 불량 컴포넌트 거부 및 UNAVAILABLE 검증.
#[test]
fn test_host_adapter_malformed_shapes_rejected_as_invalid() {
    let ctx = create_synthetic_context("192.168.1.1", 443);

    let snapshot = HostSnapshot {
        adapters: serde_json::json!({"not": "an_array"}),
        routes: serde_json::json!("string_instead_of_routes"),
        selected_route: serde_json::json!(12345),
        errors: vec![],
        limitations: vec![],
    };

    let res = host_to_quick_result(&ctx, &snapshot, None).expect("잘못된 형태 처리 성공");
    assert_eq!(res.status, QuickStatus::UNKNOWN);
    assert_eq!(res.evidence_level, EvidenceLevel::UNKNOWN);
    assert_eq!(res.details["outcome"], "UNAVAILABLE");
}

/// 18. `selected_route.remote_connectivity_evidence == true` 위조 상태 거부 및 PASS 고양 방지 검증.
#[test]
fn test_host_adapter_remote_connectivity_evidence_forgery_rejected() {
    let ctx = create_synthetic_context("192.168.1.1", 443);
    let adapters = vec![create_synthetic_adapter_entry()];
    let routes = vec![create_synthetic_route_entry()];
    // 위조된 remote_connectivity_evidence = true
    let forged_route = create_synthetic_selected_route_entry("192.168.1.1", true);

    let snapshot = HostSnapshot {
        adapters: serde_json::to_value(adapters).expect("adapters"),
        routes: serde_json::to_value(routes).expect("routes"),
        selected_route: serde_json::to_value(forged_route).expect("forged selected_route"),
        errors: vec![],
        limitations: vec![],
    };

    let res = host_to_quick_result(&ctx, &snapshot, Some(30)).expect("위조 상태 처리 성공");
    // 절대 PASS가 되어서는 안 됨! selected_route가 거부되어 PARTIAL(WARN) 상태여야 함.
    assert_ne!(
        res.status,
        QuickStatus::PASS,
        "위조 상태는 PASS가 될 수 없음"
    );
    assert_eq!(res.status, QuickStatus::WARN);
    assert_eq!(res.details["outcome"], "PARTIAL");

    let lims = res.details["limitations"].as_array().expect("limitations");
    assert!(
        lims.iter()
            .any(|v| v.as_str().unwrap_or("").contains("위조")),
        "limitations에 위조 거부 안내 문구 포함 확인"
    );
}

/// 19. 호스트 스냅샷 selected_route target IP와 컨텍스트 target IP 불일치 시 거부 검증.
#[test]
fn test_host_adapter_foreign_ip_mismatch_rejected() {
    let ctx = create_synthetic_context("192.168.1.1", 443);
    let selected_route = create_synthetic_selected_route_entry("10.0.0.99", false);

    let snapshot = HostSnapshot {
        adapters: serde_json::to_value(vec![create_synthetic_adapter_entry()]).unwrap(),
        routes: serde_json::to_value(vec![create_synthetic_route_entry()]).unwrap(),
        selected_route: serde_json::to_value(selected_route).unwrap(),
        errors: vec![],
        limitations: vec![],
    };

    let err = host_to_quick_result(&ctx, &snapshot, None).expect_err("타겟 IP 불일치 거부 기대");
    assert!(
        err.iter().any(|msg| msg.contains("일치하지 않습니다")),
        "오류 메시지에 불일치 내용 포함 확인: {err:?}"
    );
}

/// 20. 스냅샷에 target이 없거나 selected_route가 부재할 때 컨텍스트 주소로 resolved_ip를 임의 발명하지 않고 None 유지 검증.
#[test]
fn test_host_adapter_missing_target_in_snapshot_keeps_resolved_ip_null() {
    let ctx = create_synthetic_context("192.168.1.100", 80);

    let snapshot = HostSnapshot {
        adapters: serde_json::to_value(vec![create_synthetic_adapter_entry()]).unwrap(),
        routes: serde_json::to_value(vec![create_synthetic_route_entry()]).unwrap(),
        selected_route: serde_json::Value::Null,
        errors: vec![],
        limitations: vec![],
    };

    let res = host_to_quick_result(&ctx, &snapshot, None).expect("스냅샷 성공");
    assert_eq!(
        res.resolved_ip, None,
        "selected_route 부재 시 ctx IP로 resolved_ip를 임의 발명하지 않아야 함"
    );
}

/// 21. elapsed_ms의 None 값이 Some(0)으로 발명되지 않고 원형 Option 그대로 보존됨을 검증.
#[test]
fn test_host_adapter_elapsed_ms_none_preserved_not_zero() {
    let ctx = create_synthetic_context("192.168.1.1", 443);
    let snapshot = HostSnapshot {
        adapters: serde_json::to_value(vec![create_synthetic_adapter_entry()]).unwrap(),
        routes: serde_json::to_value(vec![create_synthetic_route_entry()]).unwrap(),
        selected_route: serde_json::to_value(create_synthetic_selected_route_entry(
            "192.168.1.1",
            false,
        ))
        .unwrap(),
        errors: vec![],
        limitations: vec![],
    };

    // None 케이스
    let res_none = host_to_quick_result(&ctx, &snapshot, None).expect("None 경과시간 성공");
    assert_eq!(res_none.elapsed_ms, None, "None이 0으로 발명되지 않아야 함");

    // Some(123) 케이스
    let res_some =
        host_to_quick_result(&ctx, &snapshot, Some(123)).expect("Some(123) 경과시간 성공");
    assert_eq!(res_some.elapsed_ms, Some(123));
}

/// 22. 호스트 어댑터 컨텍스트 유효성 검사 실패 케이스 검증.
#[test]
fn test_host_adapter_invalid_context_rejected() {
    let snapshot = HostSnapshot {
        adapters: serde_json::to_value(vec![create_synthetic_adapter_entry()]).unwrap(),
        routes: serde_json::to_value(vec![create_synthetic_route_entry()]).unwrap(),
        selected_route: serde_json::to_value(create_synthetic_selected_route_entry(
            "192.168.1.1",
            false,
        ))
        .unwrap(),
        errors: vec![],
        limitations: vec![],
    };

    // 1) 빈 session_id
    let mut ctx = create_synthetic_context("192.168.1.1", 443);
    ctx.session_id = "".to_string();
    assert!(host_to_quick_result(&ctx, &snapshot, None).is_err());

    // 2) 포트 0
    let ctx = create_synthetic_context("192.168.1.1", 0);
    assert!(host_to_quick_result(&ctx, &snapshot, None).is_err());

    // 3) 빈 target_host
    let mut ctx = create_synthetic_context("192.168.1.1", 443);
    ctx.target_host = "  ".to_string();
    assert!(host_to_quick_result(&ctx, &snapshot, None).is_err());
}

/// 23. 호스트 스냅샷의 errors 및 원본 데이터가 raw_measurement에 정확히 보존되는지 검증.
#[test]
fn test_host_adapter_raw_snapshot_and_errors_preserved() {
    let ctx = create_synthetic_context("192.168.1.1", 443);
    let snapshot = HostSnapshot {
        adapters: serde_json::to_value(vec![create_synthetic_adapter_entry()]).unwrap(),
        routes: serde_json::to_value(vec![create_synthetic_route_entry()]).unwrap(),
        selected_route: serde_json::to_value(create_synthetic_selected_route_entry(
            "192.168.1.1",
            false,
        ))
        .unwrap(),
        errors: vec!["synthetic error #1".to_string()],
        limitations: vec!["synthetic limitation #1".to_string()],
    };

    let res = host_to_quick_result(&ctx, &snapshot, Some(50)).expect("변환 성공");
    let raw = &res.details["raw_measurement"];
    assert_eq!(raw["errors"], serde_json::json!(["synthetic error #1"]));
    assert_eq!(
        raw["limitations"],
        serde_json::json!(["synthetic limitation #1"])
    );
    assert!(raw["adapters"].is_array());
    assert!(raw["routes"].is_array());
    assert!(raw["selected_route"].is_object());

    // 14개 필드 roundtrip 검증
    let json_val = serde_json::to_value(&res).expect("직렬화");
    let deserialized: QuickResult = serde_json::from_value(json_val).expect("역직렬화");
    assert_eq!(deserialized, res);
}

/// 24. OS 라우팅 선택 성공은 원격 연결 성공이 아니라는 명확한 한계 문구가 첨부되는지 검증.
#[test]
fn test_host_adapter_os_route_selection_limitations_attached() {
    let ctx = create_synthetic_context("192.168.1.1", 443);
    let snapshot = HostSnapshot {
        adapters: serde_json::to_value(vec![create_synthetic_adapter_entry()]).unwrap(),
        routes: serde_json::to_value(vec![create_synthetic_route_entry()]).unwrap(),
        selected_route: serde_json::to_value(create_synthetic_selected_route_entry(
            "192.168.1.1",
            false,
        ))
        .unwrap(),
        errors: vec![],
        limitations: vec![],
    };

    let res = host_to_quick_result(&ctx, &snapshot, None).expect("변환 성공");
    let lims = res.details["limitations"]
        .as_array()
        .expect("limitations 배열");
    assert!(
        lims.iter().any(|v| {
            let s = v.as_str().unwrap_or("");
            s.contains("GetBestRoute2") && s.contains("원격 호스트 연결")
        }),
        "GetBestRoute2 관련 한계 안내 확인"
    );
    assert!(
        lims.iter().any(|v| {
            let s = v.as_str().unwrap_or("");
            s.contains("원격 연결 수립을 보증하지 않습니다")
        }),
        "원격 연결 미보증 한계 안내 확인"
    );
}

/// 25. 호스트 details 객체가 정확히 3개 키(`outcome`, `limitations`, `raw_measurement`)만 갖는지 검증.
#[test]
fn test_host_adapter_details_has_exact_three_keys() {
    let ctx = create_synthetic_context("192.168.1.1", 443);
    let snapshot = HostSnapshot {
        adapters: serde_json::to_value(vec![create_synthetic_adapter_entry()]).unwrap(),
        routes: serde_json::to_value(vec![create_synthetic_route_entry()]).unwrap(),
        selected_route: serde_json::to_value(create_synthetic_selected_route_entry(
            "192.168.1.1",
            false,
        ))
        .unwrap(),
        errors: vec![],
        limitations: vec![],
    };

    let res = host_to_quick_result(&ctx, &snapshot, None).expect("변환 성공");
    let details_obj = res.details.as_object().expect("details 객체");
    let mut keys: Vec<&str> = details_obj.keys().map(String::as_str).collect();
    keys.sort();
    assert_eq!(keys, vec!["limitations", "outcome", "raw_measurement"]);
}
