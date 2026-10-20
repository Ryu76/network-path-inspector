//! `npi_probes::icmp` 통합 시험.
//!
//! 기본 시험은 소켓/핸들/네트워크 호출 없이 오프라인으로 입력 검증, 취소, DTO 계약만 확인한다.
//! 실제 Windows 루프백(`127.0.0.1`, `::1`) 호출 시험은 `#[ignore]`로 표시하여 부모만 명시적으로 실행한다.

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, atomic::AtomicBool},
    time::Duration,
};

use npi_probes::icmp::{IcmpMeasurement, ping_once};

#[test]
fn reject_zero_and_over_2000ms_timeout_without_clamping() {
    let cancelled = Arc::new(AtomicBool::new(false));
    let target = IpAddr::V4(Ipv4Addr::LOCALHOST);

    let zero_res = ping_once(target, Duration::ZERO, Arc::clone(&cancelled));
    assert_eq!(zero_res.target, "127.0.0.1");
    assert_eq!(zero_res.outcome, "LOCAL_ERROR");
    assert_eq!(zero_res.ip_status, None);
    assert_eq!(zero_res.error_code, None);
    assert_eq!(zero_res.rtt_ms, None);
    assert_eq!(zero_res.ttl, None);
    assert!(
        zero_res
            .limitations
            .iter()
            .any(|msg| msg.contains("1..=2000ms"))
    );

    let sub_ms_res = ping_once(target, Duration::from_micros(999), Arc::clone(&cancelled));
    assert_eq!(sub_ms_res.outcome, "LOCAL_ERROR");
    assert_eq!(sub_ms_res.rtt_ms, None);
    assert_eq!(sub_ms_res.ttl, None);

    let over_res = ping_once(target, Duration::from_millis(2001), Arc::clone(&cancelled));
    assert_eq!(over_res.target, "127.0.0.1");
    assert_eq!(over_res.outcome, "LOCAL_ERROR");
    assert_eq!(over_res.ip_status, None);
    assert_eq!(over_res.error_code, None);
    assert_eq!(over_res.rtt_ms, None);
    assert_eq!(over_res.ttl, None);
    assert!(
        over_res
            .limitations
            .iter()
            .any(|msg| msg.contains("1..=2000ms"))
    );
}

#[test]
fn reject_unspecified_multicast_broadcast_and_link_local_targets_offline() {
    let cancelled = Arc::new(AtomicBool::new(false));
    let timeout = Duration::from_millis(500);

    let invalid_targets = [
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::BROADCAST),
        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
    ];

    for target in invalid_targets {
        let res = ping_once(target, timeout, Arc::clone(&cancelled));
        assert_eq!(
            res.outcome, "LOCAL_ERROR",
            "대상 {target}는 호출 전 LOCAL_ERROR로 거부되어야 합니다"
        );
        assert_eq!(res.ip_status, None);
        assert_eq!(res.error_code, None);
        assert_eq!(res.rtt_ms, None);
        assert_eq!(res.ttl, None);
        assert!(!res.limitations.is_empty());
    }
}

#[test]
fn pre_cancelled_flag_returns_cancelled_without_syscall() {
    let cancelled = Arc::new(AtomicBool::new(true));
    let timeout = Duration::from_millis(1000);

    let v4_res = ping_once(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        timeout,
        Arc::clone(&cancelled),
    );
    assert_eq!(v4_res.target, "127.0.0.1");
    assert_eq!(v4_res.outcome, "CANCELLED");
    assert_eq!(v4_res.ip_status, None);
    assert_eq!(v4_res.error_code, None);
    assert_eq!(v4_res.rtt_ms, None);
    assert_eq!(v4_res.ttl, None);

    let v6_res = ping_once(
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        timeout,
        Arc::clone(&cancelled),
    );
    assert_eq!(v6_res.target, "::1");
    assert_eq!(v6_res.outcome, "CANCELLED");
    assert_eq!(v6_res.ip_status, None);
    assert_eq!(v6_res.error_code, None);
    assert_eq!(v6_res.rtt_ms, None);
    assert_eq!(v6_res.ttl, None);
    assert!(
        v6_res
            .limitations
            .iter()
            .any(|msg| msg.contains("sin6_scope_id=0"))
    );
}

#[test]
fn dto_serde_roundtrip_preserves_contract_fields() {
    let sample = IcmpMeasurement {
        target: "127.0.0.1".to_string(),
        outcome: "LOCAL_ERROR".to_string(),
        elapsed_ms: 3,
        ip_status: None,
        error_code: Some(87),
        rtt_ms: None,
        ttl: None,
        limitations: vec!["예시 제한사항".to_string()],
    };

    let json = serde_json::to_value(&sample).expect("IcmpMeasurement 직렬화 성공");
    assert_eq!(json["target"], "127.0.0.1");
    assert_eq!(json["outcome"], "LOCAL_ERROR");
    assert_eq!(json["elapsed_ms"], 3);
    assert!(json["ip_status"].is_null());
    assert_eq!(json["error_code"], 87);
    assert!(json["rtt_ms"].is_null());
    assert!(json["ttl"].is_null());

    let restored: IcmpMeasurement =
        serde_json::from_value(json).expect("IcmpMeasurement 역직렬화 성공");
    assert_eq!(restored, sample);
}

#[test]
#[ignore = "실제 루프백 검증: 부모 명시 실행"]
fn ping_ipv4_loopback_real() {
    let cancelled = Arc::new(AtomicBool::new(false));
    let res = ping_once(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        Duration::from_millis(1000),
        cancelled,
    );

    assert_eq!(res.target, "127.0.0.1");
    assert_eq!(res.outcome, "REPLY");
    assert_eq!(res.ip_status, Some(0));
    assert_eq!(res.error_code, None);
    assert!(res.rtt_ms.is_some());
    assert!(res.ttl.is_some());
    assert!(!res.limitations.is_empty());
}

#[test]
#[ignore = "실제 루프백 검증: 부모 명시 실행"]
fn ping_ipv6_loopback_real() {
    let cancelled = Arc::new(AtomicBool::new(false));
    let res = ping_once(
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        Duration::from_millis(1000),
        cancelled,
    );

    assert_eq!(res.target, "::1");
    assert_eq!(res.outcome, "REPLY");
    assert_eq!(res.ip_status, Some(0));
    assert_eq!(res.error_code, None);
    assert!(res.rtt_ms.is_some());
    assert_eq!(res.ttl, None);
    assert!(
        res.limitations
            .iter()
            .any(|msg| msg.contains("sin6_scope_id=0"))
    );
}
