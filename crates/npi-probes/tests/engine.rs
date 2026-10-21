//! `npi-probes::engine` 오프라인 계약 검증 및 루프백 통합 시험.
//!
//! - 기본 시험은 소켓이나 네이티브 호스트 API를 전혀 호출하지 않는 순수 오프라인 시험으로만 구성한다.
//! - 실제 루프백(127.0.0.1 / ::1) 소켓 및 네이티브 수집기를 호출하는 통합 시험은
//!   `#[ignore = "실제 루프백 검증: 부모 명시 실행"]`을 부여하여 부모만 명시적으로 실행한다.

use std::sync::{Arc, atomic::AtomicBool};

use npi_probes::engine::{MEASUREMENT_FORMAT_G2A, run_profile};
use serde_json::{Value, json};

fn build_profile(host: &str, port: u64, selected_features: Value) -> Value {
    json!({
        "schema_version": "1.1",
        "profile_id": "g2a-engine-test",
        "label": "G2-A 엔진 검증 프로필",
        "mode": "standalone",
        "selected_features": selected_features,
        "capture_approved": false,
        "target": {
            "host": host,
            "port": port,
            "protocol": "TCP"
        },
        "limits": {
            "tcp_timeout_ms": 1000,
            "max_hops": 30,
            "retries": 0,
            "max_concurrent_tcp": 1,
            "capture_duration_secs": 30,
            "capture_max_bytes": 52428800,
            "log_retention_days": 30,
            "ui_updates_per_second": 4
        }
    })
}

fn find_row<'a>(envelope: &'a Value, feature_id: &str) -> &'a Value {
    envelope["feature_results"]
        .as_array()
        .expect("feature_results는 배열이어야 합니다")
        .iter()
        .find(|row| row["feature_id"] == feature_id)
        .unwrap_or_else(|| panic!("feature_results에서 '{feature_id}' 행을 찾을 수 없습니다"))
}

#[tokio::test]
async fn empty_selection_returns_all_skipped_and_zero_collectors() {
    let profile = build_profile("127.0.0.1", 443, json!([]));
    let cancelled = Arc::new(AtomicBool::new(false));

    let envelope = run_profile(&profile, cancelled)
        .await
        .expect("빈 기능 선택 프로필은 성공적으로 계획/반환되어야 합니다");

    assert_eq!(envelope["measurement_format"], MEASUREMENT_FORMAT_G2A);
    assert_eq!(envelope["profile_id"], "g2a-engine-test");
    assert_eq!(envelope["target"]["host"], "127.0.0.1");
    assert_eq!(envelope["target"]["port"], 443);

    assert_eq!(envelope["collector_counts"]["host_network_snapshot"], 0);
    assert_eq!(envelope["collector_counts"]["tcp_connect"], 0);
    assert_eq!(envelope["collector_counts"]["icmp_ping"], 0);
    assert_eq!(
        envelope["measurements"]
            .as_object()
            .expect("measurements는 객체여야 합니다")
            .len(),
        0
    );

    let rows = envelope["feature_results"]
        .as_array()
        .expect("feature_results는 23개 배열이어야 합니다");
    assert_eq!(rows.len(), 23);

    for row in rows {
        assert_eq!(row["status"], "SKIPPED_BY_USER");
        assert!(row["classification"].is_null());
        assert!(row["started_at_utc"].is_null());
        assert!(row["ended_at_utc"].is_null());
        assert!(row["duration_ms"].is_null());
        assert!(row["error_code"].is_null());
        assert_eq!(row["evidence_ids"], json!([]));
    }
}

#[tokio::test]
async fn unsupported_features_return_unavailable_without_collectors() {
    let selected = json!([
        "dns_lookup",
        "icmp_traceroute",
        "tcp_traceroute",
        "packet_capture",
        "syn_rst_analysis",
        "result_json",
        "pdf_report"
    ]);
    let profile = build_profile("127.0.0.1", 443, selected);
    let cancelled = Arc::new(AtomicBool::new(false));

    let envelope = run_profile(&profile, cancelled)
        .await
        .expect("미구현 기능만 선택된 프로필도 UNAVAILABLE 상태로 반환되어야 합니다");

    assert_eq!(envelope["collector_counts"]["host_network_snapshot"], 0);
    assert_eq!(envelope["collector_counts"]["tcp_connect"], 0);
    assert_eq!(envelope["collector_counts"]["icmp_ping"], 0);
    assert!(
        envelope["measurements"]
            .as_object()
            .expect("measurements는 객체여야 합니다")
            .is_empty()
    );

    for fid in [
        "dns_lookup",
        "icmp_traceroute",
        "tcp_traceroute",
        "packet_capture",
        "syn_rst_analysis",
        "result_json",
        "pdf_report",
    ] {
        let row = find_row(&envelope, fid);
        assert_eq!(
            row["status"], "UNAVAILABLE",
            "{fid} 상태는 UNAVAILABLE이어야 합니다"
        );
        assert_eq!(row["classification"], "UNKNOWN");
        assert!(row["started_at_utc"].is_null());
        assert!(row["ended_at_utc"].is_null());
        assert!(row["duration_ms"].is_null());
        assert!(row["error_code"].is_null());
        assert_eq!(row["evidence_ids"], json!([]));
        assert!(
            !row["limitations"]
                .as_array()
                .expect("limitations는 배열이어야 합니다")
                .is_empty()
        );
    }

    for fid in ["tcp_connect", "icmp_ping", "nic_inventory", "route_table"] {
        let row = find_row(&envelope, fid);
        assert_eq!(row["status"], "SKIPPED_BY_USER");
    }
}

#[tokio::test]
async fn pre_cancelled_profile_skips_collectors_and_marks_selected_cancelled() {
    let selected = json!(["tcp_connect", "icmp_ping", "nic_inventory", "route_table"]);
    let profile = build_profile("127.0.0.1", 443, selected);
    let cancelled = Arc::new(AtomicBool::new(true));

    let envelope = run_profile(&profile, cancelled)
        .await
        .expect("사전 취소된 프로필은 프로브 호출 없이 CANCELLED 결과를 반환해야 합니다");

    assert_eq!(envelope["collector_counts"]["host_network_snapshot"], 0);
    assert_eq!(envelope["collector_counts"]["tcp_connect"], 0);
    assert_eq!(envelope["collector_counts"]["icmp_ping"], 0);
    assert!(
        envelope["measurements"]
            .as_object()
            .expect("measurements는 객체여야 합니다")
            .is_empty()
    );

    for fid in ["tcp_connect", "icmp_ping", "nic_inventory", "route_table"] {
        let row = find_row(&envelope, fid);
        assert_eq!(row["status"], "CANCELLED");
        assert_eq!(row["classification"], "UNKNOWN");
        assert!(row["started_at_utc"].is_null());
        assert!(row["ended_at_utc"].is_null());
        assert!(row["duration_ms"].is_null());
        assert!(row["error_code"].is_null());
        assert_eq!(row["evidence_ids"], json!([]));
    }
}

#[tokio::test]
async fn rejects_non_loopback_targets_before_collectors() {
    for non_loopback in [
        "192.168.1.1",
        "10.0.0.1",
        "172.16.0.1",
        "8.8.8.8",
        "0.0.0.0",
        "224.0.0.1",
        "::",
        "2001:db8::1",
        "fe80::1",
        "ff02::1",
    ] {
        let profile = build_profile(non_loopback, 443, json!(["tcp_connect"]));
        let cancelled = Arc::new(AtomicBool::new(false));
        let err = run_profile(&profile, cancelled).await.expect_err(&format!(
            "비루프백 주소({non_loopback})는 즉시 거부되어야 합니다"
        ));
        assert!(!err.is_empty());
    }
}

#[tokio::test]
async fn rejects_domain_targets_with_explicit_dns_error_unavailable() {
    for domain in ["example.com", "localhost", "internal.corp.local"] {
        let profile = build_profile(domain, 443, json!(["tcp_connect"]));
        let cancelled = Arc::new(AtomicBool::new(false));
        let errs = run_profile(&profile, cancelled).await.expect_err(&format!(
            "도메인 대상({domain})은 G2-A에서 거부되어야 합니다"
        ));
        let joined = errs.join(" ");
        assert!(
            joined.contains("DNS_ERROR") && joined.contains("UNAVAILABLE"),
            "도메인 거부 메시지에 DNS_ERROR 및 UNAVAILABLE 표기가 포함되어야 합니다: {joined}"
        );
    }
}

#[tokio::test]
async fn rejects_invalid_literal_port_zero_retries_and_missing_fields() {
    // 포트 0 거부
    let port_zero = build_profile("127.0.0.1", 0, json!([]));
    assert!(
        run_profile(&port_zero, Arc::new(AtomicBool::new(false)))
            .await
            .is_err()
    );

    // 잘못된 호스트 문자열 거부
    for bad_host in [
        "",
        "999.999.999.999",
        "http://127.0.0.1",
        "127.0.0.1/8",
        "127.0.0.1:443",
    ] {
        let bad_profile = build_profile(bad_host, 443, json!([]));
        assert!(
            run_profile(&bad_profile, Arc::new(AtomicBool::new(false)))
                .await
                .is_err(),
            "잘못된 호스트({bad_host})는 거부되어야 합니다"
        );
    }

    // retries > 0 명시적 거부
    let mut with_retries = build_profile("127.0.0.1", 443, json!(["tcp_connect"]));
    with_retries["limits"]["retries"] = json!(1);
    let retry_err = run_profile(&with_retries, Arc::new(AtomicBool::new(false)))
        .await
        .expect_err("G2-A에서 retries > 0 설정은 조용히 무시하지 않고 거부해야 합니다");
    assert!(retry_err.join(" ").contains("retries"));

    // 필수 필드 누락 거부
    let mut missing_field = build_profile("127.0.0.1", 443, json!([]));
    missing_field
        .as_object_mut()
        .expect("프로필은 객체여야 합니다")
        .remove("capture_approved");
    assert!(
        run_profile(&missing_field, Arc::new(AtomicBool::new(false)))
            .await
            .is_err()
    );
}

#[tokio::test]
#[ignore = "실제 루프백 검증: 부모 명시 실행"]
async fn loopback_ipv4_quick_default_shares_host_snapshot_once() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("루프백 임시 리스너 바인딩 성공");
    let port = listener.local_addr().expect("로컬 리스너 주소 조회").port();

    let server_task = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            drop(stream);
        }
    });

    let mut profile = build_profile(
        "127.0.0.1",
        u64::from(port),
        json!([
            "tcp_connect",
            "icmp_ping",
            "nic_inventory",
            "route_table",
            "result_json"
        ]),
    );
    profile["limits"]["tcp_timeout_ms"] = json!(5000);

    let envelope = run_profile(&profile, Arc::new(AtomicBool::new(false)))
        .await
        .expect("루프백 G2-A 프로필 실행 성공");

    let _ = server_task.await;

    assert_eq!(envelope["collector_counts"]["host_network_snapshot"], 1);
    assert_eq!(envelope["collector_counts"]["tcp_connect"], 1);
    assert_eq!(envelope["collector_counts"]["icmp_ping"], 1);

    let tcp_row = find_row(&envelope, "tcp_connect");
    assert_eq!(tcp_row["status"], "PASS");
    assert_eq!(tcp_row["classification"], "OBSERVED");
    assert!(tcp_row["duration_ms"].is_u64());
    assert_eq!(tcp_row["evidence_ids"], json!([]));
    assert_eq!(
        envelope["measurements"]["tcp_connect"]["outcome"],
        "CONNECTED"
    );
    assert_eq!(
        envelope["measurements"]["tcp_connect"]["application_bytes_sent"],
        0
    );

    let icmp_row = find_row(&envelope, "icmp_ping");
    assert_eq!(icmp_row["status"], "PASS");
    assert_eq!(icmp_row["classification"], "OBSERVED");
    assert!(
        icmp_row["limitations"]
            .as_array()
            .expect("icmp_ping limitations는 배열이어야 합니다")
            .iter()
            .filter_map(Value::as_str)
            .any(|msg| msg.contains("5000ms") && msg.contains("2000ms"))
    );

    let nic_row = find_row(&envelope, "nic_inventory");
    assert_eq!(nic_row["status"], "PASS");
    assert_eq!(nic_row["classification"], "OBSERVED");

    let route_row = find_row(&envelope, "route_table");
    assert_eq!(route_row["status"], "PASS");
    assert_eq!(route_row["classification"], "OBSERVED");

    let result_json_row = find_row(&envelope, "result_json");
    assert_eq!(result_json_row["status"], "UNAVAILABLE");
}

#[tokio::test]
#[ignore = "실제 루프백 검증: 부모 명시 실행"]
async fn loopback_ipv4_tcp_only_does_not_invoke_host_or_icmp() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("포트 할당용 임시 리스너 바인딩");
    let closed_port = listener.local_addr().expect("로컬 리스너 주소 조회").port();
    drop(listener);

    let profile = build_profile("127.0.0.1", u64::from(closed_port), json!(["tcp_connect"]));
    let envelope = run_profile(&profile, Arc::new(AtomicBool::new(false)))
        .await
        .expect("루프백 TCP 단독 실행 성공");

    assert_eq!(envelope["collector_counts"]["host_network_snapshot"], 0);
    assert_eq!(envelope["collector_counts"]["tcp_connect"], 1);
    assert_eq!(envelope["collector_counts"]["icmp_ping"], 0);

    let tcp_row = find_row(&envelope, "tcp_connect");
    assert_eq!(tcp_row["status"], "FAIL");
    assert_eq!(tcp_row["classification"], "OBSERVED");
    assert!(envelope["measurements"].get("nic_inventory").is_none());
    assert!(envelope["measurements"].get("route_table").is_none());
    assert!(envelope["measurements"].get("icmp_ping").is_none());
}

#[tokio::test]
#[ignore = "실제 루프백 검증: 부모 명시 실행"]
async fn loopback_ipv6_tcp_and_icmp() {
    let listener = tokio::net::TcpListener::bind("[::1]:0")
        .await
        .expect("IPv6 루프백 임시 리스너 바인딩");
    let port = listener.local_addr().expect("IPv6 리스너 주소 조회").port();

    let server_task = tokio::spawn(async move {
        if let Ok((stream, _)) = listener.accept().await {
            drop(stream);
        }
    });

    let profile = build_profile("::1", u64::from(port), json!(["tcp_connect", "icmp_ping"]));
    let envelope = run_profile(&profile, Arc::new(AtomicBool::new(false)))
        .await
        .expect("IPv6 루프백 G2-A 프로필 실행 성공");

    let _ = server_task.await;

    assert_eq!(envelope["collector_counts"]["host_network_snapshot"], 0);
    assert_eq!(envelope["collector_counts"]["tcp_connect"], 1);
    assert_eq!(envelope["collector_counts"]["icmp_ping"], 1);

    let tcp_row = find_row(&envelope, "tcp_connect");
    assert_eq!(tcp_row["status"], "PASS");
    assert_eq!(tcp_row["classification"], "OBSERVED");

    let icmp_row = find_row(&envelope, "icmp_ping");
    assert_eq!(icmp_row["status"], "PASS");
    assert_eq!(icmp_row["classification"], "OBSERVED");
    assert!(
        icmp_row["limitations"]
            .as_array()
            .expect("icmp_ping limitations는 배열이어야 합니다")
            .iter()
            .filter_map(Value::as_str)
            .any(|msg| msg.contains("1000ms"))
    );
}
