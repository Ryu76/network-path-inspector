//! Network Quick Check 진단 실행기(`runner.rs`) 계약 검증 및 회귀 테스트.
//!
//! ## 원칙
//! - 기본 단위 테스트는 외부 네트워크 I/O 및 OS 시스템 호출을 일체 수행하지 않는
//!   합성(synthetic) Mock 백엔드를 사용하여 비동기 스케줄링, 안정 정렬, 취소, 예산 및
//!   교차 오염 거부 로직을 순수하게 검증합니다.
//! - 실제 루프백 대상 테스트(IPv4/IPv6)는 `#[ignore = "실제 루프백 검증: 부모 명시 실행"]`으로
//!   분리하여 부모의 명시적 요청 시에만 실행되도록 격리합니다.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use network_core::measurements::{host_to_quick_result, icmp_to_quick_result};
use network_core::quick::{
    EvidenceLevel, QuickContext, QuickFeature, QuickResult, QuickStatus, tcp_to_quick_result,
};
use network_core::runner::{
    DEFAULT_MAX_RESULT_BYTES, MIN_RESULT_BYTES, NativeProbeBackend, ProbeCounts, ProbeFuture,
    QuickProbeBackend, QuickRunRequest, run_quick,
};
use network_core::targets::{QuickOptions, QuickTarget};
use network_core::{HostSnapshot, IcmpMeasurement, TcpMeasurement};

// ============================================================================
// 테스트용 모의(Mock) 백엔드 및 헬퍼
// ============================================================================

type TcpResponder =
    Arc<dyn Fn(&QuickContext, SocketAddr) -> Result<QuickResult, Vec<String>> + Send + Sync>;
type IcmpResponder =
    Arc<dyn Fn(&QuickContext, IpAddr) -> Result<QuickResult, Vec<String>> + Send + Sync>;
type HostResponder =
    Arc<dyn Fn(&QuickContext, IpAddr) -> Result<QuickResult, Vec<String>> + Send + Sync>;

#[derive(Default)]
struct MockState {
    tcp_calls: Vec<(QuickContext, SocketAddr)>,
    icmp_calls: Vec<(QuickContext, IpAddr)>,
    host_calls: Vec<(QuickContext, IpAddr)>,
    tcp_responder: Option<TcpResponder>,
    icmp_responder: Option<IcmpResponder>,
    host_responder: Option<HostResponder>,
    on_tcp_call: Option<Arc<dyn Fn() + Send + Sync>>,
    delay: Option<Duration>,
}

#[derive(Clone, Default)]
struct MockProbeBackend {
    state: Arc<Mutex<MockState>>,
}

impl MockProbeBackend {
    fn new() -> Self {
        Self::default()
    }

    fn set_tcp_responder(&self, responder: TcpResponder) {
        self.state.lock().unwrap().tcp_responder = Some(responder);
    }

    fn set_on_tcp_call(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        self.state.lock().unwrap().on_tcp_call = Some(hook);
    }

    fn set_delay(&self, delay: Duration) {
        self.state.lock().unwrap().delay = Some(delay);
    }

    fn call_counts(&self) -> (usize, usize, usize) {
        let st = self.state.lock().unwrap();
        (st.tcp_calls.len(), st.icmp_calls.len(), st.host_calls.len())
    }
}

impl QuickProbeBackend for MockProbeBackend {
    fn tcp<'a>(
        &'a self,
        ctx: QuickContext,
        target: SocketAddr,
        _timeout: Duration,
        _cancel: Arc<AtomicBool>,
    ) -> ProbeFuture<'a> {
        let (responder, on_call, delay) = {
            let mut st = self.state.lock().unwrap();
            st.tcp_calls.push((ctx.clone(), target));
            (st.tcp_responder.clone(), st.on_tcp_call.clone(), st.delay)
        };

        if let Some(hook) = on_call {
            hook();
        }

        Box::pin(async move {
            if let Some(d) = delay {
                tokio::time::sleep(d).await;
            }

            if let Some(resp) = responder {
                resp(&ctx, target)
            } else {
                let measurement = TcpMeasurement {
                    target: target.to_string(),
                    outcome: "CONNECTED".to_string(),
                    local_address: Some("127.0.0.1:54321".to_string()),
                    elapsed_ms: 10,
                    error_code: None,
                    error_message: None,
                    application_bytes_sent: 0,
                    limitations: vec!["synthetic-mock-tcp".to_string()],
                };
                tcp_to_quick_result(&ctx, &measurement)
            }
        })
    }

    fn icmp<'a>(
        &'a self,
        ctx: QuickContext,
        target: IpAddr,
        _timeout: Duration,
        _cancel: Arc<AtomicBool>,
    ) -> ProbeFuture<'a> {
        let (responder, delay) = {
            let mut st = self.state.lock().unwrap();
            st.icmp_calls.push((ctx.clone(), target));
            (st.icmp_responder.clone(), st.delay)
        };

        Box::pin(async move {
            if let Some(d) = delay {
                tokio::time::sleep(d).await;
            }

            if let Some(resp) = responder {
                resp(&ctx, target)
            } else {
                let measurement = IcmpMeasurement {
                    target: target.to_string(),
                    outcome: "REPLY".to_string(),
                    elapsed_ms: 5,
                    ip_status: Some(0),
                    error_code: None,
                    rtt_ms: Some(5),
                    ttl: Some(64),
                    limitations: vec!["synthetic-mock-icmp".to_string()],
                };
                icmp_to_quick_result(&ctx, &measurement)
            }
        })
    }

    fn host<'a>(
        &'a self,
        ctx: QuickContext,
        target: IpAddr,
        _cancel: Arc<AtomicBool>,
    ) -> ProbeFuture<'a> {
        let (responder, delay) = {
            let mut st = self.state.lock().unwrap();
            st.host_calls.push((ctx.clone(), target));
            (st.host_responder.clone(), st.delay)
        };

        Box::pin(async move {
            if let Some(d) = delay {
                tokio::time::sleep(d).await;
            }

            if let Some(resp) = responder {
                resp(&ctx, target)
            } else {
                let snapshot = HostSnapshot {
                    adapters: serde_json::json!([{
                        "interface_index": 1,
                        "ipv6_interface_index": 0,
                        "name": "SyntheticLoopback",
                        "adapter_name": "loopback_mock",
                        "friendly_name": "Synthetic Mock Adapter",
                        "description": "Mock Loopback Interface",
                        "dns_suffix": "",
                        "operational_status": "UP",
                        "oper_status_code": 1,
                        "ips": ["127.0.0.1"],
                        "unicast_addresses": [{"ip": "127.0.0.1", "prefix_length": 8}],
                        "prefixes": ["127.0.0.1/8"],
                        "prefix_entries": [{"prefix": "127.0.0.1", "prefix_length": 8, "cidr": "127.0.0.1/8"}],
                        "gateways": [],
                        "dns_servers": []
                    }]),
                    routes: serde_json::json!([{
                        "destination_prefix": "127.0.0.0/8",
                        "prefix": "127.0.0.0/8",
                        "prefix_ip": "127.0.0.0",
                        "prefix_length": 8,
                        "next_hop": "0.0.0.0",
                        "metric": 1,
                        "interface_index": 1,
                        "interface_luid": 1,
                        "protocol": 3,
                        "origin": 1,
                        "loopback": true
                    }]),
                    selected_route: serde_json::json!({
                        "target": target.to_string(),
                        "source_ip": "127.0.0.1",
                        "interface_index": 1,
                        "interface_luid": 1,
                        "destination_prefix": "127.0.0.0/8",
                        "prefix": "127.0.0.0/8",
                        "prefix_ip": "127.0.0.0",
                        "prefix_length": 8,
                        "next_hop": "0.0.0.0",
                        "metric": 1,
                        "selection_basis": "SYNTHETIC_MOCK",
                        "remote_connectivity_evidence": false,
                        "note": "synthetic mock selected route"
                    }),
                    errors: vec![],
                    limitations: vec!["synthetic-mock-host".to_string()],
                };
                host_to_quick_result(&ctx, &snapshot, Some(3))
            }
        })
    }
}

/// 공통 테스트 요청 생성 헬퍼 함수.
fn make_request(
    targets: Vec<QuickTarget>,
    features: Vec<QuickFeature>,
    concurrency: usize,
    max_bytes: usize,
) -> QuickRunRequest {
    QuickRunRequest {
        session_id: "test-sess-001".to_string(),
        timestamp_iso8601: Some("2026-10-21T12:00:00Z".to_string()),
        source_host: Some("test-client".to_string()),
        targets,
        options: QuickOptions {
            tcp_timeout_ms: 1000,
            concurrency,
            selected_features: features,
        },
        max_result_bytes: max_bytes,
    }
}

/// 단일 검사 대상 생성 헬퍼 함수.
fn make_target(host: &str, port: u16) -> QuickTarget {
    QuickTarget {
        host: host.to_string(),
        port,
        raw_input: format!("{host}:{port}"),
    }
}

// ============================================================================
// 기본 최소 10 필수 단위 테스트 (외부 I/O 0)
// ============================================================================

/// 1. 정상 TCP + Ping 선택 호출 및 결과의 대상/기능 순서 안정 정렬 검증.
#[tokio::test]
async fn test_01_normal_tcp_and_ping_ordering_and_counts() {
    let backend = Arc::new(MockProbeBackend::new());
    let cancel = Arc::new(AtomicBool::new(false));

    let targets = vec![
        make_target("127.0.0.1", 8080),
        make_target("127.0.0.2", 8081),
    ];
    let features = vec![QuickFeature::TcpConnect, QuickFeature::IcmpPing];
    let req = make_request(targets, features, 2, DEFAULT_MAX_RESULT_BYTES);

    let report = run_quick(&req, backend.clone(), cancel).await.unwrap();

    assert_eq!(report.results.len(), 4);
    assert!(!report.cancelled);
    assert!(!report.limit_reached);
    assert_eq!(report.omitted_results, 0);
    assert!(report.errors.is_empty());

    // 입력 대상 순서 및 기능 순서 안정 정렬 검증
    assert_eq!(report.results[0].target_host, "127.0.0.1");
    assert_eq!(report.results[0].target_port, 8080);
    assert_eq!(report.results[0].feature, QuickFeature::TcpConnect);
    assert_eq!(report.results[0].status, QuickStatus::PASS);

    assert_eq!(report.results[1].target_host, "127.0.0.1");
    assert_eq!(report.results[1].target_port, 8080);
    assert_eq!(report.results[1].feature, QuickFeature::IcmpPing);
    assert_eq!(report.results[1].status, QuickStatus::PASS);

    assert_eq!(report.results[2].target_host, "127.0.0.2");
    assert_eq!(report.results[2].target_port, 8081);
    assert_eq!(report.results[2].feature, QuickFeature::TcpConnect);
    assert_eq!(report.results[2].status, QuickStatus::PASS);

    assert_eq!(report.results[3].target_host, "127.0.0.2");
    assert_eq!(report.results[3].target_port, 8081);
    assert_eq!(report.results[3].feature, QuickFeature::IcmpPing);
    assert_eq!(report.results[3].status, QuickStatus::PASS);

    // 실제 백엔드 메소드 호출 횟수 검증
    assert_eq!(
        report.invocations,
        ProbeCounts {
            tcp_connect: 2,
            icmp_ping: 2,
            local_network: 0,
            dns_lookup: 0,
            icmp_traceroute: 0,
        }
    );
    assert_eq!(report.targets_started, 2);
    assert_eq!(report.targets_completed, 2);
    assert!(report.serialized_result_bytes > 0);
    assert!(report.serialized_result_bytes <= req.max_result_bytes);
}

/// 2. 개별 선택된 LocalNetwork만 실행되고 다른 프로브 호출은 0회인지 검증.
#[tokio::test]
async fn test_02_individual_selected_local_network_no_other_calls() {
    let backend = Arc::new(MockProbeBackend::new());
    let cancel = Arc::new(AtomicBool::new(false));

    let targets = vec![make_target("127.0.0.1", 80)];
    let features = vec![QuickFeature::LocalNetwork];
    let req = make_request(targets, features, 1, DEFAULT_MAX_RESULT_BYTES);

    let report = run_quick(&req, backend.clone(), cancel).await.unwrap();

    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].feature, QuickFeature::LocalNetwork);
    assert_eq!(report.results[0].status, QuickStatus::PASS);

    let (tcp, icmp, host) = backend.call_counts();
    assert_eq!(tcp, 0);
    assert_eq!(icmp, 0);
    assert_eq!(host, 1);
    assert_eq!(report.invocations.local_network, 1);
    assert_eq!(report.invocations.tcp_connect, 0);
    assert_eq!(report.invocations.icmp_ping, 0);
}

/// 3. 빈 기능 선택(selected_features = []) 시 대상 검증 통과 후 결과 0 / 백엔드 호출 0 검증.
#[tokio::test]
async fn test_03_empty_selected_features_produces_zero_results_and_calls() {
    let backend = Arc::new(MockProbeBackend::new());
    let cancel = Arc::new(AtomicBool::new(false));

    let targets = vec![make_target("127.0.0.1", 443)];
    let features = vec![];
    let req = make_request(targets, features, 2, DEFAULT_MAX_RESULT_BYTES);

    let report = run_quick(&req, backend.clone(), cancel).await.unwrap();

    assert!(report.results.is_empty());
    assert!(!report.cancelled);
    assert!(!report.limit_reached);
    assert_eq!(report.omitted_results, 0);
    assert_eq!(report.invocations, ProbeCounts::default());
    assert_eq!(backend.call_counts(), (0, 0, 0));
}

/// 4. 미지원 기능(DNS, Traceroute) 선택 시 백엔드 호출 0회 및 UNKNOWN/UNKNOWN/UNAVAILABLE 생성 검증.
#[tokio::test]
async fn test_04_unsupported_dns_and_trace_yield_unavailable_without_backend_calls() {
    let backend = Arc::new(MockProbeBackend::new());
    let cancel = Arc::new(AtomicBool::new(false));

    let targets = vec![make_target("127.0.0.1", 53)];
    let features = vec![QuickFeature::DnsLookup, QuickFeature::IcmpTraceroute];
    let req = make_request(targets, features, 1, DEFAULT_MAX_RESULT_BYTES);

    let report = run_quick(&req, backend.clone(), cancel).await.unwrap();

    assert_eq!(report.results.len(), 2);
    assert_eq!(backend.call_counts(), (0, 0, 0));
    assert_eq!(report.invocations, ProbeCounts::default());

    // DnsLookup 결과 검증
    assert_eq!(report.results[0].feature, QuickFeature::DnsLookup);
    assert_eq!(report.results[0].status, QuickStatus::UNKNOWN);
    assert_eq!(report.results[0].evidence_level, EvidenceLevel::UNKNOWN);
    assert_eq!(report.results[0].details["outcome"], "UNAVAILABLE");

    // IcmpTraceroute 결과 검증
    assert_eq!(report.results[1].feature, QuickFeature::IcmpTraceroute);
    assert_eq!(report.results[1].status, QuickStatus::UNKNOWN);
    assert_eq!(report.results[1].evidence_level, EvidenceLevel::UNKNOWN);
    assert_eq!(report.results[1].details["outcome"], "UNAVAILABLE");
}

/// 5. 도메인 대상 진단 시도 시 사전 검증에서 즉시 Err 반환 및 전 백엔드 호출 0 검증.
#[tokio::test]
async fn test_05_domain_target_requires_resolution_rejects_before_any_calls() {
    let backend = Arc::new(MockProbeBackend::new());
    let cancel = Arc::new(AtomicBool::new(false));

    let targets = vec![make_target("example.com", 443)];
    let features = vec![QuickFeature::TcpConnect];
    let req = make_request(targets, features, 1, DEFAULT_MAX_RESULT_BYTES);

    let err_result = run_quick(&req, backend.clone(), cancel).await;
    assert!(err_result.is_err());

    let errs = err_result.err().unwrap();
    assert!(errs.iter().any(|e| e.contains("도메인")));
    assert_eq!(backend.call_counts(), (0, 0, 0));
}

/// 6. 동시성 옵션 1 및 최대 4 상한(cap)에서의 실제 활성 대상 카운터 최대치 검증.
#[tokio::test]
async fn test_06_concurrency_cap_and_option_1_observes_exact_max_active() {
    let backend = Arc::new(MockProbeBackend::new());
    backend.set_delay(Duration::from_millis(20));

    let cancel = Arc::new(AtomicBool::new(false));

    // 옵션 concurrency = 1 검증
    let targets_seq = vec![
        make_target("127.0.0.1", 80),
        make_target("127.0.0.2", 80),
        make_target("127.0.0.3", 80),
    ];
    let req_seq = make_request(
        targets_seq,
        vec![QuickFeature::TcpConnect],
        1,
        DEFAULT_MAX_RESULT_BYTES,
    );
    let report_seq = run_quick(&req_seq, backend.clone(), cancel.clone())
        .await
        .unwrap();

    assert_eq!(report_seq.max_active_targets, 1);
    assert_eq!(report_seq.targets_completed, 3);

    // 옵션 concurrency = 4 검증 (작업이 4를 초과하여 동시 실행되지 않는지 확인)
    let targets_par = vec![
        make_target("127.0.0.1", 80),
        make_target("127.0.0.2", 80),
        make_target("127.0.0.3", 80),
        make_target("127.0.0.4", 80),
        make_target("127.0.0.5", 80),
    ];
    let req_par = make_request(
        targets_par,
        vec![QuickFeature::TcpConnect],
        4,
        DEFAULT_MAX_RESULT_BYTES,
    );
    let report_par = run_quick(&req_par, backend.clone(), cancel).await.unwrap();

    assert!(report_par.max_active_targets <= 4);
    assert_eq!(report_par.targets_completed, 5);
}

/// 7. 사전 취소(시작 전 cancel=true) 시 백엔드 0회 호출 및 중도 취소 시 후속 기능 차단 검증.
#[tokio::test]
async fn test_07_pre_cancellation_and_mid_cancellation_preserves_contract() {
    // 7-A: 사전 취소 검증
    let backend_pre = Arc::new(MockProbeBackend::new());
    let cancel_pre = Arc::new(AtomicBool::new(true));

    let targets = vec![make_target("127.0.0.1", 80), make_target("127.0.0.2", 80)];
    let features = vec![QuickFeature::TcpConnect, QuickFeature::IcmpPing];
    let req_pre = make_request(
        targets.clone(),
        features.clone(),
        2,
        DEFAULT_MAX_RESULT_BYTES,
    );

    let report_pre = run_quick(&req_pre, backend_pre.clone(), cancel_pre)
        .await
        .unwrap();

    assert_eq!(backend_pre.call_counts(), (0, 0, 0));
    assert!(report_pre.cancelled);
    assert_eq!(report_pre.results.len(), 4);
    assert_eq!(report_pre.omitted_results, 0);
    for res in &report_pre.results {
        assert_eq!(res.status, QuickStatus::UNKNOWN);
        assert_eq!(res.evidence_level, EvidenceLevel::UNKNOWN);
        assert_eq!(res.details["outcome"], "CANCELLED");
        assert!(res.elapsed_ms.is_none());
    }

    // 7-B: 중도 취소 검증 (첫 번째 프로브 실행 도중 cancel 트리거)
    let backend_mid = Arc::new(MockProbeBackend::new());
    let cancel_mid = Arc::new(AtomicBool::new(false));

    let cancel_trigger = cancel_mid.clone();
    backend_mid.set_on_tcp_call(Arc::new(move || {
        cancel_trigger.store(true, Ordering::SeqCst);
    }));

    let req_mid = make_request(targets, features, 1, DEFAULT_MAX_RESULT_BYTES);
    let report_mid = run_quick(&req_mid, backend_mid.clone(), cancel_mid)
        .await
        .unwrap();

    assert!(report_mid.cancelled);
    // 중도 취소로 인해 뒤따르는 프로브들은 실행되지 않고 생략됨
    assert!(report_mid.omitted_results > 0);
    let (tcp, icmp, _) = backend_mid.call_counts();
    assert_eq!(tcp, 1);
    assert_eq!(icmp, 0);
}

/// 8. 백엔드가 잘못된 컨텍스트 메타데이터를 반환했을 때 거부하고 LOCAL_ERROR로 격하하는지 검증.
#[tokio::test]
async fn test_08_backend_wrong_metadata_rejected_as_local_error() {
    let backend = Arc::new(MockProbeBackend::new());
    let cancel = Arc::new(AtomicBool::new(false));

    // 원래 포트 80 대신 위조된 포트 9999를 포함한 QuickResult 반환 설정
    backend.set_tcp_responder(Arc::new(|ctx, socket_addr| {
        let mut corrupted_ctx = ctx.clone();
        corrupted_ctx.target_port = 9999;
        let measurement = TcpMeasurement {
            target: socket_addr.to_string(),
            outcome: "CONNECTED".to_string(),
            local_address: Some("127.0.0.1:12345".to_string()),
            elapsed_ms: 10,
            error_code: None,
            error_message: None,
            application_bytes_sent: 0,
            limitations: vec![],
        };
        tcp_to_quick_result(&corrupted_ctx, &measurement)
    }));

    let targets = vec![make_target("127.0.0.1", 80)];
    let features = vec![QuickFeature::TcpConnect];
    let req = make_request(targets, features, 1, DEFAULT_MAX_RESULT_BYTES);

    let report = run_quick(&req, backend.clone(), cancel).await.unwrap();

    assert_eq!(report.results.len(), 1);
    let res = &report.results[0];
    // 포트 불일치로 인해 PASS로 승인되지 않고 UNKNOWN LOCAL_ERROR로 격하되어야 함
    assert_eq!(res.status, QuickStatus::UNKNOWN);
    assert_eq!(res.details["outcome"], "LOCAL_ERROR");
    assert!(!report.errors.is_empty());
}

/// 9. 결과 바이트 예산 초과 시 즉각 추가 저장 중단, 한도 도달 표시 및 원본 보존 검증.
#[tokio::test]
async fn test_09_result_bytes_budget_exceeded_stops_and_records_omissions() {
    let backend = Arc::new(MockProbeBackend::new());
    let cancel = Arc::new(AtomicBool::new(false));

    // 상세 내용(details)이 큰 결과를 생성하여 바이트 초과 유도
    backend.set_tcp_responder(Arc::new(|ctx, socket_addr| {
        let dummy_large = "x".repeat(1500);
        let measurement = TcpMeasurement {
            target: socket_addr.to_string(),
            outcome: "CONNECTED".to_string(),
            local_address: Some("127.0.0.1:12345".to_string()),
            elapsed_ms: 10,
            error_code: None,
            error_message: None,
            application_bytes_sent: 0,
            limitations: vec![dummy_large],
        };
        tcp_to_quick_result(ctx, &measurement)
    }));

    let targets = vec![
        make_target("127.0.0.1", 80),
        make_target("127.0.0.2", 80),
        make_target("127.0.0.3", 80),
        make_target("127.0.0.4", 80),
    ];
    let features = vec![QuickFeature::TcpConnect];
    // 4개 결과를 담기에는 부족한 최소 바이트 한도(4096) 적용
    let req = make_request(targets, features, 1, MIN_RESULT_BYTES);

    let report = run_quick(&req, backend.clone(), cancel).await.unwrap();

    assert!(report.limit_reached);
    assert!(report.results.len() < 4);
    assert!(report.serialized_result_bytes <= MIN_RESULT_BYTES);
    assert_eq!(report.omitted_results, 4 - report.results.len());
    // 이미 보관된 결과는 훼손되지 않고 유효성을 유지해야 함
    for res in &report.results {
        assert_eq!(res.status, QuickStatus::PASS);
    }
}

/// 10. OS 원시 오류 분류(REFUSED, TIMED_OUT, LOCAL_ERROR) 및 error_code 보존 검증.
#[tokio::test]
async fn test_10_raw_os_error_and_refused_timeout_classification_preserved() {
    let backend = Arc::new(MockProbeBackend::new());
    let cancel = Arc::new(AtomicBool::new(false));

    backend.set_tcp_responder(Arc::new(|ctx, socket_addr| {
        let measurement = TcpMeasurement {
            target: socket_addr.to_string(),
            outcome: "REFUSED".to_string(),
            local_address: None,
            elapsed_ms: 15,
            error_code: Some(10061),
            error_message: Some(
                "대상 컴퓨터에서 연결을 거부했으므로 연결하지 못했습니다.".to_string(),
            ),
            application_bytes_sent: 0,
            limitations: vec!["synthetic-os-refused".to_string()],
        };
        tcp_to_quick_result(ctx, &measurement)
    }));

    let targets = vec![make_target("127.0.0.1", 9999)];
    let features = vec![QuickFeature::TcpConnect];
    let req = make_request(targets, features, 1, DEFAULT_MAX_RESULT_BYTES);

    let report = run_quick(&req, backend.clone(), cancel).await.unwrap();

    assert_eq!(report.results.len(), 1);
    let res = &report.results[0];
    assert_eq!(res.status, QuickStatus::FAIL);
    assert_eq!(res.evidence_level, EvidenceLevel::OBSERVED);
    assert_eq!(res.os_error_code, Some(10061));
    assert_eq!(res.details["outcome"], "REFUSED");
    assert_eq!(res.details["raw_measurement"]["error_code"], 10061);
}

// ============================================================================
// 실제 루프백 격리 테스트 (부모 명시 실행 전용: ignored)
// ============================================================================

/// IPv4 루프백(127.0.0.1) 실제 리스너에 대한 NativeProbeBackend 연결 검증.
#[tokio::test]
#[ignore = "실제 루프백 검증: 부모 명시 실행"]
async fn test_11_live_loopback_ipv4_tcp_connect_and_ping() {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("IPv4 루프백 임의 포트 바인딩 성공");
    let local_addr = listener.local_addr().unwrap();

    let backend = Arc::new(NativeProbeBackend);
    let cancel = Arc::new(AtomicBool::new(false));

    let targets = vec![make_target("127.0.0.1", local_addr.port())];
    let features = vec![QuickFeature::TcpConnect, QuickFeature::IcmpPing];
    let req = make_request(targets, features, 1, DEFAULT_MAX_RESULT_BYTES);

    let report = run_quick(&req, backend, cancel).await.unwrap();

    assert_eq!(report.results.len(), 2);

    let tcp_res = &report.results[0];
    assert_eq!(tcp_res.feature, QuickFeature::TcpConnect);
    assert_eq!(tcp_res.status, QuickStatus::PASS);
    assert_eq!(tcp_res.evidence_level, EvidenceLevel::OBSERVED);
    assert_eq!(tcp_res.details["outcome"], "CONNECTED");
    assert_eq!(
        tcp_res.details["raw_measurement"]["application_bytes_sent"],
        0
    );

    let icmp_res = &report.results[1];
    assert_eq!(icmp_res.feature, QuickFeature::IcmpPing);
    assert_eq!(icmp_res.status, QuickStatus::PASS);

    drop(listener);
}

/// IPv6 루프백(::1) 실제 리스너에 대한 NativeProbeBackend 연결 검증.
#[tokio::test]
#[ignore = "실제 루프백 검증: 부모 명시 실행"]
async fn test_12_live_loopback_ipv6_tcp_connect_and_ping() {
    let listener = std::net::TcpListener::bind("[::1]:0")
        .expect("IPv6 루프백 바인딩이 불가하면 환경 미검증 실패로 남긴다 (침묵 성공 금지)");
    let local_addr = listener.local_addr().unwrap();

    let backend = Arc::new(NativeProbeBackend);
    let cancel = Arc::new(AtomicBool::new(false));

    let targets = vec![make_target("::1", local_addr.port())];
    let features = vec![QuickFeature::TcpConnect, QuickFeature::IcmpPing];
    let req = make_request(targets, features, 1, DEFAULT_MAX_RESULT_BYTES);

    let report = run_quick(&req, backend, cancel).await.unwrap();

    assert_eq!(report.results.len(), 2);

    let tcp_res = &report.results[0];
    assert_eq!(tcp_res.feature, QuickFeature::TcpConnect);
    assert_eq!(tcp_res.status, QuickStatus::PASS);
    assert_eq!(tcp_res.evidence_level, EvidenceLevel::OBSERVED);
    assert_eq!(tcp_res.details["outcome"], "CONNECTED");
    assert_eq!(
        tcp_res.details["raw_measurement"]["application_bytes_sent"],
        0
    );

    let icmp_res = &report.results[1];
    assert_eq!(icmp_res.feature, QuickFeature::IcmpPing);
    assert_eq!(icmp_res.status, QuickStatus::PASS);
    assert_eq!(icmp_res.evidence_level, EvidenceLevel::OBSERVED);
    assert_eq!(report.invocations.tcp_connect, 1);
    assert_eq!(report.invocations.icmp_ping, 1);
    assert!(!report.cancelled && !report.limit_reached);
    assert_eq!(report.omitted_results, 0);

    drop(listener);
}
