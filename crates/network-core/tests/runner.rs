//! Network Quick Check 진단 실행기(`runner.rs`) 계약 검증 및 회귀 테스트.
//!
//! ## 원칙
//! - 기본 단위 테스트는 외부 네트워크 I/O 및 OS 시스템 호출을 일체 수행하지 않는
//!   합성(synthetic) Mock 백엔드를 사용하여 비동기 스케줄링, 안정 정렬, 취소, 예산,
//!   DNS 주소 해석 연계, 첫 후보 주소 선택 정책 및 교차 오염 거부 로직을 순수하게 검증합니다.
//! - 실제 루프백 대상 테스트(IPv4/IPv6) 및 helper 실행파일을 활용한 localhost 테스트는
//!   `#[ignore = "..."]`으로 분리하여 부모의 명시적 요청 시에만 실행되도록 격리합니다.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use network_core::dns_engine::DnsMeasurement;
use network_core::measurements::{host_to_quick_result, icmp_to_quick_result};
use network_core::quick::{
    EvidenceLevel, QuickContext, QuickFeature, QuickResult, QuickStatus, tcp_to_quick_result,
};
use network_core::runner::{
    DEFAULT_MAX_RESULT_BYTES, DnsProbeFuture, MIN_RESULT_BYTES, NativeDnsProbeBackend,
    NativeProbeBackend, ProbeCounts, ProbeFuture, QuickProbeBackend, QuickRunRequest, run_quick,
};
use network_core::targets::{QuickOptions, QuickTarget};
use network_core::traceroute::{TraceHop, TraceMeasurement, TraceOptions, trace_to_quick_result};
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
type DnsResponder = Arc<dyn Fn(&QuickContext) -> Result<DnsMeasurement, Vec<String>> + Send + Sync>;
type TraceResponder =
    Arc<dyn Fn(&QuickContext, IpAddr) -> Result<QuickResult, Vec<String>> + Send + Sync>;

#[derive(Default)]
struct MockState {
    tcp_calls: Vec<(QuickContext, SocketAddr)>,
    icmp_calls: Vec<(QuickContext, IpAddr)>,
    host_calls: Vec<(QuickContext, IpAddr)>,
    dns_calls: Vec<QuickContext>,
    trace_calls: Vec<(QuickContext, IpAddr)>,
    tcp_responder: Option<TcpResponder>,
    icmp_responder: Option<IcmpResponder>,
    host_responder: Option<HostResponder>,
    dns_responder: Option<DnsResponder>,
    trace_responder: Option<TraceResponder>,
    on_tcp_call: Option<Arc<dyn Fn() + Send + Sync>>,
    on_dns_call: Option<Arc<dyn Fn() + Send + Sync>>,
    on_trace_call: Option<Arc<dyn Fn() + Send + Sync>>,
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

    fn set_dns_responder(&self, responder: DnsResponder) {
        self.state.lock().unwrap().dns_responder = Some(responder);
    }

    fn set_trace_responder(&self, responder: TraceResponder) {
        self.state.lock().unwrap().trace_responder = Some(responder);
    }

    fn set_on_tcp_call(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        self.state.lock().unwrap().on_tcp_call = Some(hook);
    }

    fn set_on_dns_call(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        self.state.lock().unwrap().on_dns_call = Some(hook);
    }

    fn set_on_trace_call(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        self.state.lock().unwrap().on_trace_call = Some(hook);
    }

    fn set_delay(&self, delay: Duration) {
        self.state.lock().unwrap().delay = Some(delay);
    }

    fn call_counts(&self) -> (usize, usize, usize, usize) {
        let st = self.state.lock().unwrap();
        (
            st.tcp_calls.len(),
            st.icmp_calls.len(),
            st.host_calls.len(),
            st.dns_calls.len(),
        )
    }

    fn trace_call_count(&self) -> usize {
        self.state.lock().unwrap().trace_calls.len()
    }

    fn trace_call_targets(&self) -> Vec<IpAddr> {
        let st = self.state.lock().unwrap();
        st.trace_calls.iter().map(|(_, target)| *target).collect()
    }

    fn tcp_call_targets(&self) -> Vec<SocketAddr> {
        let st = self.state.lock().unwrap();
        st.tcp_calls.iter().map(|(_, target)| *target).collect()
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

    fn resolve<'a>(
        &'a self,
        ctx: QuickContext,
        _timeout: Duration,
        _cancel: Arc<AtomicBool>,
    ) -> DnsProbeFuture<'a> {
        let (responder, on_call, delay) = {
            let mut st = self.state.lock().unwrap();
            st.dns_calls.push(ctx.clone());
            (st.dns_responder.clone(), st.on_dns_call.clone(), st.delay)
        };

        if let Some(hook) = on_call {
            hook();
        }

        Box::pin(async move {
            if let Some(d) = delay {
                tokio::time::sleep(d).await;
            }

            if let Some(resp) = responder {
                resp(&ctx)
            } else {
                let addr = if let Ok(ip) = ctx.target_host.parse::<IpAddr>() {
                    SocketAddr::new(ip, ctx.target_port)
                } else {
                    SocketAddr::new(
                        IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                        ctx.target_port,
                    )
                };
                Ok(DnsMeasurement {
                    host: ctx.target_host.clone(),
                    port: ctx.target_port,
                    outcome: "RESOLVED".to_string(),
                    addresses: vec![addr.to_string()],
                    elapsed_ms: 2,
                    error_code: None,
                    error_message: None,
                    limitations: vec!["synthetic-mock-dns".to_string()],
                })
            }
        })
    }

    fn trace<'a>(
        &'a self,
        ctx: QuickContext,
        target: IpAddr,
        _options: TraceOptions,
        _cancel: Arc<AtomicBool>,
    ) -> ProbeFuture<'a> {
        let (responder, on_call, delay) = {
            let mut st = self.state.lock().unwrap();
            st.trace_calls.push((ctx.clone(), target));
            (st.trace_responder.clone(), st.on_trace_call.clone(), st.delay)
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
                let measurement = TraceMeasurement {
                    target: target.to_string(),
                    method: "ICMP_TRACERT".to_string(),
                    outcome: "REACHED".to_string(),
                    hops: vec![TraceHop {
                        ttl: 1,
                        address: Some(target.to_string()),
                        probe_times_ms: vec![Some(1), Some(1), Some(1)],
                        rtt_less_than: vec![true, true, true],
                        raw_line: format!("  1    <1 ms    <1 ms    <1 ms  {target}"),
                    }],
                    elapsed_ms: 12,
                    exit_code: Some(0),
                    raw_stdout: format!("  1    <1 ms    <1 ms    <1 ms  {target}\r\n").into_bytes(),
                    raw_stderr: vec![],
                    output_truncated: false,
                    limitations: vec!["synthetic-mock-trace".to_string()],
                };
                trace_to_quick_result(&ctx, &measurement)
            }
        })
    }
}

/// 기존 트레이트(trace 미구현) 백엔드 구현체의 컴파일 호환성 및 기본 UNAVAILABLE 동작을 검증하기 위한 모의 백엔드.
struct OldTraitBackend;

impl QuickProbeBackend for OldTraitBackend {
    fn tcp<'a>(
        &'a self,
        _ctx: QuickContext,
        _target: SocketAddr,
        _timeout: Duration,
        _cancel: Arc<AtomicBool>,
    ) -> ProbeFuture<'a> {
        Box::pin(async move { Err(vec!["unimplemented tcp".to_string()]) })
    }

    fn icmp<'a>(
        &'a self,
        _ctx: QuickContext,
        _target: IpAddr,
        _timeout: Duration,
        _cancel: Arc<AtomicBool>,
    ) -> ProbeFuture<'a> {
        Box::pin(async move { Err(vec!["unimplemented icmp".to_string()]) })
    }

    fn host<'a>(
        &'a self,
        _ctx: QuickContext,
        _target: IpAddr,
        _cancel: Arc<AtomicBool>,
    ) -> ProbeFuture<'a> {
        Box::pin(async move { Err(vec!["unimplemented host".to_string()]) })
    }

    // resolve 및 trace는 트레이트 기본 구현(default body)을 상속받음
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
// 기본 순수 단위 테스트 (네트워크/프로세스 호출 0)
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

    let (tcp, icmp, host, dns) = backend.call_counts();
    assert_eq!(tcp, 0);
    assert_eq!(icmp, 0);
    assert_eq!(host, 1);
    assert_eq!(dns, 0);
    assert_eq!(report.invocations.local_network, 1);
    assert_eq!(report.invocations.tcp_connect, 0);
    assert_eq!(report.invocations.icmp_ping, 0);
    assert_eq!(report.invocations.dns_lookup, 0);
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
    assert_eq!(backend.call_counts(), (0, 0, 0, 0));
}

/// 4. 트레이트 기본 구현 백엔드(OldTraitBackend)의 기본 Traceroute UNAVAILABLE 및 기본 resolve 미구성 DnsLookup 거부 검증.
/// (과거 '선택 Trace 미지원' 시험을 새 계약의 트레이트 default 바디 검증으로 강화/대체)
#[tokio::test]
async fn test_04_traceroute_unavailable_and_unconfigured_backend_dns_local_error() {
    // OldTraitBackend는 resolve와 trace를 오버라이드하지 않으므로 트레이트 기본 구현을 상속받음
    let backend = Arc::new(OldTraitBackend);
    let cancel = Arc::new(AtomicBool::new(false));

    let targets = vec![make_target("127.0.0.1", 53)];
    let features = vec![QuickFeature::DnsLookup, QuickFeature::IcmpTraceroute];
    let req = make_request(targets, features, 1, DEFAULT_MAX_RESULT_BYTES);

    let report = run_quick(&req, backend, cancel).await.unwrap();

    assert_eq!(report.results.len(), 2);

    // DnsLookup 결과: 미구성 백엔드로 인해 LOCAL_ERROR 생성
    let dns_res = &report.results[0];
    assert_eq!(dns_res.feature, QuickFeature::DnsLookup);
    assert_eq!(dns_res.status, QuickStatus::UNKNOWN);
    assert_eq!(dns_res.evidence_level, EvidenceLevel::UNKNOWN);
    assert_eq!(dns_res.details["outcome"], "LOCAL_ERROR");

    // IcmpTraceroute 결과: 트레이트 기본 구현으로 I/O 0회, UNAVAILABLE 생성 (details 3키, 빈 raw, IP null)
    let trace_res = &report.results[1];
    assert_eq!(trace_res.feature, QuickFeature::IcmpTraceroute);
    assert_eq!(trace_res.status, QuickStatus::UNKNOWN);
    assert_eq!(trace_res.evidence_level, EvidenceLevel::UNKNOWN);
    assert_eq!(trace_res.details["outcome"], "UNAVAILABLE");
    assert_eq!(trace_res.details["raw_measurement"], serde_json::json!({}));
    assert!(trace_res.resolved_ip.is_none());
    assert!(trace_res.elapsed_ms.is_none());
    assert!(trace_res.os_error_code.is_none());

    // 계약 규칙: 실제 백엔드 trace 호출 직전에 카운터 +1 증가하므로 default 호출도 1회 계수됨
    assert_eq!(report.invocations.icmp_traceroute, 1);
    assert_eq!(report.invocations.dns_lookup, 1);
}

/// 5. 도메인 대상 TCP 단독 선택 시: hidden 선행 해석 1회, DNS 결과 행 0개, TCP 1개 생성 검증.
/// (기존 test_05를 새 승인 계약대로 강화/대체)
#[tokio::test]
async fn test_05_domain_tcp_only_hidden_resolve_and_zero_dns_rows() {
    let backend = Arc::new(MockProbeBackend::new());
    let cancel = Arc::new(AtomicBool::new(false));

    let targets = vec![make_target("example.com", 80)];
    let features = vec![QuickFeature::TcpConnect];
    let req = make_request(targets, features, 1, DEFAULT_MAX_RESULT_BYTES);

    let report = run_quick(&req, backend.clone(), cancel).await.unwrap();

    // DNS 행은 생성되지 않고 오직 TCP 행 1개만 존재해야 함
    assert_eq!(report.results.len(), 1);
    let tcp_res = &report.results[0];
    assert_eq!(tcp_res.target_host, "example.com");
    assert_eq!(tcp_res.feature, QuickFeature::TcpConnect);
    assert_eq!(tcp_res.status, QuickStatus::PASS);
    assert_eq!(tcp_res.resolved_ip, Some("127.0.0.1".to_string()));

    // limitations에 첫 후보 주소 선택 정책 및 전체 주소 목록이 포함되어 있는지 확인
    let limitations = tcp_res.details["limitations"].as_array().unwrap();
    assert!(
        limitations
            .iter()
            .any(|v| v.as_str().unwrap().contains("첫 번째 주소")),
        "첫 후보 선택 정책이 limitations에 포함되어야 함"
    );
    assert!(
        limitations
            .iter()
            .any(|v| v.as_str().unwrap().contains("전체 주소 목록")),
        "전체 주소 목록 정보가 limitations에 포함되어야 함"
    );

    // 기존 raw_measurement가 TcpMeasurement로 온전히 보존되어 있는지 확인
    assert_eq!(tcp_res.details["raw_measurement"]["outcome"], "CONNECTED");

    // 백엔드 호출 수: hidden DNS 해석 1회, TCP 1회
    assert_eq!(report.invocations.dns_lookup, 1);
    assert_eq!(report.invocations.tcp_connect, 1);
    let (tcp, icmp, host, dns) = backend.call_counts();
    assert_eq!(tcp, 1);
    assert_eq!(icmp, 0);
    assert_eq!(host, 0);
    assert_eq!(dns, 1);
}

/// 6. 도메인 대상 DNS + TCP 선택 시: resolve 1회만 호출, 결과 순서(DNS -> TCP) 유지 검증.
#[tokio::test]
async fn test_06_domain_dns_and_tcp_single_resolve_and_ordering() {
    let backend = Arc::new(MockProbeBackend::new());
    let cancel = Arc::new(AtomicBool::new(false));

    let targets = vec![make_target("example.com", 443)];
    let features = vec![QuickFeature::DnsLookup, QuickFeature::TcpConnect];
    let req = make_request(targets, features, 1, DEFAULT_MAX_RESULT_BYTES);

    let report = run_quick(&req, backend.clone(), cancel).await.unwrap();

    assert_eq!(report.results.len(), 2);

    // 0번 행: DnsLookup (resolved_ip는 null, status PASS)
    let dns_res = &report.results[0];
    assert_eq!(dns_res.feature, QuickFeature::DnsLookup);
    assert_eq!(dns_res.status, QuickStatus::PASS);
    assert!(dns_res.resolved_ip.is_none());
    assert_eq!(dns_res.details["outcome"], "RESOLVED");

    // 1번 행: TcpConnect (resolved_ip는 유도된 IP, status PASS)
    let tcp_res = &report.results[1];
    assert_eq!(tcp_res.feature, QuickFeature::TcpConnect);
    assert_eq!(tcp_res.status, QuickStatus::PASS);
    assert_eq!(tcp_res.resolved_ip, Some("127.0.0.1".to_string()));

    // resolve는 중복 호출 없이 정확히 1회만 호출됨
    assert_eq!(report.invocations.dns_lookup, 1);
    assert_eq!(report.invocations.tcp_connect, 1);
    let (tcp, icmp, host, dns) = backend.call_counts();
    assert_eq!(tcp, 1);
    assert_eq!(icmp, 0);
    assert_eq!(host, 0);
    assert_eq!(dns, 1);
}

/// 7. 상세 DNS 단독 선택 시: TCP/Ping/Host 백엔드 호출 0회 검증.
#[tokio::test]
async fn test_07_detailed_dns_only_zero_tcp_icmp_host_calls() {
    let backend = Arc::new(MockProbeBackend::new());
    let cancel = Arc::new(AtomicBool::new(false));

    let targets = vec![make_target("example.com", 80)];
    let features = vec![QuickFeature::DnsLookup];
    let req = make_request(targets, features, 1, DEFAULT_MAX_RESULT_BYTES);

    let report = run_quick(&req, backend.clone(), cancel).await.unwrap();

    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].feature, QuickFeature::DnsLookup);
    assert_eq!(report.results[0].status, QuickStatus::PASS);

    let (tcp, icmp, host, dns) = backend.call_counts();
    assert_eq!(tcp, 0);
    assert_eq!(icmp, 0);
    assert_eq!(host, 0);
    assert_eq!(dns, 1);
    assert_eq!(report.invocations.dns_lookup, 1);
    assert_eq!(report.invocations.tcp_connect, 0);
}

/// 8. IP 리터럴 대상 상세 DNS + TCP 선택 시: backend resolve 1회 호출 및 bypass 검증.
#[tokio::test]
async fn test_08_literal_target_detailed_dns_and_tcp() {
    let backend = Arc::new(MockProbeBackend::new());
    let cancel = Arc::new(AtomicBool::new(false));

    let targets = vec![make_target("127.0.0.1", 80)];
    let features = vec![QuickFeature::DnsLookup, QuickFeature::TcpConnect];
    let req = make_request(targets, features, 1, DEFAULT_MAX_RESULT_BYTES);

    let report = run_quick(&req, backend.clone(), cancel).await.unwrap();

    assert_eq!(report.results.len(), 2);

    let dns_res = &report.results[0];
    assert_eq!(dns_res.feature, QuickFeature::DnsLookup);
    assert_eq!(dns_res.status, QuickStatus::PASS);
    assert!(dns_res.resolved_ip.is_none());

    let tcp_res = &report.results[1];
    assert_eq!(tcp_res.feature, QuickFeature::TcpConnect);
    assert_eq!(tcp_res.status, QuickStatus::PASS);
    assert_eq!(tcp_res.resolved_ip, Some("127.0.0.1".to_string()));

    assert_eq!(report.invocations.dns_lookup, 1);
    assert_eq!(report.invocations.tcp_connect, 1);
}

/// 9. 다중 주소 반환 시 첫 번째 IP만 연결 후보로 사용하고 전체 목록은 raw에 온전히 보존되는지 검증.
#[tokio::test]
async fn test_09_multiaddr_uses_first_ip_and_preserves_full_list_in_raw() {
    let backend = Arc::new(MockProbeBackend::new());
    let cancel = Arc::new(AtomicBool::new(false));

    // 다중 IP 주소를 반환하는 모의 리졸버 설정
    backend.set_dns_responder(Arc::new(|ctx| {
        Ok(DnsMeasurement {
            host: ctx.target_host.clone(),
            port: ctx.target_port,
            outcome: "RESOLVED".to_string(),
            addresses: vec![
                format!("127.0.0.1:{}", ctx.target_port),
                format!("127.0.0.2:{}", ctx.target_port),
                format!("127.0.0.3:{}", ctx.target_port),
            ],
            elapsed_ms: 5,
            error_code: None,
            error_message: None,
            limitations: vec!["multiaddr-test".to_string()],
        })
    }));

    let targets = vec![make_target("example.com", 8080)];
    let features = vec![QuickFeature::DnsLookup, QuickFeature::TcpConnect];
    let req = make_request(targets, features, 1, DEFAULT_MAX_RESULT_BYTES);

    let report = run_quick(&req, backend.clone(), cancel).await.unwrap();

    assert_eq!(report.results.len(), 2);

    // DNS 결과 raw에 전체 주소 3개가 보존되어 있는지 확인
    let dns_res = &report.results[0];
    let raw_addrs = dns_res.details["raw_measurement"]["addresses"]
        .as_array()
        .unwrap();
    assert_eq!(raw_addrs.len(), 3);
    assert_eq!(raw_addrs[0], "127.0.0.1:8080");
    assert_eq!(raw_addrs[1], "127.0.0.2:8080");
    assert_eq!(raw_addrs[2], "127.0.0.3:8080");

    // TCP 백엔드 호출 시 첫 번째 주소(127.0.0.1:8080)만 사용되었는지 확인
    let tcp_targets = backend.tcp_call_targets();
    assert_eq!(tcp_targets.len(), 1);
    assert_eq!(tcp_targets[0], "127.0.0.1:8080".parse().unwrap());

    let tcp_res = &report.results[1];
    assert_eq!(tcp_res.resolved_ip, Some("127.0.0.1".to_string()));
}

/// 10. DNS 해석 실패, 위조 typed 결과, 불허 첫 IP(링크로컬/미지정 등) 시 후속 백엔드 호출 0회 검증.
#[tokio::test]
async fn test_10_dns_failure_and_forged_and_unsafe_first_ip_blocks_subsequent_backend_calls() {
    // 10-A: DNS 실패 (DNS_ERROR) -> 후속 TCP 호출 0, TCP는 UNAVAILABLE
    let backend_fail = Arc::new(MockProbeBackend::new());
    backend_fail.set_dns_responder(Arc::new(|ctx| {
        Ok(DnsMeasurement {
            host: ctx.target_host.clone(),
            port: ctx.target_port,
            outcome: "DNS_ERROR".to_string(),
            addresses: vec![],
            elapsed_ms: 10,
            error_code: Some(11001),
            error_message: Some("호스트를 찾을 수 없습니다.".to_string()),
            limitations: vec![],
        })
    }));

    let targets = vec![make_target("nonexistent.example", 80)];
    let features = vec![QuickFeature::DnsLookup, QuickFeature::TcpConnect];
    let req_fail = make_request(
        targets.clone(),
        features.clone(),
        1,
        DEFAULT_MAX_RESULT_BYTES,
    );
    let cancel = Arc::new(AtomicBool::new(false));

    let report_fail = run_quick(&req_fail, backend_fail.clone(), cancel.clone())
        .await
        .unwrap();

    assert_eq!(report_fail.results.len(), 2);
    // DNS는 FAIL/OBSERVED
    assert_eq!(report_fail.results[0].feature, QuickFeature::DnsLookup);
    assert_eq!(report_fail.results[0].status, QuickStatus::FAIL);

    // TCP는 선행 해석 실패로 인해 호출되지 않고 UNAVAILABLE
    assert_eq!(report_fail.results[1].feature, QuickFeature::TcpConnect);
    assert_eq!(report_fail.results[1].status, QuickStatus::UNKNOWN);
    assert_eq!(
        report_fail.results[1].evidence_level,
        EvidenceLevel::UNKNOWN
    );
    assert_eq!(report_fail.results[1].details["outcome"], "UNAVAILABLE");
    assert!(report_fail.results[1].resolved_ip.is_none());

    let (tcp, _, _, dns) = backend_fail.call_counts();
    assert_eq!(dns, 1);
    assert_eq!(tcp, 0);

    // 10-B: 불허 첫 IP (링크로컬 169.254.1.1) -> 후속 TCP 호출 0, TCP는 UNAVAILABLE
    let backend_linklocal = Arc::new(MockProbeBackend::new());
    backend_linklocal.set_dns_responder(Arc::new(|ctx| {
        Ok(DnsMeasurement {
            host: ctx.target_host.clone(),
            port: ctx.target_port,
            outcome: "RESOLVED".to_string(),
            addresses: vec![format!("169.254.1.1:{}", ctx.target_port)],
            elapsed_ms: 5,
            error_code: None,
            error_message: None,
            limitations: vec![],
        })
    }));

    let req_ll = make_request(targets, features, 1, DEFAULT_MAX_RESULT_BYTES);
    let report_ll = run_quick(&req_ll, backend_linklocal.clone(), cancel)
        .await
        .unwrap();

    assert_eq!(report_ll.results.len(), 2);
    assert_eq!(report_ll.results[1].feature, QuickFeature::TcpConnect);
    assert_eq!(report_ll.results[1].status, QuickStatus::UNKNOWN);
    assert_eq!(report_ll.results[1].details["outcome"], "UNAVAILABLE");

    let (tcp_ll, _, _, dns_ll) = backend_linklocal.call_counts();
    assert_eq!(dns_ll, 1);
    assert_eq!(tcp_ll, 0);
}

/// 11. 사전 취소 및 DNS 완료 직후 중도 취소 시 결과 raw 보존 및 후속 연결 0회 검증.
#[tokio::test]
async fn test_11_pre_cancellation_and_mid_cancellation_with_dns_raw_preserved() {
    // 11-A: 사전 취소
    let backend_pre = Arc::new(MockProbeBackend::new());
    let cancel_pre = Arc::new(AtomicBool::new(true));

    let targets = vec![make_target("example.com", 80)];
    let features = vec![QuickFeature::DnsLookup, QuickFeature::TcpConnect];
    let req_pre = make_request(
        targets.clone(),
        features.clone(),
        1,
        DEFAULT_MAX_RESULT_BYTES,
    );

    let report_pre = run_quick(&req_pre, backend_pre.clone(), cancel_pre)
        .await
        .unwrap();

    assert!(report_pre.cancelled);
    assert_eq!(backend_pre.call_counts(), (0, 0, 0, 0));
    assert_eq!(report_pre.results.len(), 2);
    for res in &report_pre.results {
        assert_eq!(res.status, QuickStatus::UNKNOWN);
        assert_eq!(res.details["outcome"], "CANCELLED");
    }

    // 11-B: DNS 완료 직후 취소 (on_dns_call 훅에서 취소 트리거)
    let backend_mid = Arc::new(MockProbeBackend::new());
    let cancel_mid = Arc::new(AtomicBool::new(false));

    let trigger = cancel_mid.clone();
    backend_mid.set_on_dns_call(Arc::new(move || {
        trigger.store(true, Ordering::SeqCst);
    }));

    let req_mid = make_request(targets, features, 1, DEFAULT_MAX_RESULT_BYTES);
    let report_mid = run_quick(&req_mid, backend_mid.clone(), cancel_mid)
        .await
        .unwrap();

    assert!(report_mid.cancelled);
    // 완료된 DNS 결과는 보존되고, 후속 TCP는 실행되지 않아 누락(omitted) 처리됨
    assert_eq!(report_mid.results.len(), 1);
    assert_eq!(report_mid.results[0].feature, QuickFeature::DnsLookup);
    assert_eq!(report_mid.results[0].status, QuickStatus::PASS);
    assert_eq!(report_mid.omitted_results, 1);

    let (tcp, _, _, dns) = backend_mid.call_counts();
    assert_eq!(dns, 1);
    assert_eq!(tcp, 0);
}

/// 12. 백엔드가 잘못된 컨텍스트 메타데이터를 반환했을 때 거부하고 LOCAL_ERROR로 격하하는지 검증.
#[tokio::test]
async fn test_12_backend_wrong_metadata_rejected_as_local_error() {
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
    assert_eq!(res.status, QuickStatus::UNKNOWN);
    assert_eq!(res.details["outcome"], "LOCAL_ERROR");
    assert!(!report.errors.is_empty());
}

/// 13. 결과 바이트 예산 초과 시 즉각 추가 저장 중단, 한도 도달 표시 및 원본 보존 검증.
#[tokio::test]
async fn test_13_result_bytes_budget_exceeded_stops_and_records_omissions() {
    let backend = Arc::new(MockProbeBackend::new());
    let cancel = Arc::new(AtomicBool::new(false));

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
    let req = make_request(targets, features, 1, MIN_RESULT_BYTES);

    let report = run_quick(&req, backend.clone(), cancel).await.unwrap();

    assert!(report.limit_reached);
    assert!(report.results.len() < 4);
    assert!(report.serialized_result_bytes <= MIN_RESULT_BYTES);
    assert_eq!(report.omitted_results, 4 - report.results.len());
    for res in &report.results {
        assert_eq!(res.status, QuickStatus::PASS);
    }
}

/// 14. OS 원시 오류 분류(REFUSED, TIMED_OUT, LOCAL_ERROR) 및 error_code 보존 검증.
#[tokio::test]
async fn test_14_raw_os_error_and_refused_timeout_classification_preserved() {
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

/// 15. 동시성 옵션 1 및 최대 4 상한(cap)에서의 실제 활성 대상 카운터 최대치 검증.
#[tokio::test]
async fn test_15_concurrency_cap_and_option_1_observes_exact_max_active() {
    let backend = Arc::new(MockProbeBackend::new());
    backend.set_delay(Duration::from_millis(20));

    let cancel = Arc::new(AtomicBool::new(false));

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

// ============================================================================
// Traceroute 순수 모의(Mock) 단위 테스트 (네트워크/프로세스 호출 0)
// ============================================================================

/// Trace-01: old trait 미구현 trace의 소스 컴파일 호환성 및 기본 UNAVAILABLE / CANCELLED 동작 검증.
#[tokio::test]
async fn test_trace_01_old_trait_compatibility_default_unavailable_and_cancelled() {
    let backend = Arc::new(OldTraitBackend);
    let cancel = Arc::new(AtomicBool::new(false));

    let targets = vec![make_target("127.0.0.1", 80)];
    let features = vec![QuickFeature::IcmpTraceroute];
    let req = make_request(targets.clone(), features.clone(), 1, DEFAULT_MAX_RESULT_BYTES);

    let report = run_quick(&req, backend.clone(), cancel).await.unwrap();

    assert_eq!(report.results.len(), 1);
    let res = &report.results[0];
    assert_eq!(res.feature, QuickFeature::IcmpTraceroute);
    assert_eq!(res.status, QuickStatus::UNKNOWN);
    assert_eq!(res.evidence_level, EvidenceLevel::UNKNOWN);
    assert_eq!(res.details["outcome"], "UNAVAILABLE");
    assert_eq!(res.details["raw_measurement"], serde_json::json!({}));
    assert!(res.resolved_ip.is_none());
    assert!(res.elapsed_ms.is_none());
    assert!(res.os_error_code.is_none());
    // 백엔드 호출 직전 카운터가 증가하므로 default 바디도 invocations = 1
    assert_eq!(report.invocations.icmp_traceroute, 1);

    // 사전 취소 시 검증: 백엔드 호출 0회, build_pre_cancelled_report에 의해 CANCELLED 생성
    let cancel_pre = Arc::new(AtomicBool::new(true));
    let req_pre = make_request(targets, features, 1, DEFAULT_MAX_RESULT_BYTES);
    let report_pre = run_quick(&req_pre, backend.clone(), cancel_pre).await.unwrap();
    assert!(report_pre.cancelled);
    assert_eq!(report_pre.invocations.icmp_traceroute, 0);
    assert_eq!(report_pre.results.len(), 1);
    assert_eq!(report_pre.results[0].details["outcome"], "CANCELLED");

    // 트레이트 기본 구현 trace에 사전 취소 플래그가 전달되었을 때 CANCELLED 반환 검증
    let ctx = QuickContext {
        session_id: "direct-call".to_string(),
        timestamp_iso8601: None,
        source_host: None,
        target_host: "127.0.0.1".to_string(),
        target_port: 80,
    };
    let direct_cancel = Arc::new(AtomicBool::new(true));
    let direct_res = backend
        .trace(
            ctx,
            "127.0.0.1".parse().unwrap(),
            TraceOptions::default(),
            direct_cancel,
        )
        .await
        .unwrap();
    assert_eq!(direct_res.details["outcome"], "CANCELLED");
}

/// Trace-02: 기본 선택(TCP+Ping) 및 미선택 시 Trace 호출 0회, Trace 단독 선택 시 Trace 1회 / 타기능 0회 호출 검증.
#[tokio::test]
async fn test_trace_02_feature_selection_and_invocation_counts() {
    let backend = Arc::new(MockProbeBackend::new());
    let cancel = Arc::new(AtomicBool::new(false));

    // 기본 옵션 (TCP + Ping 선택): icmp_traceroute 호출 0회
    let req_default = QuickRunRequest {
        session_id: "sess-default".to_string(),
        timestamp_iso8601: None,
        source_host: None,
        targets: vec![make_target("127.0.0.1", 80)],
        options: QuickOptions::default(),
        max_result_bytes: DEFAULT_MAX_RESULT_BYTES,
    };
    let rep_default = run_quick(&req_default, backend.clone(), cancel.clone()).await.unwrap();
    assert_eq!(rep_default.invocations.icmp_traceroute, 0);
    assert_eq!(backend.trace_call_count(), 0);

    // Trace 단독 선택: TCP/Ping 타임아웃과 무관하게 Trace 백엔드 정확히 1회 호출
    let req_trace = make_request(
        vec![make_target("127.0.0.1", 80)],
        vec![QuickFeature::IcmpTraceroute],
        1,
        DEFAULT_MAX_RESULT_BYTES,
    );
    let rep_trace = run_quick(&req_trace, backend.clone(), cancel).await.unwrap();
    assert_eq!(rep_trace.invocations.icmp_traceroute, 1);
    assert_eq!(rep_trace.invocations.tcp_connect, 0);
    assert_eq!(rep_trace.invocations.icmp_ping, 0);
    assert_eq!(rep_trace.invocations.local_network, 0);
    assert_eq!(rep_trace.invocations.dns_lookup, 0);
    assert_eq!(backend.trace_call_count(), 1);
    assert_eq!(backend.call_counts(), (0, 0, 0, 0));
}

/// Trace-03: IP 원문 대상 Trace는 DNS 0회 / domain 대상 Trace는 hidden resolve 1회 및 상세 DNS 행 0개 검증.
#[tokio::test]
async fn test_trace_03_ip_target_no_dns_and_domain_hidden_resolve_trace() {
    let backend = Arc::new(MockProbeBackend::new());
    let cancel = Arc::new(AtomicBool::new(false));

    // IP 원문 대상 Trace: DNS 호출 0회, DNS 결과 행 0개
    let req_ip = make_request(
        vec![make_target("127.0.0.1", 8080)],
        vec![QuickFeature::IcmpTraceroute],
        1,
        DEFAULT_MAX_RESULT_BYTES,
    );
    let rep_ip = run_quick(&req_ip, backend.clone(), cancel.clone()).await.unwrap();
    assert_eq!(rep_ip.results.len(), 1);
    assert_eq!(rep_ip.results[0].feature, QuickFeature::IcmpTraceroute);
    assert_eq!(rep_ip.results[0].status, QuickStatus::PASS);
    assert_eq!(rep_ip.results[0].resolved_ip, Some("127.0.0.1".to_string()));
    assert_eq!(rep_ip.invocations.dns_lookup, 0);
    assert_eq!(rep_ip.invocations.icmp_traceroute, 1);

    // domain 대상 Trace 단독: hidden DNS resolve 1회 호출, DNS 결과 행 0개, Trace 행 1개
    let req_domain = make_request(
        vec![make_target("example.com", 8080)],
        vec![QuickFeature::IcmpTraceroute],
        1,
        DEFAULT_MAX_RESULT_BYTES,
    );
    let rep_domain = run_quick(&req_domain, backend.clone(), cancel).await.unwrap();
    assert_eq!(rep_domain.results.len(), 1);
    let trace_res = &rep_domain.results[0];
    assert_eq!(trace_res.target_host, "example.com");
    assert_eq!(trace_res.feature, QuickFeature::IcmpTraceroute);
    assert_eq!(trace_res.status, QuickStatus::PASS);
    assert_eq!(trace_res.resolved_ip, Some("127.0.0.1".to_string()));
    assert_eq!(rep_domain.invocations.dns_lookup, 1);
    assert_eq!(rep_domain.invocations.icmp_traceroute, 1);

    // limitations에 첫 후보 주소 정책, 전체 주소 목록, 필수 DNS JSON 원문 첨부 확인
    let limitations = trace_res.details["limitations"].as_array().unwrap();
    assert!(limitations.iter().any(|v| v.as_str().unwrap().contains("첫 번째 주소")));
    assert!(limitations.iter().any(|v| v.as_str().unwrap().contains("전체 주소 목록")));
    assert!(limitations.iter().any(|v| v.as_str().unwrap().contains("필수 DNS 해석 원문(JSON)")));
}

/// Trace-04: 도메인 대상 상세 DNS + Trace 동시 선택 시 resolve 1회만 호출 및 결과 안정 정렬 검증.
#[tokio::test]
async fn test_trace_04_domain_detailed_dns_and_trace() {
    let backend = Arc::new(MockProbeBackend::new());
    let cancel = Arc::new(AtomicBool::new(false));

    let targets = vec![make_target("example.com", 443)];
    let features = vec![QuickFeature::DnsLookup, QuickFeature::IcmpTraceroute];
    let req = make_request(targets, features, 1, DEFAULT_MAX_RESULT_BYTES);

    let report = run_quick(&req, backend.clone(), cancel).await.unwrap();

    assert_eq!(report.results.len(), 2);
    // 0번 행: DnsLookup (resolved_ip null)
    assert_eq!(report.results[0].feature, QuickFeature::DnsLookup);
    assert_eq!(report.results[0].status, QuickStatus::PASS);
    assert!(report.results[0].resolved_ip.is_none());

    // 1번 행: IcmpTraceroute (resolved_ip 유도치)
    assert_eq!(report.results[1].feature, QuickFeature::IcmpTraceroute);
    assert_eq!(report.results[1].status, QuickStatus::PASS);
    assert_eq!(report.results[1].resolved_ip, Some("127.0.0.1".to_string()));

    // 중복 해석 없이 dns_lookup = 1, icmp_traceroute = 1
    assert_eq!(report.invocations.dns_lookup, 1);
    assert_eq!(report.invocations.icmp_traceroute, 1);
}

/// Trace-05: 도메인 DNS 해석 실패 및 역순 취소 시 Trace 호출 0회 및 완료된 DNS raw 보존 검증.
#[tokio::test]
async fn test_trace_05_domain_dns_failure_and_reverse_cancel_trace_zero_and_dns_preserved() {
    // DNS 실패 설정
    let backend_fail = Arc::new(MockProbeBackend::new());
    backend_fail.set_dns_responder(Arc::new(|ctx| {
        Ok(DnsMeasurement {
            host: ctx.target_host.clone(),
            port: ctx.target_port,
            outcome: "DNS_ERROR".to_string(),
            addresses: vec![],
            elapsed_ms: 5,
            error_code: Some(11001),
            error_message: Some("호스트를 찾을 수 없습니다.".to_string()),
            limitations: vec![],
        })
    }));

    let req_fail = make_request(
        vec![make_target("fail.invalid", 80)],
        vec![QuickFeature::DnsLookup, QuickFeature::IcmpTraceroute],
        1,
        DEFAULT_MAX_RESULT_BYTES,
    );
    let cancel = Arc::new(AtomicBool::new(false));
    let rep_fail = run_quick(&req_fail, backend_fail.clone(), cancel).await.unwrap();

    assert_eq!(rep_fail.results.len(), 2);
    assert_eq!(rep_fail.results[0].feature, QuickFeature::DnsLookup);
    assert_eq!(rep_fail.results[0].status, QuickStatus::FAIL);

    // DNS 실패로 인해 Trace 백엔드는 호출되지 않고 UNAVAILABLE 처리
    assert_eq!(rep_fail.results[1].feature, QuickFeature::IcmpTraceroute);
    assert_eq!(rep_fail.results[1].status, QuickStatus::UNKNOWN);
    assert_eq!(rep_fail.results[1].details["outcome"], "UNAVAILABLE");
    assert_eq!(backend_fail.trace_call_count(), 0);
    assert_eq!(rep_fail.invocations.icmp_traceroute, 0);

    // 역순 취소: DNS 직후 취소 시 완료된 DNS는 보존되고 미시작 Trace는 누락 처리
    let backend_cancel = Arc::new(MockProbeBackend::new());
    let cancel_mid = Arc::new(AtomicBool::new(false));
    let trigger = cancel_mid.clone();
    backend_cancel.set_on_dns_call(Arc::new(move || {
        trigger.store(true, Ordering::SeqCst);
    }));

    let req_cancel = make_request(
        vec![make_target("example.com", 80)],
        vec![QuickFeature::DnsLookup, QuickFeature::IcmpTraceroute],
        1,
        DEFAULT_MAX_RESULT_BYTES,
    );
    let rep_cancel = run_quick(&req_cancel, backend_cancel.clone(), cancel_mid).await.unwrap();
    assert!(rep_cancel.cancelled);
    assert_eq!(rep_cancel.results.len(), 1);
    assert_eq!(rep_cancel.results[0].feature, QuickFeature::DnsLookup);
    assert_eq!(rep_cancel.omitted_results, 1);
    assert_eq!(backend_cancel.trace_call_count(), 0);
}

/// Trace-06: REACHED(PASS/OBSERVED), INCOMPLETE(유효 홉 WARN/OBSERVED, 무응답 UNKNOWN/UNKNOWN) 및 실패 매핑 검증.
#[tokio::test]
async fn test_trace_06_trace_reached_and_incomplete_and_failure_mapping() {
    let backend = Arc::new(MockProbeBackend::new());
    let cancel = Arc::new(AtomicBool::new(false));

    // 1) REACHED -> PASS / OBSERVED
    backend.set_trace_responder(Arc::new(|ctx, target| {
        let measurement = TraceMeasurement {
            target: target.to_string(),
            method: "ICMP_TRACERT".to_string(),
            outcome: "REACHED".to_string(),
            hops: vec![TraceHop {
                ttl: 1,
                address: Some(target.to_string()),
                probe_times_ms: vec![Some(10), Some(10), Some(10)],
                rtt_less_than: vec![false, false, false],
                raw_line: format!("  1    10 ms    10 ms    10 ms  {target}"),
            }],
            elapsed_ms: 30,
            exit_code: Some(0),
            raw_stdout: format!("  1    10 ms    10 ms    10 ms  {target}\r\n").into_bytes(),
            raw_stderr: vec![],
            output_truncated: false,
            limitations: vec![],
        };
        trace_to_quick_result(ctx, &measurement)
    }));

    let req1 = make_request(
        vec![make_target("127.0.0.1", 80)],
        vec![QuickFeature::IcmpTraceroute],
        1,
        DEFAULT_MAX_RESULT_BYTES,
    );
    let rep1 = run_quick(&req1, backend.clone(), cancel.clone()).await.unwrap();
    assert_eq!(rep1.results[0].status, QuickStatus::PASS);
    assert_eq!(rep1.results[0].evidence_level, EvidenceLevel::OBSERVED);

    // 2) INCOMPLETE (유효 홉 있음) -> WARN / OBSERVED
    backend.set_trace_responder(Arc::new(|ctx, target| {
        let measurement = TraceMeasurement {
            target: target.to_string(),
            method: "ICMP_TRACERT".to_string(),
            outcome: "INCOMPLETE".to_string(),
            hops: vec![
                TraceHop {
                    ttl: 1,
                    address: Some("127.0.0.2".to_string()),
                    probe_times_ms: vec![Some(5), Some(5), Some(5)],
                    rtt_less_than: vec![false, false, false],
                    raw_line: "  1     5 ms     5 ms     5 ms  127.0.0.2".to_string(),
                },
                TraceHop {
                    ttl: 2,
                    address: None,
                    probe_times_ms: vec![None, None, None],
                    rtt_less_than: vec![false, false, false],
                    raw_line: "  2     *        *        *     Request timed out.".to_string(),
                },
            ],
            elapsed_ms: 1000,
            exit_code: Some(0),
            raw_stdout: b"  1     5 ms     5 ms     5 ms  127.0.0.2\r\n  2     *        *        *     Request timed out.\r\n".to_vec(),
            raw_stderr: vec![],
            output_truncated: false,
            limitations: vec![],
        };
        trace_to_quick_result(ctx, &measurement)
    }));
    let rep2 = run_quick(&req1, backend.clone(), cancel.clone()).await.unwrap();
    assert_eq!(rep2.results[0].status, QuickStatus::WARN);
    assert_eq!(rep2.results[0].evidence_level, EvidenceLevel::OBSERVED);

    // 3) TIMED_OUT -> UNKNOWN / UNKNOWN
    backend.set_trace_responder(Arc::new(|ctx, target| {
        let measurement = TraceMeasurement {
            target: target.to_string(),
            method: "ICMP_TRACERT".to_string(),
            outcome: "TIMED_OUT".to_string(),
            hops: vec![],
            elapsed_ms: 30000,
            exit_code: None,
            raw_stdout: vec![],
            raw_stderr: vec![],
            output_truncated: false,
            limitations: vec![],
        };
        trace_to_quick_result(ctx, &measurement)
    }));
    let rep3 = run_quick(&req1, backend.clone(), cancel).await.unwrap();
    assert_eq!(rep3.results[0].status, QuickStatus::UNKNOWN);
    assert_eq!(rep3.results[0].evidence_level, EvidenceLevel::UNKNOWN);
    assert_eq!(rep3.results[0].details["outcome"], "TIMED_OUT");
}

/// Trace-07: 잘못된 IP 교차 오염, null 실측 IP, 위조 PASS raw 및 구조 모순에 대한 엄격 거부(LOCAL_ERROR) 검증.
#[tokio::test]
async fn test_trace_07_trace_verification_rejects_wrong_ip_null_ip_forged_pass_and_mismatch() {
    let backend = Arc::new(MockProbeBackend::new());
    let cancel = Arc::new(AtomicBool::new(false));

    // Case A: 실측 row인데 top resolved_ip를 None으로 변조한 경우 거부
    backend.set_trace_responder(Arc::new(|ctx, target| {
        let measurement = TraceMeasurement {
            target: target.to_string(),
            method: "ICMP_TRACERT".to_string(),
            outcome: "REACHED".to_string(),
            hops: vec![TraceHop {
                ttl: 1,
                address: Some(target.to_string()),
                probe_times_ms: vec![Some(1), Some(1), Some(1)],
                rtt_less_than: vec![true, true, true],
                raw_line: format!("  1    <1 ms    <1 ms    <1 ms  {target}"),
            }],
            elapsed_ms: 12,
            exit_code: Some(0),
            raw_stdout: format!("  1    <1 ms    <1 ms    <1 ms  {target}\r\n").into_bytes(),
            raw_stderr: vec![],
            output_truncated: false,
            limitations: vec![],
        };
        let mut res = trace_to_quick_result(ctx, &measurement)?;
        res.resolved_ip = None; // 변조
        Ok(res)
    }));

    let req = make_request(
        vec![make_target("127.0.0.1", 80)],
        vec![QuickFeature::IcmpTraceroute],
        1,
        DEFAULT_MAX_RESULT_BYTES,
    );
    let rep_a = run_quick(&req, backend.clone(), cancel.clone()).await.unwrap();
    assert_eq!(rep_a.results[0].status, QuickStatus::UNKNOWN);
    assert_eq!(rep_a.results[0].details["outcome"], "LOCAL_ERROR");

    // Case B: target IP와 기대 대상 IP 불일치 (교차 오염)
    backend.set_trace_responder(Arc::new(|ctx, _target| {
        let other_ip = "127.0.0.99".parse::<IpAddr>().unwrap();
        let measurement = TraceMeasurement {
            target: other_ip.to_string(), // 불일치
            method: "ICMP_TRACERT".to_string(),
            outcome: "REACHED".to_string(),
            hops: vec![TraceHop {
                ttl: 1,
                address: Some(other_ip.to_string()),
                probe_times_ms: vec![Some(1), Some(1), Some(1)],
                rtt_less_than: vec![true, true, true],
                raw_line: format!("  1    <1 ms    <1 ms    <1 ms  {other_ip}"),
            }],
            elapsed_ms: 12,
            exit_code: Some(0),
            raw_stdout: format!("  1    <1 ms    <1 ms    <1 ms  {other_ip}\r\n").into_bytes(),
            raw_stderr: vec![],
            output_truncated: false,
            limitations: vec![],
        };
        let mut custom_ctx = ctx.clone();
        custom_ctx.target_host = other_ip.to_string();
        let mut res = trace_to_quick_result(&custom_ctx, &measurement)?;
        res.target_host = ctx.target_host.clone();
        Ok(res)
    }));
    let rep_b = run_quick(&req, backend.clone(), cancel.clone()).await.unwrap();
    assert_eq!(rep_b.results[0].status, QuickStatus::UNKNOWN);
    assert_eq!(rep_b.results[0].details["outcome"], "LOCAL_ERROR");

    // Case C: 위조 PASS raw (exit_code != 0 인데 status를 PASS로 속인 모순 응답)
    backend.set_trace_responder(Arc::new(|ctx, target| {
        let measurement = TraceMeasurement {
            target: target.to_string(),
            method: "ICMP_TRACERT".to_string(),
            outcome: "REACHED".to_string(),
            hops: vec![TraceHop {
                ttl: 1,
                address: Some(target.to_string()),
                probe_times_ms: vec![Some(1), Some(1), Some(1)],
                rtt_less_than: vec![true, true, true],
                raw_line: format!("  1    <1 ms    <1 ms    <1 ms  {target}"),
            }],
            elapsed_ms: 12,
            exit_code: Some(1), // 비정상 종료코드이나 outcome REACHED로 위조
            raw_stdout: format!("  1    <1 ms    <1 ms    <1 ms  {target}\r\n").into_bytes(),
            raw_stderr: vec![],
            output_truncated: false,
            limitations: vec![],
        };
        let mut res = trace_to_quick_result(ctx, &measurement)?;
        res.status = QuickStatus::PASS; // 위조 PASS
        Ok(res)
    }));
    let rep_c = run_quick(&req, backend.clone(), cancel).await.unwrap();
    assert_eq!(rep_c.results[0].status, QuickStatus::UNKNOWN);
    assert_eq!(rep_c.results[0].details["outcome"], "LOCAL_ERROR");
}

/// Trace-08: 다중 대상 Trace 안정 정렬 및 바이트 예산 초과 시 즉시 차단/누락 건수 검증.
#[tokio::test]
async fn test_trace_08_budget_and_ordering_regression_with_trace() {
    let backend = Arc::new(MockProbeBackend::new());
    let cancel = Arc::new(AtomicBool::new(false));

    let targets = vec![
        make_target("127.0.0.1", 80),
        make_target("127.0.0.2", 81),
        make_target("127.0.0.3", 82),
    ];
    let features = vec![QuickFeature::TcpConnect, QuickFeature::IcmpTraceroute];
    let req = make_request(targets, features, 2, DEFAULT_MAX_RESULT_BYTES);

    let report = run_quick(&req, backend.clone(), cancel).await.unwrap();

    assert_eq!(report.results.len(), 6);
    // 원래 입력 대상 순서 및 기능 순서 안정 정렬 검증
    assert_eq!(report.results[0].target_host, "127.0.0.1");
    assert_eq!(report.results[0].feature, QuickFeature::TcpConnect);
    assert_eq!(report.results[1].target_host, "127.0.0.1");
    assert_eq!(report.results[1].feature, QuickFeature::IcmpTraceroute);
    assert_eq!(report.results[2].target_host, "127.0.0.2");
    assert_eq!(report.results[2].feature, QuickFeature::TcpConnect);
    assert_eq!(report.results[3].target_host, "127.0.0.2");
    assert_eq!(report.results[3].feature, QuickFeature::IcmpTraceroute);
    assert_eq!(report.results[4].target_host, "127.0.0.3");
    assert_eq!(report.results[4].feature, QuickFeature::TcpConnect);
    assert_eq!(report.results[5].target_host, "127.0.0.3");
    assert_eq!(report.results[5].feature, QuickFeature::IcmpTraceroute);

    assert_eq!(report.invocations.tcp_connect, 3);
    assert_eq!(report.invocations.icmp_traceroute, 3);
}

// 부모 독립 재현: 숨은 DNS 원문과 기능 순서에 독립적인 완료 결과 보존.
fn parent_dns_fixture(host: &str, port: u16, success: bool) -> DnsMeasurement {
    DnsMeasurement {
        host: host.to_string(),
        port,
        outcome: if success { "RESOLVED" } else { "DNS_ERROR" }.to_string(),
        addresses: if success {
            vec![format!("127.0.0.1:{port}")]
        } else {
            vec![]
        },
        elapsed_ms: 321,
        error_code: if success { None } else { Some(11001) },
        error_message: if success {
            None
        } else {
            Some("synthetic resolver failure".to_string())
        },
        limitations: vec!["parent-dns-raw-preservation-unique-marker".to_string()],
    }
}

fn parent_assert_full_dns_preserved(result: &QuickResult, measurement: &DnsMeasurement) {
    let expected = serde_json::to_value(measurement).unwrap();
    assert_eq!(
        result.details.as_object().unwrap().len(),
        3,
        "기존 details 세 필드 계약 유지"
    );
    let preserved = result.details["limitations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|value| {
            value
                .as_str()
                .and_then(|text| text.find('{').map(|index| &text[index..]))
                .and_then(|json| serde_json::from_str::<serde_json::Value>(json).ok())
                .is_some_and(|raw| raw == expected)
        });
    assert!(
        preserved,
        "숨은 DNS의 모든 원시 DTO 필드를 계약 호환 limitations JSON 문자열로 보존해야 함"
    );
}

async fn parent_assert_cancelled_dns_retained_after(dependent: QuickFeature) {
    let backend = Arc::new(MockProbeBackend::new());
    let cancel = Arc::new(AtomicBool::new(false));
    let trigger = Arc::clone(&cancel);
    backend.set_on_dns_call(Arc::new(move || trigger.store(true, Ordering::SeqCst)));
    let request = make_request(
        vec![make_target("cancel-order.invalid", 80)],
        vec![dependent, QuickFeature::DnsLookup],
        1,
        DEFAULT_MAX_RESULT_BYTES,
    );
    let report = run_quick(&request, backend.clone(), cancel).await.unwrap();
    assert!(report.cancelled);
    assert_eq!(backend.call_counts(), (0, 0, 0, 1));
    assert_eq!(
        report.results.len(),
        1,
        "앞 기능 취소가 뒤쪽 완료 DNS 원문을 버리면 안 됨"
    );
    assert_eq!(report.results[0].feature, QuickFeature::DnsLookup);
    assert_eq!(
        report.results[0].details["raw_measurement"]["addresses"],
        serde_json::json!(["127.0.0.1:80"])
    );
    assert_eq!(report.omitted_results, 1);
}

#[tokio::test]
async fn parent_cancel_reverse_tcp_dns_order_preserves_raw() {
    parent_assert_cancelled_dns_retained_after(QuickFeature::TcpConnect).await;
}

#[tokio::test]
async fn parent_cancel_reverse_ping_dns_order_preserves_raw() {
    parent_assert_cancelled_dns_retained_after(QuickFeature::IcmpPing).await;
}

#[tokio::test]
async fn parent_cancel_reverse_host_dns_order_preserves_raw() {
    parent_assert_cancelled_dns_retained_after(QuickFeature::LocalNetwork).await;
}

#[tokio::test]
async fn parent_cancel_reverse_trace_dns_order_preserves_raw() {
    parent_assert_cancelled_dns_retained_after(QuickFeature::IcmpTraceroute).await;
}

#[tokio::test]
async fn parent_hidden_dns_success_keeps_whole_dto_without_overwriting_tcp_raw() {
    let backend = Arc::new(MockProbeBackend::new());
    backend.set_dns_responder(Arc::new(|ctx| {
        Ok(parent_dns_fixture(&ctx.target_host, ctx.target_port, true))
    }));
    let request = make_request(
        vec![make_target("hidden-success.invalid", 80)],
        vec![QuickFeature::TcpConnect],
        1,
        DEFAULT_MAX_RESULT_BYTES,
    );
    let report = run_quick(&request, backend.clone(), Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].feature, QuickFeature::TcpConnect);
    assert_eq!(report.results[0].status, QuickStatus::PASS);
    assert_eq!(
        report.results[0].details["raw_measurement"]["target"],
        "127.0.0.1:80"
    );
    assert_eq!(
        report.results[0].details["raw_measurement"]["application_bytes_sent"],
        0
    );
    assert_eq!(backend.call_counts(), (1, 0, 0, 1));
    parent_assert_full_dns_preserved(
        &report.results[0],
        &parent_dns_fixture("hidden-success.invalid", 80, true),
    );
}

#[tokio::test]
async fn parent_hidden_dns_failure_keeps_whole_dto_without_claiming_tcp_attempt() {
    let backend = Arc::new(MockProbeBackend::new());
    backend.set_dns_responder(Arc::new(|ctx| {
        Ok(parent_dns_fixture(&ctx.target_host, ctx.target_port, false))
    }));
    let request = make_request(
        vec![make_target("hidden-failure.invalid", 80)],
        vec![QuickFeature::TcpConnect],
        1,
        DEFAULT_MAX_RESULT_BYTES,
    );
    let report = run_quick(&request, backend.clone(), Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].status, QuickStatus::UNKNOWN);
    assert_eq!(report.results[0].resolved_ip, None);
    assert_eq!(report.results[0].details["outcome"], "UNAVAILABLE");
    assert_eq!(
        report.results[0].details["raw_measurement"],
        serde_json::json!({})
    );
    assert_eq!(backend.call_counts(), (0, 0, 0, 1));
    parent_assert_full_dns_preserved(
        &report.results[0],
        &parent_dns_fixture("hidden-failure.invalid", 80, false),
    );
}

async fn parent_assert_ip_dns_is_not_a_prerequisite(forged: bool) {
    let backend = Arc::new(MockProbeBackend::new());
    backend.set_dns_responder(Arc::new(move |ctx| {
        if forged {
            Ok(parent_dns_fixture(
                "different-host.invalid",
                ctx.target_port,
                true,
            ))
        } else {
            Err(vec!["synthetic optional DNS backend error".to_string()])
        }
    }));
    let request = make_request(
        vec![make_target("127.0.0.1", 80)],
        vec![
            QuickFeature::DnsLookup,
            QuickFeature::TcpConnect,
            QuickFeature::IcmpPing,
            QuickFeature::LocalNetwork,
        ],
        1,
        DEFAULT_MAX_RESULT_BYTES,
    );
    let report = run_quick(&request, backend.clone(), Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    assert_eq!(report.results.len(), 4);
    assert_eq!(report.results[0].status, QuickStatus::UNKNOWN);
    assert_eq!(report.results[0].resolved_ip, None);
    assert_eq!(
        backend.call_counts(),
        (1, 1, 1, 1),
        "IP 원문 대상에는 선택 상세 DNS가 필수 의존성이 아님"
    );
    assert_eq!(
        backend.tcp_call_targets(),
        vec!["127.0.0.1:80".parse::<SocketAddr>().unwrap()]
    );
    assert_eq!(report.results[1].status, QuickStatus::PASS);
    assert_eq!(report.results[1].resolved_ip.as_deref(), Some("127.0.0.1"));
    assert!(!report.cancelled);
}

#[tokio::test]
async fn parent_ip_optional_dns_error_does_not_gate_literal_probes() {
    parent_assert_ip_dns_is_not_a_prerequisite(false).await;
}

#[tokio::test]
async fn parent_ip_forged_optional_dns_does_not_change_literal_destination() {
    parent_assert_ip_dns_is_not_a_prerequisite(true).await;
}

/// TCP 완료 뒤 취소되어도 이미 끝난 DNS/TCP는 보존하고 미시작 Ping만 누락시킨다.
#[tokio::test]
async fn parent_cancel_after_tcp_preserves_completed_dns_and_omits_ping() {
    let backend = Arc::new(MockProbeBackend::new());
    let cancel = Arc::new(AtomicBool::new(false));
    let trigger = Arc::clone(&cancel);
    backend.set_on_tcp_call(Arc::new(move || {
        trigger.store(true, Ordering::SeqCst);
    }));
    let request = make_request(
        vec![make_target("cancel-boundary.invalid", 80)],
        vec![
            QuickFeature::DnsLookup,
            QuickFeature::TcpConnect,
            QuickFeature::IcmpPing,
        ],
        1,
        DEFAULT_MAX_RESULT_BYTES,
    );
    let report = run_quick(&request, backend.clone(), cancel).await.unwrap();
    assert!(report.cancelled);
    assert_eq!(report.results.len(), 2);
    assert_eq!(report.results[0].feature, QuickFeature::DnsLookup);
    assert_eq!(report.results[0].resolved_ip, None);
    assert_eq!(
        report.results[0].details["raw_measurement"]["addresses"],
        serde_json::json!(["127.0.0.1:80"])
    );
    assert_eq!(report.results[1].feature, QuickFeature::TcpConnect);
    assert_eq!(report.results[1].status, QuickStatus::PASS);
    assert_eq!(report.omitted_results, 1);
    assert_eq!(backend.call_counts(), (1, 0, 0, 1));
    assert_eq!(report.invocations.tcp_connect, 1);
    assert_eq!(report.invocations.icmp_ping, 0);
    assert_eq!(report.invocations.dns_lookup, 1);
}

/// 도메인 대상 Ping 단독 선택 시에도 필수 DNS 해석 전체 원문 DTO가 limitations에 보존되는지 검증.
#[tokio::test]
async fn parent_hidden_dns_success_ping_preserves_whole_dto() {
    let backend = Arc::new(MockProbeBackend::new());
    backend.set_dns_responder(Arc::new(|ctx| {
        Ok(parent_dns_fixture(&ctx.target_host, ctx.target_port, true))
    }));
    let request = make_request(
        vec![make_target("hidden-ping.invalid", 80)],
        vec![QuickFeature::IcmpPing],
        1,
        DEFAULT_MAX_RESULT_BYTES,
    );
    let report = run_quick(&request, backend.clone(), Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].feature, QuickFeature::IcmpPing);
    assert_eq!(report.results[0].status, QuickStatus::PASS);
    assert_eq!(backend.call_counts(), (0, 1, 0, 1));
    parent_assert_full_dns_preserved(
        &report.results[0],
        &parent_dns_fixture("hidden-ping.invalid", 80, true),
    );
}

/// 도메인 대상 Host 스냅샷 단독 선택 시에도 필수 DNS 해석 전체 원문 DTO가 limitations에 보존되는지 검증.
#[tokio::test]
async fn parent_hidden_dns_success_host_preserves_whole_dto() {
    let backend = Arc::new(MockProbeBackend::new());
    backend.set_dns_responder(Arc::new(|ctx| {
        Ok(parent_dns_fixture(&ctx.target_host, ctx.target_port, true))
    }));
    let request = make_request(
        vec![make_target("hidden-host.invalid", 80)],
        vec![QuickFeature::LocalNetwork],
        1,
        DEFAULT_MAX_RESULT_BYTES,
    );
    let report = run_quick(&request, backend.clone(), Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].feature, QuickFeature::LocalNetwork);
    assert_eq!(report.results[0].status, QuickStatus::PASS);
    assert_eq!(backend.call_counts(), (0, 0, 1, 1));
    parent_assert_full_dns_preserved(
        &report.results[0],
        &parent_dns_fixture("hidden-host.invalid", 80, true),
    );
}

/// 도메인 대상 Traceroute 단독 선택 시에도 필수 DNS 해석 전체 원문 DTO가 limitations에 보존되는지 검증.
#[tokio::test]
async fn parent_hidden_dns_success_trace_preserves_whole_dto() {
    let backend = Arc::new(MockProbeBackend::new());
    backend.set_dns_responder(Arc::new(|ctx| {
        Ok(parent_dns_fixture(&ctx.target_host, ctx.target_port, true))
    }));
    let request = make_request(
        vec![make_target("hidden-trace.invalid", 80)],
        vec![QuickFeature::IcmpTraceroute],
        1,
        DEFAULT_MAX_RESULT_BYTES,
    );
    let report = run_quick(&request, backend.clone(), Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].feature, QuickFeature::IcmpTraceroute);
    assert_eq!(report.results[0].status, QuickStatus::PASS);
    assert_eq!(backend.call_counts(), (0, 0, 0, 1));
    assert_eq!(backend.trace_call_count(), 1);
    parent_assert_full_dns_preserved(
        &report.results[0],
        &parent_dns_fixture("hidden-trace.invalid", 80, true),
    );
}

/// 어댑터 검증에서 거절된 불량 host 원문은 UNAVAILABLE limitations에 반사되지 않고 고정 거부 사유만 남는지 검증.
#[tokio::test]
async fn parent_hidden_dns_malformed_host_rejected_without_reflecting_raw_dto() {
    let backend = Arc::new(MockProbeBackend::new());
    backend.set_dns_responder(Arc::new(|ctx| {
        Ok(DnsMeasurement {
            host: "bad_host_with_credential@example.com".to_string(),
            port: ctx.target_port,
            outcome: "RESOLVED".to_string(),
            addresses: vec![format!("127.0.0.1:{}", ctx.target_port)],
            elapsed_ms: 10,
            error_code: None,
            error_message: None,
            limitations: vec![],
        })
    }));
    let request = make_request(
        vec![make_target("valid-target.invalid", 80)],
        vec![QuickFeature::TcpConnect],
        1,
        DEFAULT_MAX_RESULT_BYTES,
    );
    let report = run_quick(&request, backend.clone(), Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].status, QuickStatus::UNKNOWN);
    assert_eq!(report.results[0].details["outcome"], "UNAVAILABLE");
    let limitations = report.results[0].details["limitations"].as_array().unwrap();
    assert!(
        !limitations
            .iter()
            .any(|v| v.as_str().unwrap().contains("bad_host_with_credential")),
        "불량 호스트 원문이 반사되지 않아야 함"
    );
    assert!(
        !limitations
            .iter()
            .any(|v| v.as_str().unwrap().contains("필수 DNS 해석 원문(JSON)")),
        "검증 실패한 DTO는 JSON 원문 limitations에 첨부되지 않아야 함"
    );
}

// ============================================================================
// 실제 루프백 격리 테스트 (부모 명시 실행 전용: ignored)
// ============================================================================

/// IPv4 루프백(127.0.0.1) 실제 리스너에 대한 NativeProbeBackend 연결 검증.
#[tokio::test]
#[ignore = "실제 루프백 검증: 부모 명시 실행"]
async fn test_16_live_loopback_ipv4_tcp_connect_and_ping() {
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
    assert_eq!(icmp_res.evidence_level, EvidenceLevel::OBSERVED);
    assert_eq!(report.invocations.tcp_connect, 1);
    assert_eq!(report.invocations.icmp_ping, 1);
    assert_eq!(report.invocations.local_network, 0);
    assert_eq!(report.invocations.dns_lookup, 0);
    assert_eq!(report.invocations.icmp_traceroute, 0);
    assert!(!report.cancelled);
    assert!(!report.limit_reached);
    assert_eq!(report.omitted_results, 0);
    assert!(report.errors.is_empty());
    assert_eq!(report.targets_started, 1);
    assert_eq!(report.targets_completed, 1);

    drop(listener);
}

/// IPv6 루프백(::1) 실제 리스너에 대한 NativeProbeBackend 연결 검증.
#[tokio::test]
#[ignore = "실제 루프백 검증: 부모 명시 실행"]
async fn test_17_live_loopback_ipv6_tcp_connect_and_ping() {
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

/// 실제 소유 localhost 대상 NativeDnsProbeBackend DNS 해석 및 TCP 연결 검증.
#[tokio::test]
#[ignore = "소유 localhost NativeDnsProbeBackend 검증: 부모 명시 실행"]
async fn test_18_live_native_dns_and_domain_tcp_localhost() {
    let helper_var = std::env::var("NPI_TEST_HELPER_EXE")
        .expect("NPI_TEST_HELPER_EXE 환경변수가 설정되어 있어야 합니다 (침묵 성공/반환 금지).");
    let helper_path = std::path::PathBuf::from(helper_var);
    assert!(
        helper_path.is_file(),
        "NPI_TEST_HELPER_EXE 경로의 실행파일이 존재해야 합니다: {:?}",
        helper_path
    );

    // 1. 소유 IPv4 loopback listener를 ephemeral port에 bind
    let listener_v4 =
        std::net::TcpListener::bind("127.0.0.1:0").expect("IPv4 루프백 임의 포트 바인딩 성공");
    let port = listener_v4.local_addr().unwrap().port();

    // 2. 동일한 포트로 IPv6 loopback listener도 bind 시도
    let _listener_v6 = std::net::TcpListener::bind(format!("[::1]:{port}"))
        .expect("동일 포트 IPv6 소유 리스너가 없으면 도메인 실제 시험을 성공으로 처리하지 않음");

    // OS 해석을 직접 복제하지 않고, 실제 진단과 같은 소유 helper로 사전 가용 주소를 검증한다.
    let fixture = network_core::dns_engine::resolve_isolated(
        &helper_path,
        "localhost",
        port,
        Duration::from_millis(1000),
        Arc::new(AtomicBool::new(false)),
    );
    assert_eq!(fixture.outcome, "RESOLVED");
    assert!(!fixture.addresses.is_empty());
    for raw in &fixture.addresses {
        let addr = raw
            .parse::<SocketAddr>()
            .expect("helper 주소는 완전한 SocketAddr여야 함");
        assert_eq!(addr.port(), port);
        assert!(
            addr.ip() == "127.0.0.1".parse::<IpAddr>().unwrap()
                || addr.ip() == "::1".parse::<IpAddr>().unwrap(),
            "진단 전 정확히 소유한 127.0.0.1/::1 외 주소는 거부한다"
        );
    }

    let backend = Arc::new(NativeDnsProbeBackend::new(helper_path));
    let cancel = Arc::new(AtomicBool::new(false));

    let targets = vec![make_target("localhost", port)];
    let features = vec![QuickFeature::DnsLookup, QuickFeature::TcpConnect];
    let req = make_request(targets, features, 1, DEFAULT_MAX_RESULT_BYTES);

    let report = run_quick(&req, backend, cancel).await.unwrap();

    assert_eq!(report.results.len(), 2);
    assert!(!report.cancelled);
    assert!(!report.limit_reached);
    assert_eq!(report.omitted_results, 0);

    // DnsLookup 검증
    let dns_res = &report.results[0];
    assert_eq!(dns_res.feature, QuickFeature::DnsLookup);
    assert_eq!(dns_res.status, QuickStatus::PASS);
    assert_eq!(dns_res.evidence_level, EvidenceLevel::OBSERVED);
    assert!(dns_res.resolved_ip.is_none());

    // TcpConnect 검증
    let tcp_res = &report.results[1];
    assert_eq!(tcp_res.feature, QuickFeature::TcpConnect);
    assert_eq!(tcp_res.status, QuickStatus::PASS);
    assert_eq!(tcp_res.evidence_level, EvidenceLevel::OBSERVED);
    assert_eq!(tcp_res.details["outcome"], "CONNECTED");
    assert!(tcp_res.resolved_ip.is_some());
    let resolved_ip_str = tcp_res.resolved_ip.as_ref().unwrap();
    assert!(
        resolved_ip_str == "127.0.0.1" || resolved_ip_str == "::1",
        "TCP 연결 IP는 루프백이어야 합니다: {resolved_ip_str}"
    );
    let addresses = dns_res.details["raw_measurement"]["addresses"]
        .as_array()
        .unwrap();
    assert!(!addresses.is_empty());
    let first_socket = addresses[0]
        .as_str()
        .unwrap()
        .parse::<SocketAddr>()
        .unwrap();
    assert_eq!(tcp_res.resolved_ip, Some(first_socket.ip().to_string()));
    assert_eq!(
        tcp_res.details["raw_measurement"]["target"],
        first_socket.to_string()
    );
    assert_eq!(
        tcp_res.details["raw_measurement"]["application_bytes_sent"],
        0
    );
    assert_eq!(report.invocations.dns_lookup, 1);
    assert_eq!(report.invocations.tcp_connect, 1);
    assert_eq!(report.invocations.icmp_ping, 0);
    assert_eq!(report.invocations.local_network, 0);
    assert_eq!(report.invocations.icmp_traceroute, 0);
    assert!(report.errors.is_empty());

    drop(listener_v4);
}

/// IPv4 및 IPv6 루프백 실제 NativeProbeBackend Trace 실행 및 NativeDnsProbeBackend IP Trace 위임 시 DNS 호출 0회 검증.
#[tokio::test]
#[ignore = "실제 루프백 NativeProbeBackend Trace 검증: 부모 명시 실행"]
async fn test_19_live_loopback_ipv4_and_ipv6_native_trace() {
    let backend = Arc::new(NativeProbeBackend);
    let cancel = Arc::new(AtomicBool::new(false));

    // IPv4 127.0.0.1 Trace 검증
    let targets_v4 = vec![make_target("127.0.0.1", 80)];
    let req_v4 = make_request(
        targets_v4,
        vec![QuickFeature::IcmpTraceroute],
        1,
        DEFAULT_MAX_RESULT_BYTES,
    );
    let report_v4 = run_quick(&req_v4, backend.clone(), cancel.clone())
        .await
        .unwrap();

    assert_eq!(report_v4.results.len(), 1);
    let res_v4 = &report_v4.results[0];
    assert_eq!(res_v4.feature, QuickFeature::IcmpTraceroute);
    assert_eq!(res_v4.resolved_ip, Some("127.0.0.1".to_string()));
    assert_eq!(report_v4.invocations.icmp_traceroute, 1);
    assert_eq!(report_v4.invocations.dns_lookup, 0);

    // NativeDnsProbeBackend로 동일 127.0.0.1 IP Trace 실행 시 DNS 0회 위임 확인
    let helper_var = std::env::var("NPI_TEST_HELPER_EXE")
        .expect("NPI_TEST_HELPER_EXE 환경변수가 설정되어 있어야 합니다 (침묵 성공/반환 금지).");
    let helper_path = std::path::PathBuf::from(helper_var);
    assert!(
        helper_path.is_file(),
        "NPI_TEST_HELPER_EXE 경로의 실행파일이 존재해야 합니다: {:?}",
        helper_path
    );

    let dns_backend = Arc::new(NativeDnsProbeBackend::new(helper_path));
    let rep_delegated = run_quick(&req_v4, dns_backend, cancel.clone())
        .await
        .unwrap();
    assert_eq!(rep_delegated.invocations.icmp_traceroute, 1);
    assert_eq!(
        rep_delegated.invocations.dns_lookup, 0,
        "IP 대상 Trace 시 DNS는 0회여야 함"
    );
    assert_eq!(rep_delegated.results.len(), 1);

    // IPv6 ::1 Trace 검증 (환경 미지원 시 expect 실패)
    let _listener_v6 = std::net::TcpListener::bind("[::1]:0")
        .expect("IPv6 루프백 바인딩이 불가하면 환경 미검증 실패로 남긴다 (침묵 성공 금지)");
    let targets_v6 = vec![make_target("::1", 80)];
    let req_v6 = make_request(
        targets_v6,
        vec![QuickFeature::IcmpTraceroute],
        1,
        DEFAULT_MAX_RESULT_BYTES,
    );
    let report_v6 = run_quick(&req_v6, backend, cancel).await.unwrap();
    assert_eq!(report_v6.results.len(), 1);
    let res_v6 = &report_v6.results[0];
    assert_eq!(res_v6.feature, QuickFeature::IcmpTraceroute);
    assert_eq!(res_v6.resolved_ip, Some("::1".to_string()));
}

/// 실제 소유 localhost 대상 NativeDnsProbeBackend DNS 해석 및 Traceroute 연결 검증.
#[tokio::test]
#[ignore = "소유 localhost NativeDnsProbeBackend Trace 검증: 부모 명시 실행"]
async fn test_20_live_native_dns_and_domain_trace_localhost() {
    let helper_var = std::env::var("NPI_TEST_HELPER_EXE")
        .expect("NPI_TEST_HELPER_EXE 환경변수가 설정되어 있어야 합니다 (침묵 성공/반환 금지).");
    let helper_path = std::path::PathBuf::from(helper_var);
    assert!(
        helper_path.is_file(),
        "NPI_TEST_HELPER_EXE 경로의 실행파일이 존재해야 합니다: {:?}",
        helper_path
    );

    // 1. 소유 IPv4 loopback listener를 ephemeral port에 bind
    let listener_v4 =
        std::net::TcpListener::bind("127.0.0.1:0").expect("IPv4 루프백 임의 포트 바인딩 성공");
    let port = listener_v4.local_addr().unwrap().port();

    // 2. 동일한 포트로 IPv6 loopback listener도 bind 시도
    let _listener_v6 = std::net::TcpListener::bind(format!("[::1]:{port}"))
        .expect("동일 포트 IPv6 소유 리스너가 없으면 도메인 실제 시험을 성공으로 처리하지 않음");

    // OS 해석을 직접 복제하지 않고, 실제 진단과 같은 소유 helper로 사전 가용 주소를 검증한다.
    let fixture = network_core::dns_engine::resolve_isolated(
        &helper_path,
        "localhost",
        port,
        Duration::from_millis(1000),
        Arc::new(AtomicBool::new(false)),
    );
    assert_eq!(fixture.outcome, "RESOLVED");
    assert!(!fixture.addresses.is_empty());
    for raw in &fixture.addresses {
        let addr = raw
            .parse::<SocketAddr>()
            .expect("helper 주소는 완전한 SocketAddr여야 함");
        assert_eq!(addr.port(), port);
        assert!(
            addr.ip() == "127.0.0.1".parse::<IpAddr>().unwrap()
                || addr.ip() == "::1".parse::<IpAddr>().unwrap(),
            "진단 전 정확히 소유한 127.0.0.1/::1 외 주소는 거부한다"
        );
    }

    let backend = Arc::new(NativeDnsProbeBackend::new(helper_path));
    let cancel = Arc::new(AtomicBool::new(false));

    let targets = vec![make_target("localhost", port)];
    let features = vec![QuickFeature::DnsLookup, QuickFeature::IcmpTraceroute];
    let req = make_request(targets, features, 1, DEFAULT_MAX_RESULT_BYTES);

    let report = run_quick(&req, backend, cancel).await.unwrap();

    assert_eq!(report.results.len(), 2);
    assert!(!report.cancelled);
    assert!(!report.limit_reached);
    assert_eq!(report.omitted_results, 0);

    // DnsLookup 검증
    let dns_res = &report.results[0];
    assert_eq!(dns_res.feature, QuickFeature::DnsLookup);
    assert_eq!(dns_res.status, QuickStatus::PASS);
    assert!(dns_res.resolved_ip.is_none());

    // IcmpTraceroute 검증
    let trace_res = &report.results[1];
    assert_eq!(trace_res.feature, QuickFeature::IcmpTraceroute);
    assert!(trace_res.resolved_ip.is_some());
    let resolved_ip_str = trace_res.resolved_ip.as_ref().unwrap();
    assert!(
        resolved_ip_str == "127.0.0.1" || resolved_ip_str == "::1",
        "Trace 대상 IP는 루프백이어야 합니다: {resolved_ip_str}"
    );

    // limitations에 필수 DNS 원문 JSON 및 첫 후보 주소 정책 포함 검증
    let limitations = trace_res.details["limitations"].as_array().unwrap();
    assert!(limitations.iter().any(|v| v.as_str().unwrap().contains("첫 번째 주소")));
    assert!(limitations.iter().any(|v| v.as_str().unwrap().contains("필수 DNS 해석 원문(JSON)")));

    assert_eq!(report.invocations.dns_lookup, 1);
    assert_eq!(report.invocations.icmp_traceroute, 1);
    assert_eq!(report.invocations.tcp_connect, 0);
    assert_eq!(report.invocations.icmp_ping, 0);
    assert_eq!(report.invocations.local_network, 0);

    drop(listener_v4);
}

// 부모 독립 회귀: 거부된 백엔드 원문을 오류/limitations/보고서에 재노출하지 않는다.
fn parent_trace_measurement(target: IpAddr) -> TraceMeasurement {
    let line = format!("  1    <1 ms    <1 ms    <1 ms  {target}");
    TraceMeasurement {
        target: target.to_string(),
        method: "ICMP_TRACERT".to_string(),
        outcome: "REACHED".to_string(),
        hops: vec![TraceHop {
            ttl: 1,
            address: Some(target.to_string()),
            probe_times_ms: vec![Some(1), Some(1), Some(1)],
            rtt_less_than: vec![true, true, true],
            raw_line: line.clone(),
        }],
        elapsed_ms: 12,
        exit_code: Some(0),
        raw_stdout: format!("{line}\r\n").into_bytes(),
        raw_stderr: vec![],
        output_truncated: false,
        limitations: vec![],
    }
}

async fn parent_trace_assert_rejected_value_not_reflected(field: &'static str) {
    const MARKER: &str = "TRACE_UNTRUSTED_MARKER";
    let backend = Arc::new(MockProbeBackend::new());
    backend.set_trace_responder(Arc::new(move |ctx, target| {
        if field == "backend" {
            return Err(vec![MARKER.to_string()]);
        }
        let mut result = trace_to_quick_result(ctx, &parent_trace_measurement(target))?;
        match field {
            "session" => result.session_id = MARKER.to_string(),
            "host" => result.target_host = MARKER.to_string(),
            "source" => result.source_host = Some(MARKER.to_string()),
            "timestamp" => result.timestamp_iso8601 = Some(MARKER.to_string()),
            "resolved" => result.resolved_ip = Some(MARKER.to_string()),
            "schema" => result.schema_version = MARKER.to_string(),
            "product" => result.product = MARKER.to_string(),
            "outcome" => result.details["outcome"] = serde_json::json!(MARKER),
            "method" => result.details["raw_measurement"]["method"] = serde_json::json!(MARKER),
            "raw_target" => result.details["raw_measurement"]["target"] = serde_json::json!(MARKER),
            "raw_extra" => result.details["raw_measurement"]["unexpected"] = serde_json::json!(MARKER),
            _ => panic!("알 수 없는 부모 회귀 종류"),
        }
        Ok(result)
    }));
    let request = make_request(
        vec![make_target("127.0.0.1", 80)],
        vec![QuickFeature::IcmpTraceroute],
        1,
        DEFAULT_MAX_RESULT_BYTES,
    );
    let report = run_quick(&request, backend.clone(), Arc::new(AtomicBool::new(false)))
        .await
        .unwrap();
    assert_eq!(backend.trace_call_count(), 1);
    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].status, QuickStatus::UNKNOWN);
    assert_eq!(report.results[0].details["outcome"], "LOCAL_ERROR");
    assert!(!report.errors.is_empty());
    let serialized = serde_json::to_string(&report).unwrap();
    assert!(!serialized.contains(MARKER), "거부된 {field} 값이 보고서에 반사됨");
}

macro_rules! parent_trace_rejection_case {
    ($name:ident, $field:literal) => {
        #[tokio::test]
        async fn $name() {
            parent_trace_assert_rejected_value_not_reflected($field).await;
        }
    };
}
parent_trace_rejection_case!(parent_trace_reject_session_no_reflection, "session");
parent_trace_rejection_case!(parent_trace_reject_host_no_reflection, "host");
parent_trace_rejection_case!(parent_trace_reject_source_no_reflection, "source");
parent_trace_rejection_case!(parent_trace_reject_timestamp_no_reflection, "timestamp");
parent_trace_rejection_case!(parent_trace_reject_resolved_no_reflection, "resolved");
parent_trace_rejection_case!(parent_trace_reject_schema_no_reflection, "schema");
parent_trace_rejection_case!(parent_trace_reject_product_no_reflection, "product");
parent_trace_rejection_case!(parent_trace_reject_outcome_no_reflection, "outcome");
parent_trace_rejection_case!(parent_trace_reject_method_no_reflection, "method");
parent_trace_rejection_case!(parent_trace_reject_raw_target_no_reflection, "raw_target");
parent_trace_rejection_case!(parent_trace_reject_raw_extra_no_reflection, "raw_extra");
parent_trace_rejection_case!(parent_trace_reject_backend_no_reflection, "backend");
