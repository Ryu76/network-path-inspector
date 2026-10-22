//! 제품 동일 EXE DNS worker 통합 테스트 (`resolver_dispatch.rs`).
//!
//! 본 파일의 모든 테스트는 `#[ignore]`로 지정되어 부모 감독자의 명시적 지시에 의해서만 실행됩니다.
//! 제품 바이너리(`NetworkQuickCheck`)를 helper 프로세스로 기동하여 `NativeDnsProbeBackend`를 통한
//! localhost 이름 해석 IPC가 올바르게 작동하는지 검증합니다.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use network_core::dns_engine::{OUTCOME_RESOLVED, parse_helper_port, validate_host};
use network_core::quick::QuickContext;
use network_core::runner::{NativeDnsProbeBackend, QuickProbeBackend};

#[test]
#[ignore = "부모 감독자가 명시적으로 제품 바이너리와 함께 실행하는 native 통합 테스트"]
fn test_product_exe_dns_worker_dispatch_localhost() {
    // Cargo가 주입하는 컴파일된 제품 실행 파일 절대 경로를 확인합니다.
    let exe_path = PathBuf::from(env!("CARGO_BIN_EXE_NetworkQuickCheck"));
    assert!(
        exe_path.is_absolute(),
        "제품 실행 파일 경로는 절대 경로여야 합니다: {:?}",
        exe_path
    );
    assert!(
        exe_path.exists(),
        "제품 실행 파일이 디스크에 존재해야 합니다: {:?}",
        exe_path
    );

    // 부모 소유 localhost 리스너를 바인딩합니다 (127.0.0.1:0 및 동일 포트 [::1]).
    // 시험 종료 시점까지 리스너 핸들을 유지하여 포트가 유효하게 점유되도록 보장합니다.
    let mut bound = None;
    for _ in 0..10 {
        let v4 = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(_) => continue,
        };
        let port = match v4.local_addr() {
            Ok(addr) => addr.port(),
            Err(_) => continue,
        };
        let v6 = TcpListener::bind(format!("[::1]:{port}")).ok();
        bound = Some((v4, v6, port));
        break;
    }
    let (_v4_listener, _v6_listener, port) =
        bound.expect("localhost 테스트를 위한 TcpListener 바인딩 실패");

    // 포트 및 호스트 사전 검증 (엔진 계약 확인)
    assert!(validate_host("localhost").is_ok());
    assert!(parse_helper_port(&port.to_string()).is_ok());

    // NativeDnsProbeBackend 생성
    let backend = NativeDnsProbeBackend::new(exe_path);

    // QuickContext 구성 (단일 localhost 대상)
    let ctx = QuickContext {
        session_id: "test-product-exe-worker-dispatch-session".to_string(),
        timestamp_iso8601: Some("2026-10-22T15:30:00Z".to_string()),
        source_host: None,
        target_host: "localhost".to_string(),
        target_port: port,
    };

    // Tokio 런타임은 ignored 테스트 함수 내부에서만 생성하여 사용합니다.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("단위 테스트용 Tokio 런타임 생성 실패");

    let cancel = Arc::new(AtomicBool::new(false));
    let timeout = Duration::from_secs(5);

    // 단 1회의 resolve 프로브만 실행합니다 (TCP/Ping/Host/Trace 호출 금지).
    let measurement = rt
        .block_on(backend.resolve(ctx, timeout, cancel))
        .expect("NativeDnsProbeBackend::resolve 호출 실패");

    // 해석 결과 검증: RESOLVED, nonempty addresses, 오류 없음
    assert_eq!(
        measurement.outcome, OUTCOME_RESOLVED,
        "localhost 해석 outcome이 RESOLVED가 아닙니다: {:?}",
        measurement.outcome
    );
    assert!(
        !measurement.addresses.is_empty(),
        "해석된 주소 목록이 비어 있습니다."
    );
    assert!(
        measurement.error_code.is_none(),
        "RESOLVED 결과에 error_code가 존재합니다: {:?}",
        measurement.error_code
    );
    assert!(
        measurement.error_message.is_none(),
        "RESOLVED 결과에 error_message가 존재합니다: {:?}",
        measurement.error_message
    );

    // 원본 호스트 및 포트 불일치 여부 검증
    assert_eq!(measurement.host, "localhost");
    assert_eq!(measurement.port, port);

    // 반환된 모든 SocketAddr 검증: 포트 일치 및 127.0.0.1 또는 ::1인지 엄격 확인
    for addr_str in &measurement.addresses {
        let sock_addr: SocketAddr = addr_str
            .parse()
            .unwrap_or_else(|e| panic!("반환 주소 '{addr_str}' 파싱 실패: {e}"));
        assert_eq!(
            sock_addr.port(),
            port,
            "반환 주소 포트가 요청 포트와 일치하지 않습니다: {sock_addr}"
        );
        let ip = sock_addr.ip();
        let is_loopback = ip == IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))
            || ip == IpAddr::V6(Ipv6Addr::LOCALHOST);
        assert!(
            is_loopback,
            "반환 IP가 허용된 루프백 주소(127.0.0.1 또는 ::1)가 아닙니다: {ip}"
        );
    }
}
