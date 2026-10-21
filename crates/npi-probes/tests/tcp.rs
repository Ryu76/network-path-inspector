//! `npi_probes::tcp` 통합 테스트.
//!
//! - 기본 테스트(`cargo test`)는 소켓이나 네트워크 호출을 전혀 수행하지 않는 오프라인 검증만 실행한다.
//! - 실제 루프백(`127.0.0.1`, `::1`) 소켓을 생성하는 테스트는 모두
//!   `#[ignore = "실제 루프백 검증: 부모 명시 실행"]`으로 표시하여 부모가 명시적으로만 실행한다.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use npi_probes::tcp::{TcpMeasurement, connect_once};
use tokio::net::{TcpListener, TcpStream};

/// `tokio::io::AsyncReadExt`(`io-util` 피처)에 의존하지 않고 연결된 피어 스트림에서 바이트를 읽는다.
async fn read_peer_once(stream: &TcpStream, buf: &mut [u8]) -> io::Result<usize> {
    loop {
        stream.readable().await?;
        match stream.try_read(buf) {
            Ok(n) => return Ok(n),
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => continue,
            Err(err) => return Err(err),
        }
    }
}

#[tokio::test]
async fn rejects_port_zero_ipv4_and_ipv6_without_socket() {
    let cancelled = Arc::new(AtomicBool::new(false));
    let timeout = Duration::from_millis(500);

    for target in [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
    ] {
        let m = connect_once(target, timeout, Arc::clone(&cancelled)).await;
        assert_eq!(m.target, target.to_string());
        assert_eq!(m.outcome, "LOCAL_ERROR");
        assert!(m.local_address.is_none());
        assert!(m.error_code.is_none());
        assert!(m.error_message.is_some());
        assert_eq!(m.application_bytes_sent, 0);
        assert!(!m.limitations.is_empty());
    }
}

#[tokio::test]
async fn rejects_unspecified_addresses_without_socket() {
    let cancelled = Arc::new(AtomicBool::new(false));
    let timeout = Duration::from_millis(500);

    let targets = [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 80),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 80),
        SocketAddr::new(IpAddr::V6(Ipv4Addr::UNSPECIFIED.to_ipv6_mapped()), 80),
    ];

    for target in targets {
        let m = connect_once(target, timeout, Arc::clone(&cancelled)).await;
        assert_eq!(m.target, target.to_string());
        assert_eq!(m.outcome, "LOCAL_ERROR");
        assert!(m.local_address.is_none());
        assert!(m.error_code.is_none());
        assert!(m.error_message.is_some());
        assert_eq!(m.application_bytes_sent, 0);
    }
}

#[tokio::test]
async fn rejects_multicast_addresses_without_socket() {
    let cancelled = Arc::new(AtomicBool::new(false));
    let timeout = Duration::from_millis(500);

    let ipv4_mcast = Ipv4Addr::new(224, 0, 0, 1);
    let ipv6_mcast = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

    let targets = [
        SocketAddr::new(IpAddr::V4(ipv4_mcast), 443),
        SocketAddr::new(IpAddr::V6(ipv6_mcast), 443),
        SocketAddr::new(IpAddr::V6(ipv4_mcast.to_ipv6_mapped()), 443),
    ];

    for target in targets {
        let m = connect_once(target, timeout, Arc::clone(&cancelled)).await;
        assert_eq!(m.target, target.to_string());
        assert_eq!(m.outcome, "LOCAL_ERROR");
        assert!(m.local_address.is_none());
        assert!(m.error_code.is_none());
        assert!(m.error_message.is_some());
        assert_eq!(m.application_bytes_sent, 0);
    }
}

#[tokio::test]
async fn rejects_out_of_bounds_timeout_without_socket() {
    let cancelled = Arc::new(AtomicBool::new(false));
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);

    for invalid_timeout in [
        Duration::ZERO,
        Duration::from_micros(999),
        Duration::from_millis(60_001),
        Duration::from_secs(120),
    ] {
        let m = connect_once(target, invalid_timeout, Arc::clone(&cancelled)).await;
        assert_eq!(m.outcome, "LOCAL_ERROR");
        assert!(m.local_address.is_none());
        assert!(m.error_code.is_none());
        assert!(m.error_message.is_some());
        assert_eq!(m.application_bytes_sent, 0);
    }
}

#[tokio::test]
async fn pre_cancelled_flag_wins_immediately_without_socket() {
    let cancelled = Arc::new(AtomicBool::new(true));
    let timeout = Duration::from_millis(1_000);

    for target in [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443),
    ] {
        let m = connect_once(target, timeout, Arc::clone(&cancelled)).await;
        assert_eq!(m.target, target.to_string());
        assert_eq!(m.outcome, "CANCELLED");
        assert!(m.local_address.is_none());
        assert!(m.error_code.is_none());
        assert!(m.error_message.is_some());
        assert_eq!(m.application_bytes_sent, 0);
    }
}

#[tokio::test]
async fn dto_serde_roundtrip_and_limitations_safety() {
    let cancelled = Arc::new(AtomicBool::new(false));
    let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let m = connect_once(target, Duration::from_millis(100), cancelled).await;

    let serialized = serde_json::to_value(&m).expect("TcpMeasurement 직렬화 성공");
    let obj = serialized.as_object().expect("JSON 객체여야 함");
    assert_eq!(obj.len(), 8);
    assert!(obj.contains_key("target"));
    assert!(obj.contains_key("outcome"));
    assert!(obj.contains_key("local_address"));
    assert!(obj.contains_key("elapsed_ms"));
    assert!(obj.contains_key("error_code"));
    assert!(obj.contains_key("error_message"));
    assert!(obj.contains_key("application_bytes_sent"));
    assert!(obj.contains_key("limitations"));

    let restored: TcpMeasurement =
        serde_json::from_value(serialized).expect("TcpMeasurement 역직렬화 성공");
    assert_eq!(restored, m);
    assert!(
        restored
            .limitations
            .iter()
            .any(|s| s.contains("패킷 캡처 근거 없이"))
    );
}

#[tokio::test]
#[ignore = "실제 루프백 검증: 부모 명시 실행"]
async fn loopback_ipv4_connect_success_and_zero_app_payload() {
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .expect("IPv4 루프백 리스너 바인딩 성공");
    let listen_addr = listener.local_addr().expect("리스너 로컬 주소 조회 성공");
    let cancelled = Arc::new(AtomicBool::new(false));

    let (measurement, accept_res) = tokio::join!(
        connect_once(listen_addr, Duration::from_millis(2_000), cancelled),
        listener.accept()
    );

    let (peer_stream, peer_addr) = accept_res.expect("IPv4 루프백 연결 수락 성공");

    assert_eq!(measurement.target, listen_addr.to_string());
    assert_eq!(measurement.outcome, "CONNECTED");
    assert_eq!(measurement.local_address, Some(peer_addr.to_string()));
    assert!(measurement.error_code.is_none());
    assert!(measurement.error_message.is_none());
    assert_eq!(measurement.application_bytes_sent, 0);

    let mut buf = [0u8; 32];
    let n = tokio::time::timeout(
        Duration::from_millis(500),
        read_peer_once(&peer_stream, &mut buf),
    )
    .await
    .expect("connect_once 반환 시점에 소켓이 이미 닫혀 즉시 EOF가 도착해야 함")
    .expect("피어 소켓 EOF 읽기 성공");
    assert_eq!(n, 0, "애플리케이션 페이로드 전송 바이트는 0이어야 함");
}

#[tokio::test]
#[ignore = "실제 루프백 검증: 부모 명시 실행"]
async fn loopback_ipv6_connect_success_and_zero_app_payload() {
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
        .await
        .expect("IPv6 루프백 리스너 바인딩 성공");
    let listen_addr = listener.local_addr().expect("리스너 로컬 주소 조회 성공");
    let cancelled = Arc::new(AtomicBool::new(false));

    let (measurement, accept_res) = tokio::join!(
        connect_once(listen_addr, Duration::from_millis(2_000), cancelled),
        listener.accept()
    );

    let (peer_stream, peer_addr) = accept_res.expect("IPv6 루프백 연결 수락 성공");

    assert_eq!(measurement.target, listen_addr.to_string());
    assert_eq!(measurement.outcome, "CONNECTED");
    assert_eq!(measurement.local_address, Some(peer_addr.to_string()));
    assert!(measurement.error_code.is_none());
    assert!(measurement.error_message.is_none());
    assert_eq!(measurement.application_bytes_sent, 0);

    let mut buf = [0u8; 32];
    let n = tokio::time::timeout(
        Duration::from_millis(500),
        read_peer_once(&peer_stream, &mut buf),
    )
    .await
    .expect("connect_once 반환 시점에 소켓이 이미 닫혀 즉시 EOF가 도착해야 함")
    .expect("피어 소켓 EOF 읽기 성공");
    assert_eq!(n, 0, "애플리케이션 페이로드 전송 바이트는 0이어야 함");
}

#[tokio::test]
#[ignore = "실제 루프백 검증: 부모 명시 실행"]
async fn loopback_ipv4_connect_refused() {
    // `socket2` 직접 의존성이 없어 bind-only(미리스닝) 소켓을 유지할 수 없으므로,
    // 임시 리스너를 바인딩한 뒤 즉시 drop하여 닫힌 포트를 확보한다(bind/drop 사이 극소 경합 가능).
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .await
        .expect("임시 IPv4 루프백 리스너 바인딩 성공");
    let closed_addr = listener.local_addr().expect("임시 포트 조회 성공");
    drop(listener);

    // Windows 루프백 닫힌 포트 실측에서 OS의 WSAECONNREFUSED(10061) 반환이 2000ms를 초과(IPv4 약 2088ms,
    // IPv6 약 2099ms)하여 2000ms 설정 시 제품 데드라인 의미론에 따라 TIMED_OUT이 반환된다.
    // 이는 제품 성능 기준 완화가 아니라 PRD 기본 TCP 타임아웃(5000ms)을 사용해 실제 OS REFUSED 도달을 검증하는 것이다.
    let cancelled = Arc::new(AtomicBool::new(false));
    let measurement = connect_once(closed_addr, Duration::from_millis(5_000), cancelled).await;

    assert_eq!(measurement.target, closed_addr.to_string());
    assert_eq!(measurement.outcome, "REFUSED");
    assert!(measurement.local_address.is_none());
    assert!(measurement.error_code.is_some());
    assert!(measurement.error_message.is_some());
    assert_eq!(measurement.application_bytes_sent, 0);
}

#[tokio::test]
#[ignore = "실제 루프백 검증: 부모 명시 실행"]
async fn loopback_ipv6_connect_refused() {
    // `socket2` 직접 의존성이 없어 bind-only(미리스닝) 소켓을 유지할 수 없으므로,
    // 임시 리스너를 바인딩한 뒤 즉시 drop하여 닫힌 포트를 확보한다(bind/drop 사이 극소 경합 가능).
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
        .await
        .expect("임시 IPv6 루프백 리스너 바인딩 성공");
    let closed_addr = listener.local_addr().expect("임시 포트 조회 성공");
    drop(listener);

    // Windows 루프백 닫힌 포트 실측에서 OS의 WSAECONNREFUSED(10061) 반환이 2000ms를 초과(IPv4 약 2088ms,
    // IPv6 약 2099ms)하여 2000ms 설정 시 제품 데드라인 의미론에 따라 TIMED_OUT이 반환된다.
    // 이는 제품 성능 기준 완화가 아니라 PRD 기본 TCP 타임아웃(5000ms)을 사용해 실제 OS REFUSED 도달을 검증하는 것이다.
    let cancelled = Arc::new(AtomicBool::new(false));
    let measurement = connect_once(closed_addr, Duration::from_millis(5_000), cancelled).await;

    assert_eq!(measurement.target, closed_addr.to_string());
    assert_eq!(measurement.outcome, "REFUSED");
    assert!(measurement.local_address.is_none());
    assert!(measurement.error_code.is_some());
    assert!(measurement.error_message.is_some());
    assert_eq!(measurement.application_bytes_sent, 0);
}

#[tokio::test]
#[ignore = "실제 루프백 검증: 부모 명시 실행"]
async fn loopback_connect_cancelled() {
    let cancelled = Arc::new(AtomicBool::new(false));
    cancelled.store(true, Ordering::SeqCst);

    for target in [
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9),
        SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9),
    ] {
        let measurement =
            connect_once(target, Duration::from_millis(1_000), Arc::clone(&cancelled)).await;
        assert_eq!(measurement.outcome, "CANCELLED");
        assert!(measurement.local_address.is_none());
        assert_eq!(measurement.application_bytes_sent, 0);
    }
}
