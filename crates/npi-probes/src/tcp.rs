//! G2-A 단일 대상 TCP 연결 측정 모듈.
//!
//! - 이미 해석된 `SocketAddr`에 대해서만 비동기 TCP 연결(`tokio::net::TcpStream::connect`)을 수행하며,
//!   암묵적인 DNS 조회나 블로킹 스레드 생성을 수행하지 않는다.
//! - 취소 플래그(`cancelled`)를 최우선(`tokio::select! { biased; ... }`)으로 감시하며,
//!   폴링 주기는 20ms 이하(10ms)이고 전체 타임아웃은 단일 데드라인으로 유지한다.
//! - 연결 직후 로컬 주소(`local_addr`)만 확인하고 즉시 소켓/퓨처를 drop하며,
//!   애플리케이션 페이로드(TLS/HTTP/Oracle 등)는 절대 전송하거나 읽지 않는다(`application_bytes_sent = 0`).
//! - OS 소켓 오류는 `npi_core::classify_tcp_error`로 분류하며, 패킷 캡처 근거 없이
//!   SYN/RST 패킷 관찰이나 중간 차단 장비를 추론·단정하지 않는다.

use std::{
    future::Future,
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use npi_core::{TcpOutcome, classify_tcp_error};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;

/// 최소 허용 TCP 타임아웃 (1ms).
const MIN_TIMEOUT: Duration = Duration::from_millis(1);

/// 최대 허용 TCP 타임아웃 (60,000ms).
const MAX_TIMEOUT: Duration = Duration::from_millis(60_000);

/// 취소 플래그 감시 폴링 주기 (계약 상한 20ms 이하인 10ms).
const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// TCP 단일 연결 시도 측정 결과 DTO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpMeasurement {
    pub target: String,
    pub outcome: String,
    pub local_address: Option<String>,
    pub elapsed_ms: u64,
    pub error_code: Option<i32>,
    pub error_message: Option<String>,
    pub application_bytes_sent: u64,
    pub limitations: Vec<String>,
}

/// 내부 비동기 연결 구동 결과.
#[derive(Debug)]
enum ConnectDriveResult<T> {
    Connected(T),
    OsError(io::Error),
    TimedOut,
    Cancelled,
}

/// 공통 측정 한계 및 안전 고지 문구를 생성한다.
fn base_limitations() -> Vec<String> {
    vec![
        "OS 소켓 API 수준의 관찰 결과이며, 패킷 캡처 근거 없이 실제 SYN/RST 패킷 송수신이나 중간 차단 장비를 단정하지 않습니다."
            .to_string(),
        "TCP 연결 수립 여부만 확인하며 애플리케이션 페이로드(TLS/HTTP/Oracle 등)는 0바이트 전송합니다."
            .to_string(),
        "elapsed_ms는 단조 시계(Instant) 기준 경과 시간이며 UTC 시각이 아닙니다.".to_string(),
    ]
}

/// 단조 시계 시작점으로부터 경과 시간을 밀리초(`u64`)로 환산한다.
fn elapsed_millis(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// 소켓 생성 전 대상 주소 및 타임아웃 범위를 검증한다.
///
/// - 타임아웃은 `1..=60000ms` 범위만 허용한다.
/// - 포트 0, 미지정(unspecified) IP, 멀티캐스트(multicast) IP는 소켓 생성 전에 거부한다.
fn validate_before_socket(target: SocketAddr, timeout: Duration) -> Result<(), String> {
    if timeout < MIN_TIMEOUT || timeout > MAX_TIMEOUT {
        return Err(format!(
            "허용 범위를 벗어난 TCP 타임아웃({}ms): 1..=60000ms 범위여야 합니다.",
            timeout.as_millis()
        ));
    }

    if target.port() == 0 {
        return Err("유효하지 않은 대상 포트(0): 소켓 생성 전 거부되었습니다.".to_string());
    }

    let ip = target.ip();
    let is_unspecified = match ip {
        IpAddr::V4(v4) => v4.is_unspecified(),
        IpAddr::V6(v6) => {
            v6.is_unspecified() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_unspecified())
        }
    };
    if is_unspecified {
        return Err(
            "미지정(unspecified) 대상 IP 주소는 소켓 생성 전 거부되었습니다.".to_string(),
        );
    }

    let is_multicast = match ip {
        IpAddr::V4(v4) => v4.is_multicast(),
        IpAddr::V6(v6) => {
            v6.is_multicast() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_multicast())
        }
    };
    if is_multicast {
        return Err(
            "멀티캐스트(multicast) 대상 IP 주소는 소켓 생성 전 거부되었습니다.".to_string(),
        );
    }

    Ok(())
}

/// 취소 원자 플래그가 설정될 때까지 20ms 이하 주기로 대기한다.
async fn wait_for_cancellation(cancelled: &AtomicBool) {
    loop {
        if cancelled.load(Ordering::SeqCst) {
            return;
        }
        tokio::time::sleep(CANCEL_POLL_INTERVAL).await;
    }
}

/// 순수 비동기 연결 퓨처에 대해 취소 우선(`biased;`) 및 전체 데드라인을 적용해 구동한다.
/// 반환 전에 내부 연결 퓨처가 반드시 drop되도록 보장한다.
async fn drive_connect_future<F, T>(
    connect_future: F,
    timeout: Duration,
    cancelled: &AtomicBool,
) -> ConnectDriveResult<T>
where
    F: Future<Output = io::Result<T>>,
{
    if cancelled.load(Ordering::SeqCst) {
        drop(connect_future);
        return ConnectDriveResult::Cancelled;
    }

    let cancel_fut = wait_for_cancellation(cancelled);
    let timeout_fut = tokio::time::sleep(timeout);

    tokio::pin!(connect_future);
    tokio::pin!(cancel_fut);
    tokio::pin!(timeout_fut);

    let outcome = tokio::select! {
        biased;
        _ = &mut cancel_fut => ConnectDriveResult::Cancelled,
        _ = &mut timeout_fut => ConnectDriveResult::TimedOut,
        res = &mut connect_future => match res {
            Ok(connected) => ConnectDriveResult::Connected(connected),
            Err(err) => ConnectDriveResult::OsError(err),
        },
    };

    // 동시 완료 경합 시에도 취소 요청이 항상 우선하도록 보장한다.
    if cancelled.load(Ordering::SeqCst) {
        return ConnectDriveResult::Cancelled;
    }

    outcome
}

/// 구동 결과를 계약된 `TcpMeasurement` DTO로 변환한다.
fn finalize_measurement(
    target: SocketAddr,
    started: Instant,
    timeout: Duration,
    drive_result: ConnectDriveResult<io::Result<SocketAddr>>,
) -> TcpMeasurement {
    let target_str = target.to_string();
    let mut limitations = base_limitations();

    match drive_result {
        ConnectDriveResult::Cancelled => TcpMeasurement {
            target: target_str,
            outcome: classify_tcp_error(None, false, true),
            local_address: None,
            elapsed_ms: elapsed_millis(started),
            error_code: None,
            error_message: Some("사용자 취소 요청으로 TCP 연결 시도가 중단되었습니다.".to_string()),
            application_bytes_sent: 0,
            limitations,
        },
        ConnectDriveResult::TimedOut => TcpMeasurement {
            target: target_str,
            outcome: classify_tcp_error(None, true, false),
            local_address: None,
            elapsed_ms: elapsed_millis(started),
            error_code: None,
            error_message: Some(format!(
                "지정된 제한 시간({}ms) 내에 TCP 연결이 완료되지 않아 시간 초과되었습니다.",
                timeout.as_millis()
            )),
            application_bytes_sent: 0,
            limitations,
        },
        ConnectDriveResult::OsError(err) => {
            let raw_code = err.raw_os_error();
            let raw_message = err.to_string();
            let is_timed_out = err.kind() == io::ErrorKind::TimedOut;
            let outcome = classify_tcp_error(raw_code, is_timed_out, false);

            TcpMeasurement {
                target: target_str,
                outcome,
                local_address: None,
                elapsed_ms: elapsed_millis(started),
                error_code: raw_code,
                error_message: Some(raw_message),
                application_bytes_sent: 0,
                limitations,
            }
        }
        ConnectDriveResult::Connected(local_addr_result) => {
            let local_address = match local_addr_result {
                Ok(addr) => Some(addr.to_string()),
                Err(err) => {
                    limitations.push(format!(
                        "TCP 연결은 성립되었으나 실제 소켓 로컬 주소(local_addr) 조회에 실패했습니다: {err}"
                    ));
                    None
                }
            };

            TcpMeasurement {
                target: target_str,
                outcome: TcpOutcome::Connected.as_str().to_string(),
                local_address,
                elapsed_ms: elapsed_millis(started),
                error_code: None,
                error_message: None,
                application_bytes_sent: 0,
                limitations,
            }
        }
    }
}

/// 이미 해석된 단일 `SocketAddr`에 대해 1회 비동기 TCP 연결을 시도하고 결과를 반환한다.
///
/// - 암묵적 DNS 조회나 백그라운드 태스크 생성(`tokio::spawn`)을 수행하지 않는다.
/// - 취소 플래그(`cancelled`)가 설정된 경우 즉시 `CANCELLED`를 반환한다.
/// - 타임아웃 범위(`1..=60000ms`) 위반 및 포트 0 / 미지정 / 멀티캐스트 대상은 소켓 생성 전 `LOCAL_ERROR`로 거부한다.
/// - 연결 성공 시 실제 `stream.local_addr()`만 읽고 반환 전에 연결 스트림을 즉시 drop한다.
pub async fn connect_once(
    target: SocketAddr,
    timeout: Duration,
    cancelled: Arc<AtomicBool>,
) -> TcpMeasurement {
    let started = Instant::now();

    if cancelled.load(Ordering::SeqCst) {
        return finalize_measurement(target, started, timeout, ConnectDriveResult::Cancelled);
    }

    if let Err(validation_msg) = validate_before_socket(target, timeout) {
        let mut limitations = base_limitations();
        limitations.push("사전 입력 검증 실패로 인해 실제 OS 소켓을 생성하지 않았습니다.".to_string());
        return TcpMeasurement {
            target: target.to_string(),
            outcome: classify_tcp_error(None, false, false),
            local_address: None,
            elapsed_ms: elapsed_millis(started),
            error_code: None,
            error_message: Some(validation_msg),
            application_bytes_sent: 0,
            limitations,
        };
    }

    let drive_result = drive_connect_future(
        async {
            let stream = TcpStream::connect(target).await?;
            let local_addr = stream.local_addr();
            // 반환 전에 연결 소켓을 명시적으로 닫아 잔류 리소스를 남기지 않는다.
            drop(stream);
            Ok(local_addr)
        },
        timeout,
        cancelled.as_ref(),
    )
    .await;

    finalize_measurement(target, started, timeout, drive_result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[tokio::test]
    async fn pending_future_times_out_at_deadline_without_socket() {
        let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080));
        let timeout = Duration::from_millis(30);
        let cancelled = AtomicBool::new(false);
        let started = Instant::now();

        let drive_res = drive_connect_future(
            std::future::pending::<io::Result<io::Result<SocketAddr>>>(),
            timeout,
            &cancelled,
        )
        .await;

        assert!(matches!(drive_res, ConnectDriveResult::TimedOut));
        let measurement = finalize_measurement(target, started, timeout, drive_res);
        assert_eq!(measurement.outcome, "TIMED_OUT");
        assert!(measurement.local_address.is_none());
        assert!(measurement.error_code.is_none());
        assert!(measurement.error_message.is_some());
        assert_eq!(measurement.application_bytes_sent, 0);
        assert!(measurement.elapsed_ms >= 20);
    }

    #[tokio::test]
    async fn pending_future_cancels_within_polling_bound_without_socket() {
        let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080));
        let timeout = Duration::from_millis(5_000);
        let cancelled = AtomicBool::new(false);
        let started = Instant::now();

        let (drive_res, _) = tokio::join!(
            drive_connect_future(
                std::future::pending::<io::Result<io::Result<SocketAddr>>>(),
                timeout,
                &cancelled,
            ),
            async {
                tokio::time::sleep(Duration::from_millis(15)).await;
                cancelled.store(true, Ordering::SeqCst);
            }
        );

        assert!(matches!(drive_res, ConnectDriveResult::Cancelled));
        let measurement = finalize_measurement(target, started, timeout, drive_res);
        assert_eq!(measurement.outcome, "CANCELLED");
        assert!(measurement.local_address.is_none());
        assert!(measurement.error_code.is_none());
        assert!(measurement.error_message.is_some());
        assert_eq!(measurement.application_bytes_sent, 0);
        assert!(measurement.elapsed_ms < 1_000);
    }

    #[tokio::test]
    async fn os_error_mapping_uses_core_taxonomy_without_socket() {
        let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8080));
        let timeout = Duration::from_millis(100);
        let cancelled = AtomicBool::new(false);

        let cases = [
            (10061, "REFUSED"),
            (10054, "RESET"),
            (10060, "TIMED_OUT"),
            (10051, "UNREACHABLE"),
            (10065, "UNREACHABLE"),
            (10050, "LOCAL_ERROR"),
            (10013, "LOCAL_ERROR"),
        ];

        for (code, expected_outcome) in cases {
            let started = Instant::now();
            let drive_res = drive_connect_future(
                std::future::ready(Err::<io::Result<SocketAddr>, _>(
                    io::Error::from_raw_os_error(code),
                )),
                timeout,
                &cancelled,
            )
            .await;

            let measurement = finalize_measurement(target, started, timeout, drive_res);
            assert_eq!(measurement.outcome, expected_outcome);
            assert_eq!(measurement.error_code, Some(code));
            assert!(measurement.error_message.is_some());
            assert!(measurement.local_address.is_none());
            assert_eq!(measurement.application_bytes_sent, 0);
        }
    }
}
