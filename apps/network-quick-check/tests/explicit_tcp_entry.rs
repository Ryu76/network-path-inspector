//! Network Quick Check(Part B) 제품 EXE 명시 개발용 단일 TCP 진입점 실제 소유 루프백 시험.
//!
//! ## 원칙 및 설계
//! - 본 시험은 실제 빌드된 제품 단일 실행 파일(`NetworkQuickCheck.exe`)을 직접 자식 프로세스로 실행하여,
//!   `--dev-tcp-once-v1 <host> <port>` 진입점의 실제 OS 소켓 동작 및 계약 준수를 검증합니다.
//! - 소유 루프백(`127.0.0.1` 및 `::1`) 대상과 OS가 할당한 ephemeral port만 사용하며,
//!   외부 네트워크, 임의 대상, 도메인, localhost, 와일드카드 주소는 일체 호출하지 않습니다.
//! - 실제 네트워크 소켓을 생성하고 제품 프로세스를 실행하는 4개 테스트(`native_ipv4_connected`,
//!   `native_ipv4_refused`, `native_ipv6_connected`, `native_ipv6_refused`)는 모두
//!   `#[ignore = "부모 소유 루프백 명시 실행"]`으로 격리되어 기본 시험 실행 시 어떤 네트워크 소켓이나
//!   자식 프로세스도 기동하지 않습니다.
//! - 직접 spawn한 Child는 예상 오류에도 kill/wait하며, unwind에는 kill_on_drop을 최후 요청으로 둡니다.
//! - 표준 출력은 65,536바이트 이하의 단일 행 JSON(`QuickRunReport`)으로 전달되어야 하며,
//!   표준 에러는 성공 시 비어있어야 하고 비정상적인 버퍼 오버플로를 방지합니다.
//! - 연결 성공 픽스처는 서버 쓰기 없이 클라이언트의 정상 접속 및 연결 종료(EOF)를 관찰하며,
//!   수신된 애플리케이션 바이트 0과 서버의 accept peer_addr가 raw.local_address와 일치함을 대조합니다.
//! - 연결 거부 픽스처는 bound/nonlisten 상태의 `TcpSocket`을 자식 프로세스 완료 시까지 유지하여
//!   실제 OS 거부 오류(WSAECONNREFUSED 10061)와 local_address=null을 확인합니다.

#![cfg(windows)]

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use network_core::TcpMeasurement;
use network_core::quick::{
    EvidenceLevel, QUICK_PRODUCT_NAME, QUICK_SCHEMA_VERSION, QuickFeature, QuickStatus,
};
use network_core::runner::QuickRunReport;
use tokio::net::{TcpListener, TcpSocket};

/// 최대 허용 stdout 바이트 (65,536 바이트).
const MAX_STDOUT_BYTES: usize = 65536;

/// 최대 허용 stderr 바이트 (4,096 바이트).
const MAX_STDERR_BYTES: usize = 4096;

/// 자식 프로세스 실행 및 통신 최대 허용 시한 (5초).
const STAGE_TIMEOUT: Duration = Duration::from_secs(5);

/// 서버 accept 및 스트림 EOF 관찰 허용 시한 (3초).
const STREAM_TIMEOUT: Duration = Duration::from_secs(3);

/// 테스트 대상 제품 실행 파일의 절대 경로를 안전하게 확인하고 반환합니다.
fn get_target_exe() -> PathBuf {
    let exe_str = env!("CARGO_BIN_EXE_NetworkQuickCheck");
    let path = PathBuf::from(exe_str);
    assert!(
        path.is_absolute(),
        "CARGO_BIN_EXE_NetworkQuickCheck 경로가 절대 경로여야 합니다: {exe_str}"
    );
    assert!(
        path.is_file(),
        "CARGO_BIN_EXE_NetworkQuickCheck 실행 파일이 실제로 존재해야 합니다: {exe_str}"
    );
    path
}

/// 부모가 직접 시작한 비동기 Child만 소유한다. 예상 오류에서도 kill().await로 회수한다.
/// unwind의 kill_on_drop은 최후의 종료 요청이며 즉각적인 OS 회수 인증은 아니다.
struct ChildGuard {
    child: tokio::process::Child,
}

type ChildOutput = (std::process::ExitStatus, Vec<u8>, Vec<u8>);

/// reader thread를 직접 분리하지 않고 상한+1 byte만 비동기로 수집한다.
async fn collect_capped<R: tokio::io::AsyncRead + Unpin>(
    mut pipe: R,
    limit: usize,
) -> Result<Vec<u8>, String> {
    let capacity = limit.checked_add(1).ok_or("파이프 상한 오류")?;
    let mut bytes = Vec::with_capacity(capacity);
    loop {
        let mut chunk = [0u8; 1024];
        let take = chunk.len().min(capacity - bytes.len());
        let mut read = tokio::io::ReadBuf::new(&mut chunk[..take]);
        std::future::poll_fn(|cx| std::pin::Pin::new(&mut pipe).poll_read(cx, &mut read))
            .await
            .map_err(|_| "소유 파이프 읽기 오류")?;
        let received = read.filled();
        if received.is_empty() {
            return Ok(bytes);
        }
        bytes.extend_from_slice(received);
        if bytes.len() > limit {
            return Err("소유 파이프 상한 초과".to_string());
        }
    }
}

impl ChildGuard {
    async fn stop_and_reap(&mut self) -> Result<(), String> {
        // kill()은 종료 요청 뒤 wait까지 포함한다. 실패/시한 초과는 성공으로 숨기지 않는다.
        tokio::time::timeout(Duration::from_secs(3), self.child.kill())
            .await
            .map_err(|_| "소유 Child 정리 시한 초과".to_string())?
            .map_err(|_| "소유 Child kill/wait 실패".to_string())
    }

    async fn wait_output_bounded(
        mut self,
        max_stdout: usize,
        max_stderr: usize,
        timeout: Duration,
    ) -> Result<ChildOutput, String> {
        let pipes = (self.child.stdout.take(), self.child.stderr.take());
        let (stdout, stderr) = match pipes {
            (Some(stdout), Some(stderr)) => (stdout, stderr),
            _ => {
                self.stop_and_reap().await?;
                return Err("소유 Child 파이프 누락".to_string());
            }
        };
        let result = tokio::time::timeout(timeout, async {
            tokio::join!(
                collect_capped(stdout, max_stdout),
                collect_capped(stderr, max_stderr),
                self.child.wait()
            )
        })
        .await;
        match result {
            Ok((stdout, stderr, Ok(status))) => {
                // 세 future가 모두 끝난 뒤 오류를 반환한다. 첫 reader 오류가 다른 회수를 건너뛰지 않는다.
                Ok((status, stdout?, stderr?))
            }
            Ok((_, _, Err(_))) => {
                self.stop_and_reap().await?;
                Err("소유 Child 대기 실패".to_string())
            }
            Err(_) => {
                // timeout은 inline 수집 future를 drop한다. 분리된 reader task는 만들지 않았다.
                self.stop_and_reap().await?;
                Err("소유 Child 실행/출력 시한 초과".to_string())
            }
        }
    }
}

/// 정확한 제품 EXE·literal 소유 주소만 호출한다. stdin null·숨김 콘솔·drop 시 종료 요청.
fn spawn_product_child(exe_path: &Path, host: &str, port: u16) -> ChildGuard {
    let mut command = tokio::process::Command::new(exe_path);
    command
        .arg("--dev-tcp-once-v1")
        .arg(host)
        .arg(port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .creation_flags(0x0800_0000);
    ChildGuard {
        child: command.spawn().expect("소유 제품 Child spawn 실패"),
    }
}

/// 서버 스트림이 클라이언트에 의해 정상적으로 닫힐 때까지(EOF) 대기하고 수신 바이트를 확인합니다.
async fn wait_for_stream_eof(
    stream: &mut tokio::net::TcpStream,
    timeout: Duration,
) -> Result<usize, String> {
    tokio::time::timeout(timeout, async {
        let mut buf = [0u8; 64];
        let mut total_bytes = 0usize;
        loop {
            stream
                .readable()
                .await
                .map_err(|e| format!("stream.readable 대기 실패: {e}"))?;
            match stream.try_read(&mut buf) {
                Ok(0) => return Ok(total_bytes),
                Ok(n) => total_bytes += n,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(format!("stream.try_read 실패: {e}")),
            }
        }
    })
    .await
    .map_err(|_| "서버 EOF 관찰 시한 초과".to_string())?
}

/// JSON 값 내 필수 nullable 키들이 명시적 null인지 엄격히 검증합니다.
fn assert_explicit_nulls(value: &serde_json::Value, keys: &[&str]) {
    for key in keys {
        assert_eq!(
            value.get(*key),
            Some(&serde_json::Value::Null),
            "필수 명시적 null 키 누락 또는 불일치: {key}"
        );
    }
}

/// 자식 프로세스의 출력 보고서 및 원시 측정값을 계약에 따라 종합 검증합니다.
fn verify_product_child_report(
    stdout_bytes: &[u8],
    stderr_bytes: &[u8],
    status: std::process::ExitStatus,
    expected_ip: &str,
    expected_port: u16,
    expected_outcome: &str,
    expected_os_code: Option<i32>,
) -> (QuickRunReport, TcpMeasurement) {
    assert!(
        status.success(),
        "자식 프로세스 종료 코드가 0이어야 합니다: {status:?}"
    );
    assert!(
        stderr_bytes.is_empty(),
        "성공 실행 시 stderr는 비어있어야 합니다: {}",
        String::from_utf8_lossy(stderr_bytes)
    );
    assert!(!stdout_bytes.is_empty(), "stdout은 비어있지 않아야 합니다");
    assert!(
        stdout_bytes.ends_with(b"\n"),
        "stdout은 최종 LF 1개로 끝나야 합니다"
    );
    assert_eq!(
        stdout_bytes.iter().filter(|&&b| b == b'\n').count(),
        1,
        "stdout은 단 1개의 행(LF 1개)으로만 구성되어야 합니다"
    );
    assert!(
        !stdout_bytes.contains(&b'\r'),
        "stdout에 CR 문자가 포함되어서는 안 됩니다"
    );
    assert!(
        stdout_bytes.len() <= MAX_STDOUT_BYTES,
        "stdout 크기가 최대 wire 한도(65536) 이하여야 합니다"
    );

    let report: QuickRunReport =
        serde_json::from_slice(stdout_bytes).expect("QuickRunReport JSON 역직렬화 실패");

    assert_eq!(report.results.len(), 1, "결과 행은 정확히 1개여야 합니다");
    assert!(!report.cancelled, "cancelled는 false여야 합니다");
    assert!(!report.limit_reached, "limit_reached는 false여야 합니다");
    assert_eq!(
        report.omitted_results, 0,
        "omitted_results는 0이어야 합니다"
    );
    assert!(
        report.errors.is_empty(),
        "errors는 비어있어야 합니다: {:?}",
        report.errors
    );
    assert_eq!(report.targets_started, 1);
    assert_eq!(report.targets_completed, 1);
    assert_eq!(report.max_active_targets, 1);

    assert_eq!(
        report.invocations.tcp_connect, 1,
        "tcp_connect 호출 카운트는 1이어야 합니다"
    );
    assert_eq!(report.invocations.icmp_ping, 0);
    assert_eq!(report.invocations.local_network, 0);
    assert_eq!(report.invocations.dns_lookup, 0);
    assert_eq!(report.invocations.icmp_traceroute, 0);

    let result_row = &report.results[0];
    let row_bytes = serde_json::to_vec(result_row).expect("결과 행 직렬화 실패");
    assert_eq!(
        report.serialized_result_bytes,
        row_bytes.len(),
        "serialized_result_bytes는 결과 행의 직렬화 크기와 일치해야 합니다"
    );

    assert_eq!(result_row.schema_version, QUICK_SCHEMA_VERSION);
    assert_eq!(result_row.product, QUICK_PRODUCT_NAME);
    assert_eq!(result_row.feature, QuickFeature::TcpConnect);
    assert_eq!(result_row.target_host, expected_ip);
    assert_eq!(result_row.target_port, expected_port);
    assert_eq!(result_row.resolved_ip.as_deref(), Some(expected_ip));

    let (exp_status, exp_evidence) = match expected_outcome {
        "CONNECTED" => (QuickStatus::PASS, EvidenceLevel::OBSERVED),
        "REFUSED" => (QuickStatus::FAIL, EvidenceLevel::OBSERVED),
        _ => panic!("지원하지 않는 시험 outcome: {expected_outcome}"),
    };
    assert_eq!(result_row.status, exp_status);
    assert_eq!(result_row.evidence_level, exp_evidence);
    assert_eq!(result_row.os_error_code, expected_os_code);

    let row_json: serde_json::Value = serde_json::to_value(result_row).unwrap();
    assert_explicit_nulls(&row_json, &["timestamp_iso8601", "source_host"]);
    if expected_os_code.is_none() {
        assert_explicit_nulls(&row_json, &["os_error_code"]);
    }

    let raw_val = &result_row.details["raw_measurement"];
    let raw: TcpMeasurement =
        serde_json::from_value(raw_val.clone()).expect("details.raw_measurement 역직렬화 실패");

    let expected_target_addr = if expected_ip.contains(':') {
        format!("[{expected_ip}]:{expected_port}")
    } else {
        format!("{expected_ip}:{expected_port}")
    };
    assert_eq!(raw.target, expected_target_addr);
    assert_eq!(raw.outcome, expected_outcome);
    assert_eq!(raw.error_code, expected_os_code);
    assert_eq!(raw.application_bytes_sent, 0);
    assert_eq!(result_row.elapsed_ms, Some(raw.elapsed_ms));

    let raw_json_map: serde_json::Value = serde_json::to_value(&raw).unwrap();
    assert_eq!(&raw_json_map, raw_val);

    match expected_outcome {
        "CONNECTED" => {
            assert_eq!(raw.error_message, None);
            assert!(raw.local_address.is_some());
            assert_explicit_nulls(raw_val, &["error_code", "error_message"]);
        }
        "REFUSED" => {
            assert!(
                raw.error_message
                    .as_deref()
                    .is_some_and(|message| !message.is_empty())
            );
            assert_eq!(raw.local_address, None);
            assert_explicit_nulls(raw_val, &["local_address"]);
        }
        _ => panic!("지원하지 않는 시험 outcome: {expected_outcome}"),
    }

    (report, raw)
}

/// 1. IPv4 실제 소유 루프백 연결 시험 (`127.0.0.1`).
#[tokio::test]
#[ignore = "부모 소유 루프백 명시 실행"]
async fn native_ipv4_connected() {
    let exe_path = get_target_exe();
    let ip_str = "127.0.0.1";
    let ip: IpAddr = ip_str.parse().expect("IPv4 파싱");

    let listener = TcpListener::bind(SocketAddr::new(ip, 0))
        .await
        .expect("IPv4 소유 루프백 listener bind 실패");
    let port = listener.local_addr().expect("local_addr 실패").port();
    assert_ne!(port, 0, "OS 할당 포트는 0이 아니어야 합니다");

    let child_guard = spawn_product_child(&exe_path, ip_str, port);

    // 서버 accept 및 클라이언트 접속/EOF 관찰
    let server_task = async {
        let (mut stream, peer_addr) = tokio::time::timeout(STREAM_TIMEOUT, listener.accept())
            .await
            .map_err(|_| "accept 시한 초과".to_string())?
            .map_err(|_| "accept 실패".to_string())?;
        let bytes_read = wait_for_stream_eof(&mut stream, STREAM_TIMEOUT).await?;
        Ok::<_, String>((peer_addr, bytes_read))
    };

    let client_task = async {
        child_guard
            .wait_output_bounded(MAX_STDOUT_BYTES, MAX_STDERR_BYTES, STAGE_TIMEOUT)
            .await
    };

    // server 오류가 먼저 발생해도 Child 감독 완료까지 join하여 회수를 건너뛰지 않는다.
    let (server_result, child_result) = tokio::join!(server_task, client_task);
    let (status, stdout_bytes, stderr_bytes) = child_result.expect("소유 Child 감독 실패");
    let (peer_addr, bytes_read) = server_result.expect("소유 서버 관찰 실패");

    assert_eq!(
        bytes_read, 0,
        "서버는 클라이언트로부터 애플리케이션 바이트 0을 관찰해야 합니다"
    );

    let (_report, raw) = verify_product_child_report(
        &stdout_bytes,
        &stderr_bytes,
        status,
        ip_str,
        port,
        "CONNECTED",
        None,
    );

    assert_eq!(
        raw.local_address,
        Some(peer_addr.to_string()),
        "raw.local_address는 서버가 관찰한 accept peer_addr와 정확히 일치해야 합니다"
    );

    drop(listener);
}

/// 2. IPv4 실제 소유 루프백 거부 시험 (`127.0.0.1` bound/nonlisten).
#[tokio::test]
#[ignore = "부모 소유 루프백 명시 실행"]
async fn native_ipv4_refused() {
    let exe_path = get_target_exe();
    let ip_str = "127.0.0.1";
    let ip: IpAddr = ip_str.parse().expect("IPv4 파싱");

    let socket = TcpSocket::new_v4().expect("IPv4 TcpSocket 생성 실패");
    socket
        .bind(SocketAddr::new(ip, 0))
        .expect("IPv4 소켓 bind 실패");
    let port = socket.local_addr().expect("local_addr 실패").port();
    assert_ne!(port, 0, "OS 할당 포트는 0이 아니어야 합니다");

    let child_guard = spawn_product_child(&exe_path, ip_str, port);

    // socket 소유를 유지한 채로 자식 프로세스 완료 대기
    let (status, stdout_bytes, stderr_bytes) = child_guard
        .wait_output_bounded(MAX_STDOUT_BYTES, MAX_STDERR_BYTES, STAGE_TIMEOUT)
        .await
        .expect("소유 Child 감독 실패");

    let (_report, raw) = verify_product_child_report(
        &stdout_bytes,
        &stderr_bytes,
        status,
        ip_str,
        port,
        "REFUSED",
        Some(10061),
    );

    assert_eq!(
        raw.local_address, None,
        "거부 결과의 local_address는 null이어야 합니다"
    );
    assert_eq!(
        raw.error_code,
        Some(10061),
        "WSAECONNREFUSED(10061) 오류 코드가 보존되어야 합니다"
    );

    drop(socket);
}

/// 3. IPv6 실제 소유 루프백 연결 시험 (`::1`).
#[tokio::test]
#[ignore = "부모 소유 루프백 명시 실행"]
async fn native_ipv6_connected() {
    let exe_path = get_target_exe();
    let ip_str = "::1";
    let ip: IpAddr = ip_str.parse().expect("IPv6 파싱");

    let listener = TcpListener::bind(SocketAddr::new(ip, 0))
        .await
        .expect("IPv6 소유 루프백 listener bind 실패");
    let port = listener.local_addr().expect("local_addr 실패").port();
    assert_ne!(port, 0, "OS 할당 포트는 0이 아니어야 합니다");

    let child_guard = spawn_product_child(&exe_path, ip_str, port);

    // 서버 accept 및 클라이언트 접속/EOF 관찰
    let server_task = async {
        let (mut stream, peer_addr) = tokio::time::timeout(STREAM_TIMEOUT, listener.accept())
            .await
            .map_err(|_| "accept 시한 초과".to_string())?
            .map_err(|_| "accept 실패".to_string())?;
        let bytes_read = wait_for_stream_eof(&mut stream, STREAM_TIMEOUT).await?;
        Ok::<_, String>((peer_addr, bytes_read))
    };

    let client_task = async {
        child_guard
            .wait_output_bounded(MAX_STDOUT_BYTES, MAX_STDERR_BYTES, STAGE_TIMEOUT)
            .await
    };

    // server 오류가 먼저 발생해도 Child 감독 완료까지 join하여 회수를 건너뛰지 않는다.
    let (server_result, child_result) = tokio::join!(server_task, client_task);
    let (status, stdout_bytes, stderr_bytes) = child_result.expect("소유 Child 감독 실패");
    let (peer_addr, bytes_read) = server_result.expect("소유 서버 관찰 실패");

    assert_eq!(
        bytes_read, 0,
        "서버는 클라이언트로부터 애플리케이션 바이트 0을 관찰해야 합니다"
    );

    let (_report, raw) = verify_product_child_report(
        &stdout_bytes,
        &stderr_bytes,
        status,
        ip_str,
        port,
        "CONNECTED",
        None,
    );

    assert_eq!(
        raw.local_address,
        Some(peer_addr.to_string()),
        "raw.local_address는 서버가 관찰한 accept peer_addr와 정확히 일치해야 합니다"
    );

    drop(listener);
}

/// 4. IPv6 실제 소유 루프백 거부 시험 (`::1` bound/nonlisten).
#[tokio::test]
#[ignore = "부모 소유 루프백 명시 실행"]
async fn native_ipv6_refused() {
    let exe_path = get_target_exe();
    let ip_str = "::1";
    let ip: IpAddr = ip_str.parse().expect("IPv6 파싱");

    let socket = TcpSocket::new_v6().expect("IPv6 TcpSocket 생성 실패");
    socket
        .bind(SocketAddr::new(ip, 0))
        .expect("IPv6 소켓 bind 실패");
    let port = socket.local_addr().expect("local_addr 실패").port();
    assert_ne!(port, 0, "OS 할당 포트는 0이 아니어야 합니다");

    let child_guard = spawn_product_child(&exe_path, ip_str, port);

    // socket 소유를 유지한 채로 자식 프로세스 완료 대기
    let (status, stdout_bytes, stderr_bytes) = child_guard
        .wait_output_bounded(MAX_STDOUT_BYTES, MAX_STDERR_BYTES, STAGE_TIMEOUT)
        .await
        .expect("소유 Child 감독 실패");

    let (_report, raw) = verify_product_child_report(
        &stdout_bytes,
        &stderr_bytes,
        status,
        ip_str,
        port,
        "REFUSED",
        Some(10061),
    );

    assert_eq!(
        raw.local_address, None,
        "거부 결과의 local_address는 null이어야 합니다"
    );
    assert_eq!(
        raw.error_code,
        Some(10061),
        "WSAECONNREFUSED(10061) 오류 코드가 보존되어야 합니다"
    );

    drop(socket);
}

/// 메모리 slice만 읽는다. 기본 실행에서도 소켓/프로세스/IO·time driver는 시작하지 않는다.
#[test]
fn capped_collector_memory_only() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    for length in [MAX_STDOUT_BYTES - 1, MAX_STDOUT_BYTES, MAX_STDOUT_BYTES + 1] {
        let bytes = vec![b'x'; length];
        let result = runtime.block_on(collect_capped(bytes.as_slice(), MAX_STDOUT_BYTES));
        if length > MAX_STDOUT_BYTES {
            assert!(result.is_err());
        } else {
            assert_eq!(result.unwrap(), bytes);
        }
    }
}
