//! Network Quick Check(Part B) 명시 개발용 TCP 단일 대상 진단 진입점 모듈.
//!
//! 제품 단일 실행 파일(`NetworkQuickCheck`)의 명시 개발용 진입점인
//! `--dev-tcp-once-v1 <host> <port>` 인자를 처리하며, 단일 대상에 대한 비동기
//! TCP 연결 진단을 격리 실행하고 결과를 1줄 JSON으로 표준 출력에 기록합니다.
//!
//! ## 핵심 설계 및 안전 원칙
//! - **비파괴·단일 대상 격리**: 임의 대상을 스캔하거나 시스템 구성을 변경하지 않으며,
//!   사전 검증된 단일 대상에 대해서만 정확히 1회의 TCP 연결 프로브를 수행합니다.
//! - **단일 진실 공급원 및 입력 사전 검증**:
//!   - 호스트 검증은 `network_core::dns_engine::validate_host`, 포트 검증은 `parse_helper_port` 및
//!     `network_core::targets::parse_target_pair`, `build_quick_plan`을 I/O 전에 모두 통과해야 합니다.
//!   - bare IPv6만 허용하며 대괄호, URI, 자격증명, 와일드카드, CIDR, 목록 구분자, 선행 0 포트 등은
//!     I/O 시작 전에 엄격히 거부합니다 (Fail-Closed).
//!   - 거부 시 사용자 입력이나 OS 오류 문자열을 stderr에 반사하지 않고 고정된 정적 메시지를 출력합니다.
//! - **기존 코어 진단 엔진 재사용**:
//!   - 새로운 측정 엔진이나 DTO 변환기를 발명하지 않으며, 검증된 `network_core::runner::run_quick`과
//!     기존 `NativeDnsProbeBackend`를 그대로 호출합니다.
//! - **Windows 콘솔 신호 안전 처리**:
//!   - Windows 환경에서 `run_quick` 시작 전에 `ctrl_c` 및 `ctrl_break` 수신기를 사전 등록합니다.
//!   - 신호 수신 시 원자적 취소 플래그만 설정하며, 비동기 runner future를 drop하거나 강제 종료하여
//!     DNS helper 프로세스 정리 작업을 건너뛰지 않습니다.
//!   - `run_quick` 반환 후 신호 대기 태스크를 안전하게 abort 및 await하여 런타임을 해제합니다.
//! - **출력 안전성 및 상한 준수**:
//!   - 직렬화 결과는 전체 wire 바이트(구두점, UTF-8, 최종 LF 포함) 상한인 65,536바이트를
//!     초과하지 않는지 메모리 버퍼에서 먼저 검증한 후 stdout에 단일 행으로 씁니다.
//!   - 상한 초과 또는 직렬화 실패 시 stdout에 아무것도 쓰지 않고 exit 1로 종료합니다.

use std::ffi::OsString;
use std::future::Future;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use network_core::quick::QuickFeature;
use network_core::runner::{QuickProbeBackend, QuickRunReport, QuickRunRequest};
use network_core::targets::{DEFAULT_TCP_TIMEOUT_MS, QuickOptions, QuickTarget};

/// 명시 개발용 TCP 진입점 셀렉터 플래그 문자열.
pub(super) const DEV_TCP_SELECTOR: &str = "--dev-tcp-once-v1";

/// 전체 wire 바이트 최대 상한 (64KiB = 65,536 바이트, JSON 문자열 및 최종 LF 포함).
pub(super) const DEV_TCP_MAX_WIRE_BYTES: usize = 65536;

/// QuickRunRequest 결과 보관 직렬화 바이트 최대 한도 (32KiB = 32,768 바이트).
pub(super) const DEV_TCP_MAX_RESULT_BYTES: usize = 32768;

/// 명시 개발용 진단 실행 시 기본 TCP 타임아웃 (3,000ms = 3초).
pub(super) const DEV_TCP_TIMEOUT_MS: u64 = DEFAULT_TCP_TIMEOUT_MS;

/// 명시 개발용 진단 실행 시 동시성 (단일 대상 1).
pub(super) const DEV_TCP_CONCURRENCY: usize = 1;

/// 진단 실행 중 로컬 오류 또는 신호 등록 실패 시 stderr에 출력하는 정적 메시지.
pub(super) const LOCAL_ERROR_STDERR: &str =
    "Network Quick Check: 진단 실행 중 로컬 오류가 발생했습니다.\n";

/// 인자 파싱 결과 내부 열거형.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DevTcpParsedArgs {
    /// 새 진단 셀렉터가 지정되지 않음 (기존 레거시 진입점으로 위임 필요).
    NotSelected,
    /// 새 셀렉터는 지정되었으나 인자 개수, 비유니코드, 또는 형식 검증에 실패함.
    Invalid,
    /// 사전 검증을 완전히 통과한 유효한 호스트 및 포트.
    Valid {
        /// 사전 검증된 호스트명 또는 IP 리터럴.
        host: String,
        /// 사전 검증된 10진 포트 번호 (1..=65535).
        port: u16,
    },
}

/// 명령행 인자 목록(argv0 제외)에서 명시 개발용 TCP 셀렉터를 검사하고 사전 검증을 수행합니다.
///
/// ## 인자 파싱 및 검증 규칙
/// 1. 인자가 없거나 첫 번째 인자가 `DEV_TCP_SELECTOR`(`--dev-tcp-once-v1`)가 아닌 경우:
///    기존 진입점으로 위임하기 위해 `DevTcpParsedArgs::NotSelected`를 반환합니다.
/// 2. 첫 번째 인자가 `DEV_TCP_SELECTOR`인 경우:
///    - 인자 개수는 정확히 3개(`[--dev-tcp-once-v1, <host>, <canonical-decimal-port>]`)여야 합니다.
///    - `main.rs`의 `take(4)`에 의해 4번째 초과 인자가 수집된 경우 즉시 `Invalid`로 거부됩니다.
///    - 모든 인자는 유효한 UTF-8 문자열이어야 합니다 (비Unicode 거부).
///    - `network_core::dns_engine::validate_host`로 호스트를 검증합니다.
///    - `network_core::dns_engine::parse_helper_port`로 포트를 검증합니다 (선행 0, 부호, 공백 등 거부).
///    - `network_core::targets::parse_target_pair` 및 `build_quick_plan`을 I/O 전에 통과해야 합니다.
///    - 도메인 후행 점은 두 검증기의 교집합에 따라 거부됩니다.
pub(super) fn parse_dev_tcp_args(args: &[OsString]) -> DevTcpParsedArgs {
    if args.is_empty() {
        return DevTcpParsedArgs::NotSelected;
    }

    let first_arg = match args[0].to_str() {
        Some(s) => s,
        None => return DevTcpParsedArgs::NotSelected,
    };

    if first_arg != DEV_TCP_SELECTOR {
        return DevTcpParsedArgs::NotSelected;
    }

    // 인자 수는 argv0 제외 정확히 3개여야 함 (초과 인자 sentinel 또는 인자 부족 거부)
    if args.len() != 3 {
        return DevTcpParsedArgs::Invalid;
    }

    let host_str = match args[1].to_str() {
        Some(s) => s,
        None => return DevTcpParsedArgs::Invalid,
    };

    let port_str = match args[2].to_str() {
        Some(s) => s,
        None => return DevTcpParsedArgs::Invalid,
    };

    // 1. 코어 resolver 검증기 수행
    if network_core::dns_engine::validate_host(host_str).is_err() {
        return DevTcpParsedArgs::Invalid;
    }
    if network_core::dns_engine::parse_helper_port(port_str).is_err() {
        return DevTcpParsedArgs::Invalid;
    }

    // 2. targets 파서 및 계획 수립기 교차 검증 수행
    let target = match network_core::targets::parse_target_pair(host_str, port_str) {
        Ok(t) => t,
        Err(_) => return DevTcpParsedArgs::Invalid,
    };

    let options = QuickOptions {
        tcp_timeout_ms: DEV_TCP_TIMEOUT_MS,
        concurrency: DEV_TCP_CONCURRENCY,
        selected_features: vec![QuickFeature::TcpConnect],
    };

    if network_core::targets::build_quick_plan(std::slice::from_ref(&target), &options).is_err() {
        return DevTcpParsedArgs::Invalid;
    }

    DevTcpParsedArgs::Valid {
        host: target.host,
        port: target.port,
    }
}

/// 사전 검증된 호스트와 포트로부터 유효한 `QuickRunRequest`를 생성합니다.
///
/// ## 제약 조건 준수
/// - `session_id`는 프로세스 내 고유한 로컬 ID를 생성합니다.
/// - `timestamp_iso8601`과 `source_host`는 정직하게 `None`(`null`)으로 유지합니다 (임의 타임스탬프 발명 금지).
/// - `QuickOptions`는 `TcpConnect`만 명시하여 Ping 프로브 활성화를 원천 차단합니다.
/// - `max_result_bytes`는 계약에 정의된 32,768바이트로 지정합니다.
pub(super) fn build_dev_tcp_request(host: String, port: u16) -> QuickRunRequest {
    static NEXT_SESSION: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let session_id = format!(
        "npi-dev-tcp-{}-{}",
        std::process::id(),
        NEXT_SESSION.fetch_add(1, Ordering::Relaxed)
    );
    let raw_input = format!("{host}:{port}");

    QuickRunRequest {
        session_id,
        timestamp_iso8601: None,
        source_host: None,
        targets: vec![QuickTarget {
            host,
            port,
            raw_input,
        }],
        options: QuickOptions {
            tcp_timeout_ms: DEV_TCP_TIMEOUT_MS,
            concurrency: DEV_TCP_CONCURRENCY,
            selected_features: vec![QuickFeature::TcpConnect],
        },
        max_result_bytes: DEV_TCP_MAX_RESULT_BYTES,
    }
}

/// 직렬화 도중부터 payload 상한을 적용하는 메모리 writer. 최종 LF 공간은 별도 예약한다.
struct CappedWire {
    bytes: Vec<u8>,
    payload_limit: usize,
}

impl CappedWire {
    fn new(payload_limit: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(payload_limit + 1),
            payload_limit,
        }
    }
}

impl Write for CappedWire {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.len() > self.payload_limit.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("전체 JSON wire 상한 초과"));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// 진단 보고서를 직렬화하여 표준 출력에 한 줄 JSON으로 안전하게 기록하고 종료 코드를 결정합니다.
///
/// ## 종료 코드 우선순위 및 규칙
/// 1. 출력 오류, 직렬화 실패, 또는 `force_local_error`인 경우: exit 1 (stderr에 정적 오류 출력).
/// 2. `report.errors`가 비어있지 않거나 `report.limit_reached`가 true인 경우: exit 1.
/// 3. 오류 없이 취소된 경우(`report.cancelled`가 true): exit 3.
/// 4. 정상 완료된 경우: exit 0 (TCP 연결 실패나 DNS 실패도 정상 보고서로 전달되면 exit 0).
pub(super) fn emit_report(
    report: &QuickRunReport,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    force_local_error: bool,
) -> u8 {
    // LF 1바이트를 미리 제외한 writer에 직렬화한다. to_vec 후 사후검사/2중 버퍼를 만들지 않는다.
    let mut wire = CappedWire::new(DEV_TCP_MAX_WIRE_BYTES - 1);
    if serde_json::to_writer(&mut wire, report).is_err() {
        let _ = crate::write_static_stderr(stderr, crate::OUTPUT_FAILURE_STDERR);
        return 1;
    }
    wire.bytes.push(b'\n');

    // 4. stdout 쓰기 및 플러시
    if stdout
        .write_all(&wire.bytes)
        .and_then(|_| stdout.flush())
        .is_err()
    {
        let _ = crate::write_static_stderr(stderr, crate::OUTPUT_FAILURE_STDERR);
        return 1;
    }

    // 5. 종료 코드 결정 (우선순위: local/출력 오류 1 > cancel 3 > 정상 0)
    if force_local_error {
        let _ = crate::write_static_stderr(stderr, LOCAL_ERROR_STDERR);
        1
    } else if !report.errors.is_empty() || report.limit_reached {
        1
    } else if report.cancelled {
        3
    } else {
        0
    }
}

/// report와 로컬 감독 오류를 분리한다. JSON에는 기존 report만 직렬화한다.
type RunResult = Result<(QuickRunReport, bool), ()>;

/// 실제 Windows 수신기와 모의 수신기가 같은 취소·drain 경로를 사용한다.
async fn run_with_cancellation<S>(
    request: &QuickRunRequest,
    backend: Arc<dyn QuickProbeBackend>,
    cancel: Arc<AtomicBool>,
    signal: S,
) -> RunResult
where
    S: Future<Output = Result<(), ()>> + Send + 'static,
{
    let for_signal = Arc::clone(&cancel);
    let signal_task = tokio::spawn(async move {
        let result = signal.await;
        for_signal.store(true, Ordering::SeqCst);
        result
    });
    // 신호는 flag만 설정한다. 진행 중 backend와 DNS 정리가 반환될 때까지 await한다.
    let report = network_core::runner::run_quick(request, backend, Arc::clone(&cancel)).await;
    signal_task.abort();
    let local_error = match signal_task.await {
        Ok(Ok(())) => false,
        Err(error) if error.is_cancelled() => false,
        _ => true,
    };
    report.map(|report| (report, local_error)).map_err(|_| ())
}

/// 실제 수신 등록 실패는 runner 시작 전에 닫는다. receiver drop은 전역 handler 원복 인증이 아니다.
#[cfg(windows)]
async fn run_with_windows_signals(
    request: &QuickRunRequest,
    backend: Arc<dyn QuickProbeBackend>,
    cancel: Arc<AtomicBool>,
) -> RunResult {
    let mut ctrl_c = tokio::signal::windows::ctrl_c().map_err(|_| ())?;
    let mut ctrl_break = tokio::signal::windows::ctrl_break().map_err(|_| ())?;
    run_with_cancellation(request, backend, cancel, async move {
        tokio::select! {
            result = ctrl_c.recv() => result.ok_or(()),
            result = ctrl_break.recv() => result.ok_or(()),
        }
    })
    .await
}

/// 이 함수는 검증된 opt-in의 공통 dispatcher에서만 호출된다.
#[cfg(windows)]
fn run_native(request: QuickRunRequest) -> RunResult {
    let backend = Arc::new(crate::native_backend_for_current_exe().map_err(|_| ())?);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ())?;
    let cancel = Arc::new(AtomicBool::new(false));
    // block_on 반환 시 신호 task abort/await와 runner drain이 이미 끝났다.
    runtime.block_on(run_with_windows_signals(&request, backend, cancel))
}

/// 다른 OS에서는 지원하지 않는 네이티브 경로를 고정 로컬 오류로 닫는다.
#[cfg(not(windows))]
fn run_native(_request: QuickRunRequest) -> RunResult {
    Err(())
}

/// 생산과 모의 시험이 실제로 공유하는 사전검증→실행→출력 제어 경로.
fn try_entry_with_runner<F>(
    args: &[OsString],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    runner: F,
) -> Option<u8>
where
    F: FnOnce(QuickRunRequest) -> RunResult,
{
    match parse_dev_tcp_args(args) {
        DevTcpParsedArgs::NotSelected => None,
        DevTcpParsedArgs::Invalid => Some(
            if crate::write_static_stderr(stderr, crate::INVALID_STDERR) {
                2
            } else {
                1
            },
        ),
        DevTcpParsedArgs::Valid { host, port } => {
            Some(match runner(build_dev_tcp_request(host, port)) {
                Ok((report, local_error)) => emit_report(&report, stdout, stderr, local_error),
                Err(()) => {
                    let _ = crate::write_static_stderr(stderr, LOCAL_ERROR_STDERR);
                    1
                }
            })
        }
    }
}

/// 새 selector 이외에는 None을 반환하여 기존 worker/안내 parser에 위임한다.
pub(super) fn try_entry(
    args: &[OsString],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Option<u8> {
    try_entry_with_runner(args, stdout, stderr, run_native)
}

// 별도 시험용 dispatcher 구현이 아니라 동일 생산 함수의 비공개 별칭이다.
#[cfg(test)]
use try_entry_with_runner as try_entry_with_mock_runner;

#[cfg(test)]
mod tests {
    use super::*;
    use network_core::TcpMeasurement;
    use network_core::dns_engine::DnsMeasurement;
    use network_core::quick::{
        EvidenceLevel, QUICK_PRODUCT_NAME, QUICK_SCHEMA_VERSION, QuickContext, QuickFeature,
        QuickResult, QuickStatus, tcp_to_quick_result,
    };
    use network_core::runner::{DnsProbeFuture, ProbeCounts, ProbeFuture, run_quick};
    use std::net::{IpAddr, SocketAddr};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// 쓰기 실패를 시뮬레이션하는 모의 Writer.
    struct MockFailWriter;

    impl Write for MockFailWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("테스트용 모의 쓰기 실패"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// 플러시 실패를 시뮬레이션하는 모의 Writer.
    struct MockFailFlushWriter {
        buf: Vec<u8>,
    }

    impl MockFailFlushWriter {
        fn new() -> Self {
            Self { buf: Vec::new() }
        }
    }

    impl Write for MockFailFlushWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.buf.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("테스트용 모의 플러시 실패"))
        }
    }

    /// Ok(0) 반환으로 WriteZero 오류를 시뮬레이션하는 모의 Writer.
    struct MockWriteZeroWriter;

    impl Write for MockWriteZeroWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Ok(0)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// 작은 단위로 청크 쓰기를 수행하는 모의 Writer.
    struct MockChunkWriter {
        chunk_size: usize,
        buf: Vec<u8>,
    }

    impl MockChunkWriter {
        fn new(chunk_size: usize) -> Self {
            Self {
                chunk_size,
                buf: Vec::new(),
            }
        }
    }

    impl Write for MockChunkWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            let take = buf.len().min(self.chunk_size);
            self.buf.extend_from_slice(&buf[..take]);
            Ok(take)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// 테스트용 순수 모의 백엔드 구현체.
    struct TestMockBackend {
        tcp_invocations: AtomicUsize,
        resolve_invocations: AtomicUsize,
        icmp_invocations: AtomicUsize,
        host_invocations: AtomicUsize,
        trace_invocations: AtomicUsize,
        resolve_result: Option<Result<DnsMeasurement, Vec<String>>>,
        tcp_result: Option<TcpMeasurement>,
        first_poll_tx: Option<tokio::sync::mpsc::Sender<()>>,
        release_rx: tokio::sync::Mutex<Option<tokio::sync::mpsc::Receiver<()>>>,
        expected_cancel: Option<Arc<AtomicBool>>,
        cleanup_finished: AtomicBool,
    }

    impl TestMockBackend {
        fn new() -> Self {
            Self {
                tcp_invocations: AtomicUsize::new(0),
                resolve_invocations: AtomicUsize::new(0),
                icmp_invocations: AtomicUsize::new(0),
                host_invocations: AtomicUsize::new(0),
                trace_invocations: AtomicUsize::new(0),
                resolve_result: None,
                tcp_result: None,
                first_poll_tx: None,
                release_rx: tokio::sync::Mutex::new(None),
                expected_cancel: None,
                cleanup_finished: AtomicBool::new(false),
            }
        }
    }

    impl QuickProbeBackend for TestMockBackend {
        fn tcp<'a>(
            &'a self,
            ctx: QuickContext,
            target: SocketAddr,
            _timeout: Duration,
            cancel: Arc<AtomicBool>,
        ) -> ProbeFuture<'a> {
            self.tcp_invocations.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if let Some(expected) = &self.expected_cancel {
                    assert!(Arc::ptr_eq(expected, &cancel), "동일 취소 Arc 전달 필수");
                }
                // barrier 알림 전송 (first poll 진입 알림)
                if let Some(ref tx) = self.first_poll_tx {
                    let _ = tx.send(()).await;
                }
                // release 신호 대기
                let mut rx_guard = self.release_rx.lock().await;
                if let Some(ref mut rx) = *rx_guard {
                    let _ = rx.recv().await;
                }
                if self.expected_cancel.is_some() {
                    assert!(
                        cancel.load(Ordering::SeqCst),
                        "정리 해제 전에 취소가 전달되어야 함"
                    );
                    self.cleanup_finished.store(true, Ordering::SeqCst);
                }

                let meas = self.tcp_result.clone().unwrap_or_else(|| TcpMeasurement {
                    target: target.to_string(),
                    outcome: "CONNECTED".to_string(),

                    elapsed_ms: 10,
                    error_code: None,
                    error_message: None,
                    application_bytes_sent: 0,
                    local_address: Some("127.0.0.1:54321".to_string()),
                    limitations: Vec::new(),
                });

                tcp_to_quick_result(&ctx, &meas)
            })
        }

        fn icmp<'a>(
            &'a self,
            _ctx: QuickContext,
            _target: IpAddr,
            _timeout: Duration,
            _cancel: Arc<AtomicBool>,
        ) -> ProbeFuture<'a> {
            self.icmp_invocations.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                Err(vec![
                    "테스트 모의 백엔드: ICMP 호출은 허용되지 않습니다.".to_string(),
                ])
            })
        }

        fn host<'a>(
            &'a self,
            _ctx: QuickContext,
            _target: IpAddr,
            _cancel: Arc<AtomicBool>,
        ) -> ProbeFuture<'a> {
            self.host_invocations.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                Err(vec![
                    "테스트 모의 백엔드: Host 호출은 허용되지 않습니다.".to_string(),
                ])
            })
        }

        fn trace<'a>(
            &'a self,
            _ctx: QuickContext,
            _target: IpAddr,
            _options: network_core::traceroute::TraceOptions,
            _cancel: Arc<AtomicBool>,
        ) -> ProbeFuture<'a> {
            self.trace_invocations.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(vec!["미선택 Trace 호출 감지".to_string()]) })
        }

        fn resolve<'a>(
            &'a self,
            ctx: QuickContext,
            _timeout: Duration,
            _cancel: Arc<AtomicBool>,
        ) -> DnsProbeFuture<'a> {
            self.resolve_invocations.fetch_add(1, Ordering::SeqCst);
            let res = self.resolve_result.clone().unwrap_or_else(|| {
                Ok(DnsMeasurement {
                    host: ctx.target_host.clone(),
                    port: ctx.target_port,
                    outcome: "RESOLVED".to_string(),
                    addresses: vec![format!("192.0.2.1:{}", ctx.target_port)],
                    elapsed_ms: 5,
                    error_code: None,
                    error_message: None,
                    limitations: Vec::new(),
                })
            });
            Box::pin(async move { res })
        }
    }

    #[test]
    fn test_parse_dev_tcp_args_boundaries() {
        // 1. 빈 인자 및 기존 플래그는 NotSelected
        assert_eq!(parse_dev_tcp_args(&[]), DevTcpParsedArgs::NotSelected);
        let help_arg = vec![OsString::from("--help")];
        assert_eq!(parse_dev_tcp_args(&help_arg), DevTcpParsedArgs::NotSelected);
        let worker_args = vec![
            OsString::from(network_core::dns_engine::WORKER_FLAG),
            OsString::from("127.0.0.1"),
            OsString::from("80"),
        ];
        assert_eq!(
            parse_dev_tcp_args(&worker_args),
            DevTcpParsedArgs::NotSelected
        );
        let other_args = vec![OsString::from("--other-flag")];
        assert_eq!(
            parse_dev_tcp_args(&other_args),
            DevTcpParsedArgs::NotSelected
        );

        // 2. DEV_TCP_SELECTOR 인자 개수 불일치 -> Invalid
        let one_arg = vec![OsString::from(DEV_TCP_SELECTOR)];
        assert_eq!(parse_dev_tcp_args(&one_arg), DevTcpParsedArgs::Invalid);

        let two_args = vec![
            OsString::from(DEV_TCP_SELECTOR),
            OsString::from("127.0.0.1"),
        ];
        assert_eq!(parse_dev_tcp_args(&two_args), DevTcpParsedArgs::Invalid);

        let four_args = vec![
            OsString::from(DEV_TCP_SELECTOR),
            OsString::from("127.0.0.1"),
            OsString::from("80"),
            OsString::from("extra_sentinel"),
        ];
        assert_eq!(parse_dev_tcp_args(&four_args), DevTcpParsedArgs::Invalid);

        // 3. 잘못된 호스트 형식들 -> Invalid
        for bad_host in [
            "",
            "   ",
            "example .com",
            "http://example.com",
            "user:pass@example.com",
            "[::1]",
            "192.168.1.999",
            "0.0.0.0",
            "255.255.255.255",
            "224.0.0.1",
            "::ffff:0.0.0.0",
            "-leading-hyphen.com",
            "trailing-hyphen-.com",
            "example.com.",
            "127.0.0.1.",
        ] {
            let args = vec![
                OsString::from(DEV_TCP_SELECTOR),
                OsString::from(bad_host),
                OsString::from("80"),
            ];
            assert_eq!(
                parse_dev_tcp_args(&args),
                DevTcpParsedArgs::Invalid,
                "거부되어야 할 호스트: {bad_host}"
            );
        }

        // 4. 잘못된 포트 형식들 -> Invalid
        for bad_port in [
            "", "0", "65536", "080", "+80", " 80 ", "http", "-1", "999999",
        ] {
            let args = vec![
                OsString::from(DEV_TCP_SELECTOR),
                OsString::from("127.0.0.1"),
                OsString::from(bad_port),
            ];
            assert_eq!(
                parse_dev_tcp_args(&args),
                DevTcpParsedArgs::Invalid,
                "거부되어야 할 포트: {bad_port}"
            );
        }

        // 5. 정상 유효 입력 (IPv4, IPv6, Domain)
        let valid_v4 = vec![
            OsString::from(DEV_TCP_SELECTOR),
            OsString::from("127.0.0.1"),
            OsString::from("80"),
        ];
        assert_eq!(
            parse_dev_tcp_args(&valid_v4),
            DevTcpParsedArgs::Valid {
                host: "127.0.0.1".to_string(),
                port: 80,
            }
        );

        let valid_v6 = vec![
            OsString::from(DEV_TCP_SELECTOR),
            OsString::from("::1"),
            OsString::from("8080"),
        ];
        assert_eq!(
            parse_dev_tcp_args(&valid_v6),
            DevTcpParsedArgs::Valid {
                host: "::1".to_string(),
                port: 8080,
            }
        );

        let valid_domain = vec![
            OsString::from(DEV_TCP_SELECTOR),
            OsString::from("example.com"),
            OsString::from("443"),
        ];
        assert_eq!(
            parse_dev_tcp_args(&valid_domain),
            DevTcpParsedArgs::Valid {
                host: "example.com".to_string(),
                port: 443,
            }
        );
    }

    #[cfg(windows)]
    #[test]
    fn test_parse_dev_tcp_args_non_unicode_windows() {
        use std::os::windows::ffi::OsStringExt;

        let unpaired = OsString::from_wide(&[0xD800]);
        let sel = OsString::from(DEV_TCP_SELECTOR);
        let host = OsString::from("127.0.0.1");
        let port = OsString::from("80");

        // 호스트가 비유니코드
        let args_host = vec![sel.clone(), unpaired.clone(), port.clone()];
        assert_eq!(parse_dev_tcp_args(&args_host), DevTcpParsedArgs::Invalid);

        // 포트가 비유니코드
        let args_port = vec![sel.clone(), host.clone(), unpaired.clone()];
        assert_eq!(parse_dev_tcp_args(&args_port), DevTcpParsedArgs::Invalid);

        // 플래그가 비유니코드 -> 셀렉터 일치 불가로 NotSelected
        let args_flag = vec![unpaired, host, port];
        assert_eq!(
            parse_dev_tcp_args(&args_flag),
            DevTcpParsedArgs::NotSelected
        );
    }

    #[test]
    fn test_static_error_no_reflection_dev_tcp() {
        let sensitive = "SECRET_PASSWORD_OR_TOKEN_12345";
        let bad_args = vec![
            OsString::from(DEV_TCP_SELECTOR),
            OsString::from(format!("user:{sensitive}@example.com")),
            OsString::from("80"),
        ];

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = try_entry_with_mock_runner(&bad_args, &mut stdout, &mut stderr, |_| {
            panic!("유효하지 않은 인자에서 runner가 호출되어서는 안 됩니다");
        });

        assert_eq!(code, Some(2));
        assert!(stdout.is_empty(), "오류 시 stdout은 비어있어야 합니다");
        let stderr_str = String::from_utf8(stderr).expect("stderr는 UTF-8");
        assert_eq!(stderr_str, crate::INVALID_STDERR);
        assert!(
            !stderr_str.contains(sensitive),
            "stderr 오류 메시지에 민감 정보가 반사되어서는 안 됩니다"
        );
    }

    #[test]
    fn test_pure_callback_startup_guard_and_request_assembly() {
        let callback_invoked = AtomicUsize::new(0);

        // 1. noargs 진입 -> 진단 start 콜백 0회, None 반환
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = try_entry_with_mock_runner(&[], &mut stdout, &mut stderr, |_| {
            callback_invoked.fetch_add(1, Ordering::SeqCst);
            panic!("start 콜백 호출 금지");
        });
        assert_eq!(code, None);
        assert_eq!(callback_invoked.load(Ordering::SeqCst), 0);

        // 2. help 진입 -> start 콜백 0회, None 반환
        let help_args = vec![OsString::from("--help")];
        let code = try_entry_with_mock_runner(&help_args, &mut stdout, &mut stderr, |_| {
            callback_invoked.fetch_add(1, Ordering::SeqCst);
            panic!("start 콜백 호출 금지");
        });
        assert_eq!(code, None);
        assert_eq!(callback_invoked.load(Ordering::SeqCst), 0);

        // 3. worker 인자 -> start 콜백 0회, None 반환
        let worker_args = vec![
            OsString::from(network_core::dns_engine::WORKER_FLAG),
            OsString::from("127.0.0.1"),
            OsString::from("80"),
        ];
        let code = try_entry_with_mock_runner(&worker_args, &mut stdout, &mut stderr, |_| {
            callback_invoked.fetch_add(1, Ordering::SeqCst);
            panic!("start 콜백 호출 금지");
        });
        assert_eq!(code, None);
        assert_eq!(callback_invoked.load(Ordering::SeqCst), 0);

        // 4. 잘못된 진단 인자 -> start 콜백 0회, Some(2), stderr 출력
        let bad_args = vec![
            OsString::from(DEV_TCP_SELECTOR),
            OsString::from("127.0.0.1"),
            OsString::from("0"),
        ];
        let mut stderr_bad = Vec::new();
        let code = try_entry_with_mock_runner(&bad_args, &mut stdout, &mut stderr_bad, |_| {
            callback_invoked.fetch_add(1, Ordering::SeqCst);
            panic!("start 콜백 호출 금지");
        });
        assert_eq!(code, Some(2));
        assert_eq!(String::from_utf8_lossy(&stderr_bad), crate::INVALID_STDERR);
        assert_eq!(callback_invoked.load(Ordering::SeqCst), 0);

        // 5. 유효한 진단 인자 -> start 콜백 정확히 1회 호출 및 QuickRunRequest 필드 엄격 검증
        let valid_args = vec![
            OsString::from(DEV_TCP_SELECTOR),
            OsString::from("127.0.0.1"),
            OsString::from("8080"),
        ];
        let mock_report = QuickRunReport {
            results: Vec::new(),
            cancelled: false,
            limit_reached: false,
            omitted_results: 0,
            errors: Vec::new(),
            invocations: ProbeCounts::default(),
            max_active_targets: 1,
            targets_started: 1,
            targets_completed: 1,
            serialized_result_bytes: 0,
        };

        let mut stdout_valid = Vec::new();
        let mut stderr_valid = Vec::new();
        let r_clone = mock_report.clone();
        let counter_for_runner = &callback_invoked;
        let code = try_entry_with_mock_runner(
            &valid_args,
            &mut stdout_valid,
            &mut stderr_valid,
            move |req| {
                counter_for_runner.fetch_add(1, Ordering::SeqCst);
                // Request 필드 검증
                assert!(!req.session_id.trim().is_empty());
                assert_eq!(req.timestamp_iso8601, None);
                assert_eq!(req.source_host, None);
                assert_eq!(req.max_result_bytes, DEV_TCP_MAX_RESULT_BYTES);
                assert_eq!(req.targets.len(), 1);
                assert_eq!(req.targets[0].host, "127.0.0.1");
                assert_eq!(req.targets[0].port, 8080);
                assert_eq!(req.targets[0].raw_input, "127.0.0.1:8080");
                assert_eq!(req.options.tcp_timeout_ms, DEV_TCP_TIMEOUT_MS);
                assert_eq!(req.options.concurrency, DEV_TCP_CONCURRENCY);
                assert_eq!(
                    req.options.selected_features,
                    vec![QuickFeature::TcpConnect]
                );
                Ok((r_clone, false))
            },
        );

        assert_eq!(code, Some(0));
        assert_eq!(callback_invoked.load(Ordering::SeqCst), 1);
        assert!(stderr_valid.is_empty());
    }

    #[test]
    fn test_mock_run_quick_ip_vs_domain_and_pre_cancel() {
        // CPU 스케줄링 전용 current-thread runtime 생성 (I/O 및 time driver 활성화 0)
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("CPU 전용 current-thread runtime 생성 실패");

        // Case 1: IP 대상 -> resolve 0회, TCP 1회, others 0회
        let req_ip = build_dev_tcp_request("127.0.0.1".to_string(), 80);
        let backend_ip = Arc::new(TestMockBackend::new());
        let cancel_ip = Arc::new(AtomicBool::new(false));

        let report_ip = rt
            .block_on(run_quick(&req_ip, backend_ip.clone(), cancel_ip))
            .expect("IP 진단 성공");

        assert_eq!(backend_ip.resolve_invocations.load(Ordering::SeqCst), 0);
        assert_eq!(backend_ip.tcp_invocations.load(Ordering::SeqCst), 1);
        assert_eq!(backend_ip.icmp_invocations.load(Ordering::SeqCst), 0);
        assert_eq!(backend_ip.host_invocations.load(Ordering::SeqCst), 0);
        assert_eq!(backend_ip.trace_invocations.load(Ordering::SeqCst), 0);
        assert_eq!(report_ip.results.len(), 1);
        assert_eq!(report_ip.results[0].status, QuickStatus::PASS);

        // Case 2: 도메인 대상 (정상 해석) -> 필수 resolve 1회, TCP 1회
        let req_domain = build_dev_tcp_request("example.com".to_string(), 443);
        let mut backend_domain_inner = TestMockBackend::new();
        backend_domain_inner.resolve_result = Some(Ok(DnsMeasurement {
            host: "example.com".to_string(),
            port: 443,
            outcome: "RESOLVED".to_string(),
            addresses: vec!["93.184.216.34:443".to_string()],
            elapsed_ms: 12,
            error_code: None,
            error_message: None,
            limitations: Vec::new(),
        }));
        let backend_domain = Arc::new(backend_domain_inner);
        let cancel_domain = Arc::new(AtomicBool::new(false));

        let report_domain = rt
            .block_on(run_quick(
                &req_domain,
                backend_domain.clone(),
                cancel_domain,
            ))
            .expect("Domain 진단 성공");

        assert_eq!(backend_domain.resolve_invocations.load(Ordering::SeqCst), 1);
        assert_eq!(backend_domain.tcp_invocations.load(Ordering::SeqCst), 1);
        assert_eq!(report_domain.results.len(), 1);
        assert_eq!(report_domain.results[0].status, QuickStatus::PASS);

        // Case 3: 도메인 대상 다중 주소 -> 첫 주소만 TCP 1회
        let mut backend_multi_inner = TestMockBackend::new();
        backend_multi_inner.resolve_result = Some(Ok(DnsMeasurement {
            host: "multi.example.com".to_string(),
            port: 443,
            outcome: "RESOLVED".to_string(),
            addresses: vec![
                "93.184.216.34:443".to_string(),
                "93.184.216.35:443".to_string(),
            ],
            elapsed_ms: 12,
            error_code: None,
            error_message: None,
            limitations: Vec::new(),
        }));
        let backend_multi = Arc::new(backend_multi_inner);
        let cancel_multi = Arc::new(AtomicBool::new(false));

        let req_multi = build_dev_tcp_request("multi.example.com".to_string(), 443);
        let report_multi = rt
            .block_on(run_quick(&req_multi, backend_multi.clone(), cancel_multi))
            .expect("Domain 다중 주소 진단 성공");

        assert_eq!(backend_multi.resolve_invocations.load(Ordering::SeqCst), 1);
        assert_eq!(backend_multi.tcp_invocations.load(Ordering::SeqCst), 1);
        assert_eq!(report_multi.results.len(), 1);
        assert_eq!(
            report_multi.results[0].resolved_ip,
            Some("93.184.216.34".to_string())
        );

        // Case 4: 도메인 대상 불량 첫 주소 (0.0.0.0) -> TCP 0회, UNAVAILABLE
        let mut backend_unsafe_inner = TestMockBackend::new();
        backend_unsafe_inner.resolve_result = Some(Ok(DnsMeasurement {
            host: "unsafe.example.com".to_string(),
            port: 443,
            outcome: "RESOLVED".to_string(),
            addresses: vec!["0.0.0.0:443".to_string()],
            elapsed_ms: 12,
            error_code: None,
            error_message: None,
            limitations: Vec::new(),
        }));
        let backend_unsafe = Arc::new(backend_unsafe_inner);
        let cancel_unsafe = Arc::new(AtomicBool::new(false));

        let req_unsafe = build_dev_tcp_request("unsafe.example.com".to_string(), 443);
        let report_unsafe = rt
            .block_on(run_quick(
                &req_unsafe,
                backend_unsafe.clone(),
                cancel_unsafe,
            ))
            .expect("불량 첫 주소 진단 처리 완료");

        assert_eq!(backend_unsafe.resolve_invocations.load(Ordering::SeqCst), 1);
        assert_eq!(backend_unsafe.tcp_invocations.load(Ordering::SeqCst), 0);
        assert_eq!(report_unsafe.results.len(), 1);
        assert_eq!(
            report_unsafe.results[0].details["outcome"],
            serde_json::Value::String("UNAVAILABLE".to_string())
        );

        // Case 5: 도메인 대상 DNS 해석 실패 -> TCP 0회, UNAVAILABLE
        let mut backend_dns_err_inner = TestMockBackend::new();
        backend_dns_err_inner.resolve_result = Some(Ok(DnsMeasurement {
            host: "fail.example.com".to_string(),
            port: 443,
            outcome: "DNS_ERROR".to_string(),
            addresses: Vec::new(),
            elapsed_ms: 12,
            error_code: Some(11001),
            error_message: Some("호스트를 찾을 수 없음".to_string()),
            limitations: Vec::new(),
        }));
        let backend_dns_err = Arc::new(backend_dns_err_inner);
        let cancel_dns_err = Arc::new(AtomicBool::new(false));

        let req_dns_err = build_dev_tcp_request("fail.example.com".to_string(), 443);
        let report_dns_err = rt
            .block_on(run_quick(
                &req_dns_err,
                backend_dns_err.clone(),
                cancel_dns_err,
            ))
            .expect("DNS 실패 진단 처리 완료");

        assert_eq!(
            backend_dns_err.resolve_invocations.load(Ordering::SeqCst),
            1
        );
        assert_eq!(backend_dns_err.tcp_invocations.load(Ordering::SeqCst), 0);
        assert_eq!(report_dns_err.results.len(), 1);
        assert_eq!(
            report_dns_err.results[0].details["outcome"],
            serde_json::Value::String("UNAVAILABLE".to_string())
        );

        // Case 6: 사전 취소 (pre-cancel) 상태 -> 백엔드 프로브 호출 0회 확인
        let req_pre_cancel = build_dev_tcp_request("127.0.0.1".to_string(), 80);
        let backend_pre = Arc::new(TestMockBackend::new());
        let cancel_pre = Arc::new(AtomicBool::new(true));

        let report_pre = rt
            .block_on(run_quick(&req_pre_cancel, backend_pre.clone(), cancel_pre))
            .expect("사전 취소 처리 성공");

        assert_eq!(backend_pre.tcp_invocations.load(Ordering::SeqCst), 0);
        assert_eq!(backend_pre.resolve_invocations.load(Ordering::SeqCst), 0);
        assert!(report_pre.cancelled);
        assert_unused_and_counts(&backend_ip, &report_ip);
        assert_unused_and_counts(&backend_domain, &report_domain);
        assert_unused_and_counts(&backend_multi, &report_multi);
        assert_unused_and_counts(&backend_unsafe, &report_unsafe);
        assert_unused_and_counts(&backend_dns_err, &report_dns_err);
        assert_unused_and_counts(&backend_pre, &report_pre);
        // 원래 실패한 fixture의 host 불일치를 별도 음성 대조군으로 보존한다.
        let mut mismatched = TestMockBackend::new();
        mismatched.resolve_result = backend_multi.resolve_result.clone();
        let mismatched = Arc::new(mismatched);
        let rejected = rt
            .block_on(run_quick(
                &req_domain,
                mismatched.clone(),
                Arc::new(AtomicBool::new(false)),
            ))
            .unwrap();
        assert_eq!(mismatched.resolve_invocations.load(Ordering::SeqCst), 1);
        assert_eq!(mismatched.tcp_invocations.load(Ordering::SeqCst), 0);
        assert_eq!(rejected.results[0].details["outcome"], "UNAVAILABLE");
        assert_unused_and_counts(&mismatched, &rejected);
    }

    #[test]
    fn test_in_flight_cancellation_barrier() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let (first_tx, mut first_rx) = tokio::sync::mpsc::channel(1);
        let (release_tx, release_rx) = tokio::sync::mpsc::channel(1);
        let (signal_tx, signal_rx) = tokio::sync::oneshot::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        // 실제 OS 관측이 아닌, 완료된 raw 전체 보존을 검사하는 순수 mock 측정이다.
        let expected_raw = TcpMeasurement {
            target: "127.0.0.1:80".to_string(),
            outcome: "REFUSED".to_string(),
            elapsed_ms: 17,
            error_code: Some(10061),
            error_message: Some("합성 거부 원문\r\n한글".to_string()),
            application_bytes_sent: 0,
            local_address: None,
            limitations: vec!["중복 원문".to_string(), "중복 원문".to_string()],
        };
        let before = serde_json::to_vec(&expected_raw).unwrap();
        let mut mock = TestMockBackend::new();
        mock.first_poll_tx = Some(first_tx);
        mock.release_rx = tokio::sync::Mutex::new(Some(release_rx));
        mock.expected_cancel = Some(Arc::clone(&cancel));
        mock.tcp_result = Some(expected_raw.clone());
        let backend = Arc::new(mock);
        let for_task = Arc::clone(&backend);
        let for_runner = Arc::clone(&cancel);
        let request = build_dev_tcp_request("127.0.0.1".to_string(), 80);
        let mut task = rt.spawn(async move {
            run_with_cancellation(&request, for_task, for_runner, async move {
                signal_rx.await.map_err(|_| ())
            })
            .await
        });
        let (report, local_error) = rt.block_on(async {
            first_rx.recv().await.expect("backend 첫 poll 진입");
            signal_tx.send(()).expect("모의 신호 전달");
            for _ in 0..16 {
                if cancel.load(Ordering::SeqCst) {
                    break;
                }
                tokio::task::yield_now().await;
            }
            assert!(
                cancel.load(Ordering::SeqCst),
                "생산 신호 감독 경로가 같은 flag를 설정해야 함"
            );
            assert!(!backend.cleanup_finished.load(Ordering::SeqCst));
            assert!(
                !task.is_finished(),
                "cleanup을 보류한 동안 runner는 완료되면 안 됨"
            );
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(std::pin::Pin::new(&mut task).poll(&mut cx).is_pending());
            release_tx.send(()).await.expect("cleanup 해제");
            task.await.expect("감독 task join").expect("진단 결과")
        });
        assert!(!local_error);
        assert!(backend.cleanup_finished.load(Ordering::SeqCst));
        assert!(report.cancelled);
        assert_eq!(report.results.len(), 1);
        assert_eq!(
            report.results[0].details["raw_measurement"],
            serde_json::to_value(&expected_raw).unwrap()
        );
        assert_eq!(before, serde_json::to_vec(&expected_raw).unwrap());
        assert_eq!(report.invocations.tcp_connect, 1);
        assert_eq!(report.targets_started, 1);
        assert_eq!(report.targets_completed, 1);
        assert_unused_and_counts(&backend, &report);
    }

    fn assert_unused_and_counts(backend: &TestMockBackend, report: &QuickRunReport) {
        assert_eq!(backend.icmp_invocations.load(Ordering::SeqCst), 0);
        assert_eq!(backend.host_invocations.load(Ordering::SeqCst), 0);
        assert_eq!(backend.trace_invocations.load(Ordering::SeqCst), 0);
        assert_eq!(report.invocations.icmp_ping, 0);
        assert_eq!(report.invocations.local_network, 0);
        assert_eq!(report.invocations.icmp_traceroute, 0);
        assert_eq!(
            report.invocations.tcp_connect,
            backend.tcp_invocations.load(Ordering::SeqCst)
        );
        assert_eq!(
            report.invocations.dns_lookup,
            backend.resolve_invocations.load(Ordering::SeqCst)
        );
    }

    #[test]
    fn test_invalid_stderr_write_and_flush_errors_use_real_dispatch() {
        let args = [
            OsString::from(DEV_TCP_SELECTOR),
            OsString::from("127.0.0.1"),
            OsString::from("080"),
        ];
        for mut stderr in [
            Box::new(MockFailWriter) as Box<dyn Write>,
            Box::new(MockFailFlushWriter::new()),
        ] {
            let mut stdout = Vec::new();
            assert_eq!(try_entry(&args, &mut stdout, stderr.as_mut()), Some(1));
            assert!(stdout.is_empty());
        }
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(try_entry(&args, &mut stdout, &mut stderr), Some(2));
        assert_eq!(stderr, crate::INVALID_STDERR.as_bytes());
    }

    #[test]
    fn test_capped_writer_rejects_before_growth_and_reserves_lf() {
        let mut capped = CappedWire::new(31);
        capped.write_all(&[b'a'; 30]).unwrap();
        assert!(capped.write_all(b"bc").is_err());
        assert_eq!(capped.bytes.len(), 30);
        assert_eq!(capped.bytes.capacity(), 32);
        capped.write_all(b"b").unwrap();
        capped.bytes.push(b'\n');
        assert_eq!(capped.bytes.len(), 32);
    }

    #[test]
    fn test_shared_dispatch_roundtrips_actual_mock_runner_report() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let backend = Arc::new(TestMockBackend::new());
        let observed = std::cell::RefCell::new(None);
        let args = [
            OsString::from(DEV_TCP_SELECTOR),
            OsString::from("127.0.0.1"),
            OsString::from("80"),
        ];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = try_entry_with_runner(&args, &mut stdout, &mut stderr, |request| {
            let report = rt
                .block_on(run_quick(
                    &request,
                    backend.clone(),
                    Arc::new(AtomicBool::new(false)),
                ))
                .unwrap();
            assert_unused_and_counts(&backend, &report);
            *observed.borrow_mut() = Some(report.clone());
            Ok((report, false))
        });
        assert_eq!(code, Some(0));
        assert!(stderr.is_empty());
        let decoded: QuickRunReport = serde_json::from_slice(&stdout).unwrap();
        assert_eq!(Some(decoded), observed.into_inner());
        let mut stdout = Vec::new();
        assert_eq!(
            try_entry_with_runner(&args, &mut stdout, &mut stderr, |_| Err(())),
            Some(1)
        );
        assert!(stdout.is_empty());
        assert_eq!(stderr, LOCAL_ERROR_STDERR.as_bytes());
    }

    /// 출력 바이트 상한 가드(DEV_TCP_MAX_WIRE_BYTES = 65,536) 동작 검증을 위한 합성 보고서 생성 헬퍼.
    ///
    /// 주의: 본 헬퍼는 전체 wire 바이트 가드를 검증하기 위해 인위적인 패딩을 주입한 fixture이며,
    /// 실제 진단 결과 데이터가 아닙니다.
    fn make_synthetic_report_for_wire_guard(
        prefix: &str,
        target_wire_bytes: usize,
    ) -> QuickRunReport {
        let mut report = QuickRunReport {
            results: vec![QuickResult {
                schema_version: QUICK_SCHEMA_VERSION.to_string(),
                product: QUICK_PRODUCT_NAME.to_string(),
                session_id: "synthetic-session-id".to_string(),
                timestamp_iso8601: None,
                source_host: None,
                target_host: "127.0.0.1".to_string(),
                resolved_ip: Some("127.0.0.1".to_string()),
                target_port: 80,
                feature: QuickFeature::TcpConnect,
                status: QuickStatus::PASS,
                elapsed_ms: Some(10),
                os_error_code: None,
                details: serde_json::json!({
                    "outcome": "CONNECTED",
                    "limitations": [prefix],
                    "raw_measurement": {}
                }),
                evidence_level: EvidenceLevel::OBSERVED,
            }],
            cancelled: false,
            limit_reached: false,
            omitted_results: 0,
            errors: Vec::new(),
            invocations: ProbeCounts {
                tcp_connect: 1,
                icmp_ping: 0,
                local_network: 0,
                dns_lookup: 0,
                icmp_traceroute: 0,
            },
            max_active_targets: 1,
            targets_started: 1,
            targets_completed: 1,
            serialized_result_bytes: 0,
        };

        // 기본 JSON 직렬화 + LF 바이트 크기 계산
        let base_wire_len = serde_json::to_vec(&report).unwrap().len() + 1;
        assert!(
            base_wire_len <= target_wire_bytes,
            "기본 크기({base_wire_len})가 목표 바이트({target_wire_bytes})보다 큽니다."
        );
        let pad_len = target_wire_bytes - base_wire_len;
        let mut msg = prefix.to_string();
        msg.extend(std::iter::repeat_n('A', pad_len));

        report.results[0].details["limitations"] = serde_json::json!([msg]);
        let final_wire_len = serde_json::to_vec(&report).unwrap().len() + 1;
        assert_eq!(
            final_wire_len, target_wire_bytes,
            "합성 보고서 wire 바이트 크기가 정확히 목표 바이트와 일치해야 합니다."
        );
        report
    }

    #[test]
    fn test_wire_boundary_and_escaped_json() {
        let prefix = "한글접두사_\"따옴표\"_\\역슬래시_\r\n_오류_";

        // 1. 전체 wire 바이트 경계 3개 (MAX - 1, 정확 MAX, MAX + 1)
        for target_bytes in [
            DEV_TCP_MAX_WIRE_BYTES - 1,
            DEV_TCP_MAX_WIRE_BYTES,
            DEV_TCP_MAX_WIRE_BYTES + 1,
        ] {
            let report = make_synthetic_report_for_wire_guard(prefix, target_bytes);
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();

            let code = emit_report(&report, &mut stdout, &mut stderr, false);

            if target_bytes <= DEV_TCP_MAX_WIRE_BYTES {
                assert_eq!(
                    code, 0,
                    "상한 이하({target_bytes})는 정상 exit 0이어야 합니다."
                );
                assert_eq!(
                    stdout.len(),
                    target_bytes,
                    "stdout 바이트 크기가 정확히 일치해야 합니다."
                );
                assert!(stdout.ends_with(b"\n"), "출력은 LF로 끝나야 합니다.");
                assert!(stderr.is_empty(), "성공 시 stderr는 비어있어야 합니다.");

                // roundtrip 역직렬화 값 동등성 검증 (순서가 아닌 구조적 동등성)
                let decoded: QuickRunReport =
                    serde_json::from_slice(&stdout).expect("roundtrip 역직렬화 성공");
                assert_eq!(decoded, report);
            } else {
                assert_eq!(
                    code, 1,
                    "상한 초과({target_bytes})는 오류 exit 1이어야 합니다."
                );
                assert!(
                    stdout.is_empty(),
                    "상한 초과 시 stdout은 비어있어야 합니다 (잘린 JSON 방지)."
                );
                assert_eq!(
                    String::from_utf8_lossy(&stderr),
                    crate::OUTPUT_FAILURE_STDERR,
                    "상한 초과 시 정적 출력 실패 메시지가 출력되어야 합니다."
                );
            }
        }

        // 2. escaped CRLF 및 따옴표 1줄 wire 검증
        let escaped_report = make_synthetic_report_for_wire_guard(
            "줄1\n줄2\r\n\"따옴표\"\\역슬래시",
            DEV_TCP_MAX_WIRE_BYTES / 2,
        );
        let mut stdout_esc = Vec::new();
        let mut stderr_esc = Vec::new();
        let code_esc = emit_report(&escaped_report, &mut stdout_esc, &mut stderr_esc, false);
        assert_eq!(code_esc, 0);
        assert!(stderr_esc.is_empty());
        assert!(stdout_esc.ends_with(b"\n"));
        assert_eq!(
            stdout_esc.iter().filter(|&&b| b == b'\n').count(),
            1,
            "stdout 전체에 실제 LF는 최종 1개만 존재해야 합니다."
        );
        assert!(
            !stdout_esc.contains(&b'\r'),
            "stdout에 실제 CR 문자가 없어야 합니다."
        );
    }

    #[test]
    fn test_io_failures_and_exit_priorities() {
        let base_report = make_synthetic_report_for_wire_guard("정상_테스트", 1024);

        // 1. ChunkWriter로 작은 청크 쓰기 분할 -> 정상 exit 0
        let mut chunk_out = MockChunkWriter::new(17);
        let mut stderr = Vec::new();
        assert_eq!(
            emit_report(&base_report, &mut chunk_out, &mut stderr, false),
            0
        );
        assert!(stderr.is_empty());

        // 2. WriteZeroWriter -> exit 1 및 OUTPUT_FAILURE_STDERR
        let mut zero_out = MockWriteZeroWriter;
        let mut stderr = Vec::new();
        assert_eq!(
            emit_report(&base_report, &mut zero_out, &mut stderr, false),
            1
        );
        assert_eq!(
            String::from_utf8_lossy(&stderr),
            crate::OUTPUT_FAILURE_STDERR
        );

        // 3. MockFailFlushWriter -> exit 1
        let mut flush_out = MockFailFlushWriter::new();
        let mut stderr = Vec::new();
        assert_eq!(
            emit_report(&base_report, &mut flush_out, &mut stderr, false),
            1
        );
        assert_eq!(
            String::from_utf8_lossy(&stderr),
            crate::OUTPUT_FAILURE_STDERR
        );

        // 4. MockFailWriter -> exit 1
        let mut fail_out = MockFailWriter;
        let mut stderr = Vec::new();
        assert_eq!(
            emit_report(&base_report, &mut fail_out, &mut stderr, false),
            1
        );
        assert_eq!(
            String::from_utf8_lossy(&stderr),
            crate::OUTPUT_FAILURE_STDERR
        );

        // 5. 종료 코드 우선순위 검증
        // 5-1. report.errors가 비어있지 않음 -> exit 1
        let mut err_report = base_report.clone();
        err_report.errors = vec!["테스트 오류 발생".to_string()];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(emit_report(&err_report, &mut stdout, &mut stderr, false), 1);

        // 5-2. report.limit_reached true -> exit 1
        let mut limit_report = base_report.clone();
        limit_report.limit_reached = true;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            emit_report(&limit_report, &mut stdout, &mut stderr, false),
            1
        );

        // 5-3. cancelled=true 이고 errors/limit 없음 -> exit 3
        let mut cancel_report = base_report.clone();
        cancel_report.cancelled = true;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            emit_report(&cancel_report, &mut stdout, &mut stderr, false),
            3
        );

        // 5-4. cancelled=true 인데 errors도 있음 -> local/오류 우선(exit 1)
        let mut cancel_err_report = base_report.clone();
        cancel_err_report.cancelled = true;
        cancel_err_report.errors = vec!["취소 중 오류 발생".to_string()];
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(
            emit_report(&cancel_err_report, &mut stdout, &mut stderr, false),
            1
        );

        // 5-5. force_local_error=true (신호 태스크 panic 등) -> report 출력 후 exit 1
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        assert_eq!(emit_report(&base_report, &mut stdout, &mut stderr, true), 1);
        assert!(!stdout.is_empty(), "원문 report는 stdout에 보존되어야 함");
    }
}
