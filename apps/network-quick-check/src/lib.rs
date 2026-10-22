//! Network Quick Check(Part B) 제품 진입점 및 DNS worker 라이브러리.
//!
//! 제품 단일 실행 파일(`NetworkQuickCheck`)의 진입점 인자 해석,
//! 동일 EXE DNS worker 프로세스 격리 실행, 그리고 현재 실행 파일 기반
//! `NativeDnsProbeBackend` 생성을 담당합니다.
//!
//! ## 핵심 설계 및 안전 원칙
//! - **단일 진실 공급원 준수**: 호스트 검증(`validate_host`), 포트 파싱(`parse_helper_port`),
//!   worker 실행(`run_worker_from_args`), 결과 직렬화(`worker_output_line`) 등은 모두
//!   공유 코어인 `network_core::dns_engine`의 단일 구현을 재사용합니다.
//! - **입력 사전 검증 및 Fail-Closed**:
//!   - worker 인자는 정확히 3개(`[WORKER_FLAG, host, port]`)여야 하며, 비Unicode, 공백, URI,
//!     자격증명, 비정상 포트 등은 worker 실행 전에 엄격히 거부합니다.
//!   - 불량 호스트 원문이 worker 거부 페이로드에 반사되어 출력되는 것을 방지하기 위해,
//!     모든 인자는 worker 호출 전에 사전 검증하여 거부 시 고정 오류 메시지를 stderr로 출력하고 exit 2로 종료합니다.
//! - **정적 오류 메시지 보존**:
//!   - 인자 없는 진입(noargs), 도움말(--help), 인자 오류(invalid) 시 출력되는 stderr 메시지는
//!     계약에 명시된 정적 문자열을 그대로 사용하며, 사용자 입력 원문을 반사하지 않습니다.
//! - **결과 출력 안전성 및 상한 준수**:
//!   - worker의 정상 출력은 단 한 줄의 JSON과 최종 LF(`\n`)로 구성되며, 실제 UTF-8 바이트 크기가
//!     `MAX_PAYLOAD_BYTES`(16KiB) 이하인지 엄격히 검사한 후 stdout에 씁니다.
//!   - stdout/stderr 쓰기 또는 플러시 실패 시 부분 출력을 성공으로 간주하지 않고 exit 1로 종료합니다.
//! - **재귀 및 임의 기능 호출 배제**:
//!   - worker 분기에서는 자식 프로세스 생성, 백엔드 팩토리 호출, DNS 재귀 해석, 비동기 런타임 시작,
//!     GUI 초기화 등을 일체 수행하지 않습니다.

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;

/// 인자 없이 실행되었을 때 stderr에 출력하는 정적 메시지.
pub const NOARGS_STDERR: &str = "Network Quick Check: 진단 실행 진입점은 아직 제공하지 않습니다.\n";

/// `--help` 인자로 실행되었을 때 stderr에 출력하는 정적 메시지.
pub const HELP_STDERR: &str = "Network Quick Check: 현재 진단 실행 기능은 제공하지 않습니다.\n";

/// 잘못되거나 지원하지 않는 인자로 실행되었을 때 stderr에 출력하는 정적 메시지.
pub const INVALID_STDERR: &str = "Network Quick Check: 지원하지 않거나 잘못된 인자입니다.\n";

/// worker 결과 출력 준비, 상한 검증, 쓰기 또는 플러시 실패 시 stderr에 출력하는 정적 메시지.
pub const OUTPUT_FAILURE_STDERR: &str = "Network Quick Check: 결과 출력에 실패했습니다.\n";

/// Network Quick Check 진입 모드.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryMode {
    /// 인자 없는 기본 진입.
    Idle,
    /// `--help` 도움말 요청 진입.
    Help,
    /// 제품 동일 EXE DNS worker 진입.
    DnsWorker {
        /// 사전 검증된 대상 호스트명 또는 IP 리터럴 문자열.
        host: String,
        /// 사전 검증된 10진 포트 문자열 (1..=65535).
        port_arg: String,
    },
}

/// 인자 파싱 오류.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryError {
    /// 지원하지 않거나 잘못된 인자.
    InvalidArguments,
}

/// 명령행 인자 목록(argv0 제외)을 검증하고 실행 모드를 결정합니다.
///
/// ## 인자 파싱 규칙
/// 1. 인자가 0개인 경우: `Ok(EntryMode::Idle)`
/// 2. 인자가 정확히 1개이고 `"--help"`인 경우: `Ok(EntryMode::Help)`
/// 3. 인자가 정확히 3개이고 첫 번째가 `WORKER_FLAG`(`--npi-dns-worker-v1`)인 경우:
///    - 모든 인자가 유효한 UTF-8 문자열이어야 합니다 (비Unicode 거부).
///    - 두 번째 인자(host)는 `validate_host` 검증을 통과해야 합니다 (URI, 공백, 자격증명 등 거부).
///    - 세 번째 인자(port)는 `parse_helper_port` 검증을 통과해야 합니다 (선행 0, 부호, 공백, 0, 65536 등 거부).
///    - 사전 검증 성공 시 `Ok(EntryMode::DnsWorker { host, port_arg })`를 반환합니다.
/// 4. 그 외의 모든 경우(인자 수 불일치, 구버전 플래그, 순서 변경, `--run`, 플래그 값 결합 등):
///    `Err(EntryError::InvalidArguments)`를 반환합니다.
pub fn parse_args(args: &[OsString]) -> Result<EntryMode, EntryError> {
    match args.len() {
        0 => Ok(EntryMode::Idle),
        1 => {
            if args[0].to_str() == Some("--help") {
                Ok(EntryMode::Help)
            } else {
                Err(EntryError::InvalidArguments)
            }
        }
        3 => {
            let flag = match args[0].to_str() {
                Some(s) => s,
                None => return Err(EntryError::InvalidArguments),
            };
            if flag != network_core::dns_engine::WORKER_FLAG {
                return Err(EntryError::InvalidArguments);
            }
            let host = match args[1].to_str() {
                Some(s) => s,
                None => return Err(EntryError::InvalidArguments),
            };
            let port_arg = match args[2].to_str() {
                Some(s) => s,
                None => return Err(EntryError::InvalidArguments),
            };

            // worker 실행 전 호스트 및 포트 원본 검증 (실패 시 원문 반사 없이 고정 에러)
            if network_core::dns_engine::validate_host(host).is_err() {
                return Err(EntryError::InvalidArguments);
            }
            if network_core::dns_engine::parse_helper_port(port_arg).is_err() {
                return Err(EntryError::InvalidArguments);
            }

            Ok(EntryMode::DnsWorker {
                host: host.to_string(),
                port_arg: port_arg.to_string(),
            })
        }
        _ => Err(EntryError::InvalidArguments),
    }
}

/// 주어진 정적 메시지를 stderr에 기록하고 즉시 플러시합니다.
fn write_static_stderr(stderr: &mut dyn Write, message: &str) -> bool {
    stderr
        .write_all(message.as_bytes())
        .and_then(|_| stderr.flush())
        .is_ok()
}

/// 주입 가능한 worker 함수를 사용하여 진입점을 실행하는 내부 헬퍼.
///
/// 내부 단위 테스트에서 실제 OS getaddrinfo 호출 없이 순수 모의 worker 함수를 연결하여
/// 분기 및 I/O 동작을 완벽하게 검증할 수 있도록 지원합니다.
fn entry_with_worker<F>(
    args: &[OsString],
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    worker_fn: F,
) -> u8
where
    F: FnOnce(&str, &str) -> network_core::dns_engine::DnsWorkerPayload,
{
    let mode = match parse_args(args) {
        Ok(m) => m,
        Err(EntryError::InvalidArguments) => {
            return if write_static_stderr(stderr, INVALID_STDERR) {
                2
            } else {
                1
            };
        }
    };

    match mode {
        EntryMode::Idle => {
            if write_static_stderr(stderr, NOARGS_STDERR) {
                0
            } else {
                1
            }
        }
        EntryMode::Help => {
            if write_static_stderr(stderr, HELP_STDERR) {
                0
            } else {
                1
            }
        }
        EntryMode::DnsWorker { host, port_arg } => {
            let payload = worker_fn(&host, &port_arg);
            let line = network_core::dns_engine::worker_output_line(&payload);

            // UTF-8 바이트 크기 상한(16KiB) 및 정확한 단일 행 + 최종 LF('\n') 구조 검증
            let is_valid_line = line.len() <= network_core::dns_engine::MAX_PAYLOAD_BYTES
                && line.ends_with('\n')
                && !line[..line.len() - 1].contains('\n')
                && !line.contains('\r');

            if !is_valid_line {
                let _ = write_static_stderr(stderr, OUTPUT_FAILURE_STDERR);
                return 1;
            }

            if stdout
                .write_all(line.as_bytes())
                .and_then(|_| stdout.flush())
                .is_ok()
            {
                0
            } else {
                let _ = write_static_stderr(stderr, OUTPUT_FAILURE_STDERR);
                1
            }
        }
    }
}

/// Network Quick Check 진입점을 실행하고 종료 코드를 반환합니다.
///
/// - `0`: 인자 없는 진입 성공, `--help` 출력 성공, 또는 worker 결과 출력 성공.
/// - `1`: stdout 또는 stderr 쓰기/플러시 실패, 결과 상한 초과 등 I/O 오류.
/// - `2`: 잘못되거나 지원하지 않는 인자 (정적 오류 메시지 출력 완료).
pub fn entry(args: &[OsString], stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    entry_with_worker(
        args,
        stdout,
        stderr,
        network_core::dns_engine::run_worker_from_args,
    )
}

/// 현재 실행 파일 경로 조회 결과로부터 `NativeDnsProbeBackend`를 생성하는 내부 헬퍼.
///
/// 절대 경로만 수용하며, 상대 경로나 I/O 오류는 대체 경로(PATH, CWD 등) 없이 그대로 실패(Fail-Closed) 처리합니다.
fn backend_from_exe_path_result(
    exe_res: std::io::Result<PathBuf>,
) -> std::io::Result<network_core::runner::NativeDnsProbeBackend> {
    let exe_path = exe_res?;
    if !exe_path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "현재 실행 파일 경로가 절대 경로가 아닙니다.",
        ));
    }
    Ok(network_core::runner::NativeDnsProbeBackend::new(exe_path))
}

/// 현재 실행 중인 프로세스의 절대 실행 파일 경로로 `NativeDnsProbeBackend`를 생성합니다.
///
/// `current_exe()` 실패 또는 반환된 경로가 절대 경로가 아닌 경우 임의의 PATH나 상대 경로로
/// 폴백하지 않고 즉시 오류(`Err`)를 반환합니다(Fail-Closed).
pub fn native_backend_for_current_exe()
-> std::io::Result<network_core::runner::NativeDnsProbeBackend> {
    backend_from_exe_path_result(std::env::current_exe())
}

#[cfg(test)]
mod tests {
    use super::*;
    use network_core::dns_engine::{
        DnsWorkerPayload, MAX_PAYLOAD_BYTES, WORKER_FLAG, WORKER_FORMAT, decode_worker_payload,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// 강제로 쓰기 실패를 발생시키는 모의 Write 구현체.
    struct FailWriter;

    impl Write for FailWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("테스트용 강제 쓰기 실패"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// 쓰기는 수집하나 플러시에서 실패를 발생시키는 모의 Write 구현체.
    struct FailFlushWriter {
        buf: Vec<u8>,
    }

    impl FailFlushWriter {
        fn new() -> Self {
            Self { buf: Vec::new() }
        }
    }

    impl Write for FailFlushWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.buf.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("테스트용 강제 플러시 실패"))
        }
    }

    /// 쓰기와 플러시 모두 실패하는 모의 Write 구현체.
    struct FailAllWriter;

    impl Write for FailAllWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("테스트용 쓰기 실패"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("테스트용 플러시 실패"))
        }
    }

    /// 지정된 바이트까지만 기록하고 이후 쓰기에서 실패를 발생시키는 모의 Write 구현체.
    struct PartialFailWriter {
        written: usize,
        limit: usize,
    }

    impl PartialFailWriter {
        fn new(limit: usize) -> Self {
            Self { written: 0, limit }
        }
    }

    impl Write for PartialFailWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.written >= self.limit {
                Err(std::io::Error::other(
                    "테스트용 부분 쓰기 후 한도 초과 실패",
                ))
            } else {
                let take = (self.limit - self.written).min(buf.len());
                self.written += take;
                Ok(take)
            }
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// 부분 쓰기(청크 단위)를 시뮬레이션하는 모의 Write 구현체 (write_all의 반복 쓰기 검증용).
    struct ChunkWriter {
        chunk_size: usize,
        buf: Vec<u8>,
    }

    impl ChunkWriter {
        fn new(chunk_size: usize) -> Self {
            Self {
                chunk_size,
                buf: Vec::new(),
            }
        }
    }

    impl Write for ChunkWriter {
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

    /// write 호출 시 항상 Ok(0)을 반환하여 WriteZero 실패를 유발하는 모의 Write 구현체.
    struct WriteZeroWriter;

    impl Write for WriteZeroWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Ok(0)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_parse_args_boundaries() {
        // 1. 빈 인자 -> Idle
        assert_eq!(parse_args(&[]), Ok(EntryMode::Idle));

        // 2. 단일 인자 --help -> Help
        let help_arg = vec![OsString::from("--help")];
        assert_eq!(parse_args(&help_arg), Ok(EntryMode::Help));

        // 3. 잘못된 단일 인자들 -> InvalidArguments
        for invalid_single in ["-h", "--version", "help", "--npi-dns-worker-v1", ""] {
            let args = vec![OsString::from(invalid_single)];
            assert_eq!(parse_args(&args), Err(EntryError::InvalidArguments));
        }

        // 4. 인자 개수 불일치 (2개, 4개) -> InvalidArguments
        let two_args = vec![OsString::from(WORKER_FLAG), OsString::from("example.com")];
        assert_eq!(parse_args(&two_args), Err(EntryError::InvalidArguments));

        let four_args = vec![
            OsString::from(WORKER_FLAG),
            OsString::from("example.com"),
            OsString::from("80"),
            OsString::from("extra"),
        ];
        assert_eq!(parse_args(&four_args), Err(EntryError::InvalidArguments));

        // 5. 잘못된 플래그 또는 플래그 결합 -> InvalidArguments
        for bad_flag in [
            "--worker",
            "--npi-dns-worker-v2",
            "--npi-dns-worker-v1=example.com",
        ] {
            let args = vec![
                OsString::from(bad_flag),
                OsString::from("example.com"),
                OsString::from("80"),
            ];
            assert_eq!(parse_args(&args), Err(EntryError::InvalidArguments));
        }

        // 6. 인자 순서 변경 -> InvalidArguments
        let wrong_order = vec![
            OsString::from("example.com"),
            OsString::from(WORKER_FLAG),
            OsString::from("80"),
        ];
        assert_eq!(parse_args(&wrong_order), Err(EntryError::InvalidArguments));

        // 7. 잘못된 호스트 형식들 -> InvalidArguments
        let bad_hosts = [
            "",
            "   ",
            "example .com",
            "http://example.com",
            "user:pass@example.com",
            "[::1]",
            "192.168.1.999",
            "-leading-hyphen.com",
            "trailing-hyphen-.com",
        ];
        for bad_host in bad_hosts {
            let args = vec![
                OsString::from(WORKER_FLAG),
                OsString::from(bad_host),
                OsString::from("80"),
            ];
            assert_eq!(parse_args(&args), Err(EntryError::InvalidArguments));
        }

        // 8. 잘못된 포트 형식들 -> InvalidArguments
        let bad_ports = [
            "", "0", "65536", "080", "+80", " 80 ", "http", "-1", "999999",
        ];
        for bad_port in bad_ports {
            let args = vec![
                OsString::from(WORKER_FLAG),
                OsString::from("example.com"),
                OsString::from(bad_port),
            ];
            assert_eq!(parse_args(&args), Err(EntryError::InvalidArguments));
        }

        // 9. 정상 worker 인자 (도메인, IPv4, IPv6)
        let valid_domain = vec![
            OsString::from(WORKER_FLAG),
            OsString::from("example.com"),
            OsString::from("443"),
        ];
        assert_eq!(
            parse_args(&valid_domain),
            Ok(EntryMode::DnsWorker {
                host: "example.com".to_string(),
                port_arg: "443".to_string(),
            })
        );

        let valid_ipv4 = vec![
            OsString::from(WORKER_FLAG),
            OsString::from("127.0.0.1"),
            OsString::from("80"),
        ];
        assert_eq!(
            parse_args(&valid_ipv4),
            Ok(EntryMode::DnsWorker {
                host: "127.0.0.1".to_string(),
                port_arg: "80".to_string(),
            })
        );

        let valid_ipv6 = vec![
            OsString::from(WORKER_FLAG),
            OsString::from("::1"),
            OsString::from("8080"),
        ];
        assert_eq!(
            parse_args(&valid_ipv6),
            Ok(EntryMode::DnsWorker {
                host: "::1".to_string(),
                port_arg: "8080".to_string(),
            })
        );
    }

    #[cfg(windows)]
    #[test]
    fn test_parse_args_non_unicode_windows() {
        use std::os::windows::ffi::OsStringExt;

        // unpaired surrogate 코드포인트로 비유니코드 OsString 생성
        let unpaired = OsString::from_wide(&[0xD800]);
        let flag = OsString::from(WORKER_FLAG);
        let host = OsString::from("127.0.0.1");
        let port = OsString::from("80");

        // 1. 호스트가 비유니코드인 경우
        let args = vec![flag.clone(), unpaired.clone(), port.clone()];
        assert_eq!(parse_args(&args), Err(EntryError::InvalidArguments));

        // 2. 포트가 비유니코드인 경우
        let args = vec![flag.clone(), host.clone(), unpaired.clone()];
        assert_eq!(parse_args(&args), Err(EntryError::InvalidArguments));

        // 3. 플래그가 비유니코드인 경우
        let args = vec![unpaired, host, port];
        assert_eq!(parse_args(&args), Err(EntryError::InvalidArguments));
    }

    #[cfg(windows)]
    #[test]
    fn test_unpaired_surrogate_entry_rejection() {
        use std::os::windows::ffi::OsStringExt;

        let unpaired = OsString::from_wide(&[0xD800]);
        let flag = OsString::from(WORKER_FLAG);
        let host = OsString::from("127.0.0.1");
        let port = OsString::from("80");

        let call_count = AtomicUsize::new(0);
        let mock_worker = |_h: &str, _p: &str| {
            call_count.fetch_add(1, Ordering::SeqCst);
            DnsWorkerPayload {
                format: WORKER_FORMAT.to_string(),
                host: "127.0.0.1".to_string(),
                port: 80,
                addresses: vec!["127.0.0.1:80".to_string()],
                truncated: false,
                error_code: None,
                error_message: None,
            }
        };

        // 1. flag가 unpaired surrogate인 경우 -> entry_with_worker에서 exit 2, stderr 정적 메시지, worker 호출 0
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let args_flag = vec![unpaired.clone(), host.clone(), port.clone()];
        let code = entry_with_worker(&args_flag, &mut stdout, &mut stderr, mock_worker);
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert_eq!(String::from_utf8_lossy(&stderr), INVALID_STDERR);
        assert_eq!(call_count.load(Ordering::SeqCst), 0);

        // 2. host가 unpaired surrogate인 경우 -> exit 2, stderr 정적 메시지, worker 호출 0
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let args_host = vec![flag.clone(), unpaired.clone(), port.clone()];
        let code = entry_with_worker(&args_host, &mut stdout, &mut stderr, mock_worker);
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert_eq!(String::from_utf8_lossy(&stderr), INVALID_STDERR);
        assert_eq!(call_count.load(Ordering::SeqCst), 0);

        // 3. port가 unpaired surrogate인 경우 -> exit 2, stderr 정적 메시지, worker 호출 0
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let args_port = vec![flag, host, unpaired];
        let code = entry_with_worker(&args_port, &mut stdout, &mut stderr, mock_worker);
        assert_eq!(code, 2);
        assert!(stdout.is_empty());
        assert_eq!(String::from_utf8_lossy(&stderr), INVALID_STDERR);
        assert_eq!(call_count.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_static_error_no_reflection() {
        let sensitive_token = "SUPER_SECRET_TOKEN_98765";
        let args = vec![
            OsString::from(WORKER_FLAG),
            OsString::from(format!("user:{sensitive_token}@example.com")),
            OsString::from("80"),
        ];

        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();

        let code = entry(&args, &mut stdout_buf, &mut stderr_buf);

        assert_eq!(code, 2);
        assert!(
            stdout_buf.is_empty(),
            "오류 발생 시 stdout은 비어있어야 합니다."
        );

        let stderr_str = String::from_utf8(stderr_buf).expect("stderr는 UTF-8이어야 합니다.");
        assert_eq!(stderr_str, INVALID_STDERR);
        assert!(
            !stderr_str.contains(sensitive_token),
            "stderr 오류 메시지에 민감 정보가 반사되어서는 안 됩니다."
        );
    }

    #[test]
    fn test_worker_call_counts() {
        let call_count = AtomicUsize::new(0);
        let mock_worker = |host: &str, port: &str| {
            call_count.fetch_add(1, Ordering::SeqCst);
            DnsWorkerPayload {
                format: WORKER_FORMAT.to_string(),
                host: host.to_string(),
                port: port.parse().unwrap_or(0),
                addresses: vec![format!("127.0.0.1:{port}")],
                truncated: false,
                error_code: None,
                error_message: None,
            }
        };

        // 1. noargs 진입 -> worker 호출 0
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = entry_with_worker(&[], &mut stdout, &mut stderr, mock_worker);
        assert_eq!(code, 0);
        assert_eq!(String::from_utf8_lossy(&stderr), NOARGS_STDERR);
        assert!(stdout.is_empty());
        assert_eq!(call_count.load(Ordering::SeqCst), 0);

        // 2. help 진입 -> worker 호출 0
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let help_args = vec![OsString::from("--help")];
        let code = entry_with_worker(&help_args, &mut stdout, &mut stderr, mock_worker);
        assert_eq!(code, 0);
        assert_eq!(String::from_utf8_lossy(&stderr), HELP_STDERR);
        assert!(stdout.is_empty());
        assert_eq!(call_count.load(Ordering::SeqCst), 0);

        // 3. invalid 인자 진입 -> worker 호출 0
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let invalid_args = vec![OsString::from("--invalid")];
        let code = entry_with_worker(&invalid_args, &mut stdout, &mut stderr, mock_worker);
        assert_eq!(code, 2);
        assert_eq!(String::from_utf8_lossy(&stderr), INVALID_STDERR);
        assert!(stdout.is_empty());
        assert_eq!(call_count.load(Ordering::SeqCst), 0);

        // 4. 잘못된 worker 인자(포트 0) 진입 -> worker 호출 0
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let invalid_worker_args = vec![
            OsString::from(WORKER_FLAG),
            OsString::from("example.com"),
            OsString::from("0"),
        ];
        let code = entry_with_worker(&invalid_worker_args, &mut stdout, &mut stderr, mock_worker);
        assert_eq!(code, 2);
        assert_eq!(String::from_utf8_lossy(&stderr), INVALID_STDERR);
        assert!(stdout.is_empty());
        assert_eq!(call_count.load(Ordering::SeqCst), 0);

        // 5. 도메인 인자 단독 입력(플래그 누락) -> worker 호출 0
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let domain_only_args = vec![OsString::from("example.com"), OsString::from("80")];
        let code = entry_with_worker(&domain_only_args, &mut stdout, &mut stderr, mock_worker);
        assert_eq!(code, 2);
        assert_eq!(String::from_utf8_lossy(&stderr), INVALID_STDERR);
        assert!(stdout.is_empty());
        assert_eq!(call_count.load(Ordering::SeqCst), 0);

        // 6. 유효한 worker 인자 진입 -> worker 정확히 1회 호출
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let valid_args = vec![
            OsString::from(WORKER_FLAG),
            OsString::from("example.com"),
            OsString::from("80"),
        ];
        let code = entry_with_worker(&valid_args, &mut stdout, &mut stderr, mock_worker);
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
        assert!(!stdout.is_empty());
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_io_failures() {
        // 1. noargs에서 stderr 쓰기 실패 -> exit 1
        let mut stdout = Vec::new();
        let mut fail_stderr = FailWriter;
        assert_eq!(entry(&[], &mut stdout, &mut fail_stderr), 1);

        // 2. noargs에서 stderr 플러시 실패 -> exit 1
        let mut stdout = Vec::new();
        let mut fail_flush_stderr = FailFlushWriter::new();
        assert_eq!(entry(&[], &mut stdout, &mut fail_flush_stderr), 1);

        // 3. help에서 stderr 쓰기 실패 -> exit 1
        let mut stdout = Vec::new();
        let mut fail_stderr = FailWriter;
        let help_args = vec![OsString::from("--help")];
        assert_eq!(entry(&help_args, &mut stdout, &mut fail_stderr), 1);

        // 4. help에서 stderr 플러시 실패 -> exit 1
        let mut fail_flush_stderr = FailFlushWriter::new();
        assert_eq!(entry(&help_args, &mut stdout, &mut fail_flush_stderr), 1);

        // 5. invalid에서 stderr 쓰기 실패 -> exit 1 (정상 invalid는 2이나 I/O 실패 시 1)
        let mut stdout = Vec::new();
        let mut fail_stderr = FailWriter;
        let invalid_args = vec![OsString::from("--bad")];
        assert_eq!(entry(&invalid_args, &mut stdout, &mut fail_stderr), 1);

        // 6. invalid에서 stderr 플러시 실패 -> exit 1
        let mut fail_flush_stderr = FailFlushWriter::new();
        assert_eq!(entry(&invalid_args, &mut stdout, &mut fail_flush_stderr), 1);

        // 7. worker에서 stdout 쓰기 실패 -> exit 1 및 stderr에 failure_message 출력
        let valid_args = vec![
            OsString::from(WORKER_FLAG),
            OsString::from("127.0.0.1"),
            OsString::from("80"),
        ];
        let mut fail_stdout = FailWriter;
        let mut stderr = Vec::new();
        let mock_worker = |host: &str, _port: &str| DnsWorkerPayload {
            format: WORKER_FORMAT.to_string(),
            host: host.to_string(),
            port: 80,
            addresses: vec!["127.0.0.1:80".to_string()],
            truncated: false,
            error_code: None,
            error_message: None,
        };
        let code = entry_with_worker(&valid_args, &mut fail_stdout, &mut stderr, mock_worker);
        assert_eq!(code, 1);
        assert_eq!(String::from_utf8_lossy(&stderr), OUTPUT_FAILURE_STDERR);

        // 8. worker에서 stdout 부분 쓰기 후 실패 -> exit 1
        let mut partial_stdout = PartialFailWriter::new(10);
        let mut stderr = Vec::new();
        let code = entry_with_worker(&valid_args, &mut partial_stdout, &mut stderr, mock_worker);
        assert_eq!(code, 1);
        assert_eq!(String::from_utf8_lossy(&stderr), OUTPUT_FAILURE_STDERR);

        // 9. worker에서 stdout 플러시 실패 -> exit 1
        let mut fail_flush_stdout = FailFlushWriter::new();
        let mut stderr = Vec::new();
        let code = entry_with_worker(
            &valid_args,
            &mut fail_flush_stdout,
            &mut stderr,
            mock_worker,
        );
        assert_eq!(code, 1);
        assert_eq!(String::from_utf8_lossy(&stderr), OUTPUT_FAILURE_STDERR);

        // 10. worker에서 stdout 실패 후 stderr마저 쓰기/플러시 실패해도 exit 1 반환 (패닉 없음)
        let mut fail_stdout2 = FailWriter;
        let mut fail_stderr2 = FailAllWriter;
        let code = entry_with_worker(
            &valid_args,
            &mut fail_stdout2,
            &mut fail_stderr2,
            mock_worker,
        );
        assert_eq!(code, 1);

        // 11. 민감 입력 포함 invalid 인자에서 stderr 쓰기 실패 시에도 exit 1 반환 (반사 없음)
        let sensitive_token = "SECRET_TOKEN_XYZ";
        let bad_args = vec![
            OsString::from(WORKER_FLAG),
            OsString::from(format!("user:{sensitive_token}@example.com")),
            OsString::from("80"),
        ];
        let mut stdout = Vec::new();
        let mut fail_stderr = FailWriter;
        let code = entry(&bad_args, &mut stdout, &mut fail_stderr);
        assert_eq!(code, 1);
        assert!(stdout.is_empty());
    }

    #[test]
    fn test_chunk_writer_and_write_zero() {
        let valid_args = vec![
            OsString::from(WORKER_FLAG),
            OsString::from("127.0.0.1"),
            OsString::from("80"),
        ];
        let mock_worker = |host: &str, _port: &str| DnsWorkerPayload {
            format: WORKER_FORMAT.to_string(),
            host: host.to_string(),
            port: 80,
            addresses: vec!["127.0.0.1:80".to_string()],
            truncated: false,
            error_code: None,
            error_message: None,
        };
        let expected_line =
            network_core::dns_engine::worker_output_line(&mock_worker("127.0.0.1", "80"));

        // 1. ChunkWriter(작은 버퍼로 부분 write 반복) -> write_all에 의해 정상 exit 0 및 전체 기록 완료
        let mut chunk_stdout = ChunkWriter::new(7);
        let mut stderr = Vec::new();
        let code = entry_with_worker(&valid_args, &mut chunk_stdout, &mut stderr, mock_worker);
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
        assert_eq!(chunk_stdout.buf, expected_line.as_bytes());

        // 2. WriteZeroWriter(Ok(0) 반환하여 WriteZero 유발) -> exit 1 및 정적 실패 메시지
        let mut zero_stdout = WriteZeroWriter;
        let mut stderr = Vec::new();
        let code = entry_with_worker(&valid_args, &mut zero_stdout, &mut stderr, mock_worker);
        assert_eq!(code, 1);
        assert_eq!(String::from_utf8_lossy(&stderr), OUTPUT_FAILURE_STDERR);
    }

    #[test]
    fn test_synthetic_payloads() {
        let valid_args = vec![
            OsString::from(WORKER_FLAG),
            OsString::from("synthetic.test"),
            OsString::from("8080"),
        ];

        // 1. 합성 RESOLVED 성공 페이로드
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let expected_payload = DnsWorkerPayload {
            format: WORKER_FORMAT.to_string(),
            host: "synthetic.test".to_string(),
            port: 8080,
            addresses: vec!["192.0.2.1:8080".to_string()],
            truncated: false,
            error_code: None,
            error_message: None,
        };
        let p_clone = expected_payload.clone();
        let code = entry_with_worker(&valid_args, &mut stdout, &mut stderr, move |_h, _p| p_clone);
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
        let decoded = decode_worker_payload(&stdout, "synthetic.test", 8080)
            .expect("합성 RESOLVED 페이로드 디코드 실패");
        assert_eq!(decoded, expected_payload);

        // 2. 합성 DNS_ERROR 페이로드 (정상 OS 에러 페이로드도 exit 0으로 온전히 전달되어야 함)
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let expected_error_payload = DnsWorkerPayload {
            format: WORKER_FORMAT.to_string(),
            host: "synthetic.test".to_string(),
            port: 8080,
            addresses: Vec::new(),
            truncated: false,
            error_code: Some(10060),
            error_message: Some("연결 시간 초과".to_string()),
        };
        let p_err_clone = expected_error_payload.clone();
        let code = entry_with_worker(&valid_args, &mut stdout, &mut stderr, move |_h, _p| {
            p_err_clone
        });
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
        let decoded_err = decode_worker_payload(&stdout, "synthetic.test", 8080)
            .expect("합성 DNS_ERROR 페이로드 디코드 실패");
        assert_eq!(decoded_err, expected_error_payload);
    }

    #[test]
    fn test_literal_worker_execution() {
        // 실제 entry를 호출하되 대상은 IP 리터럴(127.0.0.1, ::1)만 사용하여
        // 네트워크 질의 없이 resolver_worker가 즉시 완료되도록 합니다.
        // 1. IPv4 리터럴
        let args_v4 = vec![
            OsString::from(WORKER_FLAG),
            OsString::from("127.0.0.1"),
            OsString::from("80"),
        ];
        let mut stdout_v4 = Vec::new();
        let mut stderr_v4 = Vec::new();
        let code_v4 = entry(&args_v4, &mut stdout_v4, &mut stderr_v4);
        assert_eq!(code_v4, 0);
        assert!(stderr_v4.is_empty());
        assert!(stdout_v4.len() <= MAX_PAYLOAD_BYTES);

        let decoded_v4 = decode_worker_payload(&stdout_v4, "127.0.0.1", 80)
            .expect("IPv4 리터럴 페이로드 디코드 실패");
        assert_eq!(decoded_v4.addresses, vec!["127.0.0.1:80".to_string()]);
        assert_eq!(decoded_v4.error_code, None);
        assert_eq!(decoded_v4.error_message, None);

        // 2. IPv6 리터럴
        let args_v6 = vec![
            OsString::from(WORKER_FLAG),
            OsString::from("::1"),
            OsString::from("8080"),
        ];
        let mut stdout_v6 = Vec::new();
        let mut stderr_v6 = Vec::new();
        let code_v6 = entry(&args_v6, &mut stdout_v6, &mut stderr_v6);
        assert_eq!(code_v6, 0);
        assert!(stderr_v6.is_empty());
        assert!(stdout_v6.len() <= MAX_PAYLOAD_BYTES);

        let decoded_v6 = decode_worker_payload(&stdout_v6, "::1", 8080)
            .expect("IPv6 리터럴 페이로드 디코드 실패");
        assert_eq!(decoded_v6.addresses, vec!["[::1]:8080".to_string()]);
        assert_eq!(decoded_v6.error_code, None);
        assert_eq!(decoded_v6.error_message, None);
    }

    /// 출력 바이트 상한 경계 검사용 합성 페이로드를 생성합니다.
    ///
    /// 주의: 본 헬퍼는 worker 출력 바이트 가드(MAX_PAYLOAD_BYTES = 16,384) 동작을 검증하기 위해
    /// 정상 엔진의 512바이트 오류 메시지 상한을 의도적으로 초과하는 긴 메시지를 주입한 합성 데이터이며,
    /// 정상 OS 페이로드 또는 decoder가 이를 수용한다는 증거가 아닙니다.
    fn make_boundary_payload(prefix: &str, target_wire_bytes: usize) -> DnsWorkerPayload {
        let mut payload = DnsWorkerPayload {
            format: WORKER_FORMAT.to_string(),
            host: "boundary.test".to_string(),
            port: 80,
            addresses: Vec::new(),
            truncated: false,
            error_code: Some(1),
            error_message: Some(prefix.to_string()),
        };
        let base_len = network_core::dns_engine::worker_output_line(&payload).len();
        assert!(
            base_len <= target_wire_bytes,
            "접두사 기본 직렬화 크기({base_len})가 목표 바이트({target_wire_bytes})보다 큽니다."
        );
        let pad_needed = target_wire_bytes - base_len;
        let mut msg = prefix.to_string();
        msg.extend(std::iter::repeat_n('A', pad_needed));
        payload.error_message = Some(msg);

        let final_len = network_core::dns_engine::worker_output_line(&payload).len();
        assert_eq!(
            final_len, target_wire_bytes,
            "생성된 페이로드의 직렬화 바이트가 정확히 목표 바이트와 일치해야 합니다."
        );
        payload
    }

    #[test]
    fn test_payload_boundary_and_escaped_multiline() {
        let valid_args = vec![
            OsString::from(WORKER_FLAG),
            OsString::from("boundary.test"),
            OsString::from("80"),
        ];

        // 1. ASCII 접두사 경계 3개 (MAX_PAYLOAD_BYTES - 1, 정확 MAX, MAX + 1)
        let ascii_prefix = "ASCII_PREFIX_";
        for target_bytes in [
            MAX_PAYLOAD_BYTES - 1,
            MAX_PAYLOAD_BYTES,
            MAX_PAYLOAD_BYTES + 1,
        ] {
            let payload = make_boundary_payload(ascii_prefix, target_bytes);
            let expected_line = network_core::dns_engine::worker_output_line(&payload);
            assert_eq!(
                expected_line.len(),
                target_bytes,
                "실제 worker_output_line 바이트 수가 목표 바이트와 정확히 일치해야 합니다."
            );

            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let p_clone = payload.clone();
            let code =
                entry_with_worker(&valid_args, &mut stdout, &mut stderr, move |_h, _p| p_clone);

            if target_bytes <= MAX_PAYLOAD_BYTES {
                assert_eq!(code, 0, "상한 이하({target_bytes})는 exit 0이어야 합니다.");
                assert_eq!(
                    stdout,
                    expected_line.as_bytes(),
                    "상한 이하 출력은 expected wire와 정확히 일치해야 합니다."
                );
                assert!(
                    stderr.is_empty(),
                    "상한 이하 성공 시 stderr는 비어있어야 합니다."
                );
            } else {
                assert_eq!(code, 1, "상한 초과({target_bytes})는 exit 1이어야 합니다.");
                assert!(
                    stdout.is_empty(),
                    "상한 초과 시 stdout은 비어있어야 합니다."
                );
                assert_eq!(
                    String::from_utf8_lossy(&stderr),
                    OUTPUT_FAILURE_STDERR,
                    "상한 초과 시 정적 실패 메시지가 출력되어야 합니다."
                );
            }
        }

        // 2. 한국어 멀티바이트 + quote / backslash / CRLF 섞은 접두사 경계 3개 (MAX - 1, MAX, MAX + 1)
        let mixed_prefix = "한국어접두사_\"따옴표\"_\\역슬래시_\r\n_오류메시지_";
        for target_bytes in [
            MAX_PAYLOAD_BYTES - 1,
            MAX_PAYLOAD_BYTES,
            MAX_PAYLOAD_BYTES + 1,
        ] {
            let payload = make_boundary_payload(mixed_prefix, target_bytes);
            let expected_line = network_core::dns_engine::worker_output_line(&payload);
            assert_eq!(
                expected_line.len(),
                target_bytes,
                "실제 worker_output_line 바이트 수가 목표 바이트와 정확히 일치해야 합니다."
            );

            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let p_clone = payload.clone();
            let code =
                entry_with_worker(&valid_args, &mut stdout, &mut stderr, move |_h, _p| p_clone);

            if target_bytes <= MAX_PAYLOAD_BYTES {
                assert_eq!(code, 0, "상한 이하({target_bytes})는 exit 0이어야 합니다.");
                assert_eq!(
                    stdout,
                    expected_line.as_bytes(),
                    "상한 이하 출력은 expected wire와 정확히 일치해야 합니다."
                );
                assert!(
                    stderr.is_empty(),
                    "상한 이하 성공 시 stderr는 비어있어야 합니다."
                );
            } else {
                assert_eq!(code, 1, "상한 초과({target_bytes})는 exit 1이어야 합니다.");
                assert!(
                    stdout.is_empty(),
                    "상한 초과 시 stdout은 비어있어야 합니다."
                );
                assert_eq!(
                    String::from_utf8_lossy(&stderr),
                    OUTPUT_FAILURE_STDERR,
                    "상한 초과 시 정적 실패 메시지가 출력되어야 합니다."
                );
            }
        }

        // 3. JSON 문자열 안의 개행/CRLF/따옴표/역슬래시가 escape되어 wire 1줄로 유지되는 유효 fixture 검증
        // (기존의 multiline fixture가 exit 1을 기대했던 계약 오류를 보정하여 exit 0, stderr empty, 디코드 동등성 검증)
        let escaped_payload = DnsWorkerPayload {
            format: WORKER_FORMAT.to_string(),
            host: "boundary.test".to_string(),
            port: 80,
            addresses: Vec::new(),
            truncated: false,
            error_code: Some(1),
            error_message: Some("첫 번째 줄\n두 번째 줄\r\n\"따옴표\"\\역슬래시".to_string()),
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let p_clone = escaped_payload.clone();
        let code = entry_with_worker(&valid_args, &mut stdout, &mut stderr, move |_h, _p| p_clone);
        assert_eq!(
            code, 0,
            "escape된 JSON 개행은 정상 1줄 wire이므로 exit 0이어야 합니다."
        );
        assert!(
            stderr.is_empty(),
            "정상 escape wire 출력 시 stderr는 비어있어야 합니다."
        );
        assert!(
            stdout.ends_with(b"\n"),
            "출력 wire는 최종 LF 1개로 끝나야 합니다."
        );
        assert_eq!(
            stdout.iter().filter(|&&b| b == b'\n').count(),
            1,
            "stdout 전체에 실제 LF는 최종 1개만 존재해야 합니다."
        );
        assert!(
            !stdout.contains(&b'\r'),
            "stdout에 실제 CR 바이트는 존재하지 않아야 합니다."
        );
        let decoded = decode_worker_payload(&stdout, "boundary.test", 80)
            .expect("escape된 개행이 포함된 stdout 디코드 실패");
        assert_eq!(
            decoded, escaped_payload,
            "디코드된 페이로드가 원본과 완전히 일치해야 합니다."
        );
    }

    #[test]
    fn test_native_backend_pure_helper() {
        // 1. 정상 합성 Windows 절대 경로 주입 -> 백엔드 생성 성공 및 helper_executable 동등성 검증
        let synthetic_abs =
            PathBuf::from(r"C:\Program Files\NetworkPathInspector\NetworkQuickCheck.exe");
        let backend_res = backend_from_exe_path_result(Ok(synthetic_abs.clone()));
        assert!(
            backend_res.is_ok(),
            "합성 절대 경로 주입 시 성공해야 합니다."
        );
        let backend = backend_res.expect("backend 추출");
        assert_eq!(backend.helper_executable, synthetic_abs);
        assert!(backend.helper_executable.is_absolute());

        // 2. 상대 경로 주입 -> InvalidInput 오류 반환 및 Fail-Closed 검증
        let synthetic_rel = PathBuf::from("relative/path/NetworkQuickCheck.exe");
        let rel_res = backend_from_exe_path_result(Ok(synthetic_rel));
        assert!(rel_res.is_err(), "상대 경로는 거부되어야 합니다.");
        assert_eq!(
            rel_res.err().unwrap().kind(),
            std::io::ErrorKind::InvalidInput
        );

        // 3. io::Error 주입 -> 오류 보존 검증
        let io_err = std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "실행 파일을 찾을 수 없습니다.",
        );
        let err_res = backend_from_exe_path_result(Err(io_err));
        assert!(err_res.is_err(), "I/O 오류는 그대로 전파되어야 합니다.");
        assert_eq!(err_res.err().unwrap().kind(), std::io::ErrorKind::NotFound);
    }

    // 부모 대조: JSON 문자열의 CR/LF/따옴표/역슬래시는 escape되어 wire 한 줄과 양립한다.
    #[test]
    fn parent_escaped_json_error_payload_is_preserved_as_one_line() {
        let args = [
            OsString::from(WORKER_FLAG),
            OsString::from("escape.invalid"),
            OsString::from("80"),
        ];
        let payload = DnsWorkerPayload {
            format: WORKER_FORMAT.to_string(),
            host: "escape.invalid".to_string(),
            port: 80,
            addresses: vec![],
            truncated: false,
            error_code: None,
            error_message: Some("한국어\r\n\"따옴표\"\\역슬래시".to_string()),
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = entry_with_worker(&args, &mut stdout, &mut stderr, |_, _| payload.clone());
        assert_eq!(code, 0);
        assert!(stderr.is_empty());
        assert!(stdout.ends_with(b"\n"));
        assert_eq!(stdout.iter().filter(|&&b| b == b'\n').count(), 1);
        assert!(!stdout.contains(&b'\r'));
        assert_eq!(
            decode_worker_payload(&stdout, "escape.invalid", 80).unwrap(),
            payload
        );
    }
}
