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

/// 주입 가능한 worker 함수를 사용하여 진입점을 실행합니다.
///
/// 내부 단위 테스트에서 실제 OS getaddrinfo 호출 없이 순수 모의 worker 함수를 연결하여
/// 분기 및 I/O 동작을 완벽하게 검증할 수 있도록 지원합니다.
pub fn entry_with_worker<F>(
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
            let bytes = line.as_bytes();

            // UTF-8 바이트 크기 상한(16KiB) 및 정확한 단일 행 + 최종 LF('\n') 구조 검증
            let is_valid_line = bytes.len() <= network_core::dns_engine::MAX_PAYLOAD_BYTES
                && line.ends_with('\n')
                && !line[..line.len() - 1].contains('\n')
                && !line.contains('\r');

            if !is_valid_line {
                let _ = write_static_stderr(stderr, OUTPUT_FAILURE_STDERR);
                return 1;
            }

            if stdout.write_all(bytes).and_then(|_| stdout.flush()).is_ok() {
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

/// 현재 실행 중인 프로세스의 절대 실행 파일 경로로 `NativeDnsProbeBackend`를 생성합니다.
///
/// `current_exe()` 실패 또는 반환된 경로가 절대 경로가 아닌 경우 임의의 PATH나 상대 경로로
/// 폴백하지 않고 즉시 오류(`Err`)를 반환합니다(Fail-Closed).
pub fn native_backend_for_current_exe(
) -> std::io::Result<network_core::runner::NativeDnsProbeBackend> {
    let exe_path = std::env::current_exe()?;
    if !exe_path.is_absolute() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "현재 실행 파일 경로가 절대 경로가 아닙니다.",
        ));
    }
    Ok(network_core::runner::NativeDnsProbeBackend::new(exe_path))
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
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "테스트용 강제 쓰기 실패",
            ))
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
            Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "테스트용 강제 플러시 실패",
            ))
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
                Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
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
        let two_args = vec![
            OsString::from(WORKER_FLAG),
            OsString::from("example.com"),
        ];
        assert_eq!(parse_args(&two_args), Err(EntryError::InvalidArguments));

        let four_args = vec![
            OsString::from(WORKER_FLAG),
            OsString::from("example.com"),
            OsString::from("80"),
            OsString::from("extra"),
        ];
        assert_eq!(parse_args(&four_args), Err(EntryError::InvalidArguments));

        // 5. 잘못된 플래그 또는 플래그 결합 -> InvalidArguments
        for bad_flag in ["--worker", "--npi-dns-worker-v2", "--npi-dns-worker-v1=example.com"] {
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
            "",
            "0",
            "65536",
            "080",
            "+80",
            " 80 ",
            "http",
            "-1",
            "999999",
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
        assert!(stdout_buf.is_empty(), "오류 발생 시 stdout은 비어있어야 합니다.");

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

        // 5. 유효한 worker 인자 진입 -> worker 정확히 1회 호출
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

        // 2. help에서 stderr 플러시 실패 -> exit 1
        let mut stdout = Vec::new();
        let mut fail_flush_stderr = FailFlushWriter::new();
        let help_args = vec![OsString::from("--help")];
        assert_eq!(entry(&help_args, &mut stdout, &mut fail_flush_stderr), 1);

        // 3. invalid에서 stderr 쓰기 실패 -> exit 1 (정상 invalid는 2이나 I/O 실패 시 1)
        let mut stdout = Vec::new();
        let mut fail_stderr = FailWriter;
        let invalid_args = vec![OsString::from("--bad")];
        assert_eq!(entry(&invalid_args, &mut stdout, &mut fail_stderr), 1);

        // 4. worker에서 stdout 쓰기 실패 -> exit 1 및 stderr에 failure_message 출력
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

        // 5. worker에서 stdout 부분 쓰기 후 실패 -> exit 1
        let mut partial_stdout = PartialFailWriter::new(10);
        let mut stderr = Vec::new();
        let code = entry_with_worker(&valid_args, &mut partial_stdout, &mut stderr, mock_worker);
        assert_eq!(code, 1);
        assert_eq!(String::from_utf8_lossy(&stderr), OUTPUT_FAILURE_STDERR);

        // 6. worker에서 stdout 플러시 실패 -> exit 1
        let mut fail_flush_stdout = FailFlushWriter::new();
        let mut stderr = Vec::new();
        let code = entry_with_worker(&valid_args, &mut fail_flush_stdout, &mut stderr, mock_worker);
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
        let code = entry_with_worker(
            &valid_args,
            &mut stdout,
            &mut stderr,
            move |_h, _p| p_clone,
        );
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
        let code = entry_with_worker(
            &valid_args,
            &mut stdout,
            &mut stderr,
            move |_h, _p| p_err_clone,
        );
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

    #[test]
    fn test_payload_overflow_and_multiline_rejection() {
        let valid_args = vec![
            OsString::from(WORKER_FLAG),
            OsString::from("overflow.test"),
            OsString::from("80"),
        ];

        // 1. 16KiB(MAX_PAYLOAD_BYTES) 초과 페이로드 주입
        let long_addresses: Vec<String> = (0..600)
            .map(|i| format!("192.0.2.{}:80", i % 250))
            .collect();
        let overflow_payload = DnsWorkerPayload {
            format: WORKER_FORMAT.to_string(),
            host: "overflow.test".to_string(),
            port: 80,
            addresses: long_addresses,
            truncated: false,
            error_code: None,
            error_message: None,
        };
        let line = network_core::dns_engine::worker_output_line(&overflow_payload);
        assert!(
            line.as_bytes().len() > MAX_PAYLOAD_BYTES,
            "테스트 fixture의 직렬화 바이트가 MAX_PAYLOAD_BYTES를 초과해야 합니다."
        );

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = entry_with_worker(
            &valid_args,
            &mut stdout,
            &mut stderr,
            move |_h, _p| overflow_payload,
        );
        assert_eq!(code, 1);
        assert!(stdout.is_empty(), "상한 초과 페이로드는 stdout에 쓰지 않아야 합니다.");
        assert_eq!(String::from_utf8_lossy(&stderr), OUTPUT_FAILURE_STDERR);

        // 2. 다중 행('\n' 또는 '\r' 포함) 페이로드 주입
        let multiline_payload = DnsWorkerPayload {
            format: WORKER_FORMAT.to_string(),
            host: "overflow.test".to_string(),
            port: 80,
            addresses: Vec::new(),
            truncated: false,
            error_code: Some(1),
            error_message: Some("첫 번째 줄\n두 번째 줄".to_string()),
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = entry_with_worker(
            &valid_args,
            &mut stdout,
            &mut stderr,
            move |_h, _p| multiline_payload,
        );
        assert_eq!(code, 1);
        assert!(stdout.is_empty(), "다중 행 페이로드는 stdout에 쓰지 않아야 합니다.");
        assert_eq!(String::from_utf8_lossy(&stderr), OUTPUT_FAILURE_STDERR);
    }

    #[test]
    fn test_native_backend_current_exe() {
        let backend_res = native_backend_for_current_exe();
        assert!(
            backend_res.is_ok(),
            "native_backend_for_current_exe 호출이 성공해야 합니다: {:?}",
            backend_res.err()
        );
        let backend = backend_res.expect("backend 객체 추출 성공");
        assert!(
            backend.helper_executable.is_absolute(),
            "백엔드의 helper 실행 파일 경로는 절대 경로여야 합니다: {:?}",
            backend.helper_executable
        );
        // 주의: 본 테스트에서 반환된 helper_executable 경로는 test harness runner의 실행 파일이며,
        // 최종 제품 실행 파일(NetworkQuickCheck.exe)의 증거가 아닙니다.
    }

    // 부모 대조: JSON 문자열의 CR/LF/따옴표/역슬래시는 escape되어 wire 한 줄과 양립한다.
    #[test]
    fn parent_escaped_json_error_payload_is_preserved_as_one_line() {
        let args = [OsString::from(WORKER_FLAG), OsString::from("escape.invalid"), OsString::from("80")];
        let payload = DnsWorkerPayload {
            format: WORKER_FORMAT.to_string(), host: "escape.invalid".to_string(), port: 80,
            addresses: vec![], truncated: false, error_code: None,
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
        assert_eq!(decode_worker_payload(&stdout, "escape.invalid", 80).unwrap(), payload);
    }
}
