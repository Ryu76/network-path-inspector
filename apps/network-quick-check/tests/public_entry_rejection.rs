//! Network Quick Check(Part B) 공개 진입점 오류 계약 회귀시험.
//!
//! 제품의 실제 공개 진입점인 `network_quick_check::entry`에 대해
//! 기본 안내 모드(idle, help), 비정상 인자 거부 행렬, 비Unicode(unpaired UTF-16) 입력,
//! 그리고 stderr의 I/O 오류(WriteZero, BrokenPipe, Flush 실패) 처리 동작을 검증합니다.

use std::ffi::OsString;
use std::io::Write;

use network_quick_check::{HELP_STDERR, INVALID_STDERR, NOARGS_STDERR, entry};

/// stdout 쓰기 또는 플러시가 호출되면 즉시 패닉하는 감시자(sentinel) 구현체.
///
/// 진입점 인자 거부 및 안내 경로에서는 stdout이 전혀 조작되지 않아야 합니다.
struct PanicStdout;

impl Write for PanicStdout {
    fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
        panic!("거부 또는 안내 경로에서 stdout write가 호출되어서는 안 됩니다");
    }

    fn flush(&mut self) -> std::io::Result<()> {
        panic!("거부 또는 안내 경로에서 stdout flush가 호출되어서는 안 됩니다");
    }
}

/// 1회성 Interrupted 오류 및 2바이트 단위 짧은 쓰기를 유발하는 모의 stderr 구현체.
///
/// 표준 `std::io::Write::write_all`의 인터럽트 재시도 및 청크 반복 쓰기를 검증합니다.
struct InterruptedAndShortStderr {
    interrupted_yielded: bool,
    buf: Vec<u8>,
    flush_count: usize,
}

impl InterruptedAndShortStderr {
    fn new() -> Self {
        Self {
            interrupted_yielded: false,
            buf: Vec::new(),
            flush_count: 0,
        }
    }
}

impl Write for InterruptedAndShortStderr {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.interrupted_yielded {
            self.interrupted_yielded = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "모의 인터럽트 발생",
            ));
        }
        let take = buf.len().min(2);
        self.buf.extend_from_slice(&buf[..take]);
        Ok(take)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flush_count += 1;
        Ok(())
    }
}

/// 정상 쓰기를 수집하고 플러시 횟수를 추적하는 모의 stderr 구현체.
struct RecordingStderr {
    buf: Vec<u8>,
    flush_count: usize,
}

impl RecordingStderr {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            flush_count: 0,
        }
    }
}

impl Write for RecordingStderr {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flush_count += 1;
        Ok(())
    }
}

/// 지정된 prefix 바이트까지만 기록하고 이후 Ok(0)을 반환하여 WriteZero 오류를 유발하는 모의 stderr 구현체.
struct WriteZeroStderr {
    buf: Vec<u8>,
    prefix_limit: usize,
    flush_count: usize,
}

impl WriteZeroStderr {
    fn new(prefix_limit: usize) -> Self {
        Self {
            buf: Vec::new(),
            prefix_limit,
            flush_count: 0,
        }
    }
}

impl Write for WriteZeroStderr {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.buf.len() < self.prefix_limit {
            let needed = self.prefix_limit - self.buf.len();
            let take = buf.len().min(needed);
            self.buf.extend_from_slice(&buf[..take]);
            Ok(take)
        } else {
            Ok(0)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flush_count += 1;
        Ok(())
    }
}

/// 지정된 prefix 바이트까지만 기록하고 이후 BrokenPipe 오류를 반환하는 모의 stderr 구현체.
struct BrokenPipeStderr {
    buf: Vec<u8>,
    prefix_limit: usize,
    flush_count: usize,
}

impl BrokenPipeStderr {
    fn new(prefix_limit: usize) -> Self {
        Self {
            buf: Vec::new(),
            prefix_limit,
            flush_count: 0,
        }
    }
}

impl Write for BrokenPipeStderr {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.buf.len() < self.prefix_limit {
            let needed = self.prefix_limit - self.buf.len();
            let take = buf.len().min(needed);
            self.buf.extend_from_slice(&buf[..take]);
            Ok(take)
        } else {
            Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "모의 BrokenPipe 오류 발생",
            ))
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flush_count += 1;
        Ok(())
    }
}

/// 쓰기는 정상 수집하나 플러시 호출 시 강제로 오류를 반환하는 모의 stderr 구현체.
struct FailFlushStderr {
    buf: Vec<u8>,
    flush_count: usize,
}

impl FailFlushStderr {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            flush_count: 0,
        }
    }
}

impl Write for FailFlushStderr {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flush_count += 1;
        Err(std::io::Error::other("모의 stderr 플러시 실패 오류"))
    }
}

/// 1. 인자 없는 기본 진입점(idle) 동작을 검증합니다.
#[test]
fn test_idle_entry_interrupted_and_short_write() {
    let mut stdout = PanicStdout;
    let mut stderr = InterruptedAndShortStderr::new();

    let exit_code = entry(&[], &mut stdout, &mut stderr);

    assert_eq!(exit_code, 0, "idle 진입은 exit 0이어야 합니다");
    assert_eq!(
        stderr.buf,
        NOARGS_STDERR.as_bytes(),
        "정확한 NOARGS_STDERR 바이트가 출력되어야 합니다"
    );
    assert_eq!(
        stderr.flush_count, 1,
        "flush는 정확히 1회 호출되어야 합니다"
    );
    assert!(
        stderr.interrupted_yielded,
        "1회성 인터럽트가 발생해야 합니다"
    );
}

/// 2. `--help` 도움말 요청 진입점 동작을 검증합니다.
#[test]
fn test_help_entry_interrupted_and_short_write() {
    let help_args = [OsString::from("--help")];
    let mut stdout = PanicStdout;
    let mut stderr = InterruptedAndShortStderr::new();

    let exit_code = entry(&help_args, &mut stdout, &mut stderr);

    assert_eq!(exit_code, 0, "--help 진입은 exit 0이어야 합니다");
    assert_eq!(
        stderr.buf,
        HELP_STDERR.as_bytes(),
        "정확한 HELP_STDERR 바이트가 출력되어야 합니다"
    );
    assert_eq!(
        stderr.flush_count, 1,
        "flush는 정확히 1회 호출되어야 합니다"
    );
    assert!(
        stderr.interrupted_yielded,
        "1회성 인터럽트가 발생해야 합니다"
    );
}

/// 3. 명시 개발용 진단 진입점(`--dev-tcp-once-v1`)의 인자 거부 행렬을 검증합니다.
#[test]
fn test_dev_tcp_argument_rejection_matrix() {
    let selector = "--dev-tcp-once-v1";
    let literal_host = "127.0.0.1";

    let mut cases = Vec::new();

    // 3-1. 인자 개수 부족 (1개, 2개)
    cases.push(vec![OsString::from(selector)]);
    cases.push(vec![OsString::from(selector), OsString::from(literal_host)]);

    // 3-2. 4번째 초과 인자 sentinel
    cases.push(vec![
        OsString::from(selector),
        OsString::from(literal_host),
        OsString::from("80"),
        OsString::from("extra_sentinel_marker"),
    ]);

    // 3-3. 호스트 거부형 (비정상 문법 합성 마커만 사용)
    let bad_hosts = [
        "http://malformed.test",
        "user:pass@malformed.test",
        "[127.0.0.1]",
        "127.0.0.1/32",
        "malformed\nhost.test",
        "malformed\0host.test",
    ];
    for bad_host in bad_hosts {
        cases.push(vec![
            OsString::from(selector),
            OsString::from(bad_host),
            OsString::from("80"),
        ]);
    }

    // 3-4. 정확한 127.0.0.1 리터럴 대상의 포트 부정 행렬
    let bad_ports = [
        "0",
        "65536",
        "-1",
        "+80",
        "080",
        " 80",
        "80 ",
        "80 80",
        "８０",
        "999999999999999999999999999999999999",
    ];
    for bad_port in bad_ports {
        cases.push(vec![
            OsString::from(selector),
            OsString::from(literal_host),
            OsString::from(bad_port),
        ]);
    }

    // 행렬 개수 검증 (부족 2 + 초과 1 + 호스트 6 + 포트 10 = 총 19개)
    assert_eq!(cases.len(), 19, "dev 인자 거부 행렬 크기 불일치");

    for case in &cases {
        let mut stdout = PanicStdout;
        let mut stderr = RecordingStderr::new();

        let exit_code = entry(case, &mut stdout, &mut stderr);

        assert_eq!(
            exit_code, 2,
            "dev 거부 대상 인자는 exit 2여야 합니다: {case:?}"
        );
        assert_eq!(
            stderr.buf,
            INVALID_STDERR.as_bytes(),
            "정확한 INVALID_STDERR 바이트가 출력되어야 합니다: {case:?}"
        );
        assert_eq!(
            stderr.flush_count, 1,
            "flush는 정확히 1회 호출되어야 합니다: {case:?}"
        );
    }
}

/// 4. 레거시 및 worker 진입점의 인자 거부 행렬을 검증합니다.
#[test]
fn test_legacy_worker_argument_rejection_matrix() {
    let worker_flag = "--npi-dns-worker-v1";
    let literal_host = "127.0.0.1";

    let mut cases = vec![
        // 4-1. --run 및 관련 변형
        vec![OsString::from("--run")],
        vec![OsString::from("--run"), OsString::from(literal_host)],
        // 4-2. selector 오타 및 인자 결합
        vec![
            OsString::from("--dev-tcp-once-v2"),
            OsString::from(literal_host),
            OsString::from("80"),
        ],
        vec![
            OsString::from("--dev-tcp-once-v1=127.0.0.1"),
            OsString::from("80"),
        ],
        vec![
            OsString::from("--npi-dns-worker-v2"),
            OsString::from(literal_host),
            OsString::from("80"),
        ],
        vec![
            OsString::from("--npi-dns-worker-v1=127.0.0.1"),
            OsString::from("80"),
        ],
        vec![
            OsString::from("--worker"),
            OsString::from(literal_host),
            OsString::from("80"),
        ],
        // 4-3. --help 추가 인자
        vec![OsString::from("--help"), OsString::from("extra_sentinel")],
        vec![
            OsString::from("--help"),
            OsString::from("--dev-tcp-once-v1"),
        ],
        // 4-4. worker 인자 부족 및 초과
        vec![OsString::from(worker_flag)],
        vec![OsString::from(worker_flag), OsString::from(literal_host)],
        vec![
            OsString::from(worker_flag),
            OsString::from(literal_host),
            OsString::from("80"),
            OsString::from("extra_sentinel"),
        ],
        // 4-5. worker invalid host (합성 마커)
        vec![
            OsString::from(worker_flag),
            OsString::from("http://malformed.test"),
            OsString::from("80"),
        ],
        vec![
            OsString::from(worker_flag),
            OsString::from("user:pass@malformed.test"),
            OsString::from("80"),
        ],
        vec![
            OsString::from(worker_flag),
            OsString::from("malformed\nhost.test"),
            OsString::from("80"),
        ],
    ];

    // 4-6. worker invalid port (정확 127.0.0.1 리터럴 대상)
    let bad_worker_ports = ["0", "65536", "-1", "+80", "080"];
    for bad_port in bad_worker_ports {
        cases.push(vec![
            OsString::from(worker_flag),
            OsString::from(literal_host),
            OsString::from(bad_port),
        ]);
    }

    // 행렬 개수 검증 (run 2 + 오타/결합 5 + help초과 2 + 개수불일치 3 + 호스트 3 + 포트 5 = 총 20개)
    assert_eq!(cases.len(), 20, "legacy/worker 인자 거부 행렬 크기 불일치");

    for case in &cases {
        let mut stdout = PanicStdout;
        let mut stderr = RecordingStderr::new();

        let exit_code = entry(case, &mut stdout, &mut stderr);

        assert_eq!(exit_code, 2, "거부 대상 인자는 exit 2여야 합니다: {case:?}");
        assert_eq!(
            stderr.buf,
            INVALID_STDERR.as_bytes(),
            "정확한 INVALID_STDERR 바이트가 출력되어야 합니다: {case:?}"
        );
        assert_eq!(
            stderr.flush_count, 1,
            "flush는 정확히 1회 호출되어야 합니다: {case:?}"
        );
    }
}

/// 5. Windows 환경에서 unpaired UTF-16 surrogate 인자 거부 행렬을 검증합니다.
#[cfg(windows)]
#[test]
fn test_unpaired_utf16_argument_rejection_matrix() {
    use std::os::windows::ffi::OsStringExt;

    let selectors = ["--dev-tcp-once-v1", "--npi-dns-worker-v1"];
    let unpaired_surrogates = [0xD800u16, 0xDC00u16];
    let positions = [0usize, 1usize, 2usize];

    let mut call_count = 0usize;

    for selector in selectors {
        for unpaired_code in unpaired_surrogates {
            let unpaired = OsString::from_wide(&[unpaired_code]);
            for position in positions {
                call_count += 1;
                let args = match position {
                    0 => vec![
                        unpaired.clone(),
                        OsString::from("127.0.0.1"),
                        OsString::from("80"),
                    ],
                    1 => vec![
                        OsString::from(selector),
                        unpaired.clone(),
                        OsString::from("80"),
                    ],
                    2 => vec![
                        OsString::from(selector),
                        OsString::from("127.0.0.1"),
                        unpaired.clone(),
                    ],
                    _ => unreachable!(),
                };

                let mut stdout = PanicStdout;
                let mut stderr = RecordingStderr::new();

                let exit_code = entry(&args, &mut stdout, &mut stderr);

                assert_eq!(
                    exit_code, 2,
                    "비유니코드 인자는 exit 2로 거부되어야 합니다 (호출 {call_count})"
                );
                assert_eq!(
                    stderr.buf,
                    INVALID_STDERR.as_bytes(),
                    "정확한 INVALID_STDERR 바이트가 출력되어야 합니다 (호출 {call_count})"
                );
                assert_eq!(
                    stderr.flush_count, 1,
                    "flush는 정확히 1회 호출되어야 합니다 (호출 {call_count})"
                );
            }
        }
    }

    assert_eq!(
        call_count, 12,
        "행렬은 정확히 12회 호출이어야 합니다 (2 selector x 2 surrogate x 3 위치)"
    );
}

/// 6. stderr 쓰기 시 WriteZero 오류 발생에 따른 거부 처리를 검증합니다.
#[test]
fn test_stderr_write_zero_rejection() {
    let test_paths: [(&[OsString], &[u8]); 4] = [
        (&[], NOARGS_STDERR.as_bytes()),
        (&[OsString::from("--help")], HELP_STDERR.as_bytes()),
        (
            &[
                OsString::from("--dev-tcp-once-v1"),
                OsString::from("malformed_marker"),
                OsString::from("80"),
            ],
            INVALID_STDERR.as_bytes(),
        ),
        (
            &[
                OsString::from("--npi-dns-worker-v1"),
                OsString::from("malformed_marker"),
                OsString::from("80"),
            ],
            INVALID_STDERR.as_bytes(),
        ),
    ];

    for (args, expected_bytes) in &test_paths {
        for &prefix_limit in &[0usize, 5usize] {
            let mut stdout = PanicStdout;
            let mut stderr = WriteZeroStderr::new(prefix_limit);

            let exit_code = entry(args, &mut stdout, &mut stderr);

            assert_eq!(exit_code, 1, "WriteZero 오류는 exit 1이어야 합니다");
            assert_eq!(
                stderr.flush_count, 0,
                "쓰기 실패 시 flush가 호출되어서는 안 됩니다"
            );
            assert_eq!(
                stderr.buf,
                &expected_bytes[..prefix_limit],
                "받은 바이트는 정확히 정적 문구의 prefix 바이트여야 합니다"
            );
        }
    }
}

/// 7. stderr 쓰기 시 BrokenPipe 오류 발생에 따른 거부 처리를 검증합니다.
#[test]
fn test_stderr_broken_pipe_rejection() {
    let test_paths: [(&[OsString], &[u8]); 4] = [
        (&[], NOARGS_STDERR.as_bytes()),
        (&[OsString::from("--help")], HELP_STDERR.as_bytes()),
        (
            &[
                OsString::from("--dev-tcp-once-v1"),
                OsString::from("malformed_marker"),
                OsString::from("80"),
            ],
            INVALID_STDERR.as_bytes(),
        ),
        (
            &[
                OsString::from("--npi-dns-worker-v1"),
                OsString::from("malformed_marker"),
                OsString::from("80"),
            ],
            INVALID_STDERR.as_bytes(),
        ),
    ];

    for (args, expected_bytes) in &test_paths {
        for &prefix_limit in &[0usize, 5usize] {
            let mut stdout = PanicStdout;
            let mut stderr = BrokenPipeStderr::new(prefix_limit);

            let exit_code = entry(args, &mut stdout, &mut stderr);

            assert_eq!(exit_code, 1, "BrokenPipe 오류는 exit 1이어야 합니다");
            assert_eq!(
                stderr.flush_count, 0,
                "쓰기 실패 시 flush가 호출되어서는 안 됩니다"
            );
            assert_eq!(
                stderr.buf,
                &expected_bytes[..prefix_limit],
                "받은 바이트는 정확히 정적 문구의 prefix 바이트여야 합니다"
            );
        }
    }
}

/// 8. stderr 플러시 실패 시 오류 처리를 검증합니다.
#[test]
fn test_stderr_flush_failure_rejection() {
    let test_paths: [(&[OsString], &[u8]); 4] = [
        (&[], NOARGS_STDERR.as_bytes()),
        (&[OsString::from("--help")], HELP_STDERR.as_bytes()),
        (
            &[
                OsString::from("--dev-tcp-once-v1"),
                OsString::from("malformed_marker"),
                OsString::from("80"),
            ],
            INVALID_STDERR.as_bytes(),
        ),
        (
            &[
                OsString::from("--npi-dns-worker-v1"),
                OsString::from("malformed_marker"),
                OsString::from("80"),
            ],
            INVALID_STDERR.as_bytes(),
        ),
    ];

    for (args, expected_bytes) in &test_paths {
        let mut stdout = PanicStdout;
        let mut stderr = FailFlushStderr::new();

        let exit_code = entry(args, &mut stdout, &mut stderr);

        assert_eq!(exit_code, 1, "flush 실패 시 exit 1이어야 합니다");
        assert_eq!(
            stderr.flush_count, 1,
            "flush는 정확히 1회 호출되어야 합니다"
        );
        assert_eq!(
            stderr.buf, *expected_bytes,
            "기록된 바이트는 정적 문구 원문 전체여야 합니다"
        );
    }
}
