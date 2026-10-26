//! Network Quick Check(Part B) 입력·계획 네이티브 GUI 진입점 모듈.
//!
//! 제품 단일 실행 파일(`NetworkQuickCheck`)의 명시적 입력·계획 GUI 진입점인
//! `--dev-gui-inputs-v1` 인자를 처리하며, Windows 네이티브 입력 및 계획 확인 화면을 실행합니다.
//!
//! ## 핵심 설계 및 안전 원칙
//! - **정확한 단일 인자 진입**: 인자는 정확히 1개(`[GUI_INPUTS_SELECTOR]`)여야 하며,
//!   인자 개수가 일치하지 않거나 비유니코드 인자인 경우 즉각 거부합니다 (Fail-Closed).
//! - **원문 반사 없는 정적 오류**:
//!   - 잘못된 인자 개수 시 기존 `INVALID_STDERR`를 출력하고 exit 2로 종료합니다.
//!   - Windows 이외 플랫폼에서는 고정 미지원 메시지를 stderr로 출력하고 exit 1로 종료합니다.
//!   - GUI 초기화 또는 메시지 루프 실패 시 고정 오류 메시지를 stderr로 출력하고 exit 1로 종료합니다.
//! - **실제 네트워크 진단 배제**: 본 진입점은 오직 네이티브 Win32 입력 및 계획 확인용 GUI만 구동하며,
//!   소켓 연결, DNS 질의, 비동기 런타임 시작, 백그라운드 워커 실행 등을 일체 수행하지 않습니다.
//! - **소유권 및 안전 경계**:
//!   - FFI 콜백 및 런처 호출은 `catch_unwind` 경계로 보호되어 패닉이 OS로 누출되지 않습니다.

use std::ffi::OsString;
use std::io::Write;

/// 네이티브 입력·계획 GUI 진입점 셀렉터 플래그 문자열.
pub(super) const GUI_INPUTS_SELECTOR: &str = "--dev-gui-inputs-v1";

/// 비Windows 환경에서 GUI 실행 시도 시 출력되는 정적 한국어 메시지.
pub(super) const GUI_UNSUPPORTED_STDERR: &str =
    "Network Quick Check: 네이티브 GUI는 Windows 환경에서만 지원됩니다.\n";

/// GUI 생성, 메시지 루프 또는 실행 중 오류 발생 시 출력되는 정적 한국어 메시지.
pub(super) const GUI_RUNTIME_ERROR_STDERR: &str =
    "Network Quick Check: GUI 초기화 또는 실행 중 오류가 발생했습니다.\n";

/// 주어진 정적 메시지를 stderr에 기록하고 플러시합니다.
fn write_static_stderr(stderr: &mut dyn Write, message: &str) -> bool {
    stderr
        .write_all(message.as_bytes())
        .and_then(|_| stderr.flush())
        .is_ok()
}

/// 공통 런처 디스패처.
///
/// 실제 프로덕션 진입과 모의 단위 테스트가 동일한 디스패처 로직을 공유합니다.
pub(super) fn dispatch_launcher<F>(
    args: &[OsString],
    stderr: &mut dyn Write,
    is_windows: bool,
    launcher: F,
) -> Option<u8>
where
    F: FnOnce() -> Result<(), ()>,
{
    if args.is_empty() {
        return None;
    }

    // Unicode 손실 변환 금지: to_str()이 None이면 비Unicode이므로 셀렉터 불일치로 간주하여 None 반환
    let first = args[0].to_str()?;

    if first != GUI_INPUTS_SELECTOR {
        return None;
    }

    // 셀렉터는 일치하지만 arity가 정확히 1이 아닌 경우
    if args.len() != 1 {
        let code = if write_static_stderr(stderr, crate::INVALID_STDERR) {
            2
        } else {
            1
        };
        return Some(code);
    }

    // Windows가 아닌 환경인 경우
    if !is_windows {
        let _ = write_static_stderr(stderr, GUI_UNSUPPORTED_STDERR);
        return Some(1);
    }

    // 런처 실행 및 패닉 방어
    let run_res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(launcher));
    match run_res {
        Ok(Ok(())) => Some(0),
        Ok(Err(())) | Err(_) => {
            let _ = write_static_stderr(stderr, GUI_RUNTIME_ERROR_STDERR);
            Some(1)
        }
    }
}

/// Network Quick Check 진입점에서 입력·계획 네이티브 GUI 실행을 시도합니다.
///
/// - `--dev-gui-inputs-v1` 단일 인자가 아니면 `None`을 반환하여 다음 진입점(legacy worker 등)으로 위임합니다.
/// - 단일 인자가 일치하면 네이티브 GUI를 열고 정상 종료 시 `Some(0)`, 오류/미지원 시 `Some(1)`, 인자 오류 시 `Some(2)`를 반환합니다.
pub(super) fn try_entry(args: &[OsString], stderr: &mut dyn Write) -> Option<u8> {
    #[cfg(windows)]
    {
        dispatch_launcher(args, stderr, true, crate::native_gui::run_native_gui)
    }
    #[cfg(not(windows))]
    {
        dispatch_launcher(args, stderr, false, || Err(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct FailWriter;

    impl Write for FailWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("테스트용 쓰기 실패"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

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
            Err(std::io::Error::other("테스트용 플러시 실패"))
        }
    }

    #[test]
    fn test_dispatch_launcher_exact_single_argument() {
        let counter = AtomicUsize::new(0);
        let mut stderr = Vec::new();
        let args = vec![OsString::from(GUI_INPUTS_SELECTOR)];

        let result = dispatch_launcher(&args, &mut stderr, true, || {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });

        assert_eq!(result, Some(0));
        assert!(stderr.is_empty());
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_dispatch_launcher_not_selected_inputs() {
        let counter = AtomicUsize::new(0);
        let mut stderr = Vec::new();

        // 1. noargs (빈 인자) -> None, launcher 0
        let res = dispatch_launcher(&[], &mut stderr, true, || {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        assert_eq!(res, None);
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        // 2. --help -> None, launcher 0
        let help_args = vec![OsString::from("--help")];
        let res = dispatch_launcher(&help_args, &mut stderr, true, || {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        assert_eq!(res, None);
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        // 3. worker selector -> None, launcher 0
        let worker_args = vec![
            OsString::from("--npi-dns-worker-v1"),
            OsString::from("example.com"),
            OsString::from("80"),
        ];
        let res = dispatch_launcher(&worker_args, &mut stderr, true, || {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        assert_eq!(res, None);
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        // 4. dev-tcp selector -> None, launcher 0
        let dev_tcp_args = vec![
            OsString::from("--dev-tcp-once-v1"),
            OsString::from("127.0.0.1"),
            OsString::from("80"),
        ];
        let res = dispatch_launcher(&dev_tcp_args, &mut stderr, true, || {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        assert_eq!(res, None);
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        // 5. unknown selector -> None, launcher 0
        let unknown_args = vec![OsString::from("--unknown")];
        let res = dispatch_launcher(&unknown_args, &mut stderr, true, || {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        assert_eq!(res, None);
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[cfg(windows)]
    #[test]
    fn test_dispatch_launcher_non_unicode_rejection() {
        use std::os::windows::ffi::OsStringExt;

        let counter = AtomicUsize::new(0);
        let mut stderr = Vec::new();
        let unpaired = OsString::from_wide(&[0xD800]);

        let res = dispatch_launcher(&[unpaired], &mut stderr, true, || {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });

        assert_eq!(res, None);
        assert_eq!(counter.load(Ordering::SeqCst), 0);
        assert!(stderr.is_empty());
    }

    #[test]
    fn test_dispatch_launcher_invalid_arity() {
        let counter = AtomicUsize::new(0);

        // 1. 셀렉터 뒤에 초과 인자가 있는 경우 (arity 2) -> Some(2), launcher 0, stderr에 INVALID_STDERR
        let mut stderr = Vec::new();
        let args_two = vec![
            OsString::from(GUI_INPUTS_SELECTOR),
            OsString::from("extra_arg"),
        ];
        let res = dispatch_launcher(&args_two, &mut stderr, true, || {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        assert_eq!(res, Some(2));
        assert_eq!(counter.load(Ordering::SeqCst), 0);
        assert_eq!(String::from_utf8_lossy(&stderr), crate::INVALID_STDERR);

        // 2. arity 3인 경우
        let mut stderr2 = Vec::new();
        let args_three = vec![
            OsString::from(GUI_INPUTS_SELECTOR),
            OsString::from("arg1"),
            OsString::from("arg2"),
        ];
        let res = dispatch_launcher(&args_three, &mut stderr2, true, || {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });
        assert_eq!(res, Some(2));
        assert_eq!(counter.load(Ordering::SeqCst), 0);
        assert_eq!(String::from_utf8_lossy(&stderr2), crate::INVALID_STDERR);
    }

    #[test]
    fn test_dispatch_launcher_non_windows_rejection() {
        let counter = AtomicUsize::new(0);
        let mut stderr = Vec::new();
        let args = vec![OsString::from(GUI_INPUTS_SELECTOR)];

        // is_windows = false
        let res = dispatch_launcher(&args, &mut stderr, false, || {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        });

        assert_eq!(res, Some(1));
        assert_eq!(counter.load(Ordering::SeqCst), 0);
        assert_eq!(String::from_utf8_lossy(&stderr), GUI_UNSUPPORTED_STDERR);
    }

    #[test]
    fn test_dispatch_launcher_panic_and_error_handling() {
        let counter = AtomicUsize::new(0);

        // 1. 런처 Err 반환 시 -> Some(1) 및 GUI_RUNTIME_ERROR_STDERR
        let mut stderr = Vec::new();
        let args = vec![OsString::from(GUI_INPUTS_SELECTOR)];
        let res = dispatch_launcher(&args, &mut stderr, true, || {
            counter.fetch_add(1, Ordering::SeqCst);
            Err(())
        });
        assert_eq!(res, Some(1));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(String::from_utf8_lossy(&stderr), GUI_RUNTIME_ERROR_STDERR);

        // 2. 런처 내부 panic 발생 시 -> catch_unwind로 방어, Some(1) 및 GUI_RUNTIME_ERROR_STDERR
        let mut stderr_panic = Vec::new();
        let res_panic = dispatch_launcher(&args, &mut stderr_panic, true, || {
            counter.fetch_add(1, Ordering::SeqCst);
            panic!("테스트용 의도적 GUI 초기화 패닉");
        });
        assert_eq!(res_panic, Some(1));
        assert_eq!(counter.load(Ordering::SeqCst), 2);
        assert_eq!(
            String::from_utf8_lossy(&stderr_panic),
            GUI_RUNTIME_ERROR_STDERR
        );
    }

    #[test]
    fn test_dispatch_launcher_io_failure_priorities() {
        let args_invalid = vec![OsString::from(GUI_INPUTS_SELECTOR), OsString::from("extra")];

        // 1. arity 오류 시 stderr 쓰기 실패 -> exit 1
        let mut fail_stderr = FailWriter;
        let res = dispatch_launcher(&args_invalid, &mut fail_stderr, true, || Ok(()));
        assert_eq!(res, Some(1));

        // 2. arity 오류 시 stderr 플러시 실패 -> exit 1
        let mut fail_flush_stderr = FailFlushWriter::new();
        let res = dispatch_launcher(&args_invalid, &mut fail_flush_stderr, true, || Ok(()));
        assert_eq!(res, Some(1));
    }
}
