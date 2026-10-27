//! Network Quick Check(Part B) 네이티브 GUI 실행 진입점 단위 테스트 모듈.
//!
//! caller 소유 슬롯, 전용 UI 스레드 격리, thread spawn 실패 처리, 비UI caller의 최종 drain,
//! after-start Pending 상태에서의 UI Err/panic 및 슬롯 poison 복구,
//! 그리고 `--dev-gui-run-v1` 단일 인자 디스패처의 정밀한 인자 검증 및 오류 제어를 검증합니다.
//! 실제 Win32 창 생성, 소켓 연결, DNS 질의 등 외부 I/O는 일체 사용하지 않으며,
//! CPU 메모리 모의 백엔드와 게이트 동기화를 통해 순수 인메모리로 검증합니다.

use super::*;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use network_core::quick::{QuickContext, QuickFeature, tcp_to_quick_result};
use network_core::runner::{ProbeFuture, QuickProbeBackend};
use network_core::{HostSnapshot, TcpMeasurement};

use crate::gui_coordinator::GuiRunCoordinator;
use crate::gui_presenter::GuiPresenter;
use crate::gui_state::RunPhase;

/// 명시적 술어가 참이 될 때까지 스레드를 양보하며 대기하는 동기화 헬퍼.
fn until(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < deadline, "명시적 동기화 타임아웃");
        std::thread::yield_now();
    }
}

/// 비동기 프로브가 특정 지점에서 대기하도록 제어하는 게이트.
#[derive(Default)]
struct Gate {
    open: AtomicBool,
    entered: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl Gate {
    fn release(&self) {
        self.open.store(true, Ordering::SeqCst);
        if let Some(w) = self.waker.lock().unwrap().take() {
            w.wake();
        }
    }
}

/// 패닉이나 언와인드 발생 시에도 게이트가 반드시 열리도록 보장하는 RAII 가드.
/// start 전에 설치되어 UI 스레드의 에러나 패닉 시에도 백그라운드 워커가 블록되지 않도록 보장합니다.
struct ReleaseGuard<'a> {
    gate: &'a Arc<Gate>,
}

impl<'a> Drop for ReleaseGuard<'a> {
    fn drop(&mut self) {
        self.gate.release();
    }
}

/// 게이트 개방 전까지 `Poll::Pending`을 명시적으로 반환하는 제어형 프로브 퓨처.
struct HeldProbe {
    gate: Arc<Gate>,
    ctx: QuickContext,
    target: SocketAddr,
    cancel: Arc<AtomicBool>,
}

impl Future for HeldProbe {
    type Output = Result<network_core::quick::QuickResult, Vec<String>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if !self.gate.open.load(Ordering::SeqCst) {
            *self.gate.waker.lock().unwrap() = Some(cx.waker().clone());
            if !self.gate.open.load(Ordering::SeqCst) {
                self.gate.entered.store(true, Ordering::SeqCst);
                return Poll::Pending;
            }
        }
        Poll::Ready(tcp_to_quick_result(
            &self.ctx,
            &tcp_measurement(self.target, self.cancel.load(Ordering::SeqCst)),
        ))
    }
}

/// 테스트용 TCP 측정 결과 DTO를 생성합니다.
fn tcp_measurement(target: SocketAddr, cancelled: bool) -> TcpMeasurement {
    TcpMeasurement {
        target: target.to_string(),
        outcome: if cancelled { "CANCELLED" } else { "CONNECTED" }.into(),
        local_address: if cancelled {
            None
        } else {
            Some("127.0.0.1:32123".into())
        },
        elapsed_ms: 7,
        error_code: None,
        error_message: None,
        application_bytes_sent: 0,
        limitations: vec!["합성 raw 보존 자료".into()],
    }
}

/// 테스트용 순수 메모리 프로브 백엔드.
#[derive(Default)]
struct TestMemoryBackend {
    tcp_calls: AtomicUsize,
    gate: Option<Arc<Gate>>,
    cancel_observed: Mutex<Option<Arc<AtomicBool>>>,
}

impl QuickProbeBackend for TestMemoryBackend {
    fn tcp<'a>(
        &'a self,
        ctx: QuickContext,
        target: SocketAddr,
        _: Duration,
        cancel: Arc<AtomicBool>,
    ) -> ProbeFuture<'a> {
        self.tcp_calls.fetch_add(1, Ordering::SeqCst);
        *self.cancel_observed.lock().unwrap() = Some(Arc::clone(&cancel));
        if let Some(gate) = &self.gate {
            Box::pin(HeldProbe {
                gate: Arc::clone(gate),
                ctx,
                target,
                cancel,
            })
        } else {
            Box::pin(async move {
                tcp_to_quick_result(
                    &ctx,
                    &tcp_measurement(target, cancel.load(Ordering::SeqCst)),
                )
            })
        }
    }

    fn icmp<'a>(
        &'a self,
        _: QuickContext,
        _: IpAddr,
        _: Duration,
        _: Arc<AtomicBool>,
    ) -> ProbeFuture<'a> {
        Box::pin(async { Err(vec!["미선택 mock ICMP 호출".into()]) })
    }

    fn host<'a>(&'a self, ctx: QuickContext, _: IpAddr, _: Arc<AtomicBool>) -> ProbeFuture<'a> {
        let raw = HostSnapshot {
            adapters: serde_json::json!([]),
            routes: serde_json::json!([]),
            selected_route: serde_json::Value::Null,
            errors: vec![],
            limitations: vec![],
        };
        Box::pin(async move {
            network_core::measurements::host_to_quick_result(&ctx, &raw, Some(9))
        })
    }
}

/// 패닉을 의도적으로 유발하는 고장 시뮬레이션 백엔드.
struct PanickingBackend;

impl QuickProbeBackend for PanickingBackend {
    fn tcp<'a>(
        &'a self,
        _: QuickContext,
        _: SocketAddr,
        _: Duration,
        _: Arc<AtomicBool>,
    ) -> ProbeFuture<'a> {
        Box::pin(async {
            panic!("의도된 테스트 워커 패닉");
        })
    }

    fn icmp<'a>(
        &'a self,
        _: QuickContext,
        _: IpAddr,
        _: Duration,
        _: Arc<AtomicBool>,
    ) -> ProbeFuture<'a> {
        Box::pin(async { Err(vec!["미호출".into()]) })
    }

    fn host<'a>(&'a self, _: QuickContext, _: IpAddr, _: Arc<AtomicBool>) -> ProbeFuture<'a> {
        Box::pin(async { Err(vec!["미호출".into()]) })
    }
}

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

/// 유효한 대상과 옵션으로 계획 확인이 완료된 프레젠터를 생성합니다.
fn valid_presenter() -> GuiPresenter {
    let mut p = GuiPresenter::new();
    p.append_targets("127.0.0.1:80").unwrap();
    p.update_draft_options("1234", "1", vec![QuickFeature::TcpConnect]);
    p.confirm_plan().unwrap();
    p
}

#[test]
fn test_dispatch_launcher_exact_single_argument() {
    let counter = AtomicUsize::new(0);
    let mut stderr = Vec::new();
    let args = vec![OsString::from(GUI_RUN_SELECTOR)];

    let result = dispatch_launcher(&args, &mut stderr, true, || {
        counter.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });

    assert_eq!(result, Some(0));
    assert!(stderr.is_empty());
    assert_eq!(counter.load(Ordering::SeqCst), 1);
}

#[test]
fn test_dispatch_launcher_not_selected() {
    let counter = AtomicUsize::new(0);
    let mut stderr = Vec::new();

    // 1. 빈 인자 (noargs) -> None, launcher 호출 0
    let res = dispatch_launcher(&[], &mut stderr, true, || {
        counter.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    assert_eq!(res, None);
    assert_eq!(counter.load(Ordering::SeqCst), 0);

    // 2. --help -> None, launcher 호출 0
    let help_args = vec![OsString::from("--help")];
    let res = dispatch_launcher(&help_args, &mut stderr, true, || {
        counter.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    assert_eq!(res, None);
    assert_eq!(counter.load(Ordering::SeqCst), 0);

    // 3. 입력 전용 셀렉터 (--dev-gui-inputs-v1) -> None, launcher 호출 0
    let inputs_args = vec![OsString::from(crate::gui_entry::GUI_INPUTS_SELECTOR)];
    let res = dispatch_launcher(&inputs_args, &mut stderr, true, || {
        counter.fetch_add(1, Ordering::SeqCst);
        Ok(())
    });
    assert_eq!(res, None);
    assert_eq!(counter.load(Ordering::SeqCst), 0);

    // 4. worker 플래그 -> None, launcher 호출 0
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

    // 5. dev-tcp 플래그 -> None, launcher 호출 0
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

    // 6. 알 수 없는 플래그 -> None, launcher 호출 0
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

    // 1. 셀렉터 뒤에 초과 인자가 있는 경우 (arity 2) -> Some(2), launcher 호출 0, stderr에 INVALID_STDERR
    let mut stderr = Vec::new();
    let args_two = vec![
        OsString::from(GUI_RUN_SELECTOR),
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
        OsString::from(GUI_RUN_SELECTOR),
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
    let args = vec![OsString::from(GUI_RUN_SELECTOR)];

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
    let args = vec![OsString::from(GUI_RUN_SELECTOR)];
    let res = dispatch_launcher(&args, &mut stderr, true, || {
        counter.fetch_add(1, Ordering::SeqCst);
        Err(())
    });
    assert_eq!(res, Some(1));
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    assert_eq!(String::from_utf8_lossy(&stderr), GUI_RUNTIME_ERROR_STDERR);

    // 2. 런처 내부 panic 발생 시 -> catch_unwind로 방어, Some(1) 및 GUI_RUNTIME_ERROR_STDERR (패닉 원문 반사 없음)
    let mut stderr_panic = Vec::new();
    let res_panic = dispatch_launcher(&args, &mut stderr_panic, true, || {
        counter.fetch_add(1, Ordering::SeqCst);
        panic!("테스트용 의도적 GUI 실행 패닉 페이로드");
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
    let args_invalid = vec![OsString::from(GUI_RUN_SELECTOR), OsString::from("extra")];

    // 1. arity 오류 시 stderr 쓰기 실패 -> exit 1
    let mut fail_stderr = FailWriter;
    let res = dispatch_launcher(&args_invalid, &mut fail_stderr, true, || Ok(()));
    assert_eq!(res, Some(1));

    // 2. arity 오류 시 stderr 플러시 실패 -> exit 1
    let mut fail_flush_stderr = FailFlushWriter::new();
    let res = dispatch_launcher(&args_invalid, &mut fail_flush_stderr, true, || Ok(()));
    assert_eq!(res, Some(1));
}

#[test]
fn test_launch_run_gui_spawn_failure() {
    let session = GuiRunSession::new(valid_presenter());
    let spawner = |_job| Err(std::io::Error::other("테스트용 UI 스레드 spawn 실패"));

    let exit = launch_run_gui_with_spawner(session, |_slot| Ok(()), spawner);

    // 스레드 spawn 실패 시 failed = true 및 caller 슬롯의 원 session 보존
    assert!(exit.failed);
    let s = exit.session.expect("spawn 실패 시에도 원 세션 보존");
    assert_eq!(s.shutdown_state(), SessionShutdown::Closed);
}

#[test]
fn test_launch_run_gui_normal_completion() {
    let session = GuiRunSession::new(valid_presenter());
    let backend = Arc::new(TestMemoryBackend::default());

    let exit = launch_run_gui_with(session, move |slot| {
        let mut guard = slot.lock().unwrap();
        let sess = guard.as_mut().unwrap();
        let b = Arc::clone(&backend);
        sess.try_start_with(|| GuiRunCoordinator::spawn(b)).unwrap();
        until(|| {
            sess.poll();
            sess.presenter().state().phase() == RunPhase::Finished
        });
        Ok(())
    });

    assert!(!exit.failed);
    let s = exit.session.expect("세션 보존");
    assert_eq!(s.shutdown_state(), SessionShutdown::Closed);
    assert!(s.completed_snapshot().is_some());
    assert!(s.presenter().state().last_result().is_some());
}

#[test]
fn test_launch_run_gui_ui_err_while_pending() {
    let gate = Arc::new(Gate::default());
    let backend = Arc::new(TestMemoryBackend {
        tcp_calls: AtomicUsize::new(0),
        gate: Some(Arc::clone(&gate)),
        cancel_observed: Mutex::new(None),
    });
    let session = GuiRunSession::new(valid_presenter());

    let gate_clone = Arc::clone(&gate);
    let exit = launch_run_gui_with(session, move |slot| {
        // gate release RAII는 start 전에 설치하여 UI 스레드 종료 시 게이트 개방 보장
        let _release_guard = ReleaseGuard { gate: &gate_clone };
        let mut guard = slot.lock().unwrap();
        let sess = guard.as_mut().unwrap();
        let b = Arc::clone(&backend);
        sess.try_start_with(|| GuiRunCoordinator::spawn(b)).unwrap();
        sess.poll();
        until(|| gate_clone.entered.load(Ordering::SeqCst));
        Err(())
    });

    assert!(exit.failed);
    let s = exit.session.expect("원 세션 회수");
    assert_eq!(s.shutdown_state(), SessionShutdown::Closed);
}

#[test]
fn test_launch_run_gui_ui_panic_while_pending() {
    let gate = Arc::new(Gate::default());
    let backend = Arc::new(TestMemoryBackend {
        tcp_calls: AtomicUsize::new(0),
        gate: Some(Arc::clone(&gate)),
        cancel_observed: Mutex::new(None),
    });
    let session = GuiRunSession::new(valid_presenter());

    let gate_clone = Arc::clone(&gate);
    let exit = launch_run_gui_with(session, move |slot| {
        // gate release RAII는 start 전에 설치하여 패닉 언와인드 시 게이트 개방 보장
        let _release_guard = ReleaseGuard { gate: &gate_clone };
        let mut guard = slot.lock().unwrap();
        let sess = guard.as_mut().unwrap();
        let b = Arc::clone(&backend);
        sess.try_start_with(|| GuiRunCoordinator::spawn(b)).unwrap();
        sess.poll();
        until(|| gate_clone.entered.load(Ordering::SeqCst));
        panic!("고유 UI 패닉 마커: after-start Pending UI panic");
    });

    assert!(exit.failed);
    let s = exit.session.expect("원 세션 회수");
    assert_eq!(s.shutdown_state(), SessionShutdown::Closed);
}

#[test]
fn test_launch_run_gui_poison_recovery_on_panic_holding_lock() {
    let session = GuiRunSession::new(valid_presenter());

    let exit = launch_run_gui_with(session, |slot| {
        let _guard = slot.lock().unwrap();
        panic!("락을 쥔 채 패닉하여 슬롯 poison 발생 유도");
    });

    assert!(exit.failed);
    let s = exit.session.expect("poison recovery를 통한 원 세션 회수");
    assert_eq!(s.shutdown_state(), SessionShutdown::Closed);
}

#[test]
fn test_launch_run_gui_ui_takes_session_abnormally() {
    let session = GuiRunSession::new(valid_presenter());

    let exit = launch_run_gui_with(session, |slot| {
        let mut guard = slot.lock().unwrap();
        let _stolen = guard.take();
        Ok(())
    });

    // 슬롯이 비어있으면 대체 세션을 발명하지 않고 None 및 failed = true
    assert!(exit.failed);
    assert!(exit.session.is_none());
}

#[test]
fn test_launch_run_gui_ui_begin_close_explicit() {
    let session = GuiRunSession::new(valid_presenter());

    let exit = launch_run_gui_with(session, |slot| {
        let mut guard = slot.lock().unwrap();
        let sess = guard.as_mut().unwrap();
        sess.begin_close().unwrap();
        Ok(())
    });

    assert!(!exit.failed);
    let s = exit.session.expect("세션 보존");
    assert_eq!(s.shutdown_state(), SessionShutdown::Closed);
}

#[test]
fn test_launch_run_gui_host_failure_panicking_backend() {
    let session = GuiRunSession::new(valid_presenter());

    let exit = launch_run_gui_with(session, |slot| {
        let mut guard = slot.lock().unwrap();
        let sess = guard.as_mut().unwrap();
        sess.try_start_with(|| GuiRunCoordinator::spawn(Arc::new(PanickingBackend))).unwrap();
        until(|| {
            sess.poll();
            matches!(
                sess.shutdown_state(),
                SessionShutdown::Failed | SessionShutdown::Closed
            )
        });
        Ok(())
    });

    assert!(exit.failed);
    let s = exit.session.expect("세션 보존");
    assert_eq!(s.shutdown_state(), SessionShutdown::Failed);
}
