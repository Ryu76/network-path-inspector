//! 소유한 숨김 창만 사용하는 명시 native 시험. clipboard/다른 앱/네트워크 접근0.

use super::*;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use windows_sys::Win32::UI::Input::KeyboardAndMouse::IsWindowEnabled;

/// 순수 인메모리 CPU 모의 프로브 백엔드 (소켓/DNS/OS I/O 0).
struct PureMockBackend {
    delay: Option<Duration>,
}

impl network_core::runner::QuickProbeBackend for PureMockBackend {
    fn tcp<'a>(
        &'a self,
        ctx: network_core::quick::QuickContext,
        target: std::net::SocketAddr,
        _timeout: Duration,
        cancel: Arc<AtomicBool>,
    ) -> network_core::runner::ProbeFuture<'a> {
        let delay = self.delay;
        Box::pin(async move {
            if let Some(d) = delay {
                let start = std::time::Instant::now();
                while start.elapsed() < d {
                    if cancel.load(Ordering::SeqCst) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
            let is_cancelled = cancel.load(Ordering::SeqCst);
            let status = if is_cancelled {
                network_core::quick::QuickStatus::SKIPPED
            } else {
                network_core::quick::QuickStatus::PASS
            };
            let outcome = if is_cancelled {
                "CANCELLED"
            } else {
                "CONNECTED"
            };
            let result = network_core::quick::QuickResult {
                schema_version: network_core::quick::QUICK_SCHEMA_VERSION.to_string(),
                product: network_core::quick::QUICK_PRODUCT_NAME.to_string(),
                session_id: ctx.session_id,
                timestamp_iso8601: ctx.timestamp_iso8601,
                source_host: ctx.source_host,
                target_host: ctx.target_host,
                resolved_ip: Some(target.ip().to_string()),
                target_port: ctx.target_port,
                feature: network_core::quick::QuickFeature::TcpConnect,
                status,
                elapsed_ms: Some(10),
                os_error_code: None,
                details: serde_json::json!({
                    "outcome": outcome,
                    "limitations": [],
                    "raw_measurement": {}
                }),
                evidence_level: network_core::quick::EvidenceLevel::OBSERVED,
            };
            Ok(result)
        })
    }

    fn icmp<'a>(
        &'a self,
        ctx: network_core::quick::QuickContext,
        target: std::net::IpAddr,
        _timeout: Duration,
        cancel: Arc<AtomicBool>,
    ) -> network_core::runner::ProbeFuture<'a> {
        Box::pin(async move {
            let is_cancelled = cancel.load(Ordering::SeqCst);
            let status = if is_cancelled {
                network_core::quick::QuickStatus::SKIPPED
            } else {
                network_core::quick::QuickStatus::PASS
            };
            let outcome = if is_cancelled { "CANCELLED" } else { "REPLIED" };
            let result = network_core::quick::QuickResult {
                schema_version: network_core::quick::QUICK_SCHEMA_VERSION.to_string(),
                product: network_core::quick::QUICK_PRODUCT_NAME.to_string(),
                session_id: ctx.session_id,
                timestamp_iso8601: ctx.timestamp_iso8601,
                source_host: ctx.source_host,
                target_host: ctx.target_host,
                resolved_ip: Some(target.to_string()),
                target_port: ctx.target_port,
                feature: network_core::quick::QuickFeature::IcmpPing,
                status,
                elapsed_ms: Some(5),
                os_error_code: None,
                details: serde_json::json!({
                    "outcome": outcome,
                    "limitations": [],
                    "raw_measurement": {}
                }),
                evidence_level: network_core::quick::EvidenceLevel::OBSERVED,
            };
            Ok(result)
        })
    }

    fn host<'a>(
        &'a self,
        _ctx: network_core::quick::QuickContext,
        _target: std::net::IpAddr,
        _cancel: Arc<AtomicBool>,
    ) -> network_core::runner::ProbeFuture<'a> {
        Box::pin(async move { Err(vec!["테스트 미사용".to_string()]) })
    }
}

struct TestWindow {
    guard: Option<WindowGuard>,
    observed: Rc<Observations>,
    slot: Option<crate::gui_run_entry::GuiSessionSlot>,
}

impl TestWindow {
    fn new() -> Self {
        let context = Box::new(Context::new());
        let observed = context.observations.clone();
        let guard = create_window(context).expect("소유 숨김 창 생성");
        Self {
            guard: Some(guard),
            observed,
            slot: None,
        }
    }

    fn new_run(slot: crate::gui_run_entry::GuiSessionSlot) -> Self {
        let context = Box::new(Context::new_run(slot.clone()));
        let observed = context.observations.clone();
        let guard = create_window(context).expect("소유 숨김 창 생성");
        Self {
            guard: Some(guard),
            observed,
            slot: Some(slot),
        }
    }

    fn set_mock_factory<F>(&self, factory: F)
    where
        F: FnMut() -> Result<
                crate::gui_coordinator::GuiRunCoordinator,
                crate::gui_run_session::SessionInitError,
            > + 'static,
    {
        *self.guard().context().mock_coordinator_factory.borrow_mut() = Some(Box::new(factory));
    }

    fn guard(&self) -> &WindowGuard {
        self.guard.as_ref().unwrap()
    }

    fn controls(&self) -> Controls {
        self.guard().context().controls.get()
    }

    fn notify(&self, index: usize, code: u32) {
        send(
            self.guard().hwnd(),
            WM_COMMAND,
            FIRST_ID + index + ((code as usize) << 16),
            self.controls().get(index) as LPARAM,
        );
        assert!(
            !self.guard().context().fatal.get(),
            "생산 WndProc 치명적 오류 없음"
        );
    }

    fn put(&self, index: usize, value: &str) {
        set_text(self.controls().get(index), value).unwrap();
        // WM_SETTEXT 주입 시험이다. multiline EDIT는 EN_CHANGE를 자동 송신하지 않을 수 있다.
        // 실제 clipboard 시험으로 주장하지 않고 동일 소유 HWND 알림을 명시 전달한다.
        self.notify(index, EN_CHANGE);
    }

    fn text(&self, index: usize) -> String {
        String::from_utf16(&read_text(self.controls().get(index), 65536).unwrap()).unwrap()
    }

    fn snapshot(&self) -> GuiPresenter {
        match &self.guard().context().model {
            GuiModel::Inputs(presenter) => presenter.borrow().clone(),
            GuiModel::Run(slot) => {
                let guard = slot.lock().unwrap();
                guard.as_ref().unwrap().presenter().clone()
            }
        }
    }

    fn tick_timer(&self) {
        let hwnd = self.guard().hwnd();
        if !hwnd.is_null() {
            send(hwnd, WM_TIMER, RUN_TIMER_ID, 0);
        }
    }

    fn finish(mut self) {
        let guard = self.guard.take().unwrap();
        let _ = guard.close();
        assert!(guard.hwnd().is_null());
        assert!(!guard.context().fatal.get());
        drop(guard);
        assert_eq!(self.observed.drops.get(), 1);
        assert_destroyed(&self.observed);
        assert_no_quit();
    }
}

// assertion panic으로 finish에 도달하지 못해도 WindowGuard Drop이 창과 자기 quit를 정리한다.
fn assert_destroyed(observed: &Observations) {
    for hwnd in observed
        .parents
        .borrow()
        .iter()
        .chain(observed.created.borrow().iter())
    {
        // 안전: 이미 관측한 자기 HWND의 생존 여부만 질의한다. 검색/다른 창 조작0.
        assert_eq!(unsafe { IsWindow(*hwnd) }, 0);
    }
}

fn assert_no_quit() {
    let mut message = MSG::default();
    // 안전: 현재 테스트 스레드의 quit 존재만 확인한다. 다른 메시지를 소비하지 않는다.
    assert_eq!(
        unsafe { PeekMessageW(&mut message, null_mut(), WM_QUIT, WM_QUIT, PM_NOREMOVE) },
        0
    );
}

#[test]
#[ignore = "부모 소유 Win32 창 명시 실행"]
fn test_native_controls_and_initial_labels() {
    let window = TestWindow::new();
    let labels = [
        (NOTICE, "입력·계획 확인 전용 / 네트워크 진단 미연결"),
        (GUIDE, "host:port 또는 [IPv6]:port (한 줄에 한 대상)"),
        (APPEND, "추가"),
        (REPLACE, "전체 교체"),
        (DELETE, "선택 삭제"),
        (PLAN, "계획 확인"),
        (CLOSE, "닫기"),
        (TCP, "TCP 연결"),
        (PING, "ICMP Ping"),
        (TRACE, "경로 추적"),
        (DNS, "DNS 조회"),
        (LOCAL, "로컬 정보"),
    ];
    for (i, expected) in labels {
        assert_eq!(window.text(i), expected);
    }
    for hwnd in window.controls().0 {
        // 안전: 소유 HWND만 확인한다.
        assert_ne!(unsafe { IsWindow(hwnd) }, 0);
    }
    for i in [TCP, PING] {
        assert_eq!(
            send(window.controls().get(i), BM_GETCHECK, 0, 0),
            BST_CHECKED as isize
        );
    }
    for i in [TRACE, DNS, LOCAL] {
        assert_eq!(send(window.controls().get(i), BM_GETCHECK, 0, 0), 0);
    }
    for i in [START, STOP, SAVE] {
        // 안전: 소유 disabled 컨트롤의 상태만 확인한다.
        assert_eq!(unsafe { IsWindowEnabled(window.controls().get(i)) }, 0);
    }
    assert_eq!(window.text(TIMEOUT), "3000");
    assert_eq!(window.text(CONCURRENCY), "4");
    assert_eq!(window.snapshot().state().targets().len(), 0);
    window.finish();
}

#[test]
#[ignore = "부모 소유 Win32 창 명시 실행"]
fn test_native_crud_and_plan_preview() {
    let window = TestWindow::new();
    window.put(INPUT, "127.0.0.1:080\r\nexample.com:443");
    window.notify(APPEND, BN_CLICKED);
    assert_eq!(send(window.controls().get(TARGETS), LB_GETCOUNT, 0, 0), 2);
    let expected =
        network_core::targets::parse_target_list("127.0.0.1:080\r\nexample.com:443").unwrap();
    assert_eq!(window.snapshot().state().targets(), expected);
    assert_eq!(window.text(INPUT), "");
    window.notify(PLAN, BN_CLICKED);
    let state = window.snapshot();
    assert_eq!(
        state.plan_preview(),
        Some(
            &network_core::targets::build_quick_plan(
                state.state().targets(),
                state.state().options()
            )
            .unwrap()
        )
    );
    assert!(
        window
            .text(PREVIEW)
            .contains("정규화 호스트: example.com, 포트: 443")
    );
    assert!(window.text(PREVIEW).contains("네트워크 진단 미연결"));
    send(window.controls().get(TARGETS), LB_SETCURSEL, 0, 0);
    window.notify(TARGETS, LBN_SELCHANGE);
    assert_eq!(window.snapshot().selected_index(), Some(0));
    window.notify(DELETE, BN_CLICKED);
    assert_eq!(
        window.snapshot().state().targets()[0].raw_input,
        "example.com:443"
    );
    assert!(window.snapshot().is_plan_stale());
    window.put(INPUT, "[::1]:8080");
    window.notify(REPLACE, BN_CLICKED);
    assert_eq!(
        window.snapshot().state().targets(),
        network_core::targets::parse_target_list("[::1]:8080").unwrap()
    );
    assert_eq!(window.snapshot().selected_index(), None);
    window.notify(PLAN, BN_CLICKED);
    let before = window.snapshot().state().clone();
    window.notify(PLAN, BN_CLICKED);
    assert_eq!(window.snapshot().state(), &before); // preview는 ID·phase·결과를 소비하지 않는다.
    window.put(TIMEOUT, "4000");
    assert!(window.snapshot().is_plan_stale());
    assert!(window.text(PREVIEW).contains("다시 실행"));
    window.notify(PLAN, BN_CLICKED);
    assert_eq!(window.snapshot().state().options().tcp_timeout_ms, 4000);
    window.finish();
}

#[test]
#[ignore = "부모 소유 Win32 창 명시 실행"]
fn test_native_invalid_input_and_truncation_stale() {
    let window = TestWindow::new();
    window.put(INPUT, "127.0.0.1:80");
    window.notify(APPEND, BN_CLICKED);
    window.notify(PLAN, BN_CLICKED);
    let before = window.snapshot().state().clone();
    window.put(INPUT, "http://invalid-host:80");
    window.notify(APPEND, BN_CLICKED);
    assert_eq!(window.snapshot().state(), &before);
    assert!(!window.text(ERRORS).is_empty());
    window.put(INPUT, &"가".repeat(MAX_INPUT_BYTES / 3 + 1));
    window.notify(REPLACE, BN_CLICKED);
    assert_eq!(window.snapshot().state(), &before);
    // 각 입력란의 EN_MAXTEXT는 생산 경로에 전달한다. 내부 latch/presenter 직접 쓰기0.
    for index in [INPUT, TIMEOUT, CONCURRENCY] {
        window.put(index, "");
        window.put(index, if index == INPUT { "127.0.0.1:80" } else { "1" });
        window.notify(index, EN_MAXTEXT);
        let previous = window.snapshot();
        window.notify(PLAN, BN_CLICKED);
        window.notify(APPEND, BN_CLICKED);
        window.notify(REPLACE, BN_CLICKED);
        assert_eq!(window.snapshot().state(), previous.state());
        assert_eq!(window.snapshot().plan_preview(), previous.plan_preview());
        assert!(window.text(ERRORS).contains("잘렸습니다"));
        // 비어 있지 않은 접두부로 바꿔도 잘림 상태는 해제되지 않는다.
        window.put(index, if index == INPUT { "[::1]:80" } else { "2" });
        window.notify(PLAN, BN_CLICKED);
        assert_eq!(window.snapshot().state(), &before);
        window.put(index, "");
        window.put(
            index,
            if index == INPUT {
                ""
            } else if index == TIMEOUT {
                "3000"
            } else {
                "4"
            },
        );
    }
    // 잘못된 sender의 체크박스 알림은 상태를 전혀 바꾸지 않는다.
    let previous = window.snapshot();
    send(
        window.guard().hwnd(),
        WM_COMMAND,
        FIRST_ID + TCP,
        window.controls().get(APPEND) as LPARAM,
    );
    assert_eq!(window.snapshot(), previous);
    // native 옵션 읽기에도 손실 변환이 없다. surrogate 주입은 문자열 API 시험이며 clipboard아님.
    let raw = [0xd800u16, 0];
    assert_ne!(
        unsafe { SetWindowTextW(window.controls().get(TIMEOUT), raw.as_ptr()) },
        0
    );
    window.notify(TIMEOUT, EN_CHANGE);
    window.notify(PLAN, BN_CLICKED);
    assert_eq!(window.snapshot().state(), &before);
    assert!(!window.text(ERRORS).is_empty());
    assert_eq!(unsafe { IsWindowEnabled(window.controls().get(START)) }, 0);
    window.finish();
}

#[test]
#[ignore = "부모 소유 Win32 창 명시 실행"]
fn test_native_lifecycle_and_creation_failure_drop() {
    assert_no_quit();
    for _ in 0..3 {
        let window = TestWindow::new();
        window.notify(CLOSE, BN_CLICKED); // 실제 생산 close→NCDESTROY→live무효화
        assert!(window.guard().hwnd().is_null());
        window.finish();
    }
    let mut context = Box::new(Context::new());
    let observed = context.observations.clone();
    context.fail_child_at = Some(3); // 세 자식 실제 생성 뒤 잘못된 클래스의 실제 CreateWindowEx 실패
    assert!(create_window(context).is_err());
    assert_eq!(observed.created.borrow().len(), 3);
    assert_eq!(observed.parents.borrow().len(), 1);
    assert_eq!(observed.failures.get(), 1);
    assert_eq!(observed.drops.get(), 1);
    assert_destroyed(&observed);
    assert_eq!(observed.quit_removed.get(), 1);
    assert_no_quit();
    // assertion unwind에서도 가드가 정리되는 동일 경로를 검증한다.
    let observed = Rc::new(Observations::default());
    let observed_in = observed.clone();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let mut context = Box::new(Context::new());
        context.observations = observed_in;
        let _guard = create_window(context).unwrap();
        panic!("소유 창 시험의 의도적 unwind");
    }));
    assert!(result.is_err());
    assert_eq!(observed.drops.get(), 1);
    assert_destroyed(&observed);
    assert_no_quit();
}

#[test]
#[ignore = "부모 소유 Win32 창 명시 실행"]
fn test_native_run_mode_initial_controls_and_labels() {
    let session = GuiRunSession::new(GuiPresenter::new());
    let slot = Arc::new(Mutex::new(Some(session)));
    let window = TestWindow::new_run(slot);

    assert_eq!(
        window.text(NOTICE),
        "진단 실행 화면 / [검사 시작]으로 네트워크 진단 수행"
    );
    assert_eq!(
        window.text(GUIDE),
        "host:port 또는 [IPv6]:port (한 줄에 한 대상)"
    );
    assert_eq!(window.text(START), "검사 시작");
    assert_eq!(window.text(STOP), "중지");
    assert_eq!(window.text(SAVE), "저장 (미연결)");
    assert_eq!(window.text(CLOSE), "닫기");

    assert_eq!(unsafe { IsWindowEnabled(window.controls().get(START)) }, 1);
    assert_eq!(unsafe { IsWindowEnabled(window.controls().get(STOP)) }, 0);
    assert_eq!(unsafe { IsWindowEnabled(window.controls().get(SAVE)) }, 0);
    assert_eq!(unsafe { IsWindowEnabled(window.controls().get(CLOSE)) }, 1);

    window.finish();
}

#[test]
#[ignore = "부모 소유 Win32 창 명시 실행"]
fn test_native_run_start_and_poll_result_snapshot_render() {
    let session = GuiRunSession::new(GuiPresenter::new());
    let slot = Arc::new(Mutex::new(Some(session)));
    let window = TestWindow::new_run(slot.clone());

    let factory_called = Arc::new(AtomicUsize::new(0));
    let factory_called_clone = factory_called.clone();
    window.set_mock_factory(move || {
        factory_called_clone.fetch_add(1, Ordering::SeqCst);
        let backend = Arc::new(PureMockBackend { delay: None });
        crate::gui_coordinator::GuiRunCoordinator::spawn(backend)
            .map_err(|_| crate::gui_run_session::SessionInitError::HostSpawnFailed)
    });

    window.put(INPUT, "127.0.0.1:80");
    window.notify(APPEND, BN_CLICKED);
    assert_eq!(send(window.controls().get(TARGETS), LB_GETCOUNT, 0, 0), 1);

    window.notify(START, BN_CLICKED);
    assert_eq!(factory_called.load(Ordering::SeqCst), 1);

    for _ in 0..10 {
        std::thread::sleep(Duration::from_millis(15));
        window.tick_timer();
    }

    let preview = window.text(PREVIEW);
    assert!(
        preview.contains("=== Network Quick Check 진단 결과 요약 ==="),
        "결과 화면에 요약 헤더가 표시되어야 합니다."
    );
    assert!(
        preview.contains("127.0.0.1"),
        "결과 화면에 대상 주소가 표시되어야 합니다."
    );

    {
        let guard = slot.lock().unwrap();
        let s = guard.as_ref().unwrap();
        assert!(s.completed_snapshot().is_some());
        assert!(s.presenter().state().last_result().is_some());
    }

    window.finish();
}

#[test]
#[ignore = "부모 소유 Win32 창 명시 실행"]
fn test_native_run_stop_request_cancel() {
    let session = GuiRunSession::new(GuiPresenter::new());
    let slot = Arc::new(Mutex::new(Some(session)));
    let window = TestWindow::new_run(slot.clone());

    window.set_mock_factory(|| {
        let backend = Arc::new(PureMockBackend {
            delay: Some(Duration::from_millis(500)),
        });
        crate::gui_coordinator::GuiRunCoordinator::spawn(backend)
            .map_err(|_| crate::gui_run_session::SessionInitError::HostSpawnFailed)
    });

    window.put(INPUT, "127.0.0.1:80");
    window.notify(APPEND, BN_CLICKED);

    window.notify(START, BN_CLICKED);
    window.notify(STOP, BN_CLICKED);

    {
        let guard = slot.lock().unwrap();
        let s = guard.as_ref().unwrap();
        let phase = s.presenter().state().phase();
        assert!(
            matches!(phase, RunPhase::Cancelling | RunPhase::Finished),
            "취소 요청 후 phase는 Cancelling 또는 Finished여야 합니다."
        );
    }

    window.finish();
}

#[test]
#[ignore = "부모 소유 Win32 창 명시 실행"]
fn test_native_run_close_pending_then_drain_shutdown() {
    let session = GuiRunSession::new(GuiPresenter::new());
    let slot = Arc::new(Mutex::new(Some(session)));
    let window = TestWindow::new_run(slot.clone());

    window.set_mock_factory(|| {
        let backend = Arc::new(PureMockBackend {
            delay: Some(Duration::from_millis(100)),
        });
        crate::gui_coordinator::GuiRunCoordinator::spawn(backend)
            .map_err(|_| crate::gui_run_session::SessionInitError::HostSpawnFailed)
    });

    window.put(INPUT, "127.0.0.1:80");
    window.notify(APPEND, BN_CLICKED);

    window.notify(START, BN_CLICKED);
    window.notify(CLOSE, BN_CLICKED);

    {
        let guard = slot.lock().unwrap();
        let s = guard.as_ref().unwrap();
        assert!(s.is_close_requested());
    }

    for _ in 0..20 {
        if window.guard().hwnd().is_null() {
            break;
        }
        std::thread::sleep(Duration::from_millis(15));
        window.tick_timer();
    }

    assert!(window.guard().hwnd().is_null());
    window.finish();
}

#[test]
#[ignore = "부모 소유 Win32 창 명시 실행"]
fn test_native_run_unapplied_input_and_truncation_rejection() {
    let session = GuiRunSession::new(GuiPresenter::new());
    let slot = Arc::new(Mutex::new(Some(session)));
    let window = TestWindow::new_run(slot);

    let factory_called = Arc::new(AtomicUsize::new(0));
    let factory_called_clone = factory_called.clone();
    window.set_mock_factory(move || {
        factory_called_clone.fetch_add(1, Ordering::SeqCst);
        let backend = Arc::new(PureMockBackend { delay: None });
        crate::gui_coordinator::GuiRunCoordinator::spawn(backend)
            .map_err(|_| crate::gui_run_session::SessionInitError::HostSpawnFailed)
    });

    window.put(INPUT, "127.0.0.1:80");
    window.notify(START, BN_CLICKED);

    assert_eq!(
        factory_called.load(Ordering::SeqCst),
        0,
        "미추가 텍스트가 있을 때는 Start가 거부되어 factory가 호출되지 않아야 합니다."
    );
    assert!(window.text(ERRORS).contains("아직 추가되지 않은 대상"));

    window.notify(APPEND, BN_CLICKED);
    assert_eq!(window.text(INPUT), "");

    window.notify(INPUT, EN_MAXTEXT);
    window.notify(START, BN_CLICKED);

    assert_eq!(
        factory_called.load(Ordering::SeqCst),
        0,
        "Truncation 상태에서는 Start가 거부되어 factory가 호출되지 않아야 합니다."
    );
    assert!(window.text(ERRORS).contains("잘렸습니다"));

    window.finish();
}

#[test]
#[ignore = "부모 소유 Win32 창 명시 실행"]
fn test_native_run_invalid_sender_and_disabled_command_safety() {
    let session = GuiRunSession::new(GuiPresenter::new());
    let slot = Arc::new(Mutex::new(Some(session)));
    let window = TestWindow::new_run(slot);

    let factory_called = Arc::new(AtomicUsize::new(0));
    let factory_called_clone = factory_called.clone();
    window.set_mock_factory(move || {
        factory_called_clone.fetch_add(1, Ordering::SeqCst);
        let backend = Arc::new(PureMockBackend { delay: None });
        crate::gui_coordinator::GuiRunCoordinator::spawn(backend)
            .map_err(|_| crate::gui_run_session::SessionInitError::HostSpawnFailed)
    });

    send(
        window.guard().hwnd(),
        WM_COMMAND,
        FIRST_ID + START,
        window.controls().get(APPEND) as LPARAM,
    );
    assert_eq!(factory_called.load(Ordering::SeqCst), 0);

    send(
        window.guard().hwnd(),
        WM_COMMAND,
        FIRST_ID + TCP,
        window.controls().get(INPUT) as LPARAM,
    );
    assert_eq!(
        send(window.controls().get(TCP), BM_GETCHECK, 0, 0),
        BST_CHECKED as isize
    );

    window.finish();
}

#[test]
#[ignore = "부모 소유 Win32 창 명시 실행"]
fn test_native_run_hidden_fixture_missing_fails_without_native_call() {
    let session = GuiRunSession::new(GuiPresenter::new());
    let slot = Arc::new(Mutex::new(Some(session)));
    let window = TestWindow::new_run(slot);

    window.put(INPUT, "127.0.0.1:80");
    window.notify(APPEND, BN_CLICKED);

    window.notify(START, BN_CLICKED);
    assert!(window.text(ERRORS).contains("프로브 백엔드"));

    window.finish();
}

#[test]
#[ignore = "부모 소유 Win32 창 명시 실행"]
fn test_native_run_timer_failure_and_partial_creation_drop() {
    assert_no_quit();

    let session = GuiRunSession::new(GuiPresenter::new());
    let slot = Arc::new(Mutex::new(Some(session)));
    let mut context = Box::new(Context::new_run(slot.clone()));
    let observed = context.observations.clone();
    context.fail_timer.set(true);

    assert!(create_window(context).is_err());
    assert_eq!(observed.drops.get(), 1);
    assert_destroyed(&observed);
    assert_no_quit();

    let session2 = GuiRunSession::new(GuiPresenter::new());
    let slot2 = Arc::new(Mutex::new(Some(session2)));
    let mut context2 = Box::new(Context::new_run(slot2));
    let observed2 = context2.observations.clone();
    context2.fail_child_at = Some(4);

    assert!(create_window(context2).is_err());
    assert_eq!(observed2.created.borrow().len(), 4);
    assert_eq!(observed2.failures.get(), 1);
    assert_eq!(observed2.drops.get(), 1);
    assert_destroyed(&observed2);
    assert_no_quit();
}
