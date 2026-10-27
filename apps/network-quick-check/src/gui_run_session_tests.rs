//! GUI 실행 세션(`GuiRunSession`) 단위 테스트 모듈.
//!
//! 실제 코어 러너(`run_quick`), 순수 프레젠터(`GuiPresenter`), 실제 코디네이터(`GuiRunCoordinator`)와
//! 인메모리 프로브 백엔드를 결합하여 단일 소유 세션과 typed 실행 브리지의 동작을 엄격히 검증합니다.
//! 실제 소켓, DNS, 헬퍼 프로세스, Win32 API, 환경 변수 등 외부 I/O는 일체 사용하지 않습니다.

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

/// 명시적 술어가 참이 될 때까지 스레드를 양보하며 대기하는 동기화 헬퍼.
/// 고정 시간 수면(fixed sleep)이나 고정 yield 횟수 대신 5초 상한의 타임아웃을 사용합니다.
fn until(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(
            Instant::now() < deadline,
            "명시적 동기화 및 상태 관측 타임아웃"
        );
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

/// 패닉이나 언와인드(unwind) 발생 시에도 게이트가 반드시 열리도록 보장하는 RAII 가드.
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
    icmp_calls: AtomicUsize,
    host_calls: AtomicUsize,
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
        self.icmp_calls.fetch_add(1, Ordering::SeqCst);
        Box::pin(async { Err(vec!["미선택 mock ICMP 호출".into()]) })
    }

    fn host<'a>(&'a self, ctx: QuickContext, _: IpAddr, _: Arc<AtomicBool>) -> ProbeFuture<'a> {
        self.host_calls.fetch_add(1, Ordering::SeqCst);
        let raw = HostSnapshot {
            adapters: serde_json::json!([{"name": "모의NIC", "v": [null, "null", "\u{0}", "\\u0000"]}]),
            routes: serde_json::json!([]),
            selected_route: serde_json::Value::Null,
            errors: vec!["합성 경고 보존 자료".into()],
            limitations: vec!["합성 제한 보존 자료".into()],
        };
        Box::pin(
            async move { network_core::measurements::host_to_quick_result(&ctx, &raw, Some(9)) },
        )
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

/// 유효한 대상과 옵션으로 계획 확인이 완료된 프레젠터를 생성합니다.
fn valid_presenter() -> GuiPresenter {
    let mut p = GuiPresenter::new();
    p.append_targets("127.0.0.1:080").unwrap();
    p.update_draft_options("1234", "1", vec![QuickFeature::TcpConnect]);
    p.confirm_plan().unwrap();
    p
}

/// 시작 전 설치되는 시험 소유자. unwind에서도 같은 session을 release/close/poll한다.
struct Fixture {
    session: GuiRunSession,
    releases: Vec<Arc<Gate>>,
    cleaned: Arc<AtomicBool>,
}
impl Fixture {
    fn new(presenter: GuiPresenter, releases: Vec<Arc<Gate>>) -> Self {
        Self {
            session: GuiRunSession::new(presenter),
            releases,
            cleaned: Arc::new(AtomicBool::new(false)),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for gate in &self.releases {
            gate.release();
        }
        let _ = self.session.begin_close();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            self.session.poll();
            let complete = matches!(
                self.session.shutdown_state(),
                SessionShutdown::Closed | SessionShutdown::Failed
            );
            if complete || Instant::now() >= deadline {
                self.cleaned.store(complete, Ordering::SeqCst);
                if !complete && !std::thread::panicking() {
                    panic!("시험 session 실제 worker/channel 정리 미완료");
                }
                break;
            }
            std::thread::yield_now();
        }
    }
}
fn assert_locked(session: &mut GuiRunSession, error: SessionError) {
    let before = session.presenter().clone();
    let snapshot = session.completed_snapshot().cloned();
    assert_eq!(session.append_targets("127.0.0.1:81"), Err(error.clone()));
    assert_eq!(session.presenter(), &before);
    assert_eq!(session.replace_targets("[::1]:81"), Err(error.clone()));
    assert_eq!(session.presenter(), &before);
    assert_eq!(session.remove_selected(), Err(error.clone()));
    assert_eq!(session.presenter(), &before);
    assert_eq!(session.set_selected_index(Some(0)), Err(error.clone()));
    assert_eq!(session.presenter(), &before);
    assert_eq!(
        session.update_draft_utf16(&[48], &[49], vec![QuickFeature::TcpConnect]),
        Err(error.clone())
    );
    assert_eq!(session.presenter(), &before);
    assert_eq!(
        session.update_draft_options("1000", "1", vec![QuickFeature::TcpConnect]),
        Err(error.clone())
    );
    assert_eq!(session.presenter(), &before);
    assert_eq!(session.confirm_plan(), Err(error.clone()));
    assert_eq!(session.presenter(), &before);
    assert_eq!(
        session.try_start_with(|| panic!("차단된 시작 factory 호출")),
        Err(error)
    );
    assert_eq!(session.presenter(), &before);
    assert_eq!(session.completed_snapshot(), snapshot.as_ref());
}
/// worker만 소유한 backend의 Drop 패닉은 target task JoinError와 다른 바깥 unwind다.
struct DropFaultBackend {
    inner: TestMemoryBackend,
    gate: Arc<Gate>,
}
impl Drop for DropFaultBackend {
    fn drop(&mut self) {
        self.gate.entered.store(true, Ordering::SeqCst);
        until(|| self.gate.open.load(Ordering::SeqCst));
        panic!("의도된 worker backend Drop 패닉");
    }
}
impl QuickProbeBackend for DropFaultBackend {
    fn tcp<'a>(
        &'a self,
        c: QuickContext,
        t: SocketAddr,
        d: Duration,
        a: Arc<AtomicBool>,
    ) -> ProbeFuture<'a> {
        self.inner.tcp(c, t, d, a)
    }
    fn icmp<'a>(
        &'a self,
        c: QuickContext,
        t: IpAddr,
        d: Duration,
        a: Arc<AtomicBool>,
    ) -> ProbeFuture<'a> {
        self.inner.icmp(c, t, d, a)
    }
    fn host<'a>(&'a self, c: QuickContext, t: IpAddr, a: Arc<AtomicBool>) -> ProbeFuture<'a> {
        self.inner.host(c, t, a)
    }
}

#[test]
fn test_session_send_and_single_ownership() {
    fn assert_send<T: Send>() {}
    assert_send::<GuiRunSession>();

    let presenter = valid_presenter();
    let session = GuiRunSession::new(presenter);

    assert_eq!(session.presenter().state().targets().len(), 1);
    assert_eq!(
        session.presenter().state().targets()[0].raw_input,
        "127.0.0.1:080"
    );
    assert!(session.completed_snapshot().is_none());
    assert!(session.host_lifecycle().is_none());
    assert!(!session.is_close_requested());
    assert_eq!(session.shutdown_state(), SessionShutdown::NotRequested);
}

#[test]
fn test_pre_start_validation_rejects_without_factory_call_or_id_consumption() {
    for case in 0..4 {
        let p = if case == 0 {
            GuiPresenter::new()
        } else {
            valid_presenter()
        };
        let mut f = Fixture::new(p, vec![]);
        let session = &mut f.session;
        match case {
            1 => session
                .update_draft_options("3000ms", "1", vec![QuickFeature::TcpConnect])
                .unwrap(),
            2 => session
                .update_draft_options("1234", "parallel", vec![QuickFeature::TcpConnect])
                .unwrap(),
            3 => session.update_draft_options("1234", "1", vec![]).unwrap(),
            _ => {}
        }
        let before = session.presenter().clone();
        assert!(matches!(
            session.try_start_with(|| panic!("무효 후보 factory 호출")),
            Err(SessionError::Bridge(RunBridgeError::Presenter(_)))
        ));
        assert_eq!(session.presenter(), &before);
        assert!(session.host_lifecycle().is_none());
        if case == 0 {
            session.append_targets("127.0.0.1:080").unwrap();
        }
        session
            .update_draft_options("1234", "1", vec![QuickFeature::TcpConnect])
            .unwrap();
        let id = session
            .try_start_with(|| {
                GuiRunCoordinator::spawn(Arc::new(TestMemoryBackend::default()))
                    .map_err(|_| SessionInitError::HostSpawnFailed)
            })
            .unwrap();
        assert_eq!(id.as_u64(), 1, "거부했던 동일 session의 첫 성공 ID");
        until(|| session.poll() == PollOutcome::Applied(id));
    }
}

#[test]
fn test_factory_error_propagation_and_idempotent_retry() {
    let mut fixture = Fixture::new(valid_presenter(), vec![]);
    let session = &mut fixture.session;
    let call_count = Arc::new(AtomicUsize::new(0));

    let whole_before = session.presenter().clone();
    // 고정 오류 전파 시험이며 실제 OS thread 생성 실패 주입은 아니다.
    // 1. BackendUnavailable 오류 전파 확인
    let cc1 = Arc::clone(&call_count);
    let err1 = session.try_start_with(|| {
        cc1.fetch_add(1, Ordering::SeqCst);
        Err(SessionInitError::BackendUnavailable)
    });
    assert_eq!(
        err1,
        Err(SessionError::Init(SessionInitError::BackendUnavailable))
    );
    assert_eq!(call_count.load(Ordering::SeqCst), 1);
    assert!(session.host_lifecycle().is_none());
    assert!(session.presenter().state().active_run_id().is_none());

    // 2. HostSpawnFailed 오류 전파 확인
    let cc2 = Arc::clone(&call_count);
    let err2 = session.try_start_with(|| {
        cc2.fetch_add(1, Ordering::SeqCst);
        Err(SessionInitError::HostSpawnFailed)
    });
    assert_eq!(
        err2,
        Err(SessionError::Init(SessionInitError::HostSpawnFailed))
    );
    assert_eq!(call_count.load(Ordering::SeqCst), 2);
    assert!(session.host_lifecycle().is_none());

    assert_eq!(session.presenter(), &whole_before);
    // 3. 재시도 시 정상 생성 및 RunId(1) 소비 확인
    let cc3 = Arc::clone(&call_count);
    let run_id = session
        .try_start_with(|| {
            cc3.fetch_add(1, Ordering::SeqCst);
            GuiRunCoordinator::spawn(Arc::new(TestMemoryBackend::default()))
                .map_err(|_| SessionInitError::HostSpawnFailed)
        })
        .expect("재시도 정상 시작 성공");
    assert_eq!(run_id.as_u64(), 1);
    assert_eq!(call_count.load(Ordering::SeqCst), 3);
    assert_eq!(session.host_lifecycle(), Some(HostLifecycle::Accepting));

    until(|| matches!(session.poll(), PollOutcome::Applied(_)));
    session.begin_close().unwrap();
    until(|| session.poll() == PollOutcome::Closed);
}

#[test]
fn test_initial_start_factory_once_and_subsequent_start_host_reuse() {
    let mut fixture = Fixture::new(valid_presenter(), vec![]);
    let session = &mut fixture.session;
    let backend = Arc::new(TestMemoryBackend::default());
    let factory_count = Arc::new(AtomicUsize::new(0));

    // 첫 번째 시작: 팩토리 1회 호출
    let fc1 = Arc::clone(&factory_count);
    let b1 = Arc::clone(&backend);
    let id1 = session
        .try_start_with(|| {
            fc1.fetch_add(1, Ordering::SeqCst);
            GuiRunCoordinator::spawn(b1).map_err(|_| SessionInitError::HostSpawnFailed)
        })
        .expect("첫 번째 시작 성공");
    assert_eq!(id1.as_u64(), 1);
    assert_eq!(factory_count.load(Ordering::SeqCst), 1);

    until(|| matches!(session.poll(), PollOutcome::Applied(_)));
    assert_eq!(backend.tcp_calls.load(Ordering::SeqCst), 1);
    assert_eq!(backend.icmp_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.host_calls.load(Ordering::SeqCst), 0);

    assert_eq!(
        session.completed_snapshot().map(|s| s.run_id().as_u64()),
        Some(1)
    );
    let first_report = session
        .presenter()
        .state()
        .last_result()
        .expect("결과 존재")
        .as_ref()
        .expect("정상 결과")
        .clone();
    assert_eq!(first_report.results[0].session_id, "gui-run-1");

    // 두 번째 시작: 기존 호스트 재사용 (팩토리 호출 횟수 불변)
    let fc2 = Arc::clone(&factory_count);
    let b2 = Arc::clone(&backend);
    let id2 = session
        .try_start_with(|| {
            fc2.fetch_add(1, Ordering::SeqCst);
            GuiRunCoordinator::spawn(b2).map_err(|_| SessionInitError::HostSpawnFailed)
        })
        .expect("두 번째 시작 성공");
    assert_eq!(id2.as_u64(), 2);
    assert_eq!(factory_count.load(Ordering::SeqCst), 1);

    until(|| matches!(session.poll(), PollOutcome::Applied(_)));
    assert_eq!(backend.tcp_calls.load(Ordering::SeqCst), 2);
    assert_eq!(
        session.completed_snapshot().map(|s| s.run_id().as_u64()),
        Some(2)
    );
    let second_report = session
        .presenter()
        .state()
        .last_result()
        .expect("결과 존재")
        .as_ref()
        .expect("정상 결과")
        .clone();
    assert_eq!(second_report.results[0].session_id, "gui-run-2");

    session.begin_close().unwrap();
    until(|| session.poll() == PollOutcome::Closed);
}

#[test]
fn test_failed_start_preserves_previous_report_and_snapshot() {
    let mut fixture = Fixture::new(valid_presenter(), vec![]);
    let session = &mut fixture.session;
    let backend = Arc::new(TestMemoryBackend::default());

    let id1 = session
        .try_start_with(|| {
            GuiRunCoordinator::spawn(backend).map_err(|_| SessionInitError::HostSpawnFailed)
        })
        .expect("첫 시작 성공");
    assert_eq!(id1.as_u64(), 1);

    until(|| matches!(session.poll(), PollOutcome::Applied(_)));
    let snap1 = session.completed_snapshot().cloned().expect("스냅샷 존재");
    assert_eq!(snap1.run_id().as_u64(), 1);

    // 무효한 옵션으로 draft 갱신 후 시작 시도
    session
        .update_draft_options("invalid-timeout", "1", vec![QuickFeature::TcpConnect])
        .unwrap();
    let whole_before = session.presenter().clone();
    let res = session.try_start_with(|| {
        panic!("팩토리가 호출되어서는 안 됩니다.");
    });
    assert!(matches!(
        res,
        Err(SessionError::Bridge(RunBridgeError::Presenter(_)))
    ));

    // 직전 성공한 스냅샷 및 보고서의 완전한 보존 검증
    assert_eq!(
        session.completed_snapshot().map(|s| s.run_id().as_u64()),
        Some(1)
    );
    let report = session
        .presenter()
        .state()
        .last_result()
        .unwrap()
        .as_ref()
        .unwrap();
    assert_eq!(report.results[0].session_id, "gui-run-1");
    assert_eq!(session.presenter(), &whole_before);
    assert_eq!(session.completed_snapshot(), Some(&snap1));
    session
        .update_draft_options("2222", "1", vec![QuickFeature::TcpConnect])
        .unwrap();
    let next = session
        .try_start_with(|| panic!("기존 host 재사용 factory 호출"))
        .unwrap();
    assert_eq!(next.as_u64(), 2);
    until(|| session.poll() == PollOutcome::Applied(next));
    session.begin_close().unwrap();
    until(|| session.poll() == PollOutcome::Closed);
}

#[test]
fn test_async_pending_cancel_handshake_and_raii_clean_shutdown() {
    let gate = Arc::new(Gate::default());
    let guard = ReleaseGuard { gate: &gate };
    let backend = Arc::new(TestMemoryBackend {
        gate: Some(Arc::clone(&gate)),
        ..Default::default()
    });

    let mut fixture = Fixture::new(valid_presenter(), vec![gate.clone()]);
    let session = &mut fixture.session;
    let b = Arc::clone(&backend);
    let run_id = session
        .try_start_with(|| {
            GuiRunCoordinator::spawn(b).map_err(|_| SessionInitError::HostSpawnFailed)
        })
        .expect("시작 성공");
    assert_eq!(run_id.as_u64(), 1);

    // 첫 폴링은 게이트 대기 중이므로 Idle
    assert_eq!(session.poll(), PollOutcome::Idle);

    // 비동기 핸드셰이크: 워커가 Pending 분기에 도달했음을 확인
    until(|| gate.entered.load(Ordering::SeqCst));

    let active_snapshot = session
        .presenter()
        .state()
        .active_snapshot()
        .unwrap()
        .clone();
    let received_cancel = backend.cancel_observed.lock().unwrap().clone().unwrap();
    assert!(!received_cancel.load(Ordering::SeqCst));
    // 취소 요청
    let cancel_res = session.request_cancel().expect("취소 요청 성공");
    assert_eq!(cancel_res, Some(run_id));
    assert_eq!(session.request_cancel(), Ok(None));
    assert_eq!(session.presenter().state().active_run_id(), Some(run_id));
    assert_eq!(session.presenter().state().phase(), RunPhase::Cancelling);
    assert!(received_cancel.load(Ordering::SeqCst));

    // 백엔드에서 관측된 취소 플래그가 true로 전환되었는지 확인
    until(|| {
        backend
            .cancel_observed
            .lock()
            .unwrap()
            .as_ref()
            .map(|a| a.load(Ordering::SeqCst))
            .unwrap_or(false)
    });

    // 게이트 개방 전: 미완료 상태 유지
    assert_eq!(session.poll(), PollOutcome::Idle);
    assert_eq!(session.shutdown_state(), SessionShutdown::NotRequested);

    // RAII 가드 해제 (게이트 개방)
    drop(guard);

    // 게이트 개방 후: 취소 보고서 수신 관측
    until(|| matches!(session.poll(), PollOutcome::Applied(_)));

    let report = session
        .presenter()
        .state()
        .last_result()
        .expect("결과 존재")
        .as_ref()
        .expect("보고서 유효");
    assert!(report.cancelled);
    assert_eq!(report.results[0].details["outcome"], "CANCELLED");

    assert_eq!(session.completed_snapshot(), Some(&active_snapshot));
    assert_eq!(
        report.results[0].details["raw_measurement"],
        serde_json::to_value(tcp_measurement("127.0.0.1:80".parse().unwrap(), true)).unwrap()
    );
    let report_before = report.clone();
    // 세션 닫기 요청 및 물리적 종료 관측
    session.begin_close().unwrap();
    assert_eq!(session.shutdown_state(), SessionShutdown::Pending);
    until(|| session.poll() == PollOutcome::Closed);
    assert_eq!(session.shutdown_state(), SessionShutdown::Closed);
    assert_eq!(
        session.presenter().state().last_result(),
        Some(&Ok(report_before))
    );
}

#[test]
fn test_editing_blocked_during_busy_closing_failed() {
    let gate = Arc::new(Gate::default());
    let guard = ReleaseGuard { gate: &gate };
    let backend = Arc::new(TestMemoryBackend {
        gate: Some(Arc::clone(&gate)),
        ..Default::default()
    });

    let mut fixture = Fixture::new(valid_presenter(), vec![gate.clone()]);
    let session = &mut fixture.session;
    let b = Arc::clone(&backend);
    session
        .try_start_with(|| {
            GuiRunCoordinator::spawn(b).map_err(|_| SessionInitError::HostSpawnFailed)
        })
        .unwrap();

    until(|| gate.entered.load(Ordering::SeqCst));

    assert_locked(session, SessionError::Busy);
    // 1. Running 상태에서 모든 편집 proxy 거부 확인
    assert_eq!(
        session.append_targets("127.0.0.1:81"),
        Err(SessionError::Busy)
    );
    assert_eq!(
        session.replace_targets("127.0.0.1:81"),
        Err(SessionError::Busy)
    );
    assert_eq!(session.remove_selected(), Err(SessionError::Busy));
    assert_eq!(session.set_selected_index(Some(0)), Err(SessionError::Busy));
    assert_eq!(
        session.update_draft_utf16(&[48], &[49], vec![QuickFeature::TcpConnect]),
        Err(SessionError::Busy)
    );
    assert_eq!(
        session.update_draft_options("1000", "1", vec![QuickFeature::TcpConnect]),
        Err(SessionError::Busy)
    );
    assert_eq!(session.confirm_plan(), Err(SessionError::Busy));

    // 2. Cancelling 상태에서 모든 편집 proxy 거부 확인
    session.request_cancel().unwrap();
    assert_locked(session, SessionError::Busy);
    assert_eq!(
        session.append_targets("127.0.0.1:81"),
        Err(SessionError::Busy)
    );

    // 게이트 해제 및 실행 완료 처리
    drop(guard);
    until(|| matches!(session.poll(), PollOutcome::Applied(_)));

    // 3. Closing 상태에서 모든 편집 proxy 거부 확인
    session.begin_close().unwrap();
    assert_locked(session, SessionError::Closing);
    assert_eq!(
        session.append_targets("127.0.0.1:81"),
        Err(SessionError::Closing)
    );
    assert_eq!(
        session.replace_targets("127.0.0.1:81"),
        Err(SessionError::Closing)
    );
    assert_eq!(session.remove_selected(), Err(SessionError::Closing));
    assert_eq!(
        session.set_selected_index(Some(0)),
        Err(SessionError::Closing)
    );
    assert_eq!(session.confirm_plan(), Err(SessionError::Closing));

    until(|| session.poll() == PollOutcome::Closed);
    assert_eq!(session.shutdown_state(), SessionShutdown::Closed);
    assert_locked(session, SessionError::Closing);
}

#[test]
fn test_idempotent_cancel_and_close_without_host() {
    let mut fixture = Fixture::new(valid_presenter(), vec![]);
    let session = &mut fixture.session;

    // 호스트 미생성 상태의 취소 및 폴링
    assert_eq!(session.request_cancel(), Ok(None));
    assert_eq!(session.poll(), PollOutcome::Idle);
    assert!(session.completed_snapshot().is_none());
    assert!(session.presenter().state().last_result().is_none());

    // 닫기 요청 시 즉시 Closed 전이 (진단 결과 없음)
    assert_eq!(session.begin_close(), Ok(()));
    assert_eq!(session.shutdown_state(), SessionShutdown::Closed);

    // 반복 호출의 멱등성 검증
    assert_eq!(session.begin_close(), Ok(()));
    assert_eq!(session.request_cancel(), Ok(None));
    assert_eq!(session.poll(), PollOutcome::Idle);
    assert!(session.completed_snapshot().is_none());
    assert!(session.presenter().state().last_result().is_none());
}

#[test]
fn test_host_failed_lifecycle_drains_without_auto_factory_replacement() {
    let gate = Arc::new(Gate::default());
    let mut f = Fixture::new(valid_presenter(), vec![gate.clone()]);
    let session = &mut f.session;
    let id = session
        .try_start_with(|| {
            GuiRunCoordinator::spawn(Arc::new(DropFaultBackend {
                inner: TestMemoryBackend::default(),
                gate: gate.clone(),
            }))
            .map_err(|_| SessionInitError::HostSpawnFailed)
        })
        .unwrap();
    until(|| session.poll() == PollOutcome::Applied(id));
    let before = session.presenter().clone();
    let snapshot = session.completed_snapshot().cloned();
    // 이 시험의 fault 준비만 기존 typed bridge로 host를 닫는다. session close latch 없는
    // Failed 상태를 구성하는 private-child fixture이며 제품 UI 경로의 증거는 아니다.
    let GuiRunSession {
        presenter, host, ..
    } = session;
    presenter.begin_run_close(host.as_mut().unwrap()).unwrap();
    until(|| gate.entered.load(Ordering::SeqCst));
    assert!(!session.is_close_requested());
    gate.release();
    until(|| session.poll() == PollOutcome::HostFailed);
    assert_eq!(session.host_lifecycle(), Some(HostLifecycle::Failed));
    assert_locked(session, SessionError::HostFailed);
    assert_eq!(session.presenter(), &before);
    assert_eq!(session.completed_snapshot(), snapshot.as_ref());
    assert_eq!(
        session.request_cancel(),
        Err(SessionError::Coordinator(CoordinatorError::HostFailed))
    );
    session.begin_close().unwrap();
    until(|| {
        session.poll();
        session.shutdown_state() == SessionShutdown::Failed
    });
    assert_eq!(session.presenter(), &before);
    assert_eq!(session.completed_snapshot(), snapshot.as_ref());
    assert_locked(session, SessionError::Closing);
}

#[test]
fn test_leading_zero_port_and_result_fidelity() {
    let mut fixture = Fixture::new(valid_presenter(), vec![]);
    let session = &mut fixture.session;
    let backend = Arc::new(TestMemoryBackend::default());

    session
        .try_start_with(|| {
            GuiRunCoordinator::spawn(backend).map_err(|_| SessionInitError::HostSpawnFailed)
        })
        .unwrap();

    until(|| matches!(session.poll(), PollOutcome::Applied(_)));

    let snapshot = session.completed_snapshot().expect("스냅샷 존재");
    assert_eq!(snapshot.request().session_id, "gui-run-1");
    assert_eq!(snapshot.request().targets[0].raw_input, "127.0.0.1:080");
    assert_eq!(snapshot.request().targets[0].port, 80);
    assert_eq!(snapshot.plan().tcp_timeout_ms, 1234);

    let report = session
        .presenter()
        .state()
        .last_result()
        .expect("결과 존재")
        .as_ref()
        .expect("보고서 유효");
    assert_eq!(snapshot.request().targets[0].raw_input, "127.0.0.1:080");
    assert_eq!(
        report.results[0].details["raw_measurement"]["limitations"],
        serde_json::json!(["합성 raw 보존 자료"])
    );

    // 완료 후 draft 옵션을 변경하더라도 이전 확정 스냅샷 메타데이터는 불변
    session
        .update_draft_options("9999", "8", vec![QuickFeature::TcpConnect])
        .unwrap();
    assert_eq!(
        session.completed_snapshot().unwrap().plan().tcp_timeout_ms,
        1234
    );

    session.begin_close().unwrap();
    until(|| session.poll() == PollOutcome::Closed);
}

#[test]
fn test_unwind_safety_raii_release() {
    let gate = Arc::new(Gate::default());
    let mut f = Fixture::new(valid_presenter(), vec![gate.clone()]);
    let cleaned = f.cleaned.clone();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        f.session
            .try_start_with(|| {
                GuiRunCoordinator::spawn(Arc::new(TestMemoryBackend {
                    gate: Some(gate.clone()),
                    ..Default::default()
                }))
                .map_err(|_| SessionInitError::HostSpawnFailed)
            })
            .unwrap();
        until(|| gate.entered.load(Ordering::SeqCst));
        std::panic::panic_any("qg3e:pending:assertion-unwind-witness");
    }));
    let payload = result.expect_err("의도한 Pending 이후 unwind가 발생해야 함");
    assert_eq!(
        payload.downcast_ref::<&str>(),
        Some(&"qg3e:pending:assertion-unwind-witness"),
        "준비 실패/timeout을 의도된 unwind와 혼동하지 않음"
    );
    assert!(
        cleaned.load(Ordering::SeqCst),
        "원 session release→close→poll로 worker와 channel 종료 관측"
    );
}

#[test]
fn task_join_error_is_a_report_not_host_failure() {
    let mut f = Fixture::new(valid_presenter(), vec![]);
    let session = &mut f.session;
    let id = session
        .try_start_with(|| {
            GuiRunCoordinator::spawn(Arc::new(PanickingBackend))
                .map_err(|_| SessionInitError::HostSpawnFailed)
        })
        .unwrap();
    until(|| session.poll() == PollOutcome::Applied(id));
    assert_eq!(session.host_lifecycle(), Some(HostLifecycle::Accepting));
    let report = session
        .presenter()
        .state()
        .last_result()
        .unwrap()
        .as_ref()
        .unwrap();
    assert!(report.cancelled);
    assert!(report.errors.iter().any(|e| e.contains("JoinError")));
    assert!(report.results.is_empty());
    let before = session.presenter().clone();
    assert_eq!(session.request_cancel(), Ok(None));
    assert_eq!(session.presenter(), &before);
    let next = session
        .try_start_with(|| panic!("task panic 뒤 host 자동교체 금지"))
        .unwrap();
    assert_eq!(next.as_u64(), 2);
    until(|| session.poll() == PollOutcome::Applied(next));
    assert_eq!(session.host_lifecycle(), Some(HostLifecycle::Accepting));
}
#[test]
fn pending_close_repeats_cancel_and_drains_only_after_release() {
    let gate = Arc::new(Gate::default());
    let mut f = Fixture::new(valid_presenter(), vec![gate.clone()]);
    let backend = Arc::new(TestMemoryBackend {
        gate: Some(gate.clone()),
        ..Default::default()
    });
    let b = backend.clone();
    let session = &mut f.session;
    let id = session
        .try_start_with(|| {
            GuiRunCoordinator::spawn(b).map_err(|_| SessionInitError::HostSpawnFailed)
        })
        .unwrap();
    let snapshot = session
        .presenter()
        .state()
        .active_snapshot()
        .cloned()
        .unwrap();
    until(|| gate.entered.load(Ordering::SeqCst));
    session.begin_close().unwrap();
    session.begin_close().unwrap();
    assert_eq!(session.request_cancel(), Ok(None));
    assert_eq!(session.presenter().state().active_run_id(), Some(id));
    assert_eq!(session.presenter().state().phase(), RunPhase::Cancelling);
    assert!(
        backend
            .cancel_observed
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .load(Ordering::SeqCst)
    );
    assert_eq!(session.shutdown_state(), SessionShutdown::Pending);
    assert_eq!(session.poll(), PollOutcome::Idle);
    assert_locked(session, SessionError::Closing);
    gate.release();
    until(|| session.poll() == PollOutcome::Applied(id));
    assert_eq!(session.completed_snapshot(), Some(&snapshot));
    let report = session.presenter().state().last_result().cloned();
    until(|| {
        session.poll();
        session.shutdown_state() == SessionShutdown::Closed
    });
    assert_eq!(session.presenter().state().last_result(), report.as_ref());
    assert_eq!(backend.tcp_calls.load(Ordering::SeqCst), 1);
}
#[test]
fn presenter_prepare_and_typed_convenience_are_atomic_on_real_host() {
    let mut f = Fixture::new(valid_presenter(), vec![]);
    let session = &mut f.session;
    let before = session.presenter().clone();
    let candidate = session.presenter().prepare_run_candidate().unwrap();
    assert_eq!(session.presenter(), &before);
    drop(candidate);
    // 같은 원 session 내부의 실제 host를 직접 typed 편의 API로 소비하는 시험 전용 구성이다.
    session.host = Some(GuiRunCoordinator::spawn(Arc::new(TestMemoryBackend::default())).unwrap());
    let GuiRunSession {
        presenter, host, ..
    } = session;
    let id = presenter.try_start_run(host.as_mut().unwrap()).unwrap();
    assert_eq!(id.as_u64(), 1);
    until(|| session.poll() == PollOutcome::Applied(id));
    session.begin_close().unwrap();
    until(|| {
        session.poll();
        session.shutdown_state() == SessionShutdown::Closed
    });
    let before = session.presenter().clone();
    let snapshot = session.completed_snapshot().cloned();
    let GuiRunSession {
        presenter, host, ..
    } = session;
    assert_eq!(
        presenter.try_start_run(host.as_mut().unwrap()),
        Err(RunBridgeError::Start(
            crate::gui_coordinator::StartError::NotAccepting
        ))
    );
    assert_eq!(session.presenter(), &before);
    assert_eq!(session.completed_snapshot(), snapshot.as_ref());
}
#[test]
fn invalid_candidate_and_malformed_target_preserve_model_and_next_id() {
    let mut p = valid_presenter();
    p.update_draft_options("bad", "1", vec![QuickFeature::TcpConnect]);
    let before = p.clone();
    assert!(p.prepare_run_candidate().is_err());
    assert_eq!(p, before);
    let mut f = Fixture::new(valid_presenter(), vec![]);
    let session = &mut f.session;
    let before = session.presenter().state().clone();
    assert!(session.append_targets("127.0.0.1 80").is_err());
    // 입력 API의 기존 오류 안내 변경은 보존하되 모델/ID는 불변이다.
    assert_eq!(session.presenter().state(), &before);
    assert!(session.host_lifecycle().is_none());
    let id = session
        .try_start_with(|| {
            GuiRunCoordinator::spawn(Arc::new(TestMemoryBackend::default()))
                .map_err(|_| SessionInitError::HostSpawnFailed)
        })
        .unwrap();
    assert_eq!(id.as_u64(), 1);
    until(|| session.poll() == PollOutcome::Applied(id));
}
#[test]
fn local_network_nested_null_raw_and_completed_snapshot_are_whole() {
    let mut f = Fixture::new(valid_presenter(), vec![]);
    let session = &mut f.session;
    session
        .update_draft_options("1234", "1", vec![QuickFeature::LocalNetwork])
        .unwrap();
    let backend = Arc::new(TestMemoryBackend::default());
    let b = backend.clone();
    let id = session
        .try_start_with(|| {
            GuiRunCoordinator::spawn(b).map_err(|_| SessionInitError::HostSpawnFailed)
        })
        .unwrap();
    let snapshot = session
        .presenter()
        .state()
        .active_snapshot()
        .cloned()
        .unwrap();
    until(|| session.poll() == PollOutcome::Applied(id));
    let report = session
        .presenter()
        .state()
        .last_result()
        .unwrap()
        .as_ref()
        .unwrap();
    let raw = HostSnapshot {
        adapters: serde_json::json!([{"name":"모의NIC","v":[null,"null","\u{0}","\\u0000"]}]),
        routes: serde_json::json!([]),
        selected_route: serde_json::Value::Null,
        errors: vec!["합성 경고 보존 자료".into()],
        limitations: vec!["합성 제한 보존 자료".into()],
    };
    let request = snapshot.request();
    let ctx = QuickContext {
        session_id: request.session_id.clone(),
        timestamp_iso8601: request.timestamp_iso8601.clone(),
        source_host: request.source_host.clone(),
        target_host: request.targets[0].host.clone(),
        target_port: request.targets[0].port,
    };
    let expected = network_core::measurements::host_to_quick_result(&ctx, &raw, Some(9)).unwrap();
    assert_eq!(report.results, vec![expected]);
    assert_eq!(
        report.results[0].details["raw_measurement"],
        serde_json::to_value(raw).unwrap()
    );
    assert_eq!(
        report.invocations,
        network_core::runner::ProbeCounts {
            local_network: 1,
            ..Default::default()
        }
    );
    assert_eq!(backend.tcp_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.icmp_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.host_calls.load(Ordering::SeqCst), 1);
    let whole_report = report.clone();
    assert_eq!(session.completed_snapshot(), Some(&snapshot));
    session
        .update_draft_options("9999", "8", vec![QuickFeature::TcpConnect])
        .unwrap();
    assert_eq!(session.completed_snapshot(), Some(&snapshot));
    assert_eq!(
        session.presenter().state().last_result(),
        Some(&Ok(whole_report))
    );
}
#[test]
fn backend_err_becomes_local_error_row_not_top_level_core_err() {
    let mut f = Fixture::new(valid_presenter(), vec![]);
    let session = &mut f.session;
    session
        .update_draft_options("1234", "1", vec![QuickFeature::IcmpPing])
        .unwrap();
    let id = session
        .try_start_with(|| {
            GuiRunCoordinator::spawn(Arc::new(TestMemoryBackend::default()))
                .map_err(|_| SessionInitError::HostSpawnFailed)
        })
        .unwrap();
    until(|| session.poll() == PollOutcome::Applied(id));
    let report = session
        .presenter()
        .state()
        .last_result()
        .unwrap()
        .as_ref()
        .unwrap();
    assert_eq!(report.results[0].details["outcome"], "LOCAL_ERROR");
    assert!(!report.errors.is_empty());
    assert_eq!(session.host_lifecycle(), Some(HostLifecycle::Accepting));
}
#[test]
fn original_session_moves_to_other_owner_and_idle_host_closes() {
    let mut f = Fixture::new(valid_presenter(), vec![]);
    f.session.host =
        Some(GuiRunCoordinator::spawn(Arc::new(TestMemoryBackend::default())).unwrap());
    let before = f.session.presenter().clone();
    // 소유권 이동만 검증한다. HWND/UI thread/non-UI entry 실행 증거가 아니다.
    fn consume(mut f: Fixture) -> Fixture {
        f.session.begin_close().unwrap();
        until(|| {
            f.session.poll();
            f.session.shutdown_state() == SessionShutdown::Closed
        });
        f
    }
    let f = consume(f);
    assert_eq!(f.session.presenter(), &before);
    assert!(f.session.completed_snapshot().is_none());
    assert!(f.session.presenter().state().last_result().is_none());
}

/// 진단을 한 번도 받지 않은 fresh host를 factory 안에서 닫는 한정 fault fixture.
/// 실제 queue Full/Disconnected 주입이나 GUI/OS 고장 증거와 구분한다.
#[test]
fn fresh_never_run_closed_host_enqueue_failure_keeps_session_owner_and_presenter() {
    let backend = Arc::new(TestMemoryBackend::default());
    let mut f = Fixture::new(valid_presenter(), vec![]);
    let before = f.session.presenter().clone();
    let mut closing_state = before.state().clone();
    let b = backend.clone();
    let result = f.session.try_start_with(|| {
        let mut host =
            GuiRunCoordinator::spawn(b).map_err(|_| SessionInitError::HostSpawnFailed)?;
        // 새 worker이며 accepted run은 0개다. 외부 state의 실행을 새 session에 주입하지 않는다.
        host.begin_close(&mut closing_state).unwrap();
        Ok(host)
    });
    assert_eq!(
        result,
        Err(SessionError::Bridge(RunBridgeError::Start(
            crate::gui_coordinator::StartError::NotAccepting
        )))
    );
    assert_eq!(f.session.presenter(), &before);
    assert_eq!(f.session.host_lifecycle(), Some(HostLifecycle::Closing));
    assert!(f.session.completed_snapshot().is_none());
    assert_eq!(backend.tcp_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.icmp_calls.load(Ordering::SeqCst), 0);
    assert_eq!(backend.host_calls.load(Ordering::SeqCst), 0);
    f.session.begin_close().unwrap();
    until(|| {
        f.session.poll();
        f.session.shutdown_state() == SessionShutdown::Closed
    });
    assert_eq!(f.session.presenter(), &before);
    assert!(
        f.session.host.is_some(),
        "실패해도 원 host를 session이 소유한 채 최종 종료를 관측함"
    );
}
