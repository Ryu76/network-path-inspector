//! 부모 보정의 결정적 채널·Pending·종료 시험. 실제 Core runner와 메모리 backend만 사용한다.
//! std thread/runtime/상위 timeout용 시간 관측은 존재한다. 실 socket/DNS/helper/Win32/file I/O는 없다.
use super::*;
use crate::gui_state::RunPhase;
use network_core::quick::{QuickContext, QuickFeature, tcp_to_quick_result};
use network_core::runner::{ProbeCounts, ProbeFuture};
use network_core::targets::QuickOptions;
use network_core::{HostSnapshot, TcpMeasurement};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

fn until(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < deadline, "명시 동기화/종료 관측 timeout");
        thread::yield_now();
    }
}
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
    fn blocking(&self) {
        self.entered.store(true, Ordering::SeqCst);
        until(|| self.open.load(Ordering::SeqCst));
    }
}
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
                // 이 Pending 분기를 실제로 통과한 뒤에만 부모가 취소를 시작한다.
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
        limitations: vec!["합성 raw 보존".into(), "합성 raw 보존".into()],
    }
}
#[derive(Default)]
struct MemoryBackend {
    tcp_calls: AtomicUsize,
    icmp_calls: AtomicUsize,
    host_calls: AtomicUsize,
    gate: Option<Arc<Gate>>,
    cancel: Mutex<Option<Arc<AtomicBool>>>,
    host_raw: Mutex<Option<HostSnapshot>>,
}
impl QuickProbeBackend for MemoryBackend {
    fn tcp<'a>(
        &'a self,
        ctx: QuickContext,
        target: SocketAddr,
        _: Duration,
        cancel: Arc<AtomicBool>,
    ) -> ProbeFuture<'a> {
        self.tcp_calls.fetch_add(1, Ordering::SeqCst);
        *self.cancel.lock().unwrap() = Some(Arc::clone(&cancel));
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
            adapters: serde_json::json!([{"name":"모의NIC","v":[null,"null"]}]),
            routes: serde_json::json!([]),
            selected_route: serde_json::Value::Null,
            errors: vec!["합성경고".into(), "합성경고".into()],
            limitations: vec!["읽기범위fixture".into()],
        };
        *self.host_raw.lock().unwrap() = Some(raw.clone());
        Box::pin(
            async move { network_core::measurements::host_to_quick_result(&ctx, &raw, Some(9)) },
        )
    }
}
fn state() -> GuiState {
    let mut s = GuiState::new();
    s.replace_targets("127.0.0.1:080").unwrap();
    s.set_options(QuickOptions {
        tcp_timeout_ms: 1234,
        concurrency: 1,
        selected_features: vec![QuickFeature::TcpConnect],
    })
    .unwrap();
    s
}
fn spawn(backend: Arc<dyn QuickProbeBackend>, config: WorkerConfig) -> GuiRunCoordinator {
    GuiRunCoordinator::spawn_with(backend, config, |job| thread::Builder::new().spawn(job)).unwrap()
}
/// guard의 release 목록은 worker 시작 전에 만든다. assertion unwind에서도 생산 종료 경로를 통과한다.
struct Fixture {
    coordinator: Option<GuiRunCoordinator>,
    state: GuiState,
    releases: Vec<Arc<Gate>>,
    cleanup_observed: Arc<AtomicBool>,
}
impl Fixture {
    fn new(
        backend: Arc<dyn QuickProbeBackend>,
        config: WorkerConfig,
        releases: Vec<Arc<Gate>>,
    ) -> Self {
        Self {
            coordinator: Some(spawn(backend, config)),
            state: state(),
            releases,
            cleanup_observed: Arc::new(AtomicBool::new(false)),
        }
    }
    fn start(&mut self) -> RunId {
        self.coordinator
            .as_mut()
            .unwrap()
            .try_start(&mut self.state)
            .unwrap()
    }
    fn poll_until(&mut self, expected: impl Fn(&PollOutcome) -> bool) -> PollOutcome {
        let mut last = PollOutcome::Idle;
        until(|| {
            last = self.coordinator.as_mut().unwrap().poll(&mut self.state);
            expected(&last)
        });
        last
    }
    fn close(&mut self) {
        self.coordinator
            .as_mut()
            .unwrap()
            .begin_close(&mut self.state)
            .unwrap();
        until(|| {
            let c = self.coordinator.as_mut().unwrap();
            c.poll(&mut self.state);
            c.is_shutdown_complete()
        });
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for gate in &self.releases {
            gate.release();
        }
        if let Some(c) = self.coordinator.as_mut() {
            c.fail();
            let deadline = Instant::now() + Duration::from_secs(5);
            while !c.is_shutdown_complete() && Instant::now() < deadline {
                c.poll(&mut self.state);
                thread::yield_now();
            }
            let complete = c.is_shutdown_complete();
            self.cleanup_observed.store(complete, Ordering::SeqCst);
            if !complete && !thread::panicking() {
                panic!("fixture worker 정리 미완료");
            }
        }
    }
}
fn capture() -> (WorkerConfig, Arc<Mutex<Option<RunResult>>>) {
    let captured = Arc::new(Mutex::new(None));
    let output = Arc::clone(&captured);
    (
        WorkerConfig {
            on_result: Some(Arc::new(move |r| {
                *output.lock().unwrap() = Some(r.clone());
            })),
            ..Default::default()
        },
        captured,
    )
}
// 풍부한 합성 DTO는 보존시험용이며 실측이 아니다.
fn rich() -> RunResult {
    let row = network_core::quick::QuickResult {
        schema_version: "1.0".into(),
        product: "network-quick-check".into(),
        session_id: "synthetic-preservation".into(),
        timestamp_iso8601: None,
        source_host: Some("null".into()),
        target_host: "[::1]".into(),
        resolved_ip: None,
        target_port: 443,
        feature: QuickFeature::TcpConnect,
        status: network_core::quick::QuickStatus::UNKNOWN,
        elapsed_ms: None,
        os_error_code: Some(10061),
        details: serde_json::json!({"outcome":"UNKNOWN","limitations":["중복","중복"],"raw_measurement":{"null":null,"nested":["한글🚀",null,"null"]}}),
        evidence_level: network_core::quick::EvidenceLevel::UNKNOWN,
    };
    let mut alternate = row.clone();
    alternate.elapsed_ms = Some(0);
    alternate.os_error_code = None;
    alternate.source_host = None;
    alternate.resolved_ip = Some("::1".into());
    Ok(QuickRunReport {
        results: vec![row.clone(), alternate, row],
        cancelled: false,
        limit_reached: true,
        omitted_results: 13,
        errors: vec!["중복\r\n오류".into(), "중복\r\n오류".into()],
        invocations: ProbeCounts {
            tcp_connect: 3,
            icmp_ping: 5,
            local_network: 7,
            dns_lookup: 11,
            icmp_traceroute: 17,
        },
        max_active_targets: 2,
        targets_started: 19,
        targets_completed: 18,
        serialized_result_bytes: 1234,
    })
}
fn finished() -> (GuiState, RunSnapshot) {
    let mut s = state();
    let snap = s.begin_run().unwrap();
    s.finish_run(snap.run_id(), rich()).unwrap();
    (s, snap)
}
fn manual() -> (
    GuiRunCoordinator,
    Receiver<StartCommand>,
    SyncSender<Completion>,
) {
    let (tx, rx) = mpsc::sync_channel(1);
    let (done_tx, done_rx) = mpsc::sync_channel(1);
    (
        GuiRunCoordinator {
            start_tx: Some(tx),
            completion_rx: Some(done_rx),
            worker: None,
            worker_exit: Arc::new(AtomicU8::new(EXIT_NORMAL)),
            completion_end: CompletionEnd::Open,
            inflight: None,
            completed_snapshot: None,
            unapplied_completion: None,
            lifecycle: HostLifecycle::Accepting,
        },
        rx,
        done_tx,
    )
}
fn finish_manual(c: &mut GuiRunCoordinator, s: &mut GuiState, done: SyncSender<Completion>) {
    drop(done);
    c.begin_close(s).unwrap();
    c.poll(s);
    assert!(c.is_shutdown_complete());
}

#[test]
fn parser_uses_actual_core_list_grammar_and_idle_spawn_does_not_probe() {
    let b = Arc::new(MemoryBackend::default());
    let c = GuiRunCoordinator::spawn(b.clone()).unwrap();
    let mut f = Fixture {
        coordinator: Some(c),
        state: state(),
        releases: vec![],
        cleanup_observed: Arc::new(AtomicBool::new(false)),
    };
    assert_eq!(f.state.targets()[0].raw_input, "127.0.0.1:080");
    let before = f.state.clone();
    assert!(f.state.replace_targets("127.0.0.1 80").is_err());
    assert_eq!(f.state, before);
    assert_eq!(b.tcp_calls.load(Ordering::SeqCst), 0);
    f.close();
    assert_eq!(
        f.coordinator.as_ref().unwrap().lifecycle(),
        HostLifecycle::Closed
    );
}
#[test]
fn actual_core_completion_and_snapshot_are_whole_and_selected_only() {
    let b = Arc::new(MemoryBackend::default());
    let (cfg, observed) = capture();
    let mut f = Fixture::new(b.clone(), cfg, vec![]);
    let id = f.start();
    let snap = f.state.active_snapshot().unwrap().clone();
    f.poll_until(|p| *p == PollOutcome::Applied(id));
    assert_eq!(f.state.last_result(), observed.lock().unwrap().as_ref());
    assert_eq!(
        f.coordinator.as_ref().unwrap().completed_snapshot(),
        Some(&snap)
    );
    assert_eq!(b.tcp_calls.load(Ordering::SeqCst), 1);
    assert_eq!(b.icmp_calls.load(Ordering::SeqCst), 0);
    assert_eq!(b.host_calls.load(Ordering::SeqCst), 0);
    f.close();
}
#[test]
fn host_snapshot_all_fields_and_raw_values_are_retained() {
    let b = Arc::new(MemoryBackend::default());
    let (cfg, observed) = capture();
    let mut f = Fixture::new(b.clone(), cfg, vec![]);
    f.state
        .set_options(QuickOptions {
            selected_features: vec![QuickFeature::LocalNetwork],
            ..Default::default()
        })
        .unwrap();
    let id = f.start();
    f.poll_until(|p| *p == PollOutcome::Applied(id));
    assert_eq!(f.state.last_result(), observed.lock().unwrap().as_ref());
    let report = f.state.last_result().unwrap().as_ref().unwrap();
    let raw = b.host_raw.lock().unwrap().clone().unwrap();
    assert_eq!(
        report.results[0].details["raw_measurement"],
        serde_json::to_value(raw).unwrap()
    );
    f.close();
}
#[test]
fn pending_same_arc_cancel_retains_actual_report_and_drains_before_completion() {
    let gate = Arc::new(Gate::default());
    let b = Arc::new(MemoryBackend {
        gate: Some(gate.clone()),
        ..Default::default()
    });
    let (cfg, observed) = capture();
    let mut f = Fixture::new(b.clone(), cfg, vec![gate.clone()]);
    f.state.replace_targets("127.0.0.1:80\n[::1]:81").unwrap();
    f.state
        .set_options(QuickOptions {
            concurrency: 1,
            selected_features: vec![
                QuickFeature::TcpConnect,
                QuickFeature::IcmpPing,
                QuickFeature::LocalNetwork,
            ],
            ..Default::default()
        })
        .unwrap();
    let id = f.start();
    until(|| gate.entered.load(Ordering::SeqCst));
    let cancel = f
        .coordinator
        .as_ref()
        .unwrap()
        .inflight
        .as_ref()
        .unwrap()
        .cancel
        .clone();
    assert!(Arc::ptr_eq(
        &cancel,
        b.cancel.lock().unwrap().as_ref().unwrap()
    ));
    assert!(!cancel.load(Ordering::SeqCst));
    let c = f.coordinator.as_mut().unwrap();
    assert_eq!(c.request_cancel(&mut f.state).unwrap(), Some(id));
    assert_eq!(c.request_cancel(&mut f.state).unwrap(), None);
    assert_eq!(c.poll(&mut f.state), PollOutcome::Idle);
    assert!(observed.lock().unwrap().is_none());
    assert!(!c.is_shutdown_complete());
    gate.release();
    f.poll_until(|p| *p == PollOutcome::Applied(id));
    assert_eq!(f.state.last_result(), observed.lock().unwrap().as_ref());
    assert!(f.state.last_result().unwrap().as_ref().unwrap().cancelled);
    assert_eq!(b.tcp_calls.load(Ordering::SeqCst), 1);
    assert_eq!(b.icmp_calls.load(Ordering::SeqCst), 0);
    assert_eq!(b.host_calls.load(Ordering::SeqCst), 0);
    f.close();
}
#[test]
fn closing_pending_is_repeatable_and_cannot_finish_before_release() {
    let gate = Arc::new(Gate::default());
    let b = Arc::new(MemoryBackend {
        gate: Some(gate.clone()),
        ..Default::default()
    });
    let mut f = Fixture::new(b, Default::default(), vec![gate.clone()]);
    let id = f.start();
    until(|| gate.entered.load(Ordering::SeqCst));
    let c = f.coordinator.as_mut().unwrap();
    c.begin_close(&mut f.state).unwrap();
    c.begin_close(&mut f.state).unwrap();
    assert_eq!(f.state.phase(), RunPhase::Cancelling);
    assert_eq!(c.poll(&mut f.state), PollOutcome::Idle);
    assert!(!c.is_shutdown_complete());
    gate.release();
    f.poll_until(|p| *p == PollOutcome::Applied(id));
    f.close();
    assert_eq!(
        f.coordinator.as_ref().unwrap().lifecycle(),
        HostLifecycle::Closed
    );
}
#[test]
fn queued_pre_cancel_is_gated_before_runner_and_calls_no_backend() {
    let gate = Arc::new(Gate::default());
    let g = gate.clone();
    let b = Arc::new(MemoryBackend::default());
    let (mut cfg, observed) = capture();
    cfg.before_run = Some(Arc::new(move || g.blocking()));
    let mut f = Fixture::new(b.clone(), cfg, vec![gate.clone()]);
    let id = f.start();
    until(|| gate.entered.load(Ordering::SeqCst));
    f.coordinator
        .as_mut()
        .unwrap()
        .request_cancel(&mut f.state)
        .unwrap();
    gate.release();
    f.poll_until(|p| *p == PollOutcome::Applied(id));
    assert_eq!(b.tcp_calls.load(Ordering::SeqCst), 0);
    assert_eq!(f.state.last_result(), observed.lock().unwrap().as_ref());
    assert!(f.state.last_result().unwrap().as_ref().unwrap().cancelled);
    f.close();
}
#[test]
fn cancellation_after_real_enqueue_does_not_rewrite_normal_report() {
    let enqueued = Arc::new(AtomicBool::new(false));
    let flag = enqueued.clone();
    let (mut cfg, observed) = capture();
    cfg.after_send = Some(Arc::new(move || flag.store(true, Ordering::SeqCst)));
    let mut f = Fixture::new(Arc::new(MemoryBackend::default()), cfg, vec![]);
    let id = f.start();
    until(|| enqueued.load(Ordering::SeqCst));
    let original = observed.lock().unwrap().clone().unwrap();
    assert!(!original.as_ref().unwrap().cancelled);
    f.coordinator
        .as_mut()
        .unwrap()
        .request_cancel(&mut f.state)
        .unwrap();
    f.poll_until(|p| *p == PollOutcome::Applied(id));
    assert_eq!(f.state.last_result(), Some(&original));
    f.close();
}
#[test]
fn exact_empty_enqueue_finished_interleaving_preserves_actual_completion() {
    let gate = Arc::new(Gate::default());
    let b = Arc::new(MemoryBackend {
        gate: Some(gate.clone()),
        ..Default::default()
    });
    let (cfg, observed) = capture();
    let mut f = Fixture::new(b, cfg, vec![gate.clone()]);
    let id = f.start();
    until(|| gate.entered.load(Ordering::SeqCst));
    let snapshot = f.state.active_snapshot().unwrap().clone();
    let c = f.coordinator.as_mut().unwrap();
    c.begin_close(&mut f.state).unwrap();
    let called = AtomicBool::new(false);
    let outcome = c.poll_with_after_empty(&mut f.state, |host| {
        called.store(true, Ordering::SeqCst);
        gate.release();
        until(|| host.worker.as_ref().unwrap().is_finished());
    });
    assert!(called.load(Ordering::SeqCst));
    assert_eq!(outcome, PollOutcome::Applied(id));
    assert_eq!(f.state.last_result(), observed.lock().unwrap().as_ref());
    assert_eq!(c.completed_snapshot(), Some(&snapshot));
    f.close();
    assert_eq!(
        f.coordinator.as_ref().unwrap().lifecycle(),
        HostLifecycle::Closed
    );
}
#[test]
fn accepted_request_without_completion_is_failure_with_matching_error_snapshot() {
    for closing in [false, true] {
        let gate = Arc::new(Gate::default());
        let g = gate.clone();
        let mut f = Fixture::new(
            Arc::new(MemoryBackend::default()),
            WorkerConfig {
                before_run: Some(Arc::new(move || g.blocking())),
                omit_completion_after_accept: true,
                ..Default::default()
            },
            vec![gate.clone()],
        );
        f.start();
        let snapshot = f.state.active_snapshot().unwrap().clone();
        until(|| gate.entered.load(Ordering::SeqCst));
        if closing {
            f.coordinator
                .as_mut()
                .unwrap()
                .begin_close(&mut f.state)
                .unwrap();
        }
        gate.release();
        until(|| {
            let c = f.coordinator.as_mut().unwrap();
            c.poll(&mut f.state);
            c.is_shutdown_complete()
        });
        let c = f.coordinator.as_ref().unwrap();
        assert_eq!(c.lifecycle(), HostLifecycle::Failed);
        assert_eq!(
            f.state.last_result(),
            Some(&Err(vec![LOST_COMPLETION.into()]))
        );
        assert_eq!(c.completed_snapshot(), Some(&snapshot));
    }
}
#[test]
fn receiver_loss_waits_for_runner_exit_and_never_closes_successfully() {
    for closing in [false, true] {
        let gate = Arc::new(Gate::default());
        let b = Arc::new(MemoryBackend {
            gate: Some(gate.clone()),
            ..Default::default()
        });
        let mut f = Fixture::new(b, Default::default(), vec![gate.clone()]);
        f.start();
        let snapshot = f.state.active_snapshot().unwrap().clone();
        until(|| gate.entered.load(Ordering::SeqCst));
        let c = f.coordinator.as_mut().unwrap();
        if closing {
            c.begin_close(&mut f.state).unwrap();
        }
        c.completion_rx.take();
        assert_eq!(c.poll(&mut f.state), PollOutcome::HostFailed);
        assert!(!c.is_shutdown_complete());
        assert!(f.state.active_run_id().is_some());
        gate.release();
        until(|| {
            let c = f.coordinator.as_mut().unwrap();
            c.poll(&mut f.state);
            c.is_shutdown_complete()
        });
        let c = f.coordinator.as_ref().unwrap();
        assert_eq!(c.lifecycle(), HostLifecycle::Failed);
        assert_eq!(c.completed_snapshot(), Some(&snapshot));
        assert_eq!(
            f.state.last_result(),
            Some(&Err(vec![LOST_COMPLETION.into()]))
        );
    }
}
#[test]
fn wrong_state_keeps_original_completion_unapplied_and_drains_worker() {
    let enqueued = Arc::new(AtomicBool::new(false));
    let flag = enqueued.clone();
    let (mut cfg, observed) = capture();
    cfg.after_send = Some(Arc::new(move || flag.store(true, Ordering::SeqCst)));
    let mut f = Fixture::new(Arc::new(MemoryBackend::default()), cfg, vec![]);
    f.start();
    let original = f.state.clone();
    let snapshot = original.active_snapshot().unwrap().clone();
    until(|| enqueued.load(Ordering::SeqCst));
    let mut wrong = state();
    let before = wrong.clone();
    let c = f.coordinator.as_mut().unwrap();
    assert_eq!(
        c.request_cancel(&mut wrong),
        Err(CoordinatorError::ActiveRunMismatch)
    );
    assert_eq!(
        c.begin_close(&mut wrong),
        Err(CoordinatorError::ActiveRunMismatch)
    );
    assert_eq!(c.poll(&mut wrong), PollOutcome::HostFailed);
    assert_eq!(wrong, before);
    assert_eq!(f.state, original);
    until(|| {
        c.poll(&mut wrong);
        c.is_shutdown_complete()
    });
    assert_eq!(
        c.unapplied_completion.as_ref(),
        Some(&(snapshot, observed.lock().unwrap().clone().unwrap()))
    );
}
#[test]
fn real_worker_panic_finishes_matching_request_without_reflecting_payload() {
    let mut f = Fixture::new(
        Arc::new(MemoryBackend::default()),
        WorkerConfig {
            before_run: Some(Arc::new(|| panic!("RAW_PANIC_MARKER"))),
            ..Default::default()
        },
        vec![],
    );
    f.start();
    let snapshot = f.state.active_snapshot().unwrap().clone();
    until(|| {
        let c = f.coordinator.as_mut().unwrap();
        c.poll(&mut f.state);
        c.is_shutdown_complete()
    });
    let c = f.coordinator.as_ref().unwrap();
    assert_eq!(c.lifecycle(), HostLifecycle::Failed);
    assert_eq!(c.worker_exit.load(Ordering::SeqCst), EXIT_PANICKED);
    assert_eq!(c.completed_snapshot(), Some(&snapshot));
    assert_eq!(
        f.state.last_result(),
        Some(&Err(vec![LOST_COMPLETION.into()]))
    );
    assert_eq!(
        f.coordinator.as_mut().unwrap().request_cancel(&mut f.state),
        Err(CoordinatorError::HostFailed)
    );
}
#[test]
fn panic_during_closing_with_no_active_work_is_not_success_and_keeps_prior_report() {
    for run_first in [false, true] {
        let mut f = Fixture::new(
            Arc::new(MemoryBackend::default()),
            WorkerConfig {
                before_exit: Some(Arc::new(|| panic!("EXIT_PANIC"))),
                ..Default::default()
            },
            vec![],
        );
        if run_first {
            let id = f.start();
            f.poll_until(|p| *p == PollOutcome::Applied(id));
        }
        let before = f.state.clone();
        let snapshot = f
            .coordinator
            .as_ref()
            .unwrap()
            .completed_snapshot()
            .cloned();
        f.close();
        assert_eq!(
            f.coordinator.as_ref().unwrap().lifecycle(),
            HostLifecycle::Failed
        );
        assert_eq!(f.state, before);
        assert_eq!(
            f.coordinator.as_ref().unwrap().completed_snapshot(),
            snapshot.as_ref()
        );
    }
}
struct PanicOnDropBackend(Arc<MemoryBackend>);
impl QuickProbeBackend for PanicOnDropBackend {
    fn tcp<'a>(
        &'a self,
        c: QuickContext,
        t: SocketAddr,
        d: Duration,
        x: Arc<AtomicBool>,
    ) -> ProbeFuture<'a> {
        self.0.tcp(c, t, d, x)
    }
    fn icmp<'a>(
        &'a self,
        c: QuickContext,
        t: IpAddr,
        d: Duration,
        x: Arc<AtomicBool>,
    ) -> ProbeFuture<'a> {
        self.0.icmp(c, t, d, x)
    }
    fn host<'a>(&'a self, c: QuickContext, t: IpAddr, x: Arc<AtomicBool>) -> ProbeFuture<'a> {
        self.0.host(c, t, x)
    }
}
impl Drop for PanicOnDropBackend {
    fn drop(&mut self) {
        panic!("실제 backend destructor panic fixture");
    }
}
#[test]
fn real_backend_destructor_panic_after_applied_report_stays_failed() {
    let mut f = Fixture::new(
        Arc::new(PanicOnDropBackend(Arc::new(MemoryBackend::default()))),
        Default::default(),
        vec![],
    );
    let id = f.start();
    f.poll_until(|p| *p == PollOutcome::Applied(id));
    let before = f.state.clone();
    let snapshot = f
        .coordinator
        .as_ref()
        .unwrap()
        .completed_snapshot()
        .cloned();
    f.close();
    let c = f.coordinator.as_ref().unwrap();
    assert_eq!(c.lifecycle(), HostLifecycle::Failed);
    assert_eq!(c.worker_exit.load(Ordering::SeqCst), EXIT_PANICKED);
    assert_eq!(f.state, before);
    assert_eq!(c.completed_snapshot(), snapshot.as_ref());
}
#[test]
fn missing_targets_fail_atomically_without_consuming_run_id() {
    let (mut c, rx, tx) = manual();
    let mut s = GuiState::new();
    let before = s.clone();
    assert!(matches!(
        c.try_start(&mut s),
        Err(StartError::State(GuiStateError::InvalidInput(_)))
    ));
    assert_eq!(s, before);
    s.replace_targets("127.0.0.1:80").unwrap();
    let expected = s.clone().begin_run().unwrap().run_id();
    let id = c.try_start(&mut s).unwrap();
    assert_eq!(id, expected);
    rx.try_recv().unwrap();
    tx.send(Completion { id, result: rich() }).unwrap();
    c.poll(&mut s);
    finish_manual(&mut c, &mut s, tx);
}
#[test]
fn same_numeric_id_with_different_snapshot_cannot_mutate_other_active_state() {
    let gate = Arc::new(Gate::default());
    let b = Arc::new(MemoryBackend {
        gate: Some(gate.clone()),
        ..Default::default()
    });
    let mut f = Fixture::new(b, Default::default(), vec![gate.clone()]);
    let id = f.start();
    until(|| gate.entered.load(Ordering::SeqCst));
    let mut other = state();
    other.replace_targets("[::1]:999").unwrap();
    let other_id = other.begin_run().unwrap().run_id();
    assert_eq!(id, other_id);
    let before = other.clone();
    let c = f.coordinator.as_mut().unwrap();
    assert_eq!(
        c.request_cancel(&mut other),
        Err(CoordinatorError::ActiveRunMismatch)
    );
    assert_eq!(
        c.begin_close(&mut other),
        Err(CoordinatorError::ActiveRunMismatch)
    );
    gate.release();
    until(|| {
        c.poll(&mut other);
        c.is_shutdown_complete()
    });
    assert_eq!(other, before);
    assert_eq!(c.lifecycle(), HostLifecycle::Failed);
    assert!(c.unapplied_completion.is_some());
}

#[test]
fn runtime_and_spawn_errors_use_fixed_classification_and_matching_snapshot() {
    let b = Arc::new(MemoryBackend::default());
    let mut f = Fixture::new(
        b.clone(),
        WorkerConfig {
            runtime_factory: Some(Arc::new(|| Err(std::io::Error::other("RAW_OS_MARKER")))),
            ..Default::default()
        },
        vec![],
    );
    let id = f.start();
    let snapshot = f.state.active_snapshot().unwrap().clone();
    f.poll_until(|p| *p == PollOutcome::Applied(id));
    assert_eq!(
        f.state.last_result(),
        Some(&Err(vec!["비동기 런타임 초기화에 실패했습니다.".into()]))
    );
    assert_eq!(
        f.coordinator.as_ref().unwrap().completed_snapshot(),
        Some(&snapshot)
    );
    assert_eq!(b.tcp_calls.load(Ordering::SeqCst), 0);
    f.close();
    assert!(matches!(
        GuiRunCoordinator::spawn_with(b, Default::default(), |_| Err(std::io::Error::other(
            "RAW_SPAWN"
        ))),
        Err(HostInitError::ThreadSpawnFailed)
    ));
    assert_eq!(
        HostInitError::ThreadSpawnFailed.to_string(),
        "진단 워커 생성 실패"
    );
}
#[test]
fn rich_matching_report_and_error_are_applied_whole_and_snapshot_retained() {
    for result in [
        rich(),
        Err(vec!["중복\r\n오류".into(), "중복\r\n오류".into()]),
    ] {
        let (mut c, rx, tx) = manual();
        let mut s = state();
        let id = c.try_start(&mut s).unwrap();
        let cmd = rx.try_recv().unwrap();
        tx.send(Completion {
            id,
            result: result.clone(),
        })
        .unwrap();
        assert_eq!(c.poll(&mut s), PollOutcome::Applied(id));
        assert_eq!(s.last_result(), Some(&result));
        assert_eq!(c.completed_snapshot(), Some(&cmd.snapshot));
        finish_manual(&mut c, &mut s, tx);
    }
}
#[test]
fn all_start_failure_classes_preserve_whole_state_context_and_next_id() {
    for case in [
        "full",
        "disconnected",
        "busy_state",
        "busy_host",
        "no_features",
        "closing",
    ] {
        let (mut c, rx, tx) = manual();
        let (mut s, snapshot) = finished();
        c.completed_snapshot = Some(snapshot.clone());
        if case == "no_features" {
            s.set_options(QuickOptions {
                selected_features: vec![],
                ..Default::default()
            })
            .unwrap();
        }
        if case == "busy_state" {
            s.begin_run().unwrap();
        }
        if case == "closing" {
            c.begin_close(&mut s).unwrap();
        }
        let mut receiver = Some(rx);
        if case == "disconnected" {
            receiver.take();
        }
        if case == "full" {
            c.start_tx
                .as_ref()
                .unwrap()
                .try_send(StartCommand {
                    snapshot: snapshot.clone(),
                    cancel: Arc::new(AtomicBool::new(false)),
                })
                .ok()
                .unwrap();
        }
        if case == "busy_host" {
            c.inflight = Some(InFlight {
                snapshot: snapshot.clone(),
                cancel: Arc::new(AtomicBool::new(false)),
            });
        }
        let before = s.clone();
        let expected = match case {
            "full" => StartError::QueueFull,
            "disconnected" => StartError::ChannelClosed,
            "busy_state" => StartError::State(GuiStateError::Busy),
            "busy_host" => StartError::AlreadyRunning(snapshot.run_id()),
            "no_features" => StartError::State(GuiStateError::NoFeatures),
            _ => StartError::NotAccepting,
        };
        assert_eq!(c.try_start(&mut s), Err(expected));
        assert_eq!(s, before);
        assert_eq!(c.completed_snapshot(), Some(&snapshot));
        if case == "full" {
            receiver.as_ref().unwrap().try_recv().unwrap();
            let mut expected_state = before.clone();
            let expected_id = expected_state.begin_run().unwrap().run_id();
            assert_eq!(c.try_start(&mut s).unwrap(), expected_id);
            let cmd = receiver.as_ref().unwrap().try_recv().unwrap();
            tx.send(Completion {
                id: cmd.snapshot.run_id(),
                result: rich(),
            })
            .unwrap();
            c.poll(&mut s);
        }
        // 수동 endpoint의 의도적 불일치도 생산 fail/drain으로 정리한다.
        c.fail();
        drop(tx);
        c.poll(&mut s);
        assert!(c.is_shutdown_complete());
    }
}
#[test]
fn active_stale_duplicate_and_following_execution_preserve_state_and_arc() {
    let (mut c, rx, tx) = manual();
    let (mut s, old) = finished();
    let id = c.try_start(&mut s).unwrap();
    let cmd = rx.try_recv().unwrap();
    let before = s.clone();
    let cancel = c.inflight.as_ref().unwrap().cancel.clone();
    tx.send(Completion {
        id: old.run_id(),
        result: rich(),
    })
    .unwrap();
    assert_eq!(c.poll(&mut s), PollOutcome::Stale(old.run_id()));
    assert_eq!(s, before);
    assert!(Arc::ptr_eq(&cancel, &c.inflight.as_ref().unwrap().cancel));
    assert!(!cancel.load(Ordering::SeqCst));
    tx.send(Completion { id, result: rich() }).unwrap();
    assert_eq!(c.poll(&mut s), PollOutcome::Applied(id));
    assert_eq!(c.completed_snapshot(), Some(&cmd.snapshot));
    let next = c.try_start(&mut s).unwrap();
    let next_cmd = rx.try_recv().unwrap();
    let before = s.clone();
    tx.send(Completion { id, result: rich() }).unwrap();
    assert_eq!(c.poll(&mut s), PollOutcome::Stale(id));
    assert_eq!(s, before);
    tx.send(Completion {
        id: next,
        result: rich(),
    })
    .unwrap();
    assert_eq!(c.poll(&mut s), PollOutcome::Applied(next));
    assert_eq!(c.completed_snapshot(), Some(&next_cmd.snapshot));
    finish_manual(&mut c, &mut s, tx);
}
#[test]
fn failed_host_does_not_skip_buffered_stale_completion_before_final_drain() {
    let (mut c, rx, tx) = manual();
    let (mut s, old) = finished();
    drop(rx);
    tx.send(Completion {
        id: old.run_id(),
        result: rich(),
    })
    .unwrap();
    let before = s.clone();
    assert_eq!(c.try_start(&mut s), Err(StartError::ChannelClosed));
    assert!(!c.is_shutdown_complete());
    assert_eq!(c.poll(&mut s), PollOutcome::Stale(old.run_id()));
    assert!(!c.is_shutdown_complete());
    drop(tx);
    assert_eq!(c.poll(&mut s), PollOutcome::HostFailed);
    assert!(c.is_shutdown_complete());
    assert_eq!(s, before);
}
#[test]
fn assertion_unwind_releases_pending_gate_and_observes_actual_worker_termination() {
    let cleaned = Arc::new(AtomicBool::new(false));
    let witness = cleaned.clone();
    let result = catch_unwind(AssertUnwindSafe(|| {
        let gate = Arc::new(Gate::default());
        let b = Arc::new(MemoryBackend {
            gate: Some(gate.clone()),
            ..Default::default()
        });
        let mut f = Fixture::new(b, Default::default(), vec![gate.clone()]);
        f.cleanup_observed = witness;
        f.start();
        until(|| gate.entered.load(Ordering::SeqCst));
        panic!("의도한 assertion unwind");
    }));
    assert!(result.is_err());
    assert!(cleaned.load(Ordering::SeqCst));
}
#[test]
fn drop_requests_cancel_and_external_owner_observes_real_thread_exit() {
    let gate = Arc::new(Gate::default());
    let b = Arc::new(MemoryBackend {
        gate: Some(gate.clone()),
        ..Default::default()
    });
    let mut f = Fixture::new(b, Default::default(), vec![gate.clone()]);
    f.start();
    until(|| gate.entered.load(Ordering::SeqCst));
    let mut c = f.coordinator.take().unwrap();
    let cancel = c.inflight.as_ref().unwrap().cancel.clone();
    let exit = c.worker_exit.clone();
    // 시험 소유 외부 handle로 관측한다. 생산 UI에 join을 추가한 것이 아니다.
    let worker = c.worker.take().unwrap();
    drop(c);
    assert!(cancel.load(Ordering::SeqCst));
    gate.release();
    until(|| worker.is_finished());
    worker.join().unwrap();
    assert_eq!(exit.load(Ordering::SeqCst), EXIT_NORMAL);
}
