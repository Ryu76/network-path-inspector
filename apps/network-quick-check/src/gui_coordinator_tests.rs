//! Network Quick Check(Part B) GUI 실행 코디네이터 단위 테스트 모듈.
//!
//! ## 원칙 및 안전 규칙
//! - 외부 네트워크 I/O, 실제 DNS 소켓, Win32 API, OS 레지스트리 조회를 일체 수행하지 않는
//!   순수 합성 모의(Mock) 백엔드를 사용하여 코디네이터의 수명주기 및 불변식을 검증합니다.
//! - `sleep`을 통한 시간 기반 경쟁(race condition) 판정을 배제하고, `std::thread::yield_now()`와
//!   유한 반복 관측 루프 및 RAII 해제 가드를 통해 결정론적으로 동기화합니다.
//! - 테스트 종료 시 백그라운드 워커 스레드의 정상 종료를 반드시 관측(`join_worker_for_test`)합니다.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use network_core::quick::{QuickContext, QuickFeature, QuickResult, tcp_to_quick_result};
use network_core::runner::{ProbeFuture, QuickProbeBackend, QuickRunReport};
use network_core::targets::QuickOptions;
use network_core::{HostSnapshot, IcmpMeasurement, TcpMeasurement};

use super::*;
use crate::gui_state::{GuiState, GuiStateError, RunPhase};

/// 테스트용 모의 TCP 응답 생성자 함수 타입.
type TcpResponder =
    Arc<dyn Fn(&QuickContext, SocketAddr, Arc<AtomicBool>) -> Result<QuickResult, Vec<String>> + Send + Sync>;

/// 테스트용 모의 백엔드 내부 상태.
#[derive(Default)]
struct MockState {
    tcp_calls: Vec<(QuickContext, SocketAddr, Arc<AtomicBool>)>,
    icmp_calls: Vec<(QuickContext, IpAddr)>,
    host_calls: Vec<(QuickContext, IpAddr)>,
    tcp_responder: Option<TcpResponder>,
}

/// I/O 없이 메모리 상에서 동작하는 순수 모의 프로브 백엔드.
#[derive(Clone, Default)]
struct TestMockBackend {
    state: Arc<Mutex<MockState>>,
}

impl TestMockBackend {
    fn new() -> Self {
        Self::default()
    }

    fn set_tcp_responder(&self, responder: TcpResponder) {
        self.state.lock().unwrap().tcp_responder = Some(responder);
    }

    fn tcp_calls_count(&self) -> usize {
        self.state.lock().unwrap().tcp_calls.len()
    }

    fn other_calls_count(&self) -> (usize, usize) {
        let st = self.state.lock().unwrap();
        (st.icmp_calls.len(), st.host_calls.len())
    }

    fn last_tcp_cancel_arc(&self) -> Option<Arc<AtomicBool>> {
        self.state
            .lock()
            .unwrap()
            .tcp_calls
            .last()
            .map(|(_, _, cancel)| Arc::clone(cancel))
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
        let responder = {
            let mut st = self.state.lock().unwrap();
            st.tcp_calls.push((ctx.clone(), target, Arc::clone(&cancel)));
            st.tcp_responder.clone()
        };

        Box::pin(async move {
            if let Some(resp) = responder {
                resp(&ctx, target, cancel)
            } else {
                let is_cancelled = cancel.load(Ordering::SeqCst);
                let outcome = if is_cancelled {
                    "CANCELLED"
                } else {
                    "CONNECTED"
                };
                let measurement = TcpMeasurement {
                    target: target.to_string(),
                    outcome: outcome.to_string(),
                    local_address: if is_cancelled {
                        None
                    } else {
                        Some("127.0.0.1:54321".to_string())
                    },
                    elapsed_ms: if is_cancelled { 0 } else { 5 },
                    error_code: None,
                    error_message: None,
                    application_bytes_sent: 0,
                    limitations: vec!["mock-tcp".to_string()],
                };
                tcp_to_quick_result(&ctx, &measurement)
            }
        })
    }

    fn icmp<'a>(
        &'a self,
        ctx: QuickContext,
        target: IpAddr,
        _timeout: Duration,
        _cancel: Arc<AtomicBool>,
    ) -> ProbeFuture<'a> {
        self.state.lock().unwrap().icmp_calls.push((ctx.clone(), target));
        Box::pin(async move {
            let measurement = IcmpMeasurement {
                target: target.to_string(),
                outcome: "REPLY".to_string(),
                elapsed_ms: 5,
                ip_status: Some(0),
                error_code: None,
                rtt_ms: Some(5),
                ttl: Some(64),
                limitations: vec!["mock-icmp".to_string()],
            };
            network_core::measurements::icmp_to_quick_result(&ctx, &measurement)
        })
    }

    fn host<'a>(
        &'a self,
        ctx: QuickContext,
        target: IpAddr,
        _cancel: Arc<AtomicBool>,
    ) -> ProbeFuture<'a> {
        self.state.lock().unwrap().host_calls.push((ctx.clone(), target));
        Box::pin(async move {
            let snapshot = HostSnapshot {
                adapters: serde_json::json!([]),
                routes: serde_json::json!([]),
            };
            network_core::measurements::host_to_quick_result(&ctx, &snapshot, Some(5))
        })
    }
}

/// 테스트 패닉 시에도 워커 블록을 안전하게 해제하는 RAII 가드.
struct UnblockGuard<T: Clone> {
    sender: Option<mpsc::Sender<T>>,
    value: Option<T>,
}

impl<T: Clone> UnblockGuard<T> {
    fn new(sender: mpsc::Sender<T>, value: T) -> Self {
        Self {
            sender: Some(sender),
            value: Some(value),
        }
    }

    fn fire(&mut self) {
        if let (Some(sender), Some(val)) = (self.sender.take(), self.value.take()) {
            let _ = sender.send(val);
        }
    }
}

impl<T: Clone> Drop for UnblockGuard<T> {
    fn drop(&mut self) {
        self.fire();
    }
}

/// 기대하는 PollOutcome에 도달할 때까지 유한 반복 및 yield로 관측하는 헬퍼.
fn poll_until<F>(
    coordinator: &mut GuiRunCoordinator,
    state: &mut GuiState,
    mut predicate: F,
) -> PollOutcome
where
    F: FnMut(&PollOutcome) -> bool,
{
    const MAX_POLL_ITERATIONS: usize = 30_000;
    for _ in 0..MAX_POLL_ITERATIONS {
        let outcome = coordinator.poll(state);
        if predicate(&outcome) {
            return outcome;
        }
        thread::yield_now();
    }
    panic!("지정된 최대 반복 횟수 내에 기대하는 PollOutcome에 도달하지 못했습니다.");
}

/// 기본 유효 대상("127.0.0.1 80") 및 TcpConnect 단일 기능 상태를 구성합니다.
fn create_valid_test_state() -> GuiState {
    let mut state = GuiState::new();
    state
        .replace_targets("127.0.0.1 80")
        .expect("유효 대상 설정 성공");
    let mut opts = QuickOptions::default();
    opts.selected_features = vec![QuickFeature::TcpConnect];
    state.set_options(opts).expect("유효 옵션 설정 성공");
    state
}

#[test]
fn test_try_start_validation_failure_invariance() {
    let backend = Arc::new(TestMockBackend::new());
    let mut coordinator = GuiRunCoordinator::spawn(backend).expect("코디네이터 생성 성공");

    // 1. 기능 미선택(NoFeatures) 검증 실패 시 전체 상태 불변 확인
    let mut state_no_features = GuiState::new();
    state_no_features
        .replace_targets("127.0.0.1 80")
        .expect("대상 설정");
    let mut empty_opts = QuickOptions::default();
    empty_opts.selected_features.clear();
    state_no_features
        .set_options(empty_opts)
        .expect("옵션 설정");

    let err = coordinator
        .try_start(&mut state_no_features)
        .expect_err("기능 미선택 시작 거부");
    assert_eq!(err, StartError::State(GuiStateError::NoFeatures));
    assert_eq!(state_no_features.phase(), RunPhase::Ready);
    assert_eq!(state_no_features.active_run_id(), None);
    assert!(state_no_features.last_result().is_none());
    assert!(coordinator.completed_snapshot().is_none());
    assert_eq!(coordinator.lifecycle(), HostLifecycle::Accepting);

    // 2. 대상 목록 비어있음(InvalidInput) 검증 실패 시 전체 상태 불변 확인
    let mut state_no_targets = GuiState::new();
    let mut opts = QuickOptions::default();
    opts.selected_features = vec![QuickFeature::TcpConnect];
    state_no_targets.set_options(opts).expect("옵션 설정");

    let err2 = coordinator
        .try_start(&mut state_no_targets)
        .expect_err("대상 미입력 시작 거부");
    assert!(matches!(err2, StartError::State(GuiStateError::InvalidInput(_))));
    assert_eq!(state_no_targets.phase(), RunPhase::Ready);

    // 3. 1차 정상 실행 완료 후, 2차 잘못된 시작 시도 시 직전 completed_snapshot 보존 확인
    let mut valid_state = create_valid_test_state();
    let run_id = coordinator
        .try_start(&mut valid_state)
        .expect("1차 정상 시작 성공");
    assert_eq!(valid_state.phase(), RunPhase::Running);

    poll_until(&mut coordinator, &mut valid_state, |outcome| {
        matches!(outcome, PollOutcome::Applied(id) if *id == run_id)
    });
    assert_eq!(valid_state.phase(), RunPhase::Finished);
    assert!(coordinator.completed_snapshot().is_some());
    assert_eq!(coordinator.completed_snapshot().unwrap().run_id(), run_id);

    // 잘못된 옵션으로 2차 시작 시도
    let mut invalid_opts = QuickOptions::default();
    invalid_opts.selected_features.clear();
    valid_state.set_options(invalid_opts).expect("옵션 설정");
    let err3 = coordinator
        .try_start(&mut valid_state)
        .expect_err("2차 잘못된 시작 거부");
    assert_eq!(err3, StartError::State(GuiStateError::NoFeatures));
    // 직전 완료 스냅샷이 그대로 보존되어야 함
    assert_eq!(coordinator.completed_snapshot().unwrap().run_id(), run_id);

    coordinator
        .begin_close(&mut valid_state)
        .expect("종료 시작");
    coordinator.join_worker_for_test();
}

#[test]
fn test_try_start_full_and_disconnected_invariance() {
    // 1. QueueFull 시뮬레이션: 워커 없이 채널 용량 1인 모의 코디네이터에 미리 1건 적재
    let (start_tx, _start_rx) = mpsc::sync_channel::<StartCommand>(1);
    let (_comp_tx, comp_rx) = mpsc::sync_channel::<CompletionEnvelope>(1);

    let mut state = create_valid_test_state();
    let snapshot = state.begin_run().expect("사전 스냅샷 생성");
    let dummy_cmd = StartCommand {
        snapshot: Arc::new(snapshot),
        cancel: Arc::new(AtomicBool::new(false)),
    };
    start_tx.try_send(dummy_cmd).expect("사전 큐 채우기 성공");

    let mut mock_coord =
        GuiRunCoordinator::new_mock_coordinator_for_test(start_tx, comp_rx, None);

    let mut test_state = create_valid_test_state();
    let err = mock_coord
        .try_start(&mut test_state)
        .expect_err("큐 가득 참 시작 실패");
    assert_eq!(err, StartError::QueueFull);
    assert_eq!(test_state.phase(), RunPhase::Ready);
    assert_eq!(test_state.active_run_id(), None);

    // 2. ChannelClosed 시뮬레이션: 시작 채널 닫힘
    mock_coord.drop_start_tx_for_test();
    let err2 = mock_coord
        .try_start(&mut test_state)
        .expect_err("채널 닫힘 시작 실패");
    assert_eq!(err2, StartError::ChannelClosed);
    assert_eq!(test_state.phase(), RunPhase::Ready);
    assert_eq!(mock_coord.lifecycle(), HostLifecycle::Failed);
}

#[test]
fn test_single_execution_limit_and_fast_completion() {
    let backend = Arc::new(TestMockBackend::new());
    let mut coordinator = GuiRunCoordinator::spawn(backend).expect("코디네이터 생성");

    let mut state = create_valid_test_state();
    let run_id = coordinator.try_start(&mut state).expect("시작 성공");

    // 1. 빠른 완료 환경에서도 UI poll 호출 전에는 상태가 Running이어야 함
    assert_eq!(state.phase(), RunPhase::Running);
    assert_eq!(state.active_run_id(), Some(run_id));

    // 2. 이미 실행 중인 진단이 있을 때 재시작은 즉시 AlreadyRunning으로 거부되어야 함
    let mut other_state = create_valid_test_state();
    let err = coordinator
        .try_start(&mut other_state)
        .expect_err("중복 시작 거부");
    assert_eq!(err, StartError::AlreadyRunning(run_id));
    assert_eq!(other_state.phase(), RunPhase::Ready);

    // 3. poll 호출로 완료 적용
    poll_until(&mut coordinator, &mut state, |outcome| {
        matches!(outcome, PollOutcome::Applied(id) if *id == run_id)
    });
    assert_eq!(state.phase(), RunPhase::Finished);
    assert_eq!(coordinator.completed_snapshot().unwrap().run_id(), run_id);

    coordinator.begin_close(&mut state).expect("종료 시작");
    coordinator.join_worker_for_test();
}

#[test]
fn test_selected_features_only_called() {
    let backend = Arc::new(TestMockBackend::new());
    let mut coordinator =
        GuiRunCoordinator::spawn(Arc::clone(&backend) as Arc<dyn QuickProbeBackend>)
            .expect("코디네이터 생성");

    let mut state = create_valid_test_state();
    let run_id = coordinator.try_start(&mut state).expect("시작 성공");

    poll_until(&mut coordinator, &mut state, |outcome| {
        matches!(outcome, PollOutcome::Applied(id) if *id == run_id)
    });

    // 선택된 TcpConnect만 호출되고 Icmp/Host 등 미선택 기능 호출은 0이어야 함
    assert_eq!(backend.tcp_calls_count(), 1);
    assert_eq!(backend.other_calls_count(), (0, 0));

    coordinator.begin_close(&mut state).expect("종료 시작");
    coordinator.join_worker_for_test();
}

#[test]
fn test_identical_cancel_arc_ptr_eq() {
    let backend = Arc::new(TestMockBackend::new());
    let mut coordinator =
        GuiRunCoordinator::spawn(Arc::clone(&backend) as Arc<dyn QuickProbeBackend>)
            .expect("코디네이터 생성");

    let mut state = create_valid_test_state();
    let _run_id = coordinator.try_start(&mut state).expect("시작 성공");

    // 코디네이터 inflight의 취소 Arc와 백엔드에 전달된 취소 Arc가 정확히 동일한 메모리 포인터인지 확인
    let coord_cancel = coordinator
        .inflight_cancel_arc_for_test()
        .expect("inflight cancel Arc 존재");

    // 워커가 프로브 백엔드를 호출할 때까지 유한 대기
    const MAX_WAIT: usize = 10_000;
    let mut backend_cancel = None;
    for _ in 0..MAX_WAIT {
        if let Some(arc) = backend.last_tcp_cancel_arc() {
            backend_cancel = Some(arc);
            break;
        }
        thread::yield_now();
    }
    let backend_cancel = backend_cancel.expect("백엔드에 취소 Arc 전달됨");

    assert!(Arc::ptr_eq(&coord_cancel, &backend_cancel));

    coordinator.begin_close(&mut state).expect("종료 시작");
    coordinator.join_worker_for_test();
}

#[test]
fn test_queued_pre_cancel_before_first_poll() {
    let backend = Arc::new(TestMockBackend::new());
    let mut coordinator = GuiRunCoordinator::spawn(backend).expect("코디네이터 생성");

    let mut state = create_valid_test_state();
    let run_id = coordinator.try_start(&mut state).expect("시작 성공");

    // 첫 poll() 전에 즉시 취소 요청
    let cancel_res = coordinator
        .request_cancel(&mut state)
        .expect("취소 요청 성공");
    assert_eq!(cancel_res, Some(run_id));
    assert_eq!(state.phase(), RunPhase::Cancelling);

    // 취소 반복 호출의 멱등성 검증 (이미 Cancelling이므로 Ok(None))
    let repeat_cancel = coordinator
        .request_cancel(&mut state)
        .expect("반복 취소 요청 성공");
    assert_eq!(repeat_cancel, None);

    poll_until(&mut coordinator, &mut state, |outcome| {
        matches!(outcome, PollOutcome::Applied(id) if *id == run_id)
    });

    assert_eq!(state.phase(), RunPhase::Finished);
    let last_report = state
        .last_result()
        .expect("결과 존재")
        .as_ref()
        .expect("보고서 성공 반환");
    assert!(last_report.cancelled);

    coordinator.begin_close(&mut state).expect("종료 시작");
    coordinator.join_worker_for_test();
}

#[test]
fn test_pending_cleanup_idle_and_result_retention() {
    let (block_tx, block_rx) = mpsc::channel::<()>();
    let block_rx = Arc::new(Mutex::new(block_rx));

    let backend = Arc::new(TestMockBackend::new());
    let block_rx_clone = Arc::clone(&block_rx);
    backend.set_tcp_responder(Arc::new(move |ctx, target, cancel| {
        // block 신호가 올 때까지 대기
        let rx = block_rx_clone.lock().unwrap();
        let _ = rx.recv();
        let measurement = TcpMeasurement {
            target: target.to_string(),
            outcome: "CONNECTED".to_string(),
            local_address: Some("127.0.0.1:54321".to_string()),
            elapsed_ms: 12,
            error_code: None,
            error_message: None,
            application_bytes_sent: 0,
            limitations: vec!["pending-test-mock".to_string()],
        };
        let _ = cancel;
        tcp_to_quick_result(ctx, &measurement)
    }));

    let mut coordinator =
        GuiRunCoordinator::spawn(Arc::clone(&backend) as Arc<dyn QuickProbeBackend>)
            .expect("코디네이터 생성");

    let mut state = create_valid_test_state();
    let run_id = coordinator.try_start(&mut state).expect("시작 성공");

    // 워커가 블록되어 있는 동안 poll()은 Idle이어야 하고 phase는 Running이어야 함
    let outcome = coordinator.poll(&mut state);
    assert_eq!(outcome, PollOutcome::Idle);
    assert_eq!(state.phase(), RunPhase::Running);

    // RAII 가드를 통해 안전하게 신호 발송
    let mut unblock_guard = UnblockGuard::new(block_tx, ());
    unblock_guard.fire();

    poll_until(&mut coordinator, &mut state, |outcome| {
        matches!(outcome, PollOutcome::Applied(id) if *id == run_id)
    });

    assert_eq!(state.phase(), RunPhase::Finished);
    let report = state
        .last_result()
        .expect("결과 존재")
        .as_ref()
        .expect("정상 보고서");
    assert_eq!(report.results.len(), 1);
    assert_eq!(report.results[0].feature, QuickFeature::TcpConnect);

    coordinator.begin_close(&mut state).expect("종료 시작");
    coordinator.join_worker_for_test();
}

#[test]
fn test_stale_completion_and_state_isolation() {
    let (start_tx, _start_rx) = mpsc::sync_channel::<StartCommand>(1);
    let (comp_tx, comp_rx) = mpsc::sync_channel::<CompletionEnvelope>(1);

    let mut coordinator =
        GuiRunCoordinator::new_mock_coordinator_for_test(start_tx, comp_rx, None);

    let mut state = create_valid_test_state();

    // 현재 활성 inflight가 없는 상태에서 엉뚱한 RunId(999)의 완료 통보 봉투 주입
    let dummy_report = QuickRunReport {
        results: Vec::new(),
        cancelled: false,
        limit_reached: false,
        omitted_results: 0,
        errors: Vec::new(),
        invocations: Default::default(),
        max_active_targets: 1,
        targets_started: 1,
        targets_completed: 1,
        serialized_result_bytes: 100,
    };
    let stale_envelope = CompletionEnvelope {
        run_id: RunId::from_u64_for_test(999),
        result: Ok(dummy_report),
    };
    comp_tx.send(stale_envelope).expect("봉투 주입 성공");

    let outcome = coordinator.poll(&mut state);
    assert_eq!(outcome, PollOutcome::Stale(RunId::from_u64_for_test(999)));
    // state 모델 및 completed_snapshot에 일체의 오염이 없어야 함
    assert_eq!(state.phase(), RunPhase::Ready);
    assert!(state.last_result().is_none());
    assert!(coordinator.completed_snapshot().is_none());
}

#[test]
fn test_lifecycle_transitions_and_closing_drain() {
    let backend = Arc::new(TestMockBackend::new());
    let mut coordinator = GuiRunCoordinator::spawn(backend).expect("코디네이터 생성");

    let mut state = create_valid_test_state();
    assert_eq!(coordinator.lifecycle(), HostLifecycle::Accepting);

    let run_id = coordinator.try_start(&mut state).expect("시작 성공");
    assert_eq!(state.phase(), RunPhase::Running);

    // Closing 진입
    coordinator.begin_close(&mut state).expect("종료 시작");
    assert_eq!(coordinator.lifecycle(), HostLifecycle::Closing);
    assert_eq!(state.phase(), RunPhase::Cancelling);

    // Closing 단계에서 신규 시작 시도는 즉시 거부되어야 함
    let mut other_state = create_valid_test_state();
    let err = coordinator
        .try_start(&mut other_state)
        .expect_err("Closing 중 시작 거부");
    assert_eq!(err, StartError::NotAccepting);

    // 완료 드레인 처리
    poll_until(&mut coordinator, &mut state, |outcome| {
        matches!(outcome, PollOutcome::Applied(id) if *id == run_id)
    });
    assert_eq!(state.phase(), RunPhase::Finished);

    // 워커 종료 관측 후 Closed 전이 확인
    poll_until(&mut coordinator, &mut state, |outcome| {
        matches!(outcome, PollOutcome::Closed)
    });
    assert_eq!(coordinator.lifecycle(), HostLifecycle::Closed);

    // Closed 상태에서 재차 poll 호출 시 Closed 반환
    let closed_poll = coordinator.poll(&mut state);
    assert_eq!(closed_poll, PollOutcome::Closed);

    coordinator.join_worker_for_test();
}

#[test]
fn test_active_run_mismatch_and_host_failure() {
    let backend = Arc::new(TestMockBackend::new());
    let mut coordinator = GuiRunCoordinator::spawn(backend).expect("코디네이터 생성");

    let mut state = create_valid_test_state();
    let _run_id = coordinator.try_start(&mut state).expect("시작 성공");

    // 코디네이터는 inflight를 보유하고 있으나 외부에서 다른 state 모델을 전달한 경우
    let mut mismatched_state = create_valid_test_state();
    let cancel_err = coordinator
        .request_cancel(&mut mismatched_state)
        .expect_err("불일치 상태 취소 거부");
    assert_eq!(cancel_err, CoordinatorError::ActiveRunMismatch);

    let close_err = coordinator
        .begin_close(&mut mismatched_state)
        .expect_err("불일치 상태 종료 거부");
    assert_eq!(close_err, CoordinatorError::ActiveRunMismatch);

    // poll 시점에 상태 모델의 활성 ID가 불일치하면 고장 처리
    poll_until(&mut coordinator, &mut mismatched_state, |outcome| {
        matches!(outcome, PollOutcome::HostFailed)
    });
    assert_eq!(coordinator.lifecycle(), HostLifecycle::Failed);

    coordinator.join_worker_for_test();
}

#[test]
fn test_worker_panic_failure_and_existing_report_retention() {
    let backend = Arc::new(TestMockBackend::new());
    let mut coordinator = GuiRunCoordinator::spawn(backend).expect("코디네이터 생성");

    // 1차 정상 완료로 state에 정상 보고서 확보
    let mut state = create_valid_test_state();
    let run_id = coordinator.try_start(&mut state).expect("1차 시작 성공");
    poll_until(&mut coordinator, &mut state, |outcome| {
        matches!(outcome, PollOutcome::Applied(id) if *id == run_id)
    });
    assert_eq!(state.phase(), RunPhase::Finished);
    assert!(state.last_result().is_some());

    coordinator.begin_close(&mut state).expect("1차 종료 시작");
    poll_until(&mut coordinator, &mut state, |outcome| {
        matches!(outcome, PollOutcome::Closed)
    });
    coordinator.join_worker_for_test();

    // 2차: 워커가 즉각 패닉하는 모의 코디네이터 생성
    let (start_tx, _start_rx) = mpsc::sync_channel::<StartCommand>(1);
    let (_comp_tx, comp_rx) = mpsc::sync_channel::<CompletionEnvelope>(1);

    let panic_handle = thread::spawn(|| {
        panic!("테스트용 모의 워커 패닉");
    });
    // 패닉 스레드가 완전히 종료될 때까지 대기
    let _ = panic_handle.join();

    let mut panic_coord =
        GuiRunCoordinator::new_mock_coordinator_for_test(start_tx, comp_rx, None);

    // 워커가 없는 상태에서 poll 시 HostFailed 반환
    let outcome = panic_coord.poll(&mut state);
    assert_eq!(outcome, PollOutcome::HostFailed);

    // 1차 정상 완료 보고서가 후속 고장으로 인해 덮어써지지 않고 그대로 보존되는지 검증
    assert!(state.last_result().is_some());
    let report = state.last_result().unwrap().as_ref().unwrap();
    assert_eq!(report.results.len(), 1);
}

#[test]
fn test_coordinator_drop_safety() {
    let backend = Arc::new(TestMockBackend::new());
    let mut coordinator = GuiRunCoordinator::spawn(backend).expect("코디네이터 생성");

    let mut state = create_valid_test_state();
    let _run_id = coordinator.try_start(&mut state).expect("시작 성공");

    // inflight 작업이 진행 중인 상태에서 코디네이터가 drop되어도 블로킹이나 패닉이 없어야 함
    drop(coordinator);
}

/// RunId의 비공개 생성자를 테스트에서 에뮬레이션하기 위한 헬퍼 트레이트.
trait TestRunIdExt {
    fn from_u64_for_test(val: u64) -> Self;
}

impl TestRunIdExt for RunId {
    fn from_u64_for_test(val: u64) -> Self {
        // RunId는 비공개 필드(u64)이므로 GuiState를 통해 결정론적으로 원하는 RunId를 생성
        let mut state = GuiState::new();
        state.replace_targets("127.0.0.1 80").unwrap();
        let mut opts = QuickOptions::default();
        opts.selected_features = vec![QuickFeature::TcpConnect];
        state.set_options(opts).unwrap();

        let mut last_id = None;
        for _ in 0..val {
            let snap = state.begin_run().unwrap();
            last_id = Some(snap.run_id());
            let report = QuickRunReport {
                results: Vec::new(),
                cancelled: false,
                limit_reached: false,
                omitted_results: 0,
                errors: Vec::new(),
                invocations: Default::default(),
                max_active_targets: 1,
                targets_started: 1,
                targets_completed: 1,
                serialized_result_bytes: 100,
            };
            state.finish_run(snap.run_id(), Ok(report)).unwrap();
        }
        last_id.unwrap()
    }
}
