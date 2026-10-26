//! Network Quick Check(Part B) GUI 실행 코디네이터 모듈.
//!
//! 본 모듈은 순수 GUI 상태 머신(`GuiState`)과 실제 `network_core::runner::run_quick` 비동기
//! 진단 실행기 사이를 중재하는 단일 진단 세션 수명주기 코디네이터(`GuiRunCoordinator`)를 구현합니다.
//!
//! ## 핵심 설계 및 불변식
//! - **비동기 격리 및 소유 워커 스레드**:
//!   - GUI 스레드에서의 블로킹(`recv`, `block_on`, `sleep`, `join` 등)을 일체 배제합니다.
//!   - `GuiRunCoordinator::spawn`은 `std::thread::Builder`를 통해 전용 백그라운드 워커 스레드를 생성합니다.
//! - **정확 용량 1 채널 기반 원자적 시작**:
//!   - 시작(`start`) 및 완료(`completion`) 채널은 각각 `std::sync::mpsc::sync_channel(1)`로 고정됩니다.
//!   - 전체 시스템에서 동시에 진행 중이거나 대기 중인 진단 실행은 정확히 1개로 제한됩니다.
//! - **원자적 상태 전이 (Fail-Closed)**:
//!   - `try_start`는 `state.clone()`을 통한 사전 검증(`begin_run`) 및 큐 전송(`try_send`) 성공 시에만
//!     원본 `GuiState`에 반영하며, 실패 시 원본 상태, 이전 결과, 실행 식별자를 일체 변경하지 않습니다.
//! - **취소 플래그 원자적 공유**:
//!   - 진단 취소는 백엔드에 전달된 동일한 `Arc<AtomicBool>` 인스턴스에 `store(true, Ordering::SeqCst)`를 수행하여
//!     비동기 러너와 백엔드에 즉시 전파됩니다.
//! - **결과 보존 및 불변성**:
//!   - 백엔드 및 코어 러너가 반환한 `Result<QuickRunReport, Vec<String>>`는 일체의 가공/필터링/변조 없이 보존됩니다.
//!   - 취소 요청과 정상 완료 간의 경쟁 상태 발생 시 원본 보고서의 `cancelled` 값을 강제로 변경하지 않습니다.
//! - **점진적 안전 드레인 (Closing -> Closed)**:
//!   - `begin_close`는 새 시작을 즉시 거부하고 이미 실행 중인 진단에 취소를 전파하며,
//!     UI의 주기적인 `poll` 호출을 통해 잔여 완료를 처리하고 워커 종료(`is_finished`)를 관측한 후 `Closed`로 전이합니다.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use network_core::runner::{QuickProbeBackend, QuickRunReport, run_quick};

use crate::gui_state::{GuiState, GuiStateError, RunId, RunSnapshot};

/// 워커 호스트 초기화 오류.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostInitError {
    /// 백그라운드 워커 OS 스레드 생성 실패.
    ThreadSpawnFailed,
}

impl fmt::Display for HostInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ThreadSpawnFailed => {
                write!(f, "백그라운드 진단 워커 스레드 생성에 실패했습니다.")
            }
        }
    }
}

impl std::error::Error for HostInitError {}

/// 코디네이터 진단 시작 시도 오류.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartError {
    /// 호스트가 신규 진단 요청을 수락할 수 없는 수명주기 단계임 (Closing, Closed, Failed).
    NotAccepting,
    /// 이미 실행 중인 진단 세션이 존재함.
    AlreadyRunning(RunId),
    /// 시작 큐가 가득 참.
    QueueFull,
    /// 워커 스레드와의 통신 채널이 닫힘.
    ChannelClosed,
    /// GUI 순수 상태 머신 사전 검증 실패.
    State(GuiStateError),
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAccepting => {
                write!(f, "호스트가 현재 신규 진단 요청을 수락할 수 없는 상태입니다.")
            }
            Self::AlreadyRunning(id) => {
                write!(f, "진단 세션(RunId: {id})이 이미 실행 중입니다.")
            }
            Self::QueueFull => {
                write!(f, "진단 시작 요청 큐가 가득 찼습니다.")
            }
            Self::ChannelClosed => {
                write!(f, "워커 스레드 시작 채널이 닫혔습니다.")
            }
            Self::State(err) => {
                write!(f, "상태 검증 오류: {err}")
            }
        }
    }
}

impl std::error::Error for StartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::State(err) => Some(err),
            _ => None,
        }
    }
}

/// 코디네이터 제어 작업(취소, 종료 시작) 오류.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoordinatorError {
    /// 코디네이터의 활성 실행 식별자와 GUI 상태 머신의 활성 식별자가 일치하지 않음.
    ActiveRunMismatch,
    /// 호스트 워커가 고장(Failed) 상태임.
    HostFailed,
}

impl fmt::Display for CoordinatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ActiveRunMismatch => {
                write!(
                    f,
                    "코디네이터의 활성 실행 식별자와 GUI 상태 모델의 활성 식별자가 일치하지 않습니다."
                )
            }
            Self::HostFailed => {
                write!(f, "호스트 워커가 고장 상태입니다.")
            }
        }
    }
}

impl std::error::Error for CoordinatorError {}

/// 호스트 수명주기 상태.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostLifecycle {
    /// 신규 진단 요청 수락 가능.
    Accepting,
    /// 종료 진행 중 (신규 시작 거부, 잔여 진단 드레인 대기).
    Closing,
    /// 정상 종료 완료.
    Closed,
    /// 워커 비정상 종료 또는 통신 두절 등 고장 상태.
    Failed,
}

/// 코디네이터 폴링 결과.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PollOutcome {
    /// 수신된 완료 보고가 없으며 워커가 정상 대기 또는 실행 중임.
    Idle,
    /// 진행 중이던 진단 세션의 최종 완료 보고가 상태 머신에 정상 반영됨.
    Applied(RunId),
    /// 현재 활성 세션과 무관한 구버전(stale) 또는 중복 완료 통보가 무시됨.
    Stale(RunId),
    /// 워커 패닉, 예기치 않은 단절 또는 상태 불일치로 인한 호스트 고장 감지.
    HostFailed,
    /// 드레인이 완료되어 호스트가 정상적으로 종료됨.
    Closed,
}

/// 워커 스레드로 전달되는 진단 시작 명령.
struct StartCommand {
    snapshot: Arc<RunSnapshot>,
    cancel: Arc<AtomicBool>,
}

/// 워커 스레드에서 반환되는 진단 완료 통보 봉투.
struct CompletionEnvelope {
    run_id: RunId,
    result: Result<QuickRunReport, Vec<String>>,
}

/// 현재 진행 중인 진단 세션 정보.
struct InFlight {
    run_id: RunId,
    snapshot: RunSnapshot,
    cancel: Arc<AtomicBool>,
}

/// GUI 진단 실행 코디네이터.
///
/// GUI 이벤트 루프와 비동기 코어 러너 간의 상호작용을 비차단(non-blocking) 방식으로 관리합니다.
pub struct GuiRunCoordinator {
    start_tx: Option<SyncSender<StartCommand>>,
    completion_rx: Option<Receiver<CompletionEnvelope>>,
    worker_handle: Option<JoinHandle<()>>,
    inflight: Option<InFlight>,
    completed_snapshot: Option<RunSnapshot>,
    lifecycle: HostLifecycle,
}

impl GuiRunCoordinator {
    /// 지정된 프로브 백엔드를 사용하는 백그라운드 워커 스레드를 기동하고 새 코디네이터를 생성합니다.
    pub fn spawn(backend: Arc<dyn QuickProbeBackend>) -> Result<Self, HostInitError> {
        let (start_tx, start_rx) = mpsc::sync_channel::<StartCommand>(1);
        let (completion_tx, completion_rx) = mpsc::sync_channel::<CompletionEnvelope>(1);

        let worker_handle = thread::Builder::new()
            .name("gui-coordinator-worker".to_string())
            .spawn(move || {
                run_worker_loop(backend, start_rx, completion_tx);
            })
            .map_err(|_| HostInitError::ThreadSpawnFailed)?;

        Ok(Self {
            start_tx: Some(start_tx),
            completion_rx: Some(completion_rx),
            worker_handle: Some(worker_handle),
            inflight: None,
            completed_snapshot: None,
            lifecycle: HostLifecycle::Accepting,
        })
    }

    /// 현재 GUI 상태 모델을 기반으로 새로운 진단 세션 시작을 시도합니다.
    ///
    /// ## 시작 원자성 불변식
    /// 1. 호스트 수명주기가 `Accepting` 단계이고 현재 진행 중인 실행(`inflight`)이 없는지 확인합니다.
    /// 2. `state.clone()` 사본에서 `candidate.begin_run()`을 사전 호출하여 입력 검증 및 계획 수립을 수행합니다.
    /// 3. 새 `cancel` 원자 플래그 및 확정된 스냅샷을 담은 `StartCommand`를 워커 채널에 `try_send`합니다.
    /// 4. 큐 전송에 성공한 경우에만 `*state = candidate`로 원본 상태를 갱신하고 `inflight`를 확정합니다.
    /// 5. 큐 가득 참, 채널 단절, 검증 실패 등 시작 실패 시 원본 `GuiState` 전체, 이전 결과, 직전 완료 스냅샷은 불변으로 보존됩니다.
    pub fn try_start(&mut self, state: &mut GuiState) -> Result<RunId, StartError> {
        if self.lifecycle != HostLifecycle::Accepting {
            return Err(StartError::NotAccepting);
        }

        if let Some(ref inflight) = self.inflight {
            return Err(StartError::AlreadyRunning(inflight.run_id));
        }

        let start_tx = match self.start_tx.as_ref() {
            Some(tx) => tx,
            None => {
                self.lifecycle = HostLifecycle::Failed;
                return Err(StartError::ChannelClosed);
            }
        };

        let mut candidate = state.clone();
        let snapshot = candidate.begin_run().map_err(StartError::State)?;
        let run_id = snapshot.run_id();

        let cancel = Arc::new(AtomicBool::new(false));
        let cmd = StartCommand {
            snapshot: Arc::new(snapshot.clone()),
            cancel: Arc::clone(&cancel),
        };

        match start_tx.try_send(cmd) {
            Ok(()) => {
                *state = candidate;
                self.inflight = Some(InFlight {
                    run_id,
                    snapshot,
                    cancel,
                });
                self.completed_snapshot = None;
                Ok(run_id)
            }
            Err(TrySendError::Full(_)) => Err(StartError::QueueFull),
            Err(TrySendError::Disconnected(_)) => {
                self.lifecycle = HostLifecycle::Failed;
                Err(StartError::ChannelClosed)
            }
        }
    }

    /// 현재 진행 중인 진단 세션에 대해 취소를 요청합니다.
    ///
    /// - 코디네이터의 `inflight` 식별자와 `state.active_run_id()`의 일치 여부를 먼저 검증합니다.
    /// - 불일치 시 상태를 일체 변경하지 않고 `Err(CoordinatorError::ActiveRunMismatch)`를 반환합니다.
    /// - 활성 세션의 취소 원자 플래그에 `store(true, Ordering::SeqCst)`를 수행하고 상태를 `Cancelling`으로 전이합니다.
    /// - 반복 호출은 멱등하며, 이미 취소 요청된 상태에서는 `Ok(None)`을 반환합니다.
    pub fn request_cancel(&mut self, state: &mut GuiState) -> Result<Option<RunId>, CoordinatorError> {
        if self.lifecycle == HostLifecycle::Failed {
            return Err(CoordinatorError::HostFailed);
        }

        let inflight_id = self.inflight.as_ref().map(|inf| inf.run_id);
        let state_active_id = state.active_run_id();

        if inflight_id != state_active_id {
            return Err(CoordinatorError::ActiveRunMismatch);
        }

        let Some(ref inflight) = self.inflight else {
            return Ok(None);
        };

        inflight.cancel.store(true, Ordering::SeqCst);
        let cancel_res = state.request_cancel();
        Ok(cancel_res)
    }

    /// 코디네이터의 안전한 점진적 종료 절차를 시작합니다.
    ///
    /// - 코디네이터의 `inflight` 식별자와 `state.active_run_id()`의 일치 여부를 먼저 검증합니다.
    /// - 진행 중인 세션이 있는 경우 취소를 즉시 요청합니다.
    /// - 신규 시작 채널을 닫아 추가 시작을 원천 차단하고 수명주기를 `Closing`으로 전이합니다.
    /// - 잔여 완료 수신을 위해 완료 채널은 유지되며, UI 스레드에서의 블로킹 join은 일체 수행하지 않습니다.
    pub fn begin_close(&mut self, state: &mut GuiState) -> Result<(), CoordinatorError> {
        if self.lifecycle == HostLifecycle::Failed {
            return Err(CoordinatorError::HostFailed);
        }

        let inflight_id = self.inflight.as_ref().map(|inf| inf.run_id);
        let state_active_id = state.active_run_id();

        if inflight_id != state_active_id {
            return Err(CoordinatorError::ActiveRunMismatch);
        }

        if matches!(self.lifecycle, HostLifecycle::Closing | HostLifecycle::Closed) {
            return Ok(());
        }

        if let Some(ref inflight) = self.inflight {
            inflight.cancel.store(true, Ordering::SeqCst);
            state.request_cancel();
        }

        self.lifecycle = HostLifecycle::Closing;
        self.start_tx.take();

        Ok(())
    }

    /// 비차단(non-blocking) 방식으로 완료 채널과 워커 스레드 상태를 관측하고 GUI 상태 모델을 갱신합니다.
    ///
    /// ## 폴링 처리 규칙
    /// 1. `try_recv`로 완료 보고 접수 시:
    ///    - 식별자가 현재 `inflight`와 일치하지 않으면 `PollOutcome::Stale(RunId)`를 반환하고 상태를 보존합니다.
    ///    - 상태 모델의 활성 식별자와 불일치 시 호스트를 고장으로 표시하고 작업을 취소합니다.
    ///    - 정상 일치 시 `state.finish_run(run_id, result)`를 호출하고 성공 시 스냅샷을 `completed_snapshot`으로 확정합니다.
    /// 2. 채널이 비어있는 경우(`Empty`):
    ///    - 워커 스레드가 비정상 종료(`is_finished`이나 `inflight` 존재)된 경우 `PollOutcome::HostFailed`를 반환합니다.
    ///    - `Closing` 단계에서 모든 드레인이 완료되고 워커가 종료된 경우 `PollOutcome::Closed`로 전이합니다.
    ///    - 그 외의 정상 실행 중인 경우 `PollOutcome::Idle`을 반환합니다.
    /// 3. 채널이 단절된 경우(`Disconnected`):
    ///    - 잔여 작업이 있으면 명시적 오류 완료로 종결하고 고장 처리합니다.
    pub fn poll(&mut self, state: &mut GuiState) -> PollOutcome {
        if self.lifecycle == HostLifecycle::Closed {
            return PollOutcome::Closed;
        }
        if self.lifecycle == HostLifecycle::Failed {
            return PollOutcome::HostFailed;
        }

        let rx = match self.completion_rx.as_ref() {
            Some(rx) => rx,
            None => {
                if self.lifecycle == HostLifecycle::Closing {
                    let is_worker_finished = self
                        .worker_handle
                        .as_ref()
                        .map(|h| h.is_finished())
                        .unwrap_or(true);
                    if is_worker_finished {
                        let _ = self.worker_handle.take();
                        self.lifecycle = HostLifecycle::Closed;
                        return PollOutcome::Closed;
                    }
                }
                self.lifecycle = HostLifecycle::Failed;
                return PollOutcome::HostFailed;
            }
        };

        match rx.try_recv() {
            Ok(envelope) => {
                let run_id = envelope.run_id;

                let is_matching_inflight = match self.inflight.as_ref() {
                    Some(inf) => inf.run_id == run_id,
                    None => false,
                };

                if !is_matching_inflight {
                    return PollOutcome::Stale(run_id);
                }

                if state.active_run_id() != Some(run_id) {
                    if let Some(ref inf) = self.inflight {
                        inf.cancel.store(true, Ordering::SeqCst);
                    }
                    self.lifecycle = HostLifecycle::Failed;
                    return PollOutcome::HostFailed;
                }

                match state.finish_run(run_id, envelope.result) {
                    Ok(()) => {
                        let inflight = self.inflight.take().expect("inflight exists");
                        self.completed_snapshot = Some(inflight.snapshot);
                        PollOutcome::Applied(run_id)
                    }
                    Err(_) => {
                        self.lifecycle = HostLifecycle::Failed;
                        PollOutcome::HostFailed
                    }
                }
            }
            Err(TryRecvError::Empty) => {
                let is_worker_finished = self
                    .worker_handle
                    .as_ref()
                    .map(|h| h.is_finished())
                    .unwrap_or(true);

                if is_worker_finished {
                    if self.inflight.is_some() {
                        let inflight = self.inflight.take().unwrap();
                        if state.active_run_id() == Some(inflight.run_id) {
                            let _ = state.finish_run(
                                inflight.run_id,
                                Err(vec!["호스트 스레드가 비정상적으로 종료되었습니다.".to_string()]),
                            );
                        }
                        self.lifecycle = HostLifecycle::Failed;
                        PollOutcome::HostFailed
                    } else if self.lifecycle == HostLifecycle::Closing {
                        let _ = self.worker_handle.take();
                        self.lifecycle = HostLifecycle::Closed;
                        PollOutcome::Closed
                    } else {
                        self.lifecycle = HostLifecycle::Failed;
                        PollOutcome::HostFailed
                    }
                } else {
                    PollOutcome::Idle
                }
            }
            Err(TryRecvError::Disconnected) => {
                let is_worker_finished = self
                    .worker_handle
                    .as_ref()
                    .map(|h| h.is_finished())
                    .unwrap_or(true);

                if self.inflight.is_some() {
                    let inflight = self.inflight.take().unwrap();
                    if state.active_run_id() == Some(inflight.run_id) {
                        let _ = state.finish_run(
                            inflight.run_id,
                            Err(vec!["호스트 스레드와의 통신 채널이 단절되었습니다.".to_string()]),
                        );
                    }
                    self.lifecycle = HostLifecycle::Failed;
                    PollOutcome::HostFailed
                } else if self.lifecycle == HostLifecycle::Closing && is_worker_finished {
                    let _ = self.worker_handle.take();
                    self.lifecycle = HostLifecycle::Closed;
                    PollOutcome::Closed
                } else if self.lifecycle == HostLifecycle::Closing {
                    PollOutcome::Idle
                } else {
                    self.lifecycle = HostLifecycle::Failed;
                    PollOutcome::HostFailed
                }
            }
        }
    }

    /// 현재 호스트 수명주기 상태를 반환합니다.
    pub fn lifecycle(&self) -> HostLifecycle {
        self.lifecycle
    }

    /// 가장 최근 성공적으로 완료된 진단 세션의 불변 스냅샷을 참조합니다.
    pub fn completed_snapshot(&self) -> Option<&RunSnapshot> {
        self.completed_snapshot.as_ref()
    }
}

/// 백그라운드 워커 스레드 메인 루프.
///
/// 시작 요청마다 CPU-only Tokio 런타임을 구성하여 코어 비동기 진단을 끝까지 블로킹 실행하고
/// 런타임을 명시적으로 해제한 후 완료 봉투를 전달합니다.
fn run_worker_loop(
    backend: Arc<dyn QuickProbeBackend>,
    start_rx: Receiver<StartCommand>,
    completion_tx: SyncSender<CompletionEnvelope>,
) {
    loop {
        let cmd = match start_rx.recv() {
            Ok(cmd) => cmd,
            Err(_) => {
                // 시작 채널 닫힘 -> 정상 워커 루프 종료
                break;
            }
        };

        let run_id = cmd.snapshot.run_id();

        // CPU-only Tokio 런타임 생성 (I/O, 시계 드라이버 배제)
        let rt_res = tokio::runtime::Builder::new_current_thread().build();
        let result = match rt_res {
            Ok(rt) => {
                let run_res = rt.block_on(run_quick(
                    cmd.snapshot.request(),
                    Arc::clone(&backend),
                    Arc::clone(&cmd.cancel),
                ));
                drop(rt);
                run_res
            }
            Err(rt_err) => {
                Err(vec![format!("비동기 런타임 초기화에 실패했습니다: {rt_err}")])
            }
        };

        let envelope = CompletionEnvelope { run_id, result };
        if completion_tx.send(envelope).is_err() {
            // 완료 채널 닫힘 -> 워커 루프 종료
            break;
        }
    }
}

impl Drop for GuiRunCoordinator {
    fn drop(&mut self) {
        if let Some(ref inflight) = self.inflight {
            inflight.cancel.store(true, Ordering::SeqCst);
        }
        self.start_tx.take();
        self.completion_rx.take();
    }
}

#[cfg(test)]
impl GuiRunCoordinator {
    /// 시험 전용: 백그라운드 워커 스레드가 정상 종료될 때까지 대기하고 관측합니다.
    pub(crate) fn join_worker_for_test(&mut self) {
        if let Some(handle) = self.worker_handle.take() {
            let _ = handle.join();
        }
    }

    /// 시험 전용: 현재 inflight의 취소 플래그 Arc 참조를 가져옵니다 (Arc::ptr_eq 검증용).
    pub(crate) fn inflight_cancel_arc_for_test(&self) -> Option<Arc<AtomicBool>> {
        self.inflight.as_ref().map(|inf| Arc::clone(&inf.cancel))
    }

    /// 시험 전용: 모의 채널로 코디네이터를 직접 구성합니다.
    pub(crate) fn new_mock_coordinator_for_test(
        start_tx: SyncSender<StartCommand>,
        completion_rx: Receiver<CompletionEnvelope>,
        worker_handle: Option<JoinHandle<()>>,
    ) -> Self {
        Self {
            start_tx: Some(start_tx),
            completion_rx: Some(completion_rx),
            worker_handle,
            inflight: None,
            completed_snapshot: None,
            lifecycle: HostLifecycle::Accepting,
        }
    }

    /// 시험 전용: 시작 채널을 닫아 단절 상황을 유도합니다.
    pub(crate) fn drop_start_tx_for_test(&mut self) {
        self.start_tx.take();
    }
}

#[cfg(test)]
#[path = "gui_coordinator_tests.rs"]
mod tests;
