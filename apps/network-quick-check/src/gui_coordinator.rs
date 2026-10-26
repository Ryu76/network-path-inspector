//! GUI와 실제 Core runner 사이의 단일 실행 호스트. 현재 독립 libtest에서만 소비한다.
//! UI는 비차단 관측, worker는 runtime 소유와 runner drain을 담당한다.
//! Failed와 정리 진행은 별개다. Drop의 취소 요청은 동기 drain 완료를 뜻하지 않는다.
use crate::gui_state::{GuiState, GuiStateError, RunId, RunSnapshot};
use network_core::runner::{QuickProbeBackend, QuickRunReport, run_quick};
use std::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError};
use std::thread::{self, JoinHandle};

type RunResult = Result<QuickRunReport, Vec<String>>;
const EXIT_PENDING: u8 = 0;
const EXIT_NORMAL: u8 = 1;
const EXIT_PANICKED: u8 = 2;
const EXIT_RUNTIME_FAILED: u8 = 3;
const LOST_COMPLETION: &str = "진단 호스트의 완료 전달이 유실되었습니다.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostRuntimeMode {
    CpuOnlyPerRun,
    NativeIoOnce,
}

pub(crate) fn build_runtime(mode: HostRuntimeMode) -> std::io::Result<tokio::runtime::Runtime> {
    let mut builder = tokio::runtime::Builder::new_current_thread();
    if mode == HostRuntimeMode::NativeIoOnce {
        builder.enable_io();
        builder.enable_time();
    }
    builder.build()
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HostInitError {
    ThreadSpawnFailed,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StartError {
    NotAccepting,
    AlreadyRunning(RunId),
    QueueFull,
    ChannelClosed,
    State(GuiStateError),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CoordinatorError {
    ActiveRunMismatch,
    HostFailed,
}
impl fmt::Display for HostInitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("진단 워커 생성 실패")
    }
}
impl std::error::Error for HostInitError {}
impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotAccepting => "새 실행 수락 불가",
            Self::AlreadyRunning(_) => "진단 실행 중",
            Self::QueueFull => "시작 큐 가득 참",
            Self::ChannelClosed => "시작 채널 단절",
            Self::State(_) => "진단 상태 검증 실패",
        })
    }
}
impl std::error::Error for StartError {}
impl fmt::Display for CoordinatorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ActiveRunMismatch => "활성 실행 불일치",
            Self::HostFailed => "진단 호스트 고장",
        })
    }
}
impl std::error::Error for CoordinatorError {}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostLifecycle {
    Accepting,
    Closing,
    Closed,
    Failed,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PollOutcome {
    Idle,
    Applied(RunId),
    Stale(RunId),
    HostFailed,
    Closed,
}
struct StartCommand {
    snapshot: RunSnapshot,
    cancel: Arc<AtomicBool>,
}
struct Completion {
    terminal_host_failure: bool,
    id: RunId,
    result: RunResult,
}
struct InFlight {
    snapshot: RunSnapshot,
    cancel: Arc<AtomicBool>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum CompletionEnd {
    Open,
    Drained,
    Lost,
}
#[cfg(test)]
type Hook = Arc<dyn Fn() + Send + Sync>;
#[cfg(test)]
type ResultHook = Arc<dyn Fn(&RunResult) + Send + Sync>;
#[cfg(test)]
type RuntimeFactory = Arc<dyn Fn() -> std::io::Result<tokio::runtime::Runtime> + Send + Sync>;
/// 동일 worker loop의 작은 경계를 시험한다. runner/poll 복제는 없다.
#[derive(Default)]
struct WorkerConfig {
    #[cfg(test)]
    before_run: Option<Hook>,
    #[cfg(test)]
    on_worker_idle: Option<Hook>,
    #[cfg(test)]
    after_send: Option<Hook>,
    #[cfg(test)]
    before_exit: Option<Hook>,
    #[cfg(test)]
    runtime_factory: Option<RuntimeFactory>,
    #[cfg(test)]
    on_result: Option<ResultHook>,
    #[cfg(test)]
    omit_completion_after_accept: bool,
    #[cfg(test)]
    on_runtime_drop: Option<Hook>,
}
pub(crate) struct GuiRunCoordinator {
    runtime_mode: HostRuntimeMode,
    start_tx: Option<SyncSender<StartCommand>>,
    completion_rx: Option<Receiver<Completion>>,
    worker: Option<JoinHandle<()>>,
    worker_exit: Arc<AtomicU8>,
    completion_end: CompletionEnd,
    inflight: Option<InFlight>,
    completed_snapshot: Option<RunSnapshot>,
    // 잘못된 state로 완료를 받았을 때도 원문을 버리거나 다른 state에 강제 적용하지 않는다.
    unapplied_completion: Option<(RunSnapshot, RunResult)>,
    lifecycle: HostLifecycle,
}
impl GuiRunCoordinator {
    pub(crate) fn spawn(backend: Arc<dyn QuickProbeBackend>) -> Result<Self, HostInitError> {
        Self::spawn_with_mode(
            HostRuntimeMode::CpuOnlyPerRun,
            backend,
            WorkerConfig::default(),
            |job| {
                thread::Builder::new()
                    .name("quick-gui-runner".into())
                    .spawn(job)
            },
        )
    }
    pub(crate) fn spawn_native(backend: Arc<dyn QuickProbeBackend>) -> Result<Self, HostInitError> {
        Self::spawn_with_mode(
            HostRuntimeMode::NativeIoOnce,
            backend,
            WorkerConfig::default(),
            |job| {
                thread::Builder::new()
                    .name("quick-gui-runner-native".into())
                    .spawn(job)
            },
        )
    }
    #[cfg(test)]
    fn spawn_with<F>(
        backend: Arc<dyn QuickProbeBackend>,
        config: WorkerConfig,
        spawn: F,
    ) -> Result<Self, HostInitError>
    where
        F: FnOnce(Box<dyn FnOnce() + Send>) -> std::io::Result<JoinHandle<()>>,
    {
        Self::spawn_with_mode(HostRuntimeMode::CpuOnlyPerRun, backend, config, spawn)
    }
    fn spawn_with_mode<F>(
        mode: HostRuntimeMode,
        backend: Arc<dyn QuickProbeBackend>,
        config: WorkerConfig,
        spawn: F,
    ) -> Result<Self, HostInitError>
    where
        F: FnOnce(Box<dyn FnOnce() + Send>) -> std::io::Result<JoinHandle<()>>,
    {
        let (start_tx, start_rx) = mpsc::sync_channel(1);
        let (completion_tx, completion_rx) = mpsc::sync_channel(1);
        let worker_exit = Arc::new(AtomicU8::new(EXIT_PENDING));
        let exit = Arc::clone(&worker_exit);
        let job = Box::new(move || {
            // backend/config의 destructor도 catch 경계 안이다. 전역 hook 변경/원시 payload 반사는 없다.
            let code = match catch_unwind(AssertUnwindSafe(move || {
                worker_loop(mode, backend, config, start_rx, completion_tx)
            })) {
                Ok(code) => code,
                Err(payload) => {
                    exit.store(EXIT_PANICKED, Ordering::SeqCst);
                    drop(payload);
                    return;
                }
            };
            exit.store(code, Ordering::SeqCst);
        });
        let worker = spawn(job).map_err(|_| HostInitError::ThreadSpawnFailed)?;
        Ok(Self {
            runtime_mode: mode,
            start_tx: Some(start_tx),
            completion_rx: Some(completion_rx),
            worker: Some(worker),
            worker_exit,
            completion_end: CompletionEnd::Open,
            inflight: None,
            completed_snapshot: None,
            unapplied_completion: None,
            lifecycle: HostLifecycle::Accepting,
        })
    }
    pub(crate) fn try_start(&mut self, state: &mut GuiState) -> Result<RunId, StartError> {
        if self.lifecycle != HostLifecycle::Accepting {
            return Err(StartError::NotAccepting);
        }
        if let Some(active) = &self.inflight {
            return Err(StartError::AlreadyRunning(active.snapshot.run_id()));
        }
        let mut candidate = state.clone();
        let snapshot = candidate.begin_run().map_err(StartError::State)?;
        let id = snapshot.run_id();
        let cancel = Arc::new(AtomicBool::new(false));
        let Some(tx) = &self.start_tx else {
            self.fail();
            return Err(StartError::ChannelClosed);
        };
        match tx.try_send(StartCommand {
            snapshot: snapshot.clone(),
            cancel: Arc::clone(&cancel),
        }) {
            Ok(()) => {
                *state = candidate;
                self.inflight = Some(InFlight { snapshot, cancel });
                self.completed_snapshot = None;
                Ok(id)
            }
            Err(TrySendError::Full(_)) => Err(StartError::QueueFull),
            Err(TrySendError::Disconnected(_)) => {
                self.fail();
                Err(StartError::ChannelClosed)
            }
        }
    }
    fn check_active(&self, state: &GuiState) -> Result<(), CoordinatorError> {
        let expected = self.inflight.as_ref().map(|r| &r.snapshot);
        if expected != state.active_snapshot() {
            return Err(CoordinatorError::ActiveRunMismatch);
        }
        Ok(())
    }
    pub(crate) fn request_cancel(
        &mut self,
        state: &mut GuiState,
    ) -> Result<Option<RunId>, CoordinatorError> {
        if self.lifecycle == HostLifecycle::Failed {
            self.fail();
            return Err(CoordinatorError::HostFailed);
        }
        self.check_active(state)?;
        if let Some(active) = &self.inflight {
            active.cancel.store(true, Ordering::SeqCst);
            Ok(state.request_cancel())
        } else {
            Ok(None)
        }
    }
    pub(crate) fn begin_close(&mut self, state: &mut GuiState) -> Result<(), CoordinatorError> {
        // Failed에서도 정리를 거부하지 않는다. 전달된 다른 state는 수정하지 않는다.
        if self.lifecycle == HostLifecycle::Failed {
            self.fail();
            return Ok(());
        }
        self.check_active(state)?;
        if self.lifecycle == HostLifecycle::Closed {
            return Ok(());
        }
        if let Some(active) = &self.inflight {
            active.cancel.store(true, Ordering::SeqCst);
            state.request_cancel();
        }
        self.start_tx.take();
        self.lifecycle = HostLifecycle::Closing;
        Ok(())
    }
    fn fail(&mut self) {
        self.lifecycle = HostLifecycle::Failed;
        if let Some(active) = &self.inflight {
            active.cancel.store(true, Ordering::SeqCst);
        }
        self.start_tx.take();
    }
    fn apply(&mut self, state: &mut GuiState, result: RunResult) -> PollOutcome {
        let Some(active) = self.inflight.take() else {
            self.fail();
            return PollOutcome::HostFailed;
        };
        let id = active.snapshot.run_id();
        if state.active_snapshot() != Some(&active.snapshot) {
            active.cancel.store(true, Ordering::SeqCst);
            self.unapplied_completion = Some((active.snapshot, result));
            self.fail();
            return PollOutcome::HostFailed;
        }
        // ID/phase는 같은 호출 안에서 불변. 현행 모델 공개 API로는 검증 뒤 실패하지 않는다.
        if state.finish_run(id, result).is_err() {
            self.fail();
            return PollOutcome::HostFailed;
        }
        self.completed_snapshot = Some(active.snapshot);
        PollOutcome::Applied(id)
    }
    fn received(&mut self, state: &mut GuiState, completion: Completion) -> PollOutcome {
        if self.inflight.as_ref().map(|a| a.snapshot.run_id()) != Some(completion.id) {
            return PollOutcome::Stale(completion.id);
        }
        // 고정 native 초기화 실패는 thread 정리 전에도 신규 수락을 닫는다.
        // 일반 Core Err/CPU 초기화 Err와 구별하며 원문 결과는 그대로 적용한다.
        if completion.terminal_host_failure {
            self.fail();
        }
        self.apply(state, completion.result)
    }
    fn observe_worker_exit(&mut self) {
        if self.worker.as_ref().is_some_and(JoinHandle::is_finished) {
            self.worker.take(); // 종료 확인 뒤 해제, UI join 없음.
            if self.worker_exit.load(Ordering::SeqCst) != EXIT_NORMAL
                || self.lifecycle == HostLifecycle::Accepting
            {
                self.fail();
            }
        }
    }
    pub(crate) fn poll(&mut self, state: &mut GuiState) -> PollOutcome {
        self.poll_with_after_empty(state, |_| {})
    }
    /// 시험 hook은 같은 생산 poll의 첫 Empty 직후에만 삽입하며 기본 경로는 no-op다.
    fn poll_with_after_empty<F: FnOnce(&Self)>(
        &mut self,
        state: &mut GuiState,
        after_empty: F,
    ) -> PollOutcome {
        if self.lifecycle == HostLifecycle::Closed {
            return PollOutcome::Closed;
        }
        let mut receive = self.completion_rx.as_ref().map(Receiver::try_recv);
        if matches!(receive, Some(Err(TryRecvError::Empty))) {
            after_empty(self);
            self.observe_worker_exit();
            // 첫 Empty와 worker 종료 사이 실제 완료가 enqueue될 수 있으므로 반드시 재독한다.
            if self.worker.is_none() {
                receive = self.completion_rx.as_ref().map(Receiver::try_recv);
            }
        }
        match receive {
            Some(Ok(completion)) => {
                let outcome = self.received(state, completion);
                self.observe_worker_exit();
                return outcome;
            }
            Some(Err(TryRecvError::Disconnected)) => self.completion_end = CompletionEnd::Drained,
            Some(Err(TryRecvError::Empty)) => {}
            None => {
                self.completion_end = CompletionEnd::Lost;
                self.fail();
            }
        }
        self.observe_worker_exit();
        // 전달 유실이 있어도 runner/worker 종료 관측 전에 실행 완료를 만들지 않는다.
        if self.worker.is_none()
            && self.completion_end != CompletionEnd::Open
            && self.inflight.is_some()
        {
            self.fail();
            self.apply(state, Err(vec![LOST_COMPLETION.into()]));
        }
        if self.is_shutdown_complete() && self.lifecycle == HostLifecycle::Closing {
            if self.completion_end == CompletionEnd::Drained
                && self.worker_exit.load(Ordering::SeqCst) == EXIT_NORMAL
            {
                self.lifecycle = HostLifecycle::Closed;
            } else {
                self.fail();
            }
        }
        match self.lifecycle {
            HostLifecycle::Failed => PollOutcome::HostFailed,
            HostLifecycle::Closed => PollOutcome::Closed,
            _ => PollOutcome::Idle,
        }
    }
    pub(crate) fn lifecycle(&self) -> HostLifecycle {
        self.lifecycle
    }
    pub(crate) fn completed_snapshot(&self) -> Option<&RunSnapshot> {
        self.completed_snapshot.as_ref()
    }
    /// 물리적 종료와 채널 최종 상태. Lost는 정상 drain이 아니라 Failed의 유실 기록이다.
    pub(crate) fn is_shutdown_complete(&self) -> bool {
        self.worker.is_none()
            && self.start_tx.is_none()
            && self.inflight.is_none()
            && self.completion_end != CompletionEnd::Open
    }
}
fn worker_loop(
    mode: HostRuntimeMode,
    backend: Arc<dyn QuickProbeBackend>,
    config: WorkerConfig,
    start_rx: Receiver<StartCommand>,
    completion_tx: SyncSender<Completion>,
) -> u8 {
    let mut native_runtime: Option<tokio::runtime::Runtime> = None;
    let mut exit_code = EXIT_NORMAL;
    #[cfg(test)]
    if let Some(hook) = &config.on_worker_idle {
        hook();
    }
    while let Ok(cmd) = start_rx.recv() {
        #[cfg(test)]
        if let Some(hook) = &config.before_run {
            hook();
        }
        #[cfg(test)]
        if config.omit_completion_after_accept {
            break;
        }
        let (result, should_continue) = match mode {
            HostRuntimeMode::CpuOnlyPerRun => {
                #[cfg(test)]
                let runtime = if let Some(factory) = &config.runtime_factory {
                    factory()
                } else {
                    build_runtime(mode)
                };
                #[cfg(not(test))]
                let runtime = build_runtime(mode);
                let res = match runtime {
                    Ok(runtime) => {
                        let res = runtime.block_on(run_quick(
                            cmd.snapshot.request(),
                            Arc::clone(&backend),
                            Arc::clone(&cmd.cancel),
                        ));
                        drop(runtime);
                        #[cfg(test)]
                        if let Some(hook) = &config.on_runtime_drop {
                            hook();
                        }
                        res
                    }
                    Err(_) => Err(vec!["비동기 런타임 초기화에 실패했습니다.".into()]),
                };
                (res, true)
            }
            HostRuntimeMode::NativeIoOnce => {
                if native_runtime.is_none() {
                    #[cfg(test)]
                    let created = if let Some(factory) = &config.runtime_factory {
                        factory()
                    } else {
                        build_runtime(mode)
                    };
                    #[cfg(not(test))]
                    let created = build_runtime(mode);
                    match created {
                        Ok(runtime) => {
                            native_runtime = Some(runtime);
                        }
                        Err(_) => {
                            exit_code = EXIT_RUNTIME_FAILED;
                            let res = Err(vec!["비동기 런타임 초기화에 실패했습니다.".into()]);
                            #[cfg(test)]
                            if let Some(hook) = &config.on_result {
                                hook(&res);
                            }
                            let _ = completion_tx.send(Completion {
                                terminal_host_failure: true,
                                id: cmd.snapshot.run_id(),
                                result: res,
                            });
                            break;
                        }
                    }
                }
                let runtime = native_runtime.as_ref().unwrap();
                let res = runtime.block_on(run_quick(
                    cmd.snapshot.request(),
                    Arc::clone(&backend),
                    Arc::clone(&cmd.cancel),
                ));
                (res, true)
            }
        };
        if !should_continue {
            break;
        }
        #[cfg(test)]
        if let Some(hook) = &config.on_result {
            hook(&result);
        }
        if completion_tx
            .send(Completion {
                terminal_host_failure: false,
                id: cmd.snapshot.run_id(),
                result,
            })
            .is_err()
        {
            break;
        }
        #[cfg(test)]
        if let Some(hook) = &config.after_send {
            hook();
        }
    }
    #[cfg(test)]
    let had_runtime = native_runtime.is_some();
    drop(native_runtime);
    #[cfg(test)]
    if had_runtime && let Some(hook) = &config.on_runtime_drop {
        hook();
    }
    #[cfg(test)]
    if let Some(hook) = &config.before_exit {
        hook();
    }
    // backend/config를 포함한 소유 값은 바깥 catch_unwind 안에서 해제된다.
    exit_code
}
impl Drop for GuiRunCoordinator {
    fn drop(&mut self) {
        if let Some(active) = &self.inflight {
            active.cancel.store(true, Ordering::SeqCst);
        }
        self.start_tx.take();
        self.completion_rx.take();
        // 즉시 thread 종료/OS 회수를 보장하지 않는다. non-UI drain owner는 후속 연결 범위다.
    }
}
#[cfg(test)]
#[path = "gui_coordinator_tests.rs"]
mod tests;
