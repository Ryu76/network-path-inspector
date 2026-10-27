//! GUI 프레젠터와 실행 호스트의 단일 소유 실행 세션 모듈.
//!
//! 본 모듈은 단 하나의 `GuiPresenter`와 선택적인 `GuiRunCoordinator`를
//! 단일 소유하는 `GuiRunSession`을 정의합니다.
//!
//! ## 핵심 설계 및 불변식
//! - **단일 소유 및 비복제**:
//!   `GuiRunSession`은 프레젠터와 실행 코디네이터에 대한 단일 소유자이며,
//!   `Clone`을 구현하지 않아 실행 호스트의 중복 소유를 방지합니다.
//! - **지연 호스트 생성**:
//!   세션 생성 시점에는 어떠한 호스트나 스레드도 생성하지 않으며,
//!   유효한 실행 계획이 수립된 후 최초 `try_start_with` 호출 시점에만 주입된 팩토리를 통해 생성합니다.
//! - **실행 격리 및 입력 잠금**:
//!   진단이 실행 중(`Running`), 취소 중(`Cancelling`), 종료 중/종료됨(`Closing`/`Closed`),
//!   또는 호스트 고장(`Failed`) 상태일 때는 모든 대상 및 옵션 편집 요청을 엄격히 거부합니다.
//! - **불변식 보존 및 실패-닫힘(Fail-Closed)**:
//!   계획 검증 실패나 큐 적재 실패 시 원본 프레젠터와 상태는 일체 변경되지 않으며,
//!   호스트가 고장나더라도 남아있는 리소스와 채널의 drain 정리는 지속할 수 있습니다.
//! - **결과 위조 금지**:
//!   호스트가 없는 상태의 폴링이나 닫기 요청은 진단 완료 보고서를 생성하지 않으며,
//!   보고서의 원문과 취소 여부는 변조 없이 원문 그대로 보존됩니다.

use network_core::quick::QuickFeature;

use crate::gui_coordinator::{CoordinatorError, GuiRunCoordinator, HostLifecycle, PollOutcome};
use crate::gui_presenter::{GuiPresenter, RunBridgeError};
use crate::gui_state::{RunId, RunPhase, RunSnapshot};

/// 세션 호스트 생성 중 발생하는 오류.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionInitError {
    /// 프로브 백엔드를 사용할 수 없음.
    BackendUnavailable,
    /// 호스트 워커 스레드 생성 실패.
    HostSpawnFailed,
}

impl std::fmt::Display for SessionInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BackendUnavailable => write!(f, "진단 프로브 백엔드를 사용할 수 없습니다."),
            Self::HostSpawnFailed => write!(f, "진단 실행 호스트 워커 생성에 실패했습니다."),
        }
    }
}

impl std::error::Error for SessionInitError {}

/// 세션 동작 중 발생하는 통합 오류.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SessionError {
    /// 프레젠터 실행 준비 및 큐 적재 오류.
    Bridge(RunBridgeError),
    /// 호스트 초기화 팩토리 오류.
    Init(SessionInitError),
    /// 실행 코디네이터 동작 오류.
    Coordinator(CoordinatorError),
    /// 진단이 실행 중이거나 취소 중이어서 편집 또는 시작 불가.
    Busy,
    /// 세션 종료 의사가 기록되었거나 이미 종료됨.
    Closing,
    /// 실행 호스트가 고장 상태임.
    HostFailed,
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bridge(e) => write!(f, "실행 브리지 오류: {e}"),
            Self::Init(e) => write!(f, "세션 초기화 오류: {e}"),
            Self::Coordinator(e) => write!(f, "코디네이터 오류: {e}"),
            Self::Busy => write!(f, "진단이 진행 중이거나 취소 처리 중입니다."),
            Self::Closing => write!(f, "세션 종료가 진행 중이거나 이미 종료되었습니다."),
            Self::HostFailed => write!(f, "진단 실행 호스트가 고장 상태입니다."),
        }
    }
}

impl std::error::Error for SessionError {}

/// 세션의 물리적 종료 및 채널 정리 상태.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionShutdown {
    /// 종료가 요청되지 않음.
    NotRequested,
    /// 종료 요청 후 워커 또는 채널 정리 진행 중.
    Pending,
    /// 모든 리소스와 채널이 정상적으로 정리 완료됨.
    Closed,
    /// 호스트 고장 또는 비정상 종료 상태에서 물리 정리 완료됨.
    Failed,
}

/// GUI 프레젠터와 실행 호스트의 단일 소유 실행 세션.
pub(crate) struct GuiRunSession {
    presenter: GuiPresenter,
    host: Option<GuiRunCoordinator>,
    close_requested: bool,
}

impl GuiRunSession {
    /// 주어진 프레젠터를 소유하는 새 세션을 생성합니다.
    ///
    /// 생성 시점에는 백엔드나 호스트를 생성하지 않습니다.
    pub(crate) fn new(presenter: GuiPresenter) -> Self {
        Self {
            presenter,
            host: None,
            close_requested: false,
        }
    }

    /// 소유 중인 프레젠터에 대한 읽기 전용 참조를 반환합니다.
    pub(crate) fn presenter(&self) -> &GuiPresenter {
        &self.presenter
    }

    /// 가장 최근 완료된 실행의 확정 스냅샷을 참조합니다.
    ///
    /// 실행 호스트가 존재하고 완료된 스냅샷이 있을 때에만 반환합니다.
    pub(crate) fn completed_snapshot(&self) -> Option<&RunSnapshot> {
        self.host.as_ref().and_then(|h| h.completed_snapshot())
    }

    /// 실행 호스트의 수명주기 상태를 반환합니다.
    pub(crate) fn host_lifecycle(&self) -> Option<HostLifecycle> {
        self.host.as_ref().map(|h| h.lifecycle())
    }

    /// 세션 종료 요청 여부를 반환합니다.
    pub(crate) fn is_close_requested(&self) -> bool {
        self.close_requested
    }

    /// 세션의 물리적 종료 및 채널 정리 상태를 확인합니다.
    pub(crate) fn shutdown_state(&self) -> SessionShutdown {
        if !self.close_requested {
            return SessionShutdown::NotRequested;
        }
        let Some(host) = &self.host else {
            return SessionShutdown::Closed;
        };
        if !host.is_shutdown_complete() {
            return SessionShutdown::Pending;
        }
        match host.lifecycle() {
            HostLifecycle::Closed => SessionShutdown::Closed,
            HostLifecycle::Failed => SessionShutdown::Failed,
            _ => SessionShutdown::Pending,
        }
    }

    /// 입력 편집이 가능한지 검사합니다.
    fn check_can_edit(&self) -> Result<(), SessionError> {
        if self.close_requested {
            return Err(SessionError::Closing);
        }
        if let Some(host) = &self.host {
            match host.lifecycle() {
                HostLifecycle::Closing | HostLifecycle::Closed => {
                    return Err(SessionError::Closing);
                }
                HostLifecycle::Failed => return Err(SessionError::HostFailed),
                HostLifecycle::Accepting => {}
            }
        }
        if matches!(
            self.presenter.state().phase(),
            RunPhase::Running | RunPhase::Cancelling
        ) {
            return Err(SessionError::Busy);
        }
        Ok(())
    }

    /// 대상 목록 뒤에 신규 입력을 추가합니다 (Typed Proxy).
    pub(crate) fn append_targets(&mut self, text: &str) -> Result<(), SessionError> {
        self.check_can_edit()?;
        self.presenter
            .append_targets(text)
            .map_err(|e| SessionError::Bridge(RunBridgeError::Presenter(e)))
    }

    /// 대상 목록 전체를 새 입력으로 교체합니다 (Typed Proxy).
    pub(crate) fn replace_targets(&mut self, text: &str) -> Result<(), SessionError> {
        self.check_can_edit()?;
        self.presenter
            .replace_targets(text)
            .map_err(|e| SessionError::Bridge(RunBridgeError::Presenter(e)))
    }

    /// 선택된 대상을 목록에서 제거합니다 (Typed Proxy).
    pub(crate) fn remove_selected(&mut self) -> Result<(), SessionError> {
        self.check_can_edit()?;
        self.presenter
            .remove_selected()
            .map_err(|e| SessionError::Bridge(RunBridgeError::Presenter(e)))
    }

    /// 목록 선택 인덱스를 갱신합니다 (Typed Proxy).
    pub(crate) fn set_selected_index(&mut self, index: Option<usize>) -> Result<(), SessionError> {
        self.check_can_edit()?;
        self.presenter
            .set_selected_index(index)
            .map_err(|e| SessionError::Bridge(RunBridgeError::Presenter(e)))
    }

    /// UTF-16 원문 옵션을 손실 없이 검증하고 draft를 갱신합니다 (Typed Proxy).
    pub(crate) fn update_draft_utf16(
        &mut self,
        timeout: &[u16],
        concurrency: &[u16],
        features: Vec<QuickFeature>,
    ) -> Result<(), SessionError> {
        self.check_can_edit()?;
        self.presenter
            .update_draft_utf16(timeout, concurrency, features)
            .map_err(|e| SessionError::Bridge(RunBridgeError::Presenter(e)))
    }

    /// 옵션 draft 문자열을 갱신합니다 (Typed Proxy).
    pub(crate) fn update_draft_options(
        &mut self,
        timeout_ms_str: &str,
        concurrency_str: &str,
        features: Vec<QuickFeature>,
    ) -> Result<(), SessionError> {
        self.check_can_edit()?;
        self.presenter
            .update_draft_options(timeout_ms_str, concurrency_str, features);
        Ok(())
    }

    /// 진단 계획 확인을 수행합니다 (Typed Proxy).
    pub(crate) fn confirm_plan(&mut self) -> Result<(), SessionError> {
        self.check_can_edit()?;
        self.presenter
            .confirm_plan()
            .map_err(|e| SessionError::Bridge(RunBridgeError::Presenter(e)))
    }

    /// 주입된 팩토리를 사용하여 지연 호스트를 생성하거나 기존 호스트를 재사용하여 진단을 시작합니다.
    ///
    /// ## 진행 순서
    /// 1. 종료 의사, Busy(실행 중/취소 중), 호스트 고장 여부를 확인하여 차단.
    /// 2. 원본 프레젠터의 `prepare_run_candidate`를 호출하여 불변 실행 후보 획득 (실패 시 원본 불변, 팩토리 호출 없음).
    /// 3. 호스트가 없는 경우에만 팩토리를 1회 호출하여 새 호스트를 생성하고 세션이 소유.
    /// 4. 호스트 큐에 실행 후보를 적재 (`candidate.enqueue(host)`).
    /// 5. 적재 성공 시에만 프레젠터를 확정하고 실행 식별자를 반환.
    pub(crate) fn try_start_with<F>(&mut self, factory: F) -> Result<RunId, SessionError>
    where
        F: FnOnce() -> Result<GuiRunCoordinator, SessionInitError>,
    {
        if self.close_requested {
            return Err(SessionError::Closing);
        }
        if let Some(host) = &self.host {
            match host.lifecycle() {
                HostLifecycle::Closing | HostLifecycle::Closed => {
                    return Err(SessionError::Closing);
                }
                HostLifecycle::Failed => return Err(SessionError::HostFailed),
                HostLifecycle::Accepting => {}
            }
        }
        if matches!(
            self.presenter.state().phase(),
            RunPhase::Running | RunPhase::Cancelling
        ) {
            return Err(SessionError::Busy);
        }

        let candidate = self
            .presenter
            .prepare_run_candidate()
            .map_err(SessionError::Bridge)?;

        if self.host.is_none() {
            let new_host = factory().map_err(SessionError::Init)?;
            self.host = Some(new_host);
        }

        let host = self.host.as_mut().expect("호스트 존재 보장");
        let (confirmed, run_id) = candidate.enqueue(host).map_err(SessionError::Bridge)?;

        self.presenter = confirmed;
        Ok(run_id)
    }

    /// 실행 중인 진단에 취소 의사를 전달합니다.
    pub(crate) fn request_cancel(&mut self) -> Result<Option<RunId>, SessionError> {
        if let Some(host) = &mut self.host {
            self.presenter
                .request_run_cancel(host)
                .map_err(SessionError::Coordinator)
        } else {
            Ok(None)
        }
    }

    /// 실행 상태 및 완료 통보를 폴링합니다.
    ///
    /// 호스트가 없는 경우 `PollOutcome::Idle`을 반환하며 가짜 보고서를 생성하지 않습니다.
    /// 호스트가 고장 상태인 경우에도 지속적인 drain 폴링이 가능합니다.
    pub(crate) fn poll(&mut self) -> PollOutcome {
        if let Some(host) = &mut self.host {
            self.presenter.poll_run(host)
        } else {
            PollOutcome::Idle
        }
    }

    /// 세션 종료 의사를 기록하고 호스트에 종료를 요청합니다.
    ///
    /// 반복 호출 시 멱등하며, 호스트가 없으면 즉시 종료 완료 상태가 됩니다.
    pub(crate) fn begin_close(&mut self) -> Result<(), SessionError> {
        self.close_requested = true;
        if let Some(host) = &mut self.host {
            self.presenter
                .begin_run_close(host)
                .map_err(SessionError::Coordinator)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
#[path = "gui_run_session_tests.rs"]
mod tests;
