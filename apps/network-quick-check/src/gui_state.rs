//! Network Quick Check(Part B) 순수 GUI 상태 모델 모듈.
//!
//! 본 모듈은 GUI 뷰나 비동기 런타임과 완전히 격리된 순수 상태 머신(`GuiState`)을 정의합니다.
//!
//! ## 핵심 설계 및 불변식
//! - **완전한 순수 상태 모델**: I/O, OS 호출, 비동기 런타임, 스레드, 시계 조회를 일체 수행하지 않습니다.
//! - **단일 진실 공급원 준수**: 대상 입력 분석, 검증, 중복 제거, 진단 계획 수립은 `network_core::targets`의
//!   `parse_target_list` 및 `build_quick_plan`을 그대로 재사용합니다.
//! - **원자적 상태 전이**: 파싱, 검증, 또는 계획 수립 실패 시 기존 대상 목록, 옵션, 실행 식별자, 직전 결과는
//!   어떠한 부분 변경도 없이 완전히 불변으로 유지됩니다 (Fail-Closed).
//! - **실행 수명주기 및 잠금**:
//!   - `Ready` / `Finished`: 대상 목록 및 옵션(draft) 편집 가능, 새 실행 시작(`begin_run`) 가능.
//!   - `Running` / `Cancelling`: 대상 편집, 옵션 변경, 재시작 시도 시 즉시 `GuiStateError::Busy`를 반환하고 상태 불변.
//! - **결정적 실행 식별자**: 성공한 `begin_run` 호출에서만 `RunId`가 1부터 단조 증가하며,
//!   `session_id`는 `"gui-run-N"`으로 결정적으로 생성됩니다.
//! - **취소 및 완료 통보 처리**:
//!   - `request_cancel`은 효과 데이터(상태 전이 `Cancelling` 및 활성 `RunId` 반환)만 다루며 비동기 작업을 강제 종료하지 않습니다.
//!   - `finish_run`은 현재 활성 `RunId`와 일치하는 완료 보고만 수용하며, 비활성 또는 stale 완료는
//!     `GuiStateError::InvalidCompletion`으로 거부하고 상태를 보존합니다.
//!   - 취소 요청 후 정상 완료 보고서가 도착하는 경쟁 상태(race condition)를 허용하며 보고서의 `cancelled` 필드를
//!     UI 상태로 임의 변조하지 않고 원문 그대로 보존합니다.

use std::fmt;

use network_core::runner::{DEFAULT_MAX_RESULT_BYTES, QuickRunReport, QuickRunRequest};
use network_core::targets::{
    InputError, MAX_INPUT_BYTES, QuickOptions, QuickPlan, QuickTarget, build_quick_plan,
    parse_target_list,
};

/// GUI 진단 실행 식별자 (내부 u64 카운터 기반, 비공개 필드).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RunId(u64);

impl RunId {
    /// 식별자의 내부 정수값을 반환합니다.
    pub const fn as_u64(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for RunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// GUI 진단 실행 단계.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RunPhase {
    /// 진단 준비 완료 상태 (대상 및 옵션 편집 가능).
    Ready,
    /// 진단 실행 중.
    Running,
    /// 취소 요청 전달됨 (비동기 정리 완료 대기).
    Cancelling,
    /// 진단 완료 상태 (보고서 또는 오류 보관).
    Finished,
}

/// GUI 진단 실행 시작 시 확정되는 불변 스냅샷 (내부 필드 비공개).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSnapshot {
    run_id: RunId,
    request: QuickRunRequest,
    plan: QuickPlan,
}

impl RunSnapshot {
    /// 실행 식별자를 반환합니다.
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// 확정된 진단 실행 요청 DTO를 참조합니다.
    pub const fn request(&self) -> &QuickRunRequest {
        &self.request
    }

    /// 확정된 진단 계획 DTO를 참조합니다.
    pub const fn plan(&self) -> &QuickPlan {
        &self.plan
    }
}

/// GUI 순수 상태 모델 동작 중 발생하는 오류.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GuiStateError {
    /// 진단이 실행 중이거나 취소 중이어서 편집 또는 재시작이 불가능함.
    Busy,
    /// 진단 기능이 하나도 선택되지 않음.
    NoFeatures,
    /// 대상 목록 또는 옵션 검증 실패.
    InvalidInput(Vec<InputError>),
    /// 대상 인덱스가 범위를 벗어남.
    InvalidIndex,
    /// 실행 식별자(u64) 카운터가 고갈됨.
    IdExhausted,
    /// 활성 실행이 없거나 식별자가 일치하지 않는 비정상/stale 완료 통보.
    InvalidCompletion,
}

impl fmt::Display for GuiStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => write!(f, "진단이 진행 중이거나 취소 처리 중입니다."),
            Self::NoFeatures => write!(f, "진단 기능이 하나도 선택되지 않았습니다."),
            Self::InvalidInput(errors) => {
                write!(f, "입력 검증에 실패했습니다: ")?;
                for (i, err) in errors.iter().enumerate() {
                    if i > 0 {
                        write!(f, "; ")?;
                    }
                    write!(f, "[행 {}] {}", err.line, err.message)?;
                }
                Ok(())
            }
            Self::InvalidIndex => write!(f, "대상 인덱스가 범위를 벗어났습니다."),
            Self::IdExhausted => write!(f, "실행 식별자 카운터가 최댓값에 도달했습니다."),
            Self::InvalidCompletion => {
                write!(
                    f,
                    "활성 실행 식별자와 일치하지 않거나 이미 완료된 실행입니다."
                )
            }
        }
    }
}

impl std::error::Error for GuiStateError {}

/// Network Quick Check 순수 GUI 상태 모델.
///
/// 네트워크 I/O, 스레드, 비동기 런타임, 시계, 파일 접근이 일체 배제된 순수 상태 머신입니다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuiState {
    targets: Vec<QuickTarget>,
    options: QuickOptions,
    phase: RunPhase,
    next_run_counter: u64,
    active_snapshot: Option<RunSnapshot>,
    last_result: Option<Result<QuickRunReport, Vec<String>>>,
}

impl GuiState {
    /// 기본 초기 상태를 갖는 새로운 GuiState를 생성합니다.
    pub fn new() -> Self {
        Self {
            targets: Vec::new(),
            options: QuickOptions::default(),
            phase: RunPhase::Ready,
            next_run_counter: 0,
            active_snapshot: None,
            last_result: None,
        }
    }

    /// 현재 대상 목록 전체를 새 입력 문자열로 교체합니다.
    ///
    /// - `Running` 또는 `Cancelling` 단계에서는 `Err(GuiStateError::Busy)`를 반환합니다.
    /// - 코어 파서(`parse_target_list`)를 통과한 경우에만 교체되며, 빈 문자열이나 형식 오류 시
    ///   `Err(GuiStateError::InvalidInput)`을 반환하고 기존 목록은 완전히 보존됩니다.
    pub fn replace_targets(&mut self, input: &str) -> Result<(), GuiStateError> {
        if matches!(self.phase, RunPhase::Running | RunPhase::Cancelling) {
            return Err(GuiStateError::Busy);
        }
        let parsed = parse_target_list(input).map_err(GuiStateError::InvalidInput)?;
        self.targets = parsed;
        Ok(())
    }

    /// 현재 대상 목록 뒤에 신규 입력 문자열을 이어붙여 재검증합니다.
    ///
    /// - `Running` 또는 `Cancelling` 단계에서는 `Err(GuiStateError::Busy)`를 반환합니다.
    /// - 현재 목록 각 대상의 원문(`raw_input`)을 개행(LF)으로 잇고 신규 텍스트를 결합한 후보 전체의
    ///   UTF-8 바이트 크기가 `MAX_INPUT_BYTES`(32,768 바이트) 이하인지 `checked_add`로 먼저 검증합니다.
    /// - 결합된 후보 전체를 코어 파서로 재검증하여 중복 제거 및 상한 검사를 수행하며,
    ///   파싱 실패 또는 크기 초과 시 전체 상태는 불변으로 유지됩니다.
    pub fn append_targets(&mut self, input: &str) -> Result<(), GuiStateError> {
        if matches!(self.phase, RunPhase::Running | RunPhase::Cancelling) {
            return Err(GuiStateError::Busy);
        }

        if self.targets.is_empty() {
            let parsed = parse_target_list(input).map_err(GuiStateError::InvalidInput)?;
            self.targets = parsed;
            return Ok(());
        }

        let mut total_bytes: usize = 0;
        for (i, t) in self.targets.iter().enumerate() {
            if i > 0 {
                total_bytes = total_bytes.checked_add(1).ok_or_else(|| {
                    GuiStateError::InvalidInput(vec![InputError {
                        line: 0,
                        message: "입력 바이트 합산 오버플로가 발생했습니다.".to_string(),
                    }])
                })?;
            }
            total_bytes = total_bytes.checked_add(t.raw_input.len()).ok_or_else(|| {
                GuiStateError::InvalidInput(vec![InputError {
                    line: 0,
                    message: "입력 바이트 합산 오버플로가 발생했습니다.".to_string(),
                }])
            })?;
        }
        total_bytes = total_bytes.checked_add(1).ok_or_else(|| {
            GuiStateError::InvalidInput(vec![InputError {
                line: 0,
                message: "입력 바이트 합산 오버플로가 발생했습니다.".to_string(),
            }])
        })?;
        total_bytes = total_bytes.checked_add(input.len()).ok_or_else(|| {
            GuiStateError::InvalidInput(vec![InputError {
                line: 0,
                message: "입력 바이트 합산 오버플로가 발생했습니다.".to_string(),
            }])
        })?;

        if total_bytes > MAX_INPUT_BYTES {
            return Err(GuiStateError::InvalidInput(vec![InputError {
                line: 0,
                message: format!(
                    "입력 크기({total_bytes} 바이트)가 최대 허용 크기({MAX_INPUT_BYTES} 바이트)를 초과했습니다."
                ),
            }]));
        }

        let mut candidate = String::with_capacity(total_bytes);
        for (i, t) in self.targets.iter().enumerate() {
            if i > 0 {
                candidate.push('\n');
            }
            candidate.push_str(&t.raw_input);
        }
        candidate.push('\n');
        candidate.push_str(input);

        let parsed = parse_target_list(&candidate).map_err(GuiStateError::InvalidInput)?;
        self.targets = parsed;
        Ok(())
    }

    /// 지정된 인덱스의 진단 대상을 목록에서 제거합니다.
    ///
    /// - `Running` 또는 `Cancelling` 단계에서는 `Err(GuiStateError::Busy)`를 반환합니다.
    /// - 인덱스가 범위를 벗어난 경우 `Err(GuiStateError::InvalidIndex)`를 반환하며 상태는 불변입니다.
    /// - 마지막 남은 대상 제거 시 빈 대상 목록으로 정상 전이됩니다.
    pub fn remove_target(&mut self, index: usize) -> Result<(), GuiStateError> {
        if matches!(self.phase, RunPhase::Running | RunPhase::Cancelling) {
            return Err(GuiStateError::Busy);
        }
        if index >= self.targets.len() {
            return Err(GuiStateError::InvalidIndex);
        }
        self.targets.remove(index);
        Ok(())
    }

    /// 진단 옵션을 임시 보관(draft) 상태로 갱신합니다.
    ///
    /// - `Running` 또는 `Cancelling` 단계에서는 `Err(GuiStateError::Busy)`를 반환합니다.
    /// - 실제 옵션의 정밀 유효성(기능 미선택, 타임아웃 범위, 동시성 범위)은 `begin_run` 시점에 검증됩니다.
    pub fn set_options(&mut self, options: QuickOptions) -> Result<(), GuiStateError> {
        if matches!(self.phase, RunPhase::Running | RunPhase::Cancelling) {
            return Err(GuiStateError::Busy);
        }
        self.options = options;
        Ok(())
    }

    /// 진단 실행을 시작하고 확정된 불변 스냅샷을 반환합니다.
    ///
    /// ## 검증 및 실행 순서
    /// 1. Busy 검사: `Running` 또는 `Cancelling`인 경우 즉시 `Err(GuiStateError::Busy)`.
    /// 2. NoFeatures 검사: 선택된 기능이 없으면 앱 로컬 오류인 `Err(GuiStateError::NoFeatures)` 반환.
    /// 3. 코어 계획 검증: `build_quick_plan(&self.targets, &self.options)` 호출. 실패 시 `Err(GuiStateError::InvalidInput)`.
    /// 4. 식별자 카운터 checked increment: 성공한 시작만 ID를 소비하며 오버플로 시 `Err(GuiStateError::IdExhausted)`.
    /// 5. 요청 및 계획 스냅샷 확정: `session_id`는 `"gui-run-N"`, `max_result_bytes`는 `DEFAULT_MAX_RESULT_BYTES`(16MiB).
    /// 6. 상태 갱신: active 스냅샷 설정, 직전 결과(`last_result`) 초기화, `phase = RunPhase::Running`.
    /// 7. 실패 시 상태, 카운터, 이전 최종 결과는 완전히 불변입니다.
    pub fn begin_run(&mut self) -> Result<RunSnapshot, GuiStateError> {
        if matches!(self.phase, RunPhase::Running | RunPhase::Cancelling) {
            return Err(GuiStateError::Busy);
        }

        if self.options.selected_features.is_empty() {
            return Err(GuiStateError::NoFeatures);
        }

        let plan =
            build_quick_plan(&self.targets, &self.options).map_err(GuiStateError::InvalidInput)?;

        let next_id = self
            .next_run_counter
            .checked_add(1)
            .ok_or(GuiStateError::IdExhausted)?;

        let run_id = RunId(next_id);
        let session_id = format!("gui-run-{}", next_id);

        let request = QuickRunRequest {
            session_id,
            timestamp_iso8601: None,
            source_host: None,
            targets: self.targets.clone(),
            options: self.options.clone(),
            max_result_bytes: DEFAULT_MAX_RESULT_BYTES,
        };

        let snapshot = RunSnapshot {
            run_id,
            request,
            plan,
        };

        self.next_run_counter = next_id;
        self.active_snapshot = Some(snapshot.clone());
        self.last_result = None;
        self.phase = RunPhase::Running;

        Ok(snapshot)
    }

    /// 현재 진행 중인 진단에 대해 취소 의사를 기록하고 활성 실행 식별자를 반환합니다.
    ///
    /// - `Running` 상태에서 최초 호출 시에만 `Some(RunId)`를 반환하고 단계를 `Cancelling`으로 전이합니다.
    /// - 이미 `Cancelling`이거나 비실행 상태(`Ready`, `Finished`)인 경우 `None`을 반환합니다.
    /// - 본 메서드는 취소 요청 상태만을 변경하며 비동기 런타임이나 스레드를 강제 조작하지 않습니다.
    pub fn request_cancel(&mut self) -> Option<RunId> {
        if self.phase == RunPhase::Running {
            self.phase = RunPhase::Cancelling;
            self.active_snapshot.as_ref().map(|s| s.run_id)
        } else {
            None
        }
    }

    /// 비동기 진단 실행의 최종 결과(보고서 또는 오류 목록)를 접수하여 상태를 `Finished`로 전이합니다.
    ///
    /// ## 규칙
    /// - 현재 활성 실행(`Running` 또는 `Cancelling`)이 아니거나, 전달된 `run_id`가 활성 식별자와
    ///   일치하지 않는 경우 `Err(GuiStateError::InvalidCompletion)`을 반환하며 상태는 불변입니다.
    /// - 취소 요청 후 정상 완료 보고서가 반환된 경우(`report.cancelled == false`), UI 의사로
    ///   보고서의 `cancelled` 필드를 조작하지 않고 원문 그대로 저장합니다 (race condition 허용).
    /// - 결과 객체의 모든 필드(오류 목록, 누락 수, 호출 수, DTO 원문 등)는 일체의 변조나 삭제 없이 보존됩니다.
    pub fn finish_run(
        &mut self,
        run_id: RunId,
        result: Result<QuickRunReport, Vec<String>>,
    ) -> Result<(), GuiStateError> {
        if !matches!(self.phase, RunPhase::Running | RunPhase::Cancelling) {
            return Err(GuiStateError::InvalidCompletion);
        }

        let active_id = match self.active_snapshot.as_ref() {
            Some(s) => s.run_id,
            None => return Err(GuiStateError::InvalidCompletion),
        };

        if run_id != active_id {
            return Err(GuiStateError::InvalidCompletion);
        }

        self.last_result = Some(result);
        self.active_snapshot = None;
        self.phase = RunPhase::Finished;

        Ok(())
    }

    /// 현재 실행 단계를 반환합니다.
    pub const fn phase(&self) -> RunPhase {
        self.phase
    }

    /// 현재 설정된 대상 목록을 슬라이스로 참조합니다.
    pub fn targets(&self) -> &[QuickTarget] {
        &self.targets
    }

    /// 현재 설정된 진단 옵션을 참조합니다.
    pub const fn options(&self) -> &QuickOptions {
        &self.options
    }

    /// 현재 활성 진단 실행 식별자를 반환합니다.
    pub fn active_run_id(&self) -> Option<RunId> {
        self.active_snapshot.as_ref().map(|s| s.run_id)
    }

    /// 현재 활성 진단 실행의 스냅샷을 참조합니다.
    pub fn active_snapshot(&self) -> Option<&RunSnapshot> {
        self.active_snapshot.as_ref()
    }

    /// 가장 최근 완료된 진단 실행 결과를 참조합니다.
    pub fn last_result(&self) -> Option<&Result<QuickRunReport, Vec<String>>> {
        self.last_result.as_ref()
    }
}

impl Default for GuiState {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "gui_state_tests.rs"]
mod tests;
