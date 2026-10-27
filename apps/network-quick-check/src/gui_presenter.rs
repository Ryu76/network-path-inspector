//! Network Quick Check(Part B) 순수 GUI 프레젠터 모듈.
//!
//! 입력·계획 확인 경로는 Win32 윈도우와 분리된 순수 프레젠터입니다.
//! 해당 경로에는 I/O, 네트워크, 프로세스, 시계 조회가 없습니다.
//! cfg(test) 실행 브리지는 별도 호스트에 typed 위임하며, 그 경로에는 스레드·런타임·시간 효과가 있습니다.
//!
//! ## 핵심 설계 및 불변식
//! - **GuiState 단일 소유 및 상태 비복제**: 대상 추가, 교체, 삭제는 기존 `GuiState` 메서드로만 수행합니다.
//! - **진단 미연결 계획 확인**: 계획 확인 시 `begin_run`, `finish_run`, `run_quick`을 일체 호출하지 않으며,
//!   `RunId`, `phase`, `last_result`를 변경하거나 소비하지 않습니다.
//! - **원자적 옵션/계획 확정**: 복제된 후보 상태에서 옵션 검증 및 `build_quick_plan`이 모두 성공할 때만
//!   상태와 계획 preview를 확정합니다. 실패 시 기존 모델, 옵션, 계획은 완전히 불변입니다.
//! - **stale 플래그 및 안내**: 계획 수립 후 대상 목록 변경(추가/교체/삭제)이나 옵션 수정이 발생하면
//!   `is_plan_stale`을 즉시 true로 전환하여 최신화가 필요함을 표시합니다.
//! - **엄격한 UTF-16 디코드**: 대리 코드(surrogate) 오류, 중간 NUL, UTF-16 초과, UTF-8 초과, 잘림 플래그를
//!   모두 거부하며 손실 변환이나 임의 트림/수리를 수행하지 않습니다.
//! - **64KiB 렌더링 상한 준수**: 계획 및 오류 렌더러는 65,536바이트 상한을 문자 경계에서 지키며,
//!   사전 거대 포맷팅 후 사후 절단하는 방식을 배제하고 점진적으로 작성합니다.

use std::fmt::Write as FmtWrite;

use network_core::quick::QuickFeature;
use network_core::targets::{QuickOptions, QuickPlan, build_quick_plan};

use crate::gui_state::{GuiState, GuiStateError};

/// 렌더러 최대 바이트 상한 (64KiB = 65,536 바이트).
pub const MAX_RENDER_BYTES: usize = 65536;

/// 렌더러 상한 도달 시 추가되는 정적 안내 문구.
pub const TRUNCATION_NOTICE: &str = "\r\n... (출력 상한 65,536바이트 초과로 나머지 생략됨)";

/// UTF-16 디코드 중 발생하는 오류.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// 대리 코드포인트(surrogate) 쌍이 잘못됨.
    InvalidSurrogate,
    /// 문자열 중간에 NUL(0x00) 문자가 포함됨.
    EmbeddedNul,
    /// UTF-16 코드포인트 길이가 한도를 초과함.
    Utf16TooLong { len: usize, max: usize },
    /// UTF-8로 변환 시 바이트 크기가 한도를 초과함.
    Utf8TooLong { bytes: usize, max: usize },
    /// 입력 컨트롤에서 버퍼 한도 도달 알림(EN_MAXTEXT)이 감지됨.
    TruncatedInput,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSurrogate => {
                write!(
                    f,
                    "유효하지 않은 유니코드 대리 코드(surrogate)가 포함되어 있습니다."
                )
            }
            Self::EmbeddedNul => write!(f, "문자열 중간에 NUL(0x00) 문자가 포함되어 있습니다."),
            Self::Utf16TooLong { len, max } => {
                write!(
                    f,
                    "입력 문자 수({len})가 최대 허용치({max})를 초과했습니다."
                )
            }
            Self::Utf8TooLong { bytes, max } => {
                write!(
                    f,
                    "입력 바이트 크기({bytes} 바이트)가 최대 허용 크기({max} 바이트)를 초과했습니다."
                )
            }
            Self::TruncatedInput => {
                write!(
                    f,
                    "입력 내용이 컨트롤 버퍼 상한에 도달하여 잘렸습니다. 내용을 모두 지우고 다시 입력해주세요."
                )
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// UTF-16 버퍼를 손실/트림/수리 없이 UTF-8 String으로 엄격히 디코드합니다.
pub fn decode_utf16_input(
    raw: &[u16],
    truncated: bool,
    max_utf16: usize,
    max_utf8: usize,
) -> Result<String, DecodeError> {
    if truncated {
        return Err(DecodeError::TruncatedInput);
    }
    if raw.len() > max_utf16 {
        return Err(DecodeError::Utf16TooLong {
            len: raw.len(),
            max: max_utf16,
        });
    }
    if raw.contains(&0) {
        return Err(DecodeError::EmbeddedNul);
    }

    let mut out = String::new();
    let mut total_utf8_bytes: usize = 0;

    for item in char::decode_utf16(raw.iter().copied()) {
        let ch = item.map_err(|_| DecodeError::InvalidSurrogate)?;
        let ch_len = ch.len_utf8();
        total_utf8_bytes =
            total_utf8_bytes
                .checked_add(ch_len)
                .ok_or(DecodeError::Utf8TooLong {
                    bytes: usize::MAX,
                    max: max_utf8,
                })?;
        if total_utf8_bytes > max_utf8 {
            return Err(DecodeError::Utf8TooLong {
                bytes: total_utf8_bytes,
                max: max_utf8,
            });
        }
        out.push(ch);
    }

    Ok(out)
}

/// 순수 ASCII 10진 숫자를 파싱하여 u64로 변환합니다 (부호, 공백, 소수점, 오버플로 거부).
pub fn parse_ascii_u64(s: &str) -> Result<u64, String> {
    if s.is_empty() {
        return Err("숫자가 비어 있습니다.".to_string());
    }
    if !s.chars().all(|c| c.is_ascii_digit()) {
        return Err("순수 10진 ASCII 숫자만 입력 가능합니다 (부호, 공백 불가).".to_string());
    }
    s.parse::<u64>()
        .map_err(|_| "수치 파싱 실패 또는 정수 오버플로가 발생했습니다.".to_string())
}

/// 순수 ASCII 10진 숫자를 파싱하여 usize로 변환합니다.
pub fn parse_ascii_usize(s: &str) -> Result<usize, String> {
    if s.is_empty() {
        return Err("숫자가 비어 있습니다.".to_string());
    }
    if !s.chars().all(|c| c.is_ascii_digit()) {
        return Err("순수 10진 ASCII 숫자만 입력 가능합니다 (부호, 공백 불가).".to_string());
    }
    s.parse::<usize>()
        .map_err(|_| "수치 파싱 실패 또는 정수 오버플로가 발생했습니다.".to_string())
}

/// 프레젠터 동작 중 발생하는 오류.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresenterError {
    /// 상태 모델 오류.
    StateError(GuiStateError),
    /// UTF-16 디코드 오류.
    DecodeError(DecodeError),
    /// 옵션 수치 파싱 오류.
    NumberParseError(String),
    /// 삭제할 대상이 선택되지 않음.
    NoSelection,
    /// 선택 인덱스가 범위를 벗어남.
    InvalidIndex,
    /// 진단 기능이 하나도 선택되지 않음.
    NoFeatures,
}

impl std::fmt::Display for PresenterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StateError(e) => write!(f, "{e}"),
            Self::DecodeError(e) => write!(f, "{e}"),
            Self::NumberParseError(msg) => write!(f, "수치 오류: {msg}"),
            Self::NoSelection => {
                write!(
                    f,
                    "선택된 대상이 없습니다. 목록에서 항목을 먼저 선택해주세요."
                )
            }
            Self::InvalidIndex => write!(f, "선택 인덱스가 목록 범위를 벗어났습니다."),
            Self::NoFeatures => {
                write!(
                    f,
                    "진단 기능이 하나도 선택되지 않았습니다. 최소 1개 이상의 기능을 체크해주세요."
                )
            }
        }
    }
}

impl std::error::Error for PresenterError {}

/// 문자 경계를 준수하여 최대 바이트 상한까지 안전하게 문자열을 누적하는 버퍼 빌더.
struct SafeBoundedWriter {
    buf: String,
    max_bytes: usize,
    truncated: bool,
}

impl SafeBoundedWriter {
    fn new(max_bytes: usize) -> Self {
        Self {
            buf: String::with_capacity(2048),
            max_bytes,
            truncated: false,
        }
    }

    fn push_str(&mut self, s: &str) {
        if self.truncated {
            return;
        }
        let notice_len = TRUNCATION_NOTICE.len();
        let avail = self.max_bytes.saturating_sub(notice_len);

        let current_len = self.buf.len();
        if current_len >= avail {
            self.buf.push_str(TRUNCATION_NOTICE);
            self.truncated = true;
            return;
        }

        let remaining = avail - current_len;
        if s.len() <= remaining {
            self.buf.push_str(s);
        } else {
            // s의 유효한 UTF-8 문자 경계를 찾아 remaining 이하까지만 슬라이싱
            let mut cut_idx = 0;
            for (idx, _) in s.char_indices() {
                if idx > remaining {
                    break;
                }
                cut_idx = idx;
            }
            self.buf.push_str(&s[..cut_idx]);
            self.buf.push_str(TRUNCATION_NOTICE);
            self.truncated = true;
        }
    }

    fn into_string(self) -> String {
        self.buf
    }
}

impl FmtWrite for SafeBoundedWriter {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        self.push_str(text);
        // Display의 반복도 여기서 중단한다. 큰 오류 문자열을 먼저 만들지 않는다.
        if self.truncated {
            Err(std::fmt::Error)
        } else {
            Ok(())
        }
    }
}

/// Network Quick Check 순수 GUI 프레젠터.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuiPresenter {
    state: GuiState,
    selected_index: Option<usize>,
    plan_preview: Option<QuickPlan>,
    is_plan_stale: bool,
    draft_timeout_ms: String,
    draft_concurrency: String,
    draft_features: Vec<QuickFeature>,
    last_error: Option<String>,
}

impl GuiPresenter {
    /// 기본 초기 상태를 갖는 새로운 프레젠터를 생성합니다.
    pub fn new() -> Self {
        Self {
            state: GuiState::new(),
            selected_index: None,
            plan_preview: None,
            is_plan_stale: false,
            draft_timeout_ms: "3000".to_string(),
            draft_concurrency: "4".to_string(),
            draft_features: vec![QuickFeature::TcpConnect, QuickFeature::IcmpPing],
            last_error: None,
        }
    }

    /// 내부 상태 모델에 대한 읽기 전용 참조를 반환합니다.
    pub const fn state(&self) -> &GuiState {
        &self.state
    }

    /// 현재 선택된 목록 인덱스를 반환합니다.
    pub const fn selected_index(&self) -> Option<usize> {
        self.selected_index
    }

    /// 현재 수립된 계획 preview에 대한 읽기 전용 참조를 반환합니다.
    #[cfg(test)]
    pub const fn plan_preview(&self) -> Option<&QuickPlan> {
        self.plan_preview.as_ref()
    }

    /// 현재 수립된 계획이 변경으로 인해 최신이 아닌지(stale) 여부를 반환합니다.
    #[cfg(test)]
    pub const fn is_plan_stale(&self) -> bool {
        self.is_plan_stale
    }

    /// 타임아웃 draft 문자열을 참조합니다.
    #[cfg(test)]
    pub fn draft_timeout_ms(&self) -> &str {
        &self.draft_timeout_ms
    }

    /// 동시성 draft 문자열을 참조합니다.
    #[cfg(test)]
    pub fn draft_concurrency(&self) -> &str {
        &self.draft_concurrency
    }

    /// 선택된 기능 draft 슬라이스를 참조합니다.
    #[cfg(test)]
    pub fn draft_features(&self) -> &[QuickFeature] {
        &self.draft_features
    }

    /// 가장 최근 발생한 오류 메시지를 참조합니다.
    #[cfg(test)]
    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    /// 오류 메시지를 수동으로 설정합니다.
    pub fn set_error(&mut self, message: Option<String>) {
        self.last_error = message.map(|text| {
            let mut writer = SafeBoundedWriter::new(MAX_RENDER_BYTES);
            writer.push_str(&text);
            writer.into_string()
        });
    }

    fn record_error(&mut self, error: &impl std::fmt::Display) {
        let mut writer = SafeBoundedWriter::new(MAX_RENDER_BYTES);
        let _ = write!(writer, "{error}");
        self.last_error = Some(writer.into_string());
    }

    /// 네이티브 옵션 원문을 손실 없이 검사한 뒤에만 draft를 갱신한다.
    pub fn update_draft_utf16(
        &mut self,
        timeout: &[u16],
        concurrency: &[u16],
        features: Vec<QuickFeature>,
    ) -> Result<(), PresenterError> {
        let timeout =
            decode_utf16_input(timeout, false, 32, 32).map_err(PresenterError::DecodeError)?;
        let concurrency =
            decode_utf16_input(concurrency, false, 32, 32).map_err(PresenterError::DecodeError)?;
        self.update_draft_options(&timeout, &concurrency, features);
        Ok(())
    }

    /// 적용 전 입력이 바뀌면 이전 계획을 최신 계획처럼 표시하지 않는다.
    pub fn mark_plan_stale(&mut self) {
        if self.plan_preview.is_some() {
            self.is_plan_stale = true;
        }
    }

    /// 대상 목록 뒤에 신규 입력을 추가합니다.
    ///
    /// 성공 시 선택이 해제되고 기존 계획은 stale로 표시됩니다.
    /// 실패 시 상태, 선택, 계획 전체가 불변으로 유지됩니다.
    pub fn append_targets(&mut self, text: &str) -> Result<(), PresenterError> {
        match self.state.append_targets(text) {
            Ok(()) => {
                self.selected_index = None;
                if self.plan_preview.is_some() {
                    self.is_plan_stale = true;
                }
                self.last_error = None;
                Ok(())
            }
            Err(e) => {
                let err = PresenterError::StateError(e);
                self.record_error(&err);
                Err(err)
            }
        }
    }

    /// 대상 목록 전체를 새 입력으로 교체합니다.
    ///
    /// 성공 시 선택이 해제되고 기존 계획은 stale로 표시됩니다.
    /// 실패 시 상태, 선택, 계획 전체가 불변으로 유지됩니다.
    pub fn replace_targets(&mut self, text: &str) -> Result<(), PresenterError> {
        match self.state.replace_targets(text) {
            Ok(()) => {
                self.selected_index = None;
                if self.plan_preview.is_some() {
                    self.is_plan_stale = true;
                }
                self.last_error = None;
                Ok(())
            }
            Err(e) => {
                let err = PresenterError::StateError(e);
                self.record_error(&err);
                Err(err)
            }
        }
    }

    /// 현재 선택된 대상을 목록에서 제거합니다.
    ///
    /// 선택된 대상이 없으면 `PresenterError::NoSelection`을 반환합니다.
    /// 성공 시 선택이 해제되고 기존 계획은 stale로 표시됩니다.
    /// 실패 시 상태 전체가 불변으로 유지됩니다.
    pub fn remove_selected(&mut self) -> Result<(), PresenterError> {
        let idx = match self.selected_index {
            Some(i) => i,
            None => {
                let err = PresenterError::NoSelection;
                self.record_error(&err);
                return Err(err);
            }
        };

        match self.state.remove_target(idx) {
            Ok(()) => {
                self.selected_index = None;
                if self.plan_preview.is_some() {
                    self.is_plan_stale = true;
                }
                self.last_error = None;
                Ok(())
            }
            Err(e) => {
                let err = PresenterError::StateError(e);
                self.record_error(&err);
                Err(err)
            }
        }
    }

    /// 목록 선택 인덱스를 갱신합니다.
    ///
    /// 인덱스가 범위를 벗어난 경우 `PresenterError::InvalidIndex`를 반환하며
    /// 기존 선택은 변경되지 않습니다.
    pub fn set_selected_index(&mut self, index: Option<usize>) -> Result<(), PresenterError> {
        if let Some(i) = index
            && i >= self.state.targets().len()
        {
            let err = PresenterError::InvalidIndex;
            self.record_error(&err);
            return Err(err);
        }
        self.selected_index = index;
        Ok(())
    }

    /// 옵션 draft 값들을 갱신하고 기존 계획이 있다면 stale 플래그를 세웁니다.
    pub fn update_draft_options(
        &mut self,
        timeout_ms_str: &str,
        concurrency_str: &str,
        features: Vec<QuickFeature>,
    ) {
        self.draft_timeout_ms = timeout_ms_str.to_string();
        self.draft_concurrency = concurrency_str.to_string();
        self.draft_features = features;
        if self.plan_preview.is_some() {
            self.is_plan_stale = true;
        }
    }

    /// 진단 계획 확인을 수행합니다.
    ///
    /// - `draft_timeout_ms` 및 `draft_concurrency`의 ASCII 숫자 파싱 및 오버플로를 검증합니다.
    /// - 기능 목록이 비어 있으면 `PresenterError::NoFeatures`로 거부합니다.
    /// - 복제된 후보 상태에서 `set_options` 및 `build_quick_plan`을 수행합니다.
    /// - 모든 검증이 성공할 때만 실제 모델 옵션과 계획 preview를 원자적으로 확정합니다.
    /// - 검증 실패 시 모델 상태, 옵션, 계획 preview는 완전히 불변이며 draft 문자열은 보존됩니다.
    /// - `begin_run`이나 `finish_run`을 호출하지 않으므로 `RunId`, `phase`, `last_result`는 변경되지 않습니다.
    pub fn confirm_plan(&mut self) -> Result<(), PresenterError> {
        let timeout_ms = parse_ascii_u64(&self.draft_timeout_ms).map_err(|msg| {
            let err = PresenterError::NumberParseError(msg);
            self.record_error(&err);
            err
        })?;

        let concurrency = parse_ascii_usize(&self.draft_concurrency).map_err(|msg| {
            let err = PresenterError::NumberParseError(msg);
            self.record_error(&err);
            err
        })?;

        if self.draft_features.is_empty() {
            let err = PresenterError::NoFeatures;
            self.record_error(&err);
            return Err(err);
        }

        let new_options = QuickOptions {
            tcp_timeout_ms: timeout_ms,
            concurrency,
            selected_features: self.draft_features.clone(),
        };

        // 복제 후보 상태에서 사전 검증
        let mut candidate_state = self.state.clone();
        candidate_state
            .set_options(new_options.clone())
            .map_err(|e| {
                let err = PresenterError::StateError(e);
                self.record_error(&err);
                err
            })?;

        let plan = build_quick_plan(candidate_state.targets(), candidate_state.options()).map_err(
            |errors| {
                let err = PresenterError::StateError(GuiStateError::InvalidInput(errors));
                self.record_error(&err);
                err
            },
        )?;

        // 원자적 확정
        self.state = candidate_state;
        self.plan_preview = Some(plan);
        self.is_plan_stale = false;
        self.last_error = None;

        Ok(())
    }

    /// 수립된 진단 계획 preview를 사용자용 한국어 텍스트로 렌더링합니다.
    ///
    /// 65,536바이트 상한을 문자 경계에서 지키며 상한 도달 시 생략 고지를 추가합니다.
    pub fn render_plan_preview(&self) -> String {
        self.render_plan_preview_for_mode(true)
    }

    /// 실행 화면의 계획 미리보기. 검사 결과와 혼동하지 않고 입력 전용 안내를 재사용하지 않는다.
    #[cfg(test)]
    pub(crate) fn render_execution_plan_preview(&self) -> String {
        self.render_plan_preview_for_mode(false)
    }

    fn render_plan_preview_for_mode(&self, input_only: bool) -> String {
        let mut writer = SafeBoundedWriter::new(MAX_RENDER_BYTES);
        writer.push_str("【Network Quick Check 진단 계획 확인】\r\n");
        if input_only {
            writer.push_str("모드: 입력·계획 확인 전용 (네트워크 진단 미연결 / 프로브 미실행)\r\n");
            writer.push_str(
                "안내: 본 화면은 실제 네트워크 연결을 수행하지 않으며 계획 수립 결과만 확인합니다.\r\n",
            );
        } else {
            writer.push_str("모드: 검사 계획 미리보기 (실제 진단 결과 아님)\r\n");
            writer.push_str("안내: 실행은 [시작]으로 요청하며, 완료 결과는 별도로 표시됩니다.\r\n");
        }

        if self.is_plan_stale {
            writer.push_str(
                "★ 안내: 대상 목록 또는 옵션이 변경되었습니다. [계획 확인]을 다시 실행해주세요.\r\n",
            );
        }

        let plan = match self.plan_preview.as_ref() {
            Some(p) => p,
            None => {
                writer.push_str(
                    "\r\n(수립된 계획이 없습니다. 대상을 입력하고 [계획 확인] 버튼을 눌러주세요.)\r\n",
                );
                return writer.into_string();
            }
        };

        writer.push_str("\r\n[실행 옵션 요약]\r\n");
        let _ = writeln!(writer, "- 동시 실행 작업 수: {}\r", plan.concurrency);
        let _ = writeln!(writer, "- TCP 연결 타임아웃: {} ms\r", plan.tcp_timeout_ms);
        match plan.icmp_timeout_ms {
            Some(ms) => {
                let _ = writeln!(writer, "- ICMP Ping 타임아웃: {} ms\r", ms);
            }
            None => {
                let _ = writeln!(writer, "- ICMP Ping 타임아웃: (미선택)\r");
            }
        }
        let _ = writeln!(writer, "- 계획 대상 수: {} 개\r", plan.targets.len());

        writer.push_str("\r\n[대상별 세부 계획]\r\n");
        for (i, planned) in plan.targets.iter().enumerate() {
            let _ = writeln!(
                writer,
                "{}. 원문: {}\r\n   - 정규화 호스트: {}, 포트: {}\r\n   - 사전 DNS 주소 해석 필요: {}\r\n   - 계획 진단 기능: ",
                i + 1,
                planned.target.raw_input,
                planned.target.host,
                planned.target.port,
                if planned.requires_resolution {
                    "예"
                } else {
                    "아니오"
                }
            );
            let feats: Vec<&str> = planned
                .features
                .iter()
                .map(|f| match f {
                    QuickFeature::TcpConnect => "TCP 연결",
                    QuickFeature::IcmpPing => "ICMP Ping",
                    QuickFeature::IcmpTraceroute => "경로 추적",
                    QuickFeature::DnsLookup => "DNS 조회",
                    QuickFeature::LocalNetwork => "로컬 정보",
                })
                .collect();
            writer.push_str(&feats.join(", "));
            writer.push_str("\r\n");
        }

        if !plan.limitations.is_empty() {
            writer.push_str("\r\n[제한 사항 및 안내]\r\n");
            for lim in &plan.limitations {
                writer.push_str("- ");
                writer.push_str(lim);
                writer.push_str("\r\n");
            }
        }

        writer.into_string()
    }

    /// 현재 오류 상태를 렌더링합니다.
    pub fn render_error(&self) -> String {
        match self.last_error.as_deref() {
            Some(err) => {
                let mut writer = SafeBoundedWriter::new(MAX_RENDER_BYTES);
                writer.push_str("【오류 안내】\r\n");
                writer.push_str(err);
                writer.into_string()
            }
            None => String::new(),
        }
    }
}

impl Default for GuiPresenter {
    fn default() -> Self {
        Self::new()
    }
}

/// GUI 프레젠터와 실행 호스트 브리지 사이에서 발생하는 오류.
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RunBridgeError {
    /// 프레젠터 계획 수립 및 유효성 검증 오류.
    Presenter(PresenterError),
    /// 실행 코디네이터 시작 요청 오류.
    Start(crate::gui_coordinator::StartError),
}

#[cfg(test)]
impl std::fmt::Display for RunBridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Presenter(e) => write!(f, "진단 계획 준비 오류: {e}"),
            Self::Start(e) => write!(f, "진단 시작 오류: {e}"),
        }
    }
}

#[cfg(test)]
impl std::error::Error for RunBridgeError {}

/// 사전에 계획 검증을 통과한 불변 실행 후보.
/// 외부에서 임의 생성할 수 없으며 단 1회의 enqueue 호출로 소비됩니다.
#[cfg(test)]
pub(crate) struct PreparedRunCandidate {
    presenter: GuiPresenter,
}

#[cfg(test)]
impl PreparedRunCandidate {
    /// 검증된 실행 후보를 실행 코디네이터 큐에 적재합니다.
    ///
    /// 실제 호스트의 `try_start`에 후보 상태를 전달하며, 성공 시에만
    /// 확정된 프레젠터와 실행 식별자를 반환합니다.
    pub(crate) fn enqueue(
        mut self,
        host: &mut crate::gui_coordinator::GuiRunCoordinator,
    ) -> Result<(GuiPresenter, crate::gui_state::RunId), RunBridgeError> {
        let id = host
            .try_start(&mut self.presenter.state)
            .map_err(RunBridgeError::Start)?;
        Ok((self.presenter, id))
    }
}

#[cfg(test)]
impl GuiPresenter {
    /// 원본 프레젠터 변경 없이 사전 검증된 실행 후보를 생성합니다.
    ///
    /// 복제된 후보에 기존 `confirm_plan`을 호출하며, 실패 시 원본은 완전히 불변입니다.
    pub(crate) fn prepare_run_candidate(&self) -> Result<PreparedRunCandidate, RunBridgeError> {
        let mut candidate = self.clone();
        candidate
            .confirm_plan()
            .map_err(RunBridgeError::Presenter)?;
        Ok(PreparedRunCandidate {
            presenter: candidate,
        })
    }

    /// 실행 후보 생성 및 큐 적재를 원자적으로 수행하여 성공 시에만 self를 확정합니다.
    pub(crate) fn try_start_run(
        &mut self,
        host: &mut crate::gui_coordinator::GuiRunCoordinator,
    ) -> Result<crate::gui_state::RunId, RunBridgeError> {
        let candidate = self.prepare_run_candidate()?;
        let (confirmed, id) = candidate.enqueue(host)?;
        *self = confirmed;
        Ok(id)
    }

    /// 실행 호스트에 취소 의사를 전달합니다.
    pub(crate) fn request_run_cancel(
        &mut self,
        host: &mut crate::gui_coordinator::GuiRunCoordinator,
    ) -> Result<Option<crate::gui_state::RunId>, crate::gui_coordinator::CoordinatorError> {
        host.request_cancel(&mut self.state)
    }

    /// 실행 호스트로부터 완료 통보 및 상태를 폴링하여 반영합니다.
    pub(crate) fn poll_run(
        &mut self,
        host: &mut crate::gui_coordinator::GuiRunCoordinator,
    ) -> crate::gui_coordinator::PollOutcome {
        host.poll(&mut self.state)
    }

    /// 실행 호스트에 종료를 요청합니다.
    pub(crate) fn begin_run_close(
        &mut self,
        host: &mut crate::gui_coordinator::GuiRunCoordinator,
    ) -> Result<(), crate::gui_coordinator::CoordinatorError> {
        host.begin_close(&mut self.state)
    }
}

#[cfg(test)]
#[path = "gui_presenter_tests.rs"]
mod tests;
