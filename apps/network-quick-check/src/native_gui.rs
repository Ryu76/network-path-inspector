//! Network Quick Check(Part B) 네이티브 GUI 모듈.
//!
//! 입력·계획 확인 화면(Inputs 모드)과 실제 진단 실행 화면(Run slot 모드)을 분리하여 제공합니다.
//! Win32 윈도우 프로시저는 FFI 경계를 통해 컨텍스트를 안전하게 참조하며,
//! 리소스 수명 관리는 WindowGuard가 단독으로 전담합니다.
//!
//! ## 핵심 설계 및 불변식
//! - **입력 모드 보존 및 실행 모드 분리**:
//!   - `run_native_gui`: 입력·계획 확인 전용 화면으로, 네트워크·비동기 런타임·워커를 일체 생성하지 않습니다.
//!   - `run_native_execution_gui`: 외부에서 전달받은 `GuiSessionSlot`을 통해 진단 실행·폴링·중지·종료를 연결합니다.
//! - **세션 단일 소유 및 짧은 대여**:
//!   - Run 모드는 slot의 세션을 짧게 borrow하여 typed API만 호출합니다.
//!   - UI 슬롯의 `Option::take`, 교체, 또는 새 세션 생성은 엄격히 금지됩니다.
//!   - 모든 Win32 native 호출 및 렌더링 텍스트 적용 이전 lock 대여를 반드시 해제합니다.
//! - **HWND Context 수명 및 안전한 창 파괴**:
//!   - Context는 WindowGuard가 단독 소유하며, 콜백은 일시적 참조만 빌립니다.
//!   - `WM_NCDESTROY`에서 live 핸들과 GWLP_USERDATA를 무효화하여 UAF를 방지합니다.
//!   - 창 파괴 실패 시 연결된 context 메모리 보존을 유지하되 결과는 Err를 반환합니다.
//! - **정확한 알림 발신자 및 입력 검증**:
//!   - 컨트롤 ID 및 HWND가 모두 일치하는 알림만 처리하며, 위조 알림은 상태를 변경하지 않습니다.
//!   - 각 입력란의 잘림(truncation) 감지 시 해당 입력란을 완전히 비울 때까지 실행을 거부합니다.
//!   - 시작(Start) 전 입력 상자에 남아있는 미반영 텍스트는 몰래 목록에 추가하지 않고 명확한 오류 안내 후 거부합니다.
//! - **지연 호스트 생성 및 Mock 지원**:
//!   - 프로덕션 Start factory는 반드시 `try_start_with`의 클로저 안에서만 `native_backend_for_current_exe`를 호출합니다.
//!   - 테스트 환경에서는 cfg(test) 전용 mock factory override가 설정된 경우에만 호스트를 생성하며,
//!     fixture 미설정 시 실제 native factory나 OS 소켓을 호출하지 않고 Fail-Closed로 거부합니다.
//! - **HWND 타이머 및 안전한 종료(Close)**:
//!   - 실행 모드 창은 전용 50ms 타이머를 등록하여 주기적으로 `session.poll`을 1회 호출합니다.
//!   - 타이머 tick마다 거대 결과나 목록을 무조건 재렌더링하지 않으며, 상태나 결과 변화가 있을 때만 갱신합니다.
//!   - 닫기(Close) 요청 시 `begin_close`를 전달한 뒤 타이머 poll을 유지하며,
//!     물리적 정리 완료(`Closed` 또는 `Failed`)를 관측한 후에만 창을 파괴합니다.
//!   - Save 버튼은 계속 비활성화(disabled) 상태를 유지합니다.

#![cfg(windows)]

use crate::gui_coordinator::PollOutcome;
use crate::gui_presenter::{GuiPresenter, MAX_RENDER_BYTES, decode_utf16_input};
use crate::gui_result_render::render_final_result;
use crate::gui_run_session::{GuiRunSession, SessionError, SessionShutdown};
use crate::gui_state::RunPhase;
use crate::result_view::{ResultFilter, build_result_view};
use network_core::quick::QuickFeature;
use network_core::targets::MAX_INPUT_BYTES;
use std::cell::{Cell, RefCell};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{
    ERROR_CLASS_ALREADY_EXISTS, GetLastError, HWND, LPARAM, LRESULT, SetLastError, WPARAM,
};
use windows_sys::Win32::Graphics::Gdi::{
    COLOR_WINDOW, DEFAULT_GUI_FONT, GetStockObject, UpdateWindow,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::UI::Controls::{BST_CHECKED, EM_SETLIMITTEXT};
use windows_sys::Win32::UI::Input::KeyboardAndMouse::EnableWindow;
use windows_sys::Win32::UI::WindowsAndMessaging::*;
use windows_sys::core::{PCWSTR, w};

/// 입력 전용 윈도우 클래스 이름.
const WINDOW_CLASS: PCWSTR = w!("NPI_QUICK_CHECK_GUI_INPUTS_V1");

/// 진단 실행 윈도우 클래스 이름.
const RUN_WINDOW_CLASS: PCWSTR = w!("NPI_QUICK_CHECK_GUI_RUN_V1");

/// 입력 전용 창 제목.
const WINDOW_TITLE: PCWSTR = w!("Network Quick Check - 입력·계획 확인 (진단 미연결)");

/// 진단 실행 창 제목.
const RUN_WINDOW_TITLE: PCWSTR = w!("Network Quick Check - 진단 실행");

const MIN_WIDTH: i32 = 1020;
const MIN_HEIGHT: i32 = 720;
const INPUT_LIMIT: usize = MAX_INPUT_BYTES + 1;
const OPTION_LIMIT: usize = 33;
const CONTROL_COUNT: usize = 24;

const NOTICE: usize = 0;
const GUIDE: usize = 1;
const INPUT: usize = 2;
const APPEND: usize = 3;
const REPLACE: usize = 4;
const TARGETS: usize = 5;
const DELETE: usize = 6;
const FEATURES: usize = 7;
const TCP: usize = 8;
const PING: usize = 9;
const TRACE: usize = 10;
const DNS: usize = 11;
const LOCAL: usize = 12;
const TIME_LABEL: usize = 13;
const TIMEOUT: usize = 14;
const CONC_LABEL: usize = 15;
const CONCURRENCY: usize = 16;
const PLAN: usize = 17;
const ERRORS: usize = 18;
const PREVIEW: usize = 19;
const START: usize = 20;
const STOP: usize = 21;
const SAVE: usize = 22;
const CLOSE: usize = 23;
const FIRST_ID: usize = 101;

/// 실행 모드 전용 HWND 타이머 고정 ID.
const RUN_TIMER_ID: usize = 9001;

/// 타이머 폴링 주기 (약 50ms).
const TIMER_INTERVAL_MS: u32 = 50;

const TRUNCATED: &str = "입력이 잘렸습니다. 해당 입력란을 완전히 비운 뒤 다시 입력해주세요.";
const UNAPPLIED_INPUT_WARNING: &str =
    "입력란에 아직 추가되지 않은 대상이 있습니다. [추가] 또는 [전체 교체]를 눌러 목록에 반영한 후 시작해주세요.";

/// 입력 모드와 실행 모드를 분리하는 모델 열거형.
enum GuiModel {
    /// 입력·계획 확인 전용 모델 (자체 GuiPresenter 소유).
    Inputs(RefCell<GuiPresenter>),
    /// 진단 실행 모델 (외부에서 주입된 세션 슬롯 단일 소유).
    Run(crate::gui_run_entry::GuiSessionSlot),
}

impl GuiModel {
    const fn is_run(&self) -> bool {
        matches!(self, Self::Run(_))
    }
}

#[derive(Clone, Copy)]
struct Controls([HWND; CONTROL_COUNT]);

impl Controls {
    fn empty() -> Self {
        Self([null_mut(); CONTROL_COUNT])
    }

    fn get(self, i: usize) -> HWND {
        self.0[i]
    }

    fn ready(self) -> bool {
        self.0.iter().all(|h| !h.is_null())
    }
}

#[cfg(test)]
#[derive(Default)]
struct Observations {
    drops: Cell<usize>,
    created: RefCell<Vec<HWND>>,
    parents: RefCell<Vec<HWND>>,
    failures: Cell<usize>,
    quit_removed: Cell<usize>,
}

#[cfg(test)]
type MockCoordinatorFactory = Box<
    dyn FnMut() -> Result<
            crate::gui_coordinator::GuiRunCoordinator,
            crate::gui_run_session::SessionInitError,
        > + 'static,
>;

struct Context {
    model: GuiModel,
    controls: Cell<Controls>,
    live: Cell<HWND>,
    truncated: [Cell<bool>; 3],
    handling: Cell<bool>,
    fatal: Cell<bool>,
    posted_quit: Cell<bool>,
    timer_active: Cell<bool>,
    last_phase: Cell<Option<RunPhase>>,
    #[cfg(test)]
    observations: std::rc::Rc<Observations>,
    #[cfg(test)]
    fail_child_at: Option<usize>,
    #[cfg(test)]
    fail_timer: Cell<bool>,
    #[cfg(test)]
    mock_coordinator_factory: RefCell<Option<MockCoordinatorFactory>>,
}

impl Context {
    fn new() -> Self {
        Self::new_inputs()
    }

    fn new_inputs() -> Self {
        Self {
            model: GuiModel::Inputs(RefCell::new(GuiPresenter::new())),
            controls: Cell::new(Controls::empty()),
            live: Cell::new(null_mut()),
            truncated: std::array::from_fn(|_| Cell::new(false)),
            handling: Cell::new(false),
            fatal: Cell::new(false),
            posted_quit: Cell::new(false),
            timer_active: Cell::new(false),
            last_phase: Cell::new(None),
            #[cfg(test)]
            observations: Default::default(),
            #[cfg(test)]
            fail_child_at: None,
            #[cfg(test)]
            fail_timer: Cell::new(false),
            #[cfg(test)]
            mock_coordinator_factory: RefCell::new(None),
        }
    }

    fn new_run(slot: crate::gui_run_entry::GuiSessionSlot) -> Self {
        Self {
            model: GuiModel::Run(slot),
            controls: Cell::new(Controls::empty()),
            live: Cell::new(null_mut()),
            truncated: std::array::from_fn(|_| Cell::new(false)),
            handling: Cell::new(false),
            fatal: Cell::new(false),
            posted_quit: Cell::new(false),
            timer_active: Cell::new(false),
            last_phase: Cell::new(None),
            #[cfg(test)]
            observations: Default::default(),
            #[cfg(test)]
            fail_child_at: None,
            #[cfg(test)]
            fail_timer: Cell::new(false),
            #[cfg(test)]
            mock_coordinator_factory: RefCell::new(None),
        }
    }

    fn edit<R>(&self, action: impl FnOnce(&mut GuiPresenter) -> R) -> Result<R, ()> {
        match &self.model {
            GuiModel::Inputs(presenter) => {
                let mut p = presenter.try_borrow_mut().map_err(|_| ())?;
                Ok(action(&mut p))
            }
            GuiModel::Run(_) => Err(()),
        }
    }

    fn error(&self, text: &str) -> Result<(), ()> {
        match &self.model {
            GuiModel::Inputs(presenter) => {
                let mut p = presenter.try_borrow_mut().map_err(|_| ())?;
                p.set_error(Some(text.to_owned()));
                Ok(())
            }
            GuiModel::Run(slot) => {
                let mut guard = slot.lock().map_err(|_| ())?;
                let session = guard.as_mut().ok_or(())?;
                session.set_ui_error(Some(text.to_owned()));
                Ok(())
            }
        }
    }

    fn has_truncation(&self) -> bool {
        self.truncated.iter().any(Cell::get)
    }

    fn lock_run_slot(&self) -> Result<std::sync::MutexGuard<'_, Option<GuiRunSession>>, ()> {
        match &self.model {
            GuiModel::Run(slot) => slot.lock().map_err(|_| ()),
            GuiModel::Inputs(_) => Err(()),
        }
    }

    fn append_targets(&self, text: &str) -> Result<(), ()> {
        match &self.model {
            GuiModel::Inputs(presenter) => {
                let mut p = presenter.try_borrow_mut().map_err(|_| ())?;
                p.append_targets(text).map_err(|_| ())
            }
            GuiModel::Run(slot) => {
                let mut guard = slot.lock().map_err(|_| ())?;
                let session = guard.as_mut().ok_or(())?;
                if let Err(e) = session.append_targets(text) {
                    session.set_ui_error(Some(e.to_string()));
                    return Err(());
                }
                Ok(())
            }
        }
    }

    fn replace_targets(&self, text: &str) -> Result<(), ()> {
        match &self.model {
            GuiModel::Inputs(presenter) => {
                let mut p = presenter.try_borrow_mut().map_err(|_| ())?;
                p.replace_targets(text).map_err(|_| ())
            }
            GuiModel::Run(slot) => {
                let mut guard = slot.lock().map_err(|_| ())?;
                let session = guard.as_mut().ok_or(())?;
                if let Err(e) = session.replace_targets(text) {
                    session.set_ui_error(Some(e.to_string()));
                    return Err(());
                }
                Ok(())
            }
        }
    }

    fn remove_selected(&self) -> Result<(), ()> {
        match &self.model {
            GuiModel::Inputs(presenter) => {
                let mut p = presenter.try_borrow_mut().map_err(|_| ())?;
                let _ = p.remove_selected();
                Ok(())
            }
            GuiModel::Run(slot) => {
                let mut guard = slot.lock().map_err(|_| ())?;
                let session = guard.as_mut().ok_or(())?;
                if let Err(e) = session.remove_selected() {
                    session.set_ui_error(Some(e.to_string()));
                }
                Ok(())
            }
        }
    }

    fn set_selected_index(&self, index: Option<usize>) -> Result<(), ()> {
        match &self.model {
            GuiModel::Inputs(presenter) => {
                let mut p = presenter.try_borrow_mut().map_err(|_| ())?;
                let _ = p.set_selected_index(index);
                Ok(())
            }
            GuiModel::Run(slot) => {
                let mut guard = slot.lock().map_err(|_| ())?;
                let session = guard.as_mut().ok_or(())?;
                let _ = session.set_selected_index(index);
                Ok(())
            }
        }
    }

    fn mark_plan_stale(&self) -> Result<(), ()> {
        match &self.model {
            GuiModel::Inputs(presenter) => {
                let mut p = presenter.try_borrow_mut().map_err(|_| ())?;
                p.mark_plan_stale();
                Ok(())
            }
            GuiModel::Run(slot) => {
                let mut guard = slot.lock().map_err(|_| ())?;
                let session = guard.as_mut().ok_or(())?;
                let _ = session.mark_plan_stale();
                Ok(())
            }
        }
    }

    fn confirm_plan(&self) -> Result<(), ()> {
        match &self.model {
            GuiModel::Inputs(presenter) => {
                let mut p = presenter.try_borrow_mut().map_err(|_| ())?;
                let _ = p.confirm_plan();
                Ok(())
            }
            GuiModel::Run(slot) => {
                let mut guard = slot.lock().map_err(|_| ())?;
                let session = guard.as_mut().ok_or(())?;
                if let Err(e) = session.confirm_plan() {
                    session.set_ui_error(Some(e.to_string()));
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
impl Drop for Context {
    fn drop(&mut self) {
        self.observations
            .drops
            .set(self.observations.drops.get() + 1);
    }
}

/// 유일한 소유 가드. WndProc는 Box::from_raw나 해제를 하지 않습니다.
struct WindowGuard {
    context: Option<Box<Context>>,
}

impl WindowGuard {
    fn context(&self) -> &Context {
        self.context.as_deref().expect("소유 컨텍스트")
    }

    fn hwnd(&self) -> HWND {
        self.context().live.get()
    }

    fn close(&self) -> Result<(), ()> {
        let ctx = self.context();
        let hwnd = ctx.live.get();
        if hwnd.is_null() {
            return Ok(());
        }
        if ctx.timer_active.replace(false) {
            unsafe { KillTimer(hwnd, RUN_TIMER_ID) };
        }
        // 안전: 현재 스레드의 자기 live 창만 파괴하며 NCDESTROY가 live를 지웁니다.
        let destroyed = unsafe { DestroyWindow(hwnd) };
        if destroyed == 0 || !ctx.live.get().is_null() {
            ctx.fatal.set(true);
            Err(())
        } else {
            Ok(())
        }
    }

    fn drain_owned_quit(&self) {
        let ctx = self.context();
        if ctx.posted_quit.replace(false) {
            let mut message = MSG::default();
            // 안전: 자기 창이 현재 스레드에 남긴 quit만 꺼냅니다. 다른 메시지는 건드리지 않습니다.
            let removed =
                unsafe { PeekMessageW(&mut message, null_mut(), WM_QUIT, WM_QUIT, PM_REMOVE) };
            #[cfg(test)]
            if removed != 0 {
                ctx.observations
                    .quit_removed
                    .set(ctx.observations.quit_removed.get() + 1);
            }
            #[cfg(not(test))]
            let _ = removed;
        }
    }
}

impl Drop for WindowGuard {
    fn drop(&mut self) {
        let _ = self.close();
        self.drain_owned_quit();
        if !self.context().live.get().is_null() {
            // 실패를 성공으로 숨기지 않습니다. 부착된 userdata의 UAF보다 메모리 보존을 선택합니다.
            if let Some(context) = self.context.take() {
                let _ = Box::leak(context);
            }
        }
    }
}

/// Win32 빈 문자열/오류를 구분하고 읽기 전후 길이와 복사 크기를 검증합니다.
fn read_text(hwnd: HWND, max: usize) -> Result<Vec<u16>, ()> {
    // 안전: 소유 HWND와 정확한 크기의 쓰기 버퍼만 사용합니다.
    unsafe {
        SetLastError(0);
        let before = GetWindowTextLengthW(hwnd);
        if before < 0 || (before == 0 && GetLastError() != 0) || before as usize > max {
            return Err(());
        }
        let mut data = vec![0u16; before as usize + 1];
        SetLastError(0);
        let copied = GetWindowTextW(hwnd, data.as_mut_ptr(), data.len() as i32);
        if copied < 0 || (copied == 0 && GetLastError() != 0) || copied != before {
            return Err(());
        }
        SetLastError(0);
        let after = GetWindowTextLengthW(hwnd);
        if after != before || (after == 0 && GetLastError() != 0) {
            return Err(());
        }
        data.truncate(copied as usize);
        Ok(data)
    }
}

fn set_text(hwnd: HWND, text: &str) -> Result<(), ()> {
    let wide: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
    // 안전: 동기 호출 동안 유효한 NUL 종료 버퍼와 소유 HWND입니다.
    if unsafe { SetWindowTextW(hwnd, wide.as_ptr()) } == 0 {
        Err(())
    } else {
        Ok(())
    }
}

fn send(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    // 안전: 소유 HWND와 각 메시지 계약에 맞는 스칼라/동기 호출 동안 유효한 버퍼만 전달합니다.
    unsafe { SendMessageW(hwnd, msg, wp, lp) }
}

struct ControlSpec {
    class: PCWSTR,
    label: PCWSTR,
    style: u32,
}

fn specifications(is_run: bool) -> [ControlSpec; CONTROL_COUNT] {
    let label = |text| ControlSpec {
        class: w!("STATIC"),
        label: text,
        style: 0,
    };
    let button = |text| ControlSpec {
        class: w!("BUTTON"),
        label: text,
        style: WS_TABSTOP | BS_PUSHBUTTON as u32,
    };
    let check = |text| ControlSpec {
        class: w!("BUTTON"),
        label: text,
        style: WS_TABSTOP | BS_AUTOCHECKBOX as u32,
    };
    let edit = |text, style| ControlSpec {
        class: w!("EDIT"),
        label: text,
        style: WS_BORDER | style,
    };

    let notice_label = if is_run {
        w!("진단 실행 화면 / [검사 시작]으로 네트워크 진단 수행")
    } else {
        w!("입력·계획 확인 전용 / 네트워크 진단 미연결")
    };

    let feature_label = if is_run {
        w!("검사 기능 선택")
    } else {
        w!("검사 기능 (현재는 계획 확인만 가능)")
    };

    let start_label = if is_run {
        w!("검사 시작")
    } else {
        w!("검사 시작 (미연결)")
    };

    let stop_label = if is_run {
        w!("중지")
    } else {
        w!("중지 (미연결)")
    };

    [
        label(notice_label),
        label(w!("host:port 또는 [IPv6]:port (한 줄에 한 대상)")),
        edit(
            w!(""),
            WS_TABSTOP | WS_VSCROLL | ES_MULTILINE as u32 | ES_AUTOVSCROLL as u32,
        ),
        button(w!("추가")),
        button(w!("전체 교체")),
        ControlSpec {
            class: w!("LISTBOX"),
            label: w!(""),
            style: WS_BORDER | WS_TABSTOP | WS_VSCROLL | LBS_NOTIFY as u32,
        },
        button(w!("선택 삭제")),
        label(feature_label),
        check(w!("TCP 연결")),
        check(w!("ICMP Ping")),
        check(w!("경로 추적")),
        check(w!("DNS 조회")),
        check(w!("로컬 정보")),
        label(w!("시간 제한(ms)")),
        edit(w!("3000"), WS_TABSTOP),
        label(w!("동시 실행 수")),
        edit(w!("4"), WS_TABSTOP),
        button(w!("계획 확인")),
        edit(
            w!(""),
            ES_READONLY as u32 | ES_MULTILINE as u32 | WS_VSCROLL,
        ),
        edit(
            w!(""),
            ES_READONLY as u32 | ES_MULTILINE as u32 | WS_VSCROLL | WS_TABSTOP,
        ),
        button(start_label),
        button(stop_label),
        button(w!("저장 (미연결)")),
        button(w!("닫기")),
    ]
}

fn create_controls(parent: HWND, ctx: &Context) -> Result<Controls, ()> {
    let is_run = ctx.model.is_run();
    let mut c = Controls::empty();
    // 안전: 부모/모듈은 현재 스레드 소유. 모든 생성 자식은 부모 파괴 경로에 포함됩니다.
    unsafe {
        let instance = GetModuleHandleW(null());
        if instance.is_null() {
            return Err(());
        }
        let font = GetStockObject(DEFAULT_GUI_FONT);
        if font.is_null() {
            return Err(());
        }
        for (i, spec) in specifications(is_run).iter().enumerate() {
            let class = spec.class;
            #[cfg(test)]
            let class = if ctx.fail_child_at == Some(i) {
                w!("NPI_TEST_MISSING_CHILD_CLASS_7B532")
            } else {
                class
            };
            let hwnd = CreateWindowExW(
                0,
                class,
                spec.label,
                spec.style | WS_VISIBLE | WS_CHILD,
                0,
                0,
                0,
                0,
                parent,
                (FIRST_ID + i) as HMENU,
                instance,
                null(),
            );
            if hwnd.is_null() {
                #[cfg(test)]
                ctx.observations
                    .failures
                    .set(ctx.observations.failures.get() + 1);
                return Err(());
            }
            #[cfg(test)]
            ctx.observations.created.borrow_mut().push(hwnd);
            c.0[i] = hwnd;
            SendMessageW(hwnd, WM_SETFONT, font as WPARAM, 1);
        }
        // stock font/cursor는 공유 OS 리소스입니다. DeleteObject/DestroyCursor 하지 않습니다.
        if is_run {
            EnableWindow(c.get(STOP), 0);
            EnableWindow(c.get(SAVE), 0);
        } else {
            for i in [START, STOP, SAVE] {
                EnableWindow(c.get(i), 0);
            }
        }
    }
    for i in [TCP, PING] {
        send(c.get(i), BM_SETCHECK, BST_CHECKED as usize, 0);
    }
    send(c.get(INPUT), EM_SETLIMITTEXT, INPUT_LIMIT, 0);
    for i in [TIMEOUT, CONCURRENCY] {
        send(c.get(i), EM_SETLIMITTEXT, OPTION_LIMIT, 0);
    }
    for i in [ERRORS, PREVIEW] {
        send(c.get(i), EM_SETLIMITTEXT, 65536, 0);
    }
    Ok(c)
}

fn layout(c: Controls, width: i32, height: i32) -> Result<(), ()> {
    if !c.ready() || width <= 0 || height <= 0 {
        return Ok(());
    }
    let m = 14;
    let left = ((width - m * 3) * 43 / 100).max(340);
    let x = left + m * 2;
    let right = width - x - m;
    let bottom = height - 50;
    let positions = [
        (NOTICE, m, 10, width - 28, 28),
        (GUIDE, m, 42, left, 38),
        (INPUT, m, 82, left, 116),
        (APPEND, m, 206, (left - 8) / 2, 30),
        (REPLACE, m + (left - 8) / 2 + 8, 206, (left - 8) / 2, 30),
        (TARGETS, m, 246, left, (bottom - 292).max(80)),
        (DELETE, m, bottom - 38, left, 30),
        (FEATURES, x, 44, right, 24),
        (TCP, x, 78, 120, 24),
        (PING, x + 125, 78, 130, 24),
        (TRACE, x + 260, 78, 130, 24),
        (DNS, x, 108, 120, 24),
        (LOCAL, x + 125, 108, 140, 24),
        (TIME_LABEL, x, 148, 140, 24),
        (TIMEOUT, x + 150, 144, 100, 28),
        (CONC_LABEL, x, 184, 140, 24),
        (CONCURRENCY, x + 150, 180, 100, 28),
        (PLAN, x, 220, right, 34),
        (ERRORS, x, 264, right, 70),
        (PREVIEW, x, 344, right, (bottom - 352).max(80)),
        (START, m, bottom, 210, 32),
        (STOP, m + 220, bottom, 180, 32),
        (SAVE, m + 410, bottom, 180, 32),
        (CLOSE, width - 194, bottom, 180, 32),
    ];
    for (i, x, y, w, h) in positions {
        // 안전: 자기 컨트롤만 이동하며 Rust 대여를 유지하지 않습니다.
        if unsafe { MoveWindow(c.get(i), x, y, w, h, 1) } == 0 {
            return Err(());
        }
    }
    Ok(())
}

fn update_control_states(ctx: &Context) {
    let c = ctx.controls.get();
    if !c.ready() || !ctx.model.is_run() {
        return;
    }
    let (can_edit, phase) = match ctx.lock_run_slot() {
        Ok(guard) => {
            if let Some(session) = guard.as_ref() {
                (session.can_edit(), session.presenter().state().phase())
            } else {
                (false, RunPhase::Ready)
            }
        }
        Err(_) => (false, RunPhase::Ready),
    };

    let can_start = can_edit && phase != RunPhase::Running && phase != RunPhase::Cancelling;
    let can_stop = phase == RunPhase::Running;
    let edit_enable = if can_edit { 1 } else { 0 };

    unsafe {
        for i in [
            INPUT,
            APPEND,
            REPLACE,
            DELETE,
            TCP,
            PING,
            TRACE,
            DNS,
            LOCAL,
            TIMEOUT,
            CONCURRENCY,
            PLAN,
        ] {
            EnableWindow(c.get(i), edit_enable);
        }
        EnableWindow(c.get(START), if can_start { 1 } else { 0 });
        EnableWindow(c.get(STOP), if can_stop { 1 } else { 0 });
        EnableWindow(c.get(SAVE), 0);
        EnableWindow(c.get(CLOSE), 1);
    }
}

fn render(ctx: &Context) -> Result<(), ()> {
    let c = ctx.controls.get();
    if !c.ready() {
        return Ok(());
    }

    let (rows, selection, preview_text, errors) = match &ctx.model {
        GuiModel::Inputs(presenter) => {
            let p = presenter.try_borrow().map_err(|_| ())?;
            (
                p.state()
                    .targets()
                    .iter()
                    .map(|t| t.raw_input.clone())
                    .collect::<Vec<_>>(),
                p.selected_index(),
                p.render_plan_preview(),
                p.render_error(),
            )
        }
        GuiModel::Run(slot) => {
            let guard = slot.lock().map_err(|_| ())?;
            let session = guard.as_ref().ok_or(())?;
            let p = session.presenter();
            let rows = p
                .state()
                .targets()
                .iter()
                .map(|t| t.raw_input.clone())
                .collect::<Vec<_>>();
            let selection = p.selected_index();
            let phase = p.state().phase();
            let last_res = p.state().last_result();
            let errors = p.render_error();

            let preview_text = if last_res.is_some() {
                let filter = ResultFilter::default();
                let view = build_result_view(last_res, &filter);
                let rendered = render_final_result(
                    &view,
                    session.completed_snapshot(),
                    phase,
                    MAX_RENDER_BYTES,
                );
                rendered.text
            } else {
                p.render_execution_plan_preview()
            };

            drop(guard);
            (rows, selection, preview_text, errors)
        }
    };

    send(c.get(TARGETS), LB_RESETCONTENT, 0, 0);
    for row in rows {
        let wide: Vec<u16> = row.encode_utf16().chain(Some(0)).collect();
        let result = send(c.get(TARGETS), LB_ADDSTRING, 0, wide.as_ptr() as LPARAM);
        if result == LB_ERR as isize || result == LB_ERRSPACE as isize {
            return Err(());
        }
    }
    send(
        c.get(TARGETS),
        LB_SETCURSEL,
        selection.unwrap_or(usize::MAX),
        0,
    );
    set_text(c.get(PREVIEW), &preview_text)?;
    set_text(c.get(ERRORS), &errors)?;
    update_control_states(ctx);
    Ok(())
}

fn features(c: Controls) -> Vec<QuickFeature> {
    [
        (TCP, QuickFeature::TcpConnect),
        (PING, QuickFeature::IcmpPing),
        (TRACE, QuickFeature::IcmpTraceroute),
        (DNS, QuickFeature::DnsLookup),
        (LOCAL, QuickFeature::LocalNetwork),
    ]
    .into_iter()
    .filter_map(|(i, f)| (send(c.get(i), BM_GETCHECK, 0, 0) == BST_CHECKED as isize).then_some(f))
    .collect()
}

fn read_options(ctx: &Context) -> Result<(), ()> {
    let c = ctx.controls.get();
    let time = read_text(c.get(TIMEOUT), OPTION_LIMIT)?;
    let concurrent = read_text(c.get(CONCURRENCY), OPTION_LIMIT)?;
    let chosen = features(c);

    match &ctx.model {
        GuiModel::Inputs(_) => {
            let result = ctx.edit(|p| p.update_draft_utf16(&time, &concurrent, chosen))?;
            if let Err(e) = result {
                ctx.error(&e.to_string())?;
                return Err(());
            }
        }
        GuiModel::Run(slot) => {
            let mut guard = slot.lock().map_err(|_| ())?;
            let session = guard.as_mut().ok_or(())?;
            if let Err(e) = session.update_draft_utf16(&time, &concurrent, chosen) {
                session.set_ui_error(Some(e.to_string()));
                return Err(());
            }
        }
    }
    Ok(())
}

fn apply_input(ctx: &Context, replace: bool) -> Result<(), ()> {
    if ctx.has_truncation() {
        ctx.error(TRUNCATED)?;
        return render(ctx);
    }
    let c = ctx.controls.get();
    let text = read_text(c.get(INPUT), INPUT_LIMIT)
        .map_err(|_| "입력 텍스트를 일관되게 읽을 수 없습니다.".to_owned())
        .and_then(|raw| {
            decode_utf16_input(&raw, false, INPUT_LIMIT, MAX_INPUT_BYTES).map_err(|e| e.to_string())
        });
    match text {
        Ok(text) => {
            let ok = if replace {
                ctx.replace_targets(&text).is_ok()
            } else {
                ctx.append_targets(&text).is_ok()
            };
            if ok {
                set_text(c.get(INPUT), "")?;
            }
        }
        Err(error) => ctx.error(&error)?,
    }
    render(ctx)
}

struct NotificationGuard<'a>(&'a Cell<bool>);
impl Drop for NotificationGuard<'_> {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

fn handle_start(ctx: &Context) -> Result<(), ()> {
    if !ctx.model.is_run() {
        return Ok(());
    }
    let c = ctx.controls.get();

    // 1. Truncation 검사
    if ctx.has_truncation() {
        ctx.error(TRUNCATED)?;
        return render(ctx);
    }

    // 2. 미반영 입력 상자 검사 (Start 전에 원문 입력을 몰래 추가하지 않고 명확 안내/거부)
    let raw_input = read_text(c.get(INPUT), INPUT_LIMIT).unwrap_or_default();
    if !raw_input.is_empty() {
        ctx.error(UNAPPLIED_INPUT_WARNING)?;
        return render(ctx);
    }

    // 3. 옵션 동기화
    if read_options(ctx).is_err() {
        ctx.error("옵션 입력을 손실 없이 읽을 수 없습니다.")?;
        return render(ctx);
    }

    // 4. 대상 목록 비어있음 사전 검사
    let is_empty = {
        let guard = ctx.lock_run_slot()?;
        let session = guard.as_ref().ok_or(())?;
        session.presenter().state().targets().is_empty()
    };
    if is_empty {
        ctx.error("진단 대상이 비어 있습니다. 대상을 먼저 추가해주세요.")?;
        return render(ctx);
    }

    // 5. Factory 정의 및 try_start_with 호출
    // Start factory는 반드시 try_start_with의 closure 안에서만 호출
    #[cfg(not(test))]
    let factory = || {
        let backend = crate::native_backend_for_current_exe()
            .map_err(|_| crate::gui_run_session::SessionInitError::BackendUnavailable)?;
        crate::gui_coordinator::GuiRunCoordinator::spawn_native(std::sync::Arc::new(backend))
            .map_err(|_| crate::gui_run_session::SessionInitError::HostSpawnFailed)
    };

    #[cfg(test)]
    let mut mock_factory = ctx.mock_coordinator_factory.borrow_mut();
    #[cfg(test)]
    let factory = move || {
        if let Some(f) = mock_factory.as_mut() {
            f()
        } else {
            Err(crate::gui_run_session::SessionInitError::BackendUnavailable)
        }
    };

    let start_res = {
        let mut guard = ctx.lock_run_slot()?;
        let session = guard.as_mut().ok_or(())?;
        session.try_start_with(factory)
    };

    match start_res {
        Ok(_run_id) => {
            if let Ok(mut guard) = ctx.lock_run_slot()
                && let Some(session) = guard.as_mut()
            {
                session.set_ui_error(None);
            }
        }
        Err(SessionError::Busy) => {}
        Err(e) => {
            ctx.error(&e.to_string())?;
        }
    }

    render(ctx)
}

fn handle_stop(ctx: &Context) -> Result<(), ()> {
    if !ctx.model.is_run() {
        return Ok(());
    }
    let res = {
        let mut guard = ctx.lock_run_slot()?;
        let session = guard.as_mut().ok_or(())?;
        session.request_cancel()
    };
    if let Err(e) = res {
        ctx.error(&e.to_string())?;
    }
    render(ctx)
}

fn handle_close(ctx: &Context) -> Result<(), ()> {
    if !ctx.model.is_run() {
        return destroy_owned(ctx);
    }
    let shutdown = {
        let mut guard = ctx.lock_run_slot()?;
        let session = guard.as_mut().ok_or(())?;
        let _ = session.begin_close();
        session.shutdown_state()
    };
    if matches!(shutdown, SessionShutdown::Closed | SessionShutdown::Failed) {
        destroy_owned(ctx)
    } else {
        render(ctx)
    }
}

fn handle_timer(ctx: &Context, timer_id: usize) -> Result<(), ()> {
    if timer_id != RUN_TIMER_ID || !ctx.model.is_run() {
        return Ok(());
    }
    let (outcome, shutdown, phase) = {
        let mut guard = ctx.lock_run_slot()?;
        let session = guard.as_mut().ok_or(())?;
        let outcome = session.poll();
        let shutdown = session.shutdown_state();
        let phase = session.presenter().state().phase();
        (outcome, shutdown, phase)
    };

    if matches!(shutdown, SessionShutdown::Closed | SessionShutdown::Failed) {
        let is_closing = {
            let guard = ctx.lock_run_slot()?;
            guard.as_ref().is_some_and(|s| s.is_close_requested())
        };
        if is_closing {
            return destroy_owned(ctx);
        }
    }

    let prev_phase = ctx.last_phase.get();
    let phase_changed = prev_phase != Some(phase);
    let outcome_active = !matches!(outcome, PollOutcome::Idle);

    if phase_changed || outcome_active {
        ctx.last_phase.set(Some(phase));
        render(ctx)?;
    }
    Ok(())
}

fn command(ctx: &Context, wp: WPARAM, lp: LPARAM) -> Result<(), ()> {
    let Some(i) = (wp & 0xffff)
        .checked_sub(FIRST_ID)
        .filter(|i| *i < CONTROL_COUNT)
    else {
        return Ok(());
    };
    let c = ctx.controls.get();
    // 소유 HWND도 일치해야 합니다. 잘못된 sender/메뉴 알림과 생성 초기 알림을 무시합니다.
    if !c.ready() || lp as HWND != c.get(i) || lp == 0 {
        return Ok(());
    }
    if ctx.handling.replace(true) {
        return Ok(());
    }
    let _guard = NotificationGuard(&ctx.handling);
    let code = ((wp >> 16) & 0xffff) as u32;
    if let Some(field) = [INPUT, TIMEOUT, CONCURRENCY]
        .iter()
        .position(|index| *index == i)
    {
        if code == EN_MAXTEXT {
            ctx.truncated[field].set(true);
            let _ = ctx.mark_plan_stale();
            ctx.error(TRUNCATED)?;
            return render(ctx);
        }
        if code == EN_CHANGE {
            let max = if i == INPUT {
                INPUT_LIMIT
            } else {
                OPTION_LIMIT
            };
            let raw = match read_text(c.get(i), max) {
                Ok(raw) => raw,
                Err(()) => {
                    ctx.error("입력 읽기 실패 또는 길이 초과입니다.")?;
                    let _ = ctx.mark_plan_stale();
                    return render(ctx);
                }
            };
            if raw.is_empty() {
                ctx.truncated[field].set(false);
            }
            let _ = ctx.mark_plan_stale();
            if ctx.has_truncation() {
                ctx.error(TRUNCATED)?;
            } else if i != INPUT && read_options(ctx).is_err() {
                ctx.error("옵션 입력을 손실 없이 읽을 수 없습니다.")?;
            }
            return render(ctx);
        }
    }
    match (i, code) {
        (APPEND, BN_CLICKED) => apply_input(ctx, false),
        (REPLACE, BN_CLICKED) => apply_input(ctx, true),
        (DELETE, BN_CLICKED) => {
            let _ = ctx.remove_selected();
            render(ctx)
        }
        (PLAN, BN_CLICKED) => {
            if ctx.has_truncation() {
                ctx.error(TRUNCATED)?;
                return render(ctx);
            }
            if read_options(ctx).is_err() {
                ctx.error("옵션 입력을 손실 없이 읽을 수 없습니다.")?;
            } else {
                let _ = ctx.confirm_plan();
            }
            render(ctx)
        }
        (TCP | PING | TRACE | DNS | LOCAL, BN_CLICKED) => {
            let _ = ctx.mark_plan_stale();
            if ctx.has_truncation() {
                ctx.error(TRUNCATED)?;
            } else if read_options(ctx).is_err() {
                ctx.error("옵션 입력을 손실 없이 읽을 수 없습니다.")?;
            }
            render(ctx)
        }
        (TARGETS, LBN_SELCHANGE) => {
            let selected = send(c.get(TARGETS), LB_GETCURSEL, 0, 0);
            let _ = ctx.set_selected_index((selected >= 0).then_some(selected as usize));
            Ok(())
        }
        (START, BN_CLICKED) => handle_start(ctx),
        (STOP, BN_CLICKED) => handle_stop(ctx),
        (CLOSE, BN_CLICKED) => handle_close(ctx),
        _ => Ok(()),
    }
}

fn destroy_owned(ctx: &Context) -> Result<(), ()> {
    let hwnd = ctx.live.get();
    if hwnd.is_null() {
        return Ok(());
    }
    if ctx.timer_active.replace(false) {
        unsafe { KillTimer(hwnd, RUN_TIMER_ID) };
    }
    // 안전: 현재 컨텍스트에 부착된 소유 live 창만 파괴합니다.
    if unsafe { DestroyWindow(hwnd) } == 0 || !ctx.live.get().is_null() {
        Err(())
    } else {
        Ok(())
    }
}

fn fatal(ctx: &Context) {
    ctx.fatal.set(true);
    ctx.posted_quit.set(true);
    // 안전: 자기 UI 스레드에 오류 종료만 요청하며 메모리 해제는 guard 담당입니다.
    unsafe {
        PostQuitMessage(1);
    }
}

/// 안전: 시스템이 클래스 콜백에 전달하는 메시지 ABI/포인터만 읽습니다.
unsafe fn dispatch(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    // 안전: CREATESTRUCT/MINMAXINFO는 해당 메시지 동안 유효하고 userdata는 안정된 Box입니다.
    unsafe {
        if msg == WM_NCCREATE {
            let cs = lp as *const CREATESTRUCTW;
            if cs.is_null() || (*cs).lpCreateParams.is_null() {
                return 0;
            }
            let ctx = &*((*cs).lpCreateParams as *const Context);
            SetLastError(0);
            let old = SetWindowLongPtrW(hwnd, GWLP_USERDATA, ctx as *const Context as isize);
            if old == 0 && GetLastError() != 0 {
                return 0;
            }
            ctx.live.set(hwnd);
            #[cfg(test)]
            ctx.observations.parents.borrow_mut().push(hwnd);
            return DefWindowProcW(hwnd, msg, wp, lp);
        }
        if msg == WM_GETMINMAXINFO {
            let info = lp as *mut MINMAXINFO;
            if !info.is_null() {
                (*info).ptMinTrackSize.x = MIN_WIDTH;
                (*info).ptMinTrackSize.y = MIN_HEIGHT;
            }
            return 0;
        }
        let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const Context;
        if ptr.is_null() {
            return DefWindowProcW(hwnd, msg, wp, lp);
        }
        let ctx = &*ptr;
        if msg == WM_NCDESTROY {
            if ctx.timer_active.replace(false) {
                KillTimer(hwnd, RUN_TIMER_ID);
            }
            SetLastError(0);
            let old = SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            if old == 0 && GetLastError() != 0 {
                fatal(ctx);
            } else {
                ctx.live.set(null_mut());
            }
            return DefWindowProcW(hwnd, msg, wp, lp);
        }
        if ctx.fatal.get() && msg != WM_DESTROY {
            return DefWindowProcW(hwnd, msg, wp, lp);
        }
        let result = match msg {
            WM_CREATE => match create_controls(hwnd, ctx) {
                Ok(c) => {
                    ctx.controls.set(c);
                    render(ctx)
                }
                Err(()) => return -1,
            },
            WM_COMMAND => command(ctx, wp, lp),
            WM_SIZE => layout(
                ctx.controls.get(),
                (lp & 0xffff) as i32,
                ((lp >> 16) & 0xffff) as i32,
            ),
            WM_TIMER => handle_timer(ctx, wp as usize),
            WM_CLOSE => handle_close(ctx),
            WM_DESTROY => {
                if ctx.timer_active.replace(false) {
                    KillTimer(hwnd, RUN_TIMER_ID);
                }
                ctx.posted_quit.set(true);
                PostQuitMessage(if ctx.fatal.get() { 1 } else { 0 });
                Ok(())
            }
            _ => return DefWindowProcW(hwnd, msg, wp, lp),
        };
        if result.is_err() {
            fatal(ctx);
            if msg == WM_CREATE {
                return -1;
            }
        }
        0
    }
}

unsafe extern "system" fn wnd_proc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // 안전: 등록된 시스템 콜백에서 전달받은 메시지만 내부로 위임합니다.
        unsafe { dispatch(hwnd, msg, wp, lp) }
    }));
    match result {
        Ok(value) => value,
        Err(_) => {
            // 안전: unwind 뒤 대여가 해제된 컨텍스트에 실패만 표시합니다. 해제/소유권회수0.
            unsafe {
                let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const Context;
                if !ptr.is_null() {
                    fatal(&*ptr);
                } else {
                    PostQuitMessage(1);
                }
            }
            if msg == WM_CREATE { -1 } else { 0 }
        }
    }
}

fn register_window_class(class_name: PCWSTR) -> Result<(), ()> {
    // 안전: 정적 클래스/콜백과 OS 공유 cursor/brush만 사용하며 공유 자원을 해제하지 않습니다.
    unsafe {
        let instance = GetModuleHandleW(null());
        if instance.is_null() {
            return Err(());
        }
        let cursor = LoadCursorW(null_mut(), IDC_ARROW);
        if cursor.is_null() {
            return Err(());
        }
        let class = WNDCLASSW {
            lpfnWndProc: Some(wnd_proc),
            hInstance: instance,
            lpszClassName: class_name,
            hCursor: cursor,
            hbrBackground: (COLOR_WINDOW + 1) as _,
            ..Default::default()
        };
        if RegisterClassW(&class) != 0 {
            return Ok(());
        }
        if GetLastError() != ERROR_CLASS_ALREADY_EXISTS {
            return Err(());
        }
        let mut previous = WNDCLASSW::default();
        if GetClassInfoW(instance, class_name, &mut previous) == 0
            || previous.hInstance != instance
            || previous.lpfnWndProc.map(|f| f as usize) != Some(wnd_proc as *const () as usize)
        {
            return Err(());
        }
        Ok(())
    }
}

/// 숨김 시험과 사용자 진입이 동일한 생성·초기화·실패정리 경로를 소비합니다.
fn create_window(context: Box<Context>) -> Result<WindowGuard, ()> {
    let is_run = context.model.is_run();
    let class_name = if is_run {
        RUN_WINDOW_CLASS
    } else {
        WINDOW_CLASS
    };
    let window_title = if is_run {
        RUN_WINDOW_TITLE
    } else {
        WINDOW_TITLE
    };
    register_window_class(class_name)?;

    let guard = WindowGuard {
        context: Some(context),
    };
    let ptr = guard.context() as *const Context;
    // 안전: guard Box는 모든 동기 생성 콜백과 창 수명 동안 안정 주소를 유지합니다.
    let hwnd = unsafe {
        CreateWindowExW(
            0,
            class_name,
            window_title,
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            1100,
            800,
            null_mut(),
            null_mut(),
            GetModuleHandleW(null()),
            ptr.cast(),
        )
    };
    if hwnd.is_null() || guard.context().fatal.get() || guard.hwnd() != hwnd {
        return Err(());
    }

    if is_run {
        #[cfg(test)]
        if guard.context().fail_timer.get() {
            let _ = guard.close();
            return Err(());
        }
        let tid = unsafe { SetTimer(hwnd, RUN_TIMER_ID, TIMER_INTERVAL_MS, None) };
        if tid == 0 {
            let _ = guard.close();
            return Err(());
        }
        guard.context().timer_active.set(true);
    }

    let mut rect = windows_sys::Win32::Foundation::RECT::default();
    // 안전: 자기 창과 유효 출력 RECT입니다.
    if unsafe { GetClientRect(hwnd, &mut rect) } == 0 {
        return Err(());
    }
    layout(
        guard.context().controls.get(),
        rect.right - rect.left,
        rect.bottom - rect.top,
    )?;
    Ok(guard)
}

fn run_gui_loop(context: Box<Context>) -> Result<(), ()> {
    let guard = create_window(context)?;
    // 안전: 자기 창을 표시한 뒤 현재 스레드에서 Win32 메시지만 처리합니다.
    unsafe {
        ShowWindow(guard.hwnd(), SW_SHOW);
        UpdateWindow(guard.hwnd());
    }
    let result = (|| {
        let mut msg = MSG::default();
        loop {
            // 안전: 유효 MSG이며 guard가 컨텍스트를 계속 소유합니다.
            let code = unsafe { GetMessageW(&mut msg, null_mut(), 0, 0) };
            if code == -1 {
                return Err(());
            }
            if code == 0 {
                guard.context().posted_quit.set(false);
                return if msg.wParam == 0 && !guard.context().fatal.get() {
                    Ok(())
                } else {
                    Err(())
                };
            }
            // 안전: live창만 dialog 탐색에 넘깁니다. 프로브/runner/네트워크I/O0.
            unsafe {
                if guard.hwnd().is_null() || IsDialogMessageW(guard.hwnd(), &msg) == 0 {
                    TranslateMessage(&msg);
                    DispatchMessageW(&msg);
                }
            }
            if guard.context().fatal.get() {
                return Err(());
            }
        }
    })();
    let cleanup = guard.close();
    if guard.context().fatal.get() {
        Err(())
    } else {
        result.and(cleanup)
    }
}

pub(super) fn run_native_gui() -> Result<(), ()> {
    run_gui_loop(Box::new(Context::new_inputs()))
}

pub(super) fn run_native_execution_gui(
    slot: crate::gui_run_entry::GuiSessionSlot,
) -> Result<(), ()> {
    run_gui_loop(Box::new(Context::new_run(slot)))
}

#[cfg(test)]
#[path = "native_gui_tests.rs"]
mod tests;
