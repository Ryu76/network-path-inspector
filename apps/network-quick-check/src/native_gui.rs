//! 입력·계획 전용 Win32 화면. 네트워크·runtime·worker 실행은 없다.
//! HWND는 WM_NCDESTROY로 무효화하고 Box는 호출자가 끝까지 소유한다.
//! 파괴 실패 때 연결된 컨텍스트는 해제하지 않는다. native 호출 동안 RefCell 대여0.
#![cfg(windows)]
use crate::gui_presenter::{GuiPresenter, decode_utf16_input};
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
const WINDOW_CLASS: PCWSTR = w!("NPI_QUICK_CHECK_GUI_INPUTS_V1");
const WINDOW_TITLE: PCWSTR = w!("Network Quick Check - 입력·계획 확인 (진단 미연결)");
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
const TRUNCATED: &str = "입력이 잘렸습니다. 해당 입력란을 완전히 비운 뒤 다시 입력해주세요.";
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
struct Context {
    presenter: RefCell<GuiPresenter>,
    controls: Cell<Controls>,
    live: Cell<HWND>,
    truncated: [Cell<bool>; 3],
    handling: Cell<bool>,
    fatal: Cell<bool>,
    posted_quit: Cell<bool>,
    #[cfg(test)]
    observations: std::rc::Rc<Observations>,
    #[cfg(test)]
    fail_child_at: Option<usize>,
}
impl Context {
    fn new() -> Self {
        Self {
            presenter: RefCell::new(GuiPresenter::new()),
            controls: Cell::new(Controls::empty()),
            live: Cell::new(null_mut()),
            truncated: std::array::from_fn(|_| Cell::new(false)),
            handling: Cell::new(false),
            fatal: Cell::new(false),
            posted_quit: Cell::new(false),
            #[cfg(test)]
            observations: Default::default(),
            #[cfg(test)]
            fail_child_at: None,
        }
    }
    fn edit<R>(&self, action: impl FnOnce(&mut GuiPresenter) -> R) -> Result<R, ()> {
        let mut p = self.presenter.try_borrow_mut().map_err(|_| ())?;
        Ok(action(&mut p))
    }
    fn error(&self, text: &str) -> Result<(), ()> {
        self.edit(|p| p.set_error(Some(text.to_owned())))
    }
    fn has_truncation(&self) -> bool {
        self.truncated.iter().any(Cell::get)
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
/// 유일한 소유 가드. WndProc는 Box::from_raw나 해제를 하지 않는다.
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
        // 안전: 현재 스레드의 자기 live 창만 파괴하며 NCDESTROY가 live를 지운다.
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
            // 안전: 자기 창이 현재 스레드에 남긴 quit만 꺼낸다. 다른 메시지는 건드리지 않는다.
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
            // 실패를 성공으로 숨기지 않는다. 부착된 userdata의 UAF보다 메모리 보존을 선택한다.
            if let Some(context) = self.context.take() {
                let _ = Box::leak(context);
            }
        }
    }
}
/// Win32 빈 문자열/오류를 구분하고 읽기 전후 길이와 복사 크기를 검증한다.
fn read_text(hwnd: HWND, max: usize) -> Result<Vec<u16>, ()> {
    // 안전: 소유 HWND와 정확한 크기의 쓰기 버퍼만 사용한다.
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
    // 안전: 동기 호출 동안 유효한 NUL 종료 버퍼와 소유 HWND다.
    if unsafe { SetWindowTextW(hwnd, wide.as_ptr()) } == 0 {
        Err(())
    } else {
        Ok(())
    }
}
fn send(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    // 안전: 소유 HWND와 각 메시지 계약에 맞는 스칼라/동기 호출 동안 유효한 버퍼만 전달한다.
    unsafe { SendMessageW(hwnd, msg, wp, lp) }
}
struct ControlSpec {
    class: PCWSTR,
    label: PCWSTR,
    style: u32,
}
fn specifications() -> [ControlSpec; CONTROL_COUNT] {
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
    [
        label(w!("입력·계획 확인 전용 / 네트워크 진단 미연결")),
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
        label(w!("검사 기능 (현재는 계획 확인만 가능)")),
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
        button(w!("검사 시작 (미연결)")),
        button(w!("중지 (미연결)")),
        button(w!("저장 (미연결)")),
        button(w!("닫기")),
    ]
}
fn create_controls(parent: HWND, ctx: &Context) -> Result<Controls, ()> {
    let mut c = Controls::empty();
    // 안전: 부모/모듈은 현재 스레드 소유. 모든 생성 자식은 부모 파괴 경로에 포함된다.
    unsafe {
        let instance = GetModuleHandleW(null());
        if instance.is_null() {
            return Err(());
        }
        let font = GetStockObject(DEFAULT_GUI_FONT);
        if font.is_null() {
            return Err(());
        }
        for (i, spec) in specifications().iter().enumerate() {
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
        // stock font/cursor는 공유 OS 리소스다. DeleteObject/DestroyCursor 하지 않는다.
        for i in [START, STOP, SAVE] {
            EnableWindow(c.get(i), 0);
        }
    }
    #[cfg(not(test))]
    let _ = ctx;
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
        // 안전: 자기 컨트롤만 이동하며 Rust 대여를 유지하지 않는다.
        if unsafe { MoveWindow(c.get(i), x, y, w, h, 1) } == 0 {
            return Err(());
        }
    }
    Ok(())
}
fn render(ctx: &Context) -> Result<(), ()> {
    let c = ctx.controls.get();
    let (rows, selection, plan, errors) = {
        let p = ctx.presenter.try_borrow().map_err(|_| ())?;
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
    set_text(c.get(PREVIEW), &plan)?;
    set_text(c.get(ERRORS), &errors)
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
    let result = ctx.edit(|p| p.update_draft_utf16(&time, &concurrent, chosen))?;
    if let Err(e) = result {
        ctx.error(&e.to_string())?;
        return Err(());
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
            let ok = ctx
                .edit(|p| {
                    if replace {
                        p.replace_targets(&text)
                    } else {
                        p.append_targets(&text)
                    }
                })?
                .is_ok();
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
fn command(ctx: &Context, wp: WPARAM, lp: LPARAM) -> Result<(), ()> {
    let Some(i) = (wp & 0xffff)
        .checked_sub(FIRST_ID)
        .filter(|i| *i < CONTROL_COUNT)
    else {
        return Ok(());
    };
    let c = ctx.controls.get();
    // 소유 HWND도 일치해야 한다. 잘못된 sender/메뉴 알림과 생성 초기 알림을 무시한다.
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
            ctx.edit(GuiPresenter::mark_plan_stale)?;
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
                    ctx.edit(GuiPresenter::mark_plan_stale)?;
                    return render(ctx);
                }
            };
            if raw.is_empty() {
                ctx.truncated[field].set(false);
            }
            ctx.edit(GuiPresenter::mark_plan_stale)?;
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
            ctx.edit(|p| {
                let _ = p.remove_selected();
            })?;
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
                ctx.edit(|p| {
                    let _ = p.confirm_plan();
                })?;
            }
            render(ctx)
        }
        (TCP | PING | TRACE | DNS | LOCAL, BN_CLICKED) => {
            ctx.edit(GuiPresenter::mark_plan_stale)?;
            if ctx.has_truncation() {
                ctx.error(TRUNCATED)?;
            } else if read_options(ctx).is_err() {
                ctx.error("옵션 입력을 손실 없이 읽을 수 없습니다.")?;
            }
            render(ctx)
        }
        (TARGETS, LBN_SELCHANGE) => {
            let selected = send(c.get(TARGETS), LB_GETCURSEL, 0, 0);
            ctx.edit(|p| {
                let _ = p.set_selected_index((selected >= 0).then_some(selected as usize));
            })?;
            Ok(())
        }
        (CLOSE, BN_CLICKED) => destroy_owned(ctx),
        _ => Ok(()),
    }
}
fn destroy_owned(ctx: &Context) -> Result<(), ()> {
    let hwnd = ctx.live.get();
    if hwnd.is_null() {
        return Ok(());
    }
    // 안전: 현재 컨텍스트에 부착된 소유 live 창만 파괴한다.
    if unsafe { DestroyWindow(hwnd) } == 0 || !ctx.live.get().is_null() {
        Err(())
    } else {
        Ok(())
    }
}
fn fatal(ctx: &Context) {
    ctx.fatal.set(true);
    ctx.posted_quit.set(true);
    // 안전: 자기 UI 스레드에 오류 종료만 요청하며 메모리 해제는 guard 담당이다.
    unsafe {
        PostQuitMessage(1);
    }
}
/// 안전: 시스템이 클래스 콜백에 전달하는 메시지 ABI/포인터만 읽는다.
unsafe fn dispatch(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    // 안전: CREATESTRUCT/MINMAXINFO는 해당 메시지 동안 유효하고 userdata는 안정된 Box다.
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
            WM_CLOSE => destroy_owned(ctx),
            WM_DESTROY => {
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
        // 안전: 등록된 시스템 콜백에서 전달받은 메시지만 내부로 위임한다.
        unsafe { dispatch(hwnd, msg, wp, lp) }
    }));
    match result {
        Ok(value) => value,
        Err(_) => {
            // 안전: unwind 뒤 대여가 해제된 컨텍스트에 실패만 표시한다. 해제/소유권회수0.
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
fn register_class() -> Result<(), ()> {
    // 안전: 정적 클래스/콜백과 OS 공유 cursor/brush만 사용하며 공유 자원을 해제하지 않는다.
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
            lpszClassName: WINDOW_CLASS,
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
        if GetClassInfoW(instance, WINDOW_CLASS, &mut previous) == 0
            || previous.hInstance != instance
            || previous.lpfnWndProc.map(|f| f as usize) != Some(wnd_proc as *const () as usize)
        {
            return Err(());
        }
        Ok(())
    }
}
/// 숨김 시험과 사용자 진입이 동일한 생성·초기화·실패정리 경로를 소비한다.
fn create_window(context: Box<Context>) -> Result<WindowGuard, ()> {
    register_class()?;
    let guard = WindowGuard {
        context: Some(context),
    };
    let ptr = guard.context() as *const Context;
    // 안전: guard Box는 모든 동기 생성 콜백과 창 수명 동안 안정 주소를 유지한다.
    let hwnd = unsafe {
        CreateWindowExW(
            0,
            WINDOW_CLASS,
            WINDOW_TITLE,
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
    let mut rect = windows_sys::Win32::Foundation::RECT::default();
    // 안전: 자기 창과 유효 출력 RECT다.
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
pub(super) fn run_native_gui() -> Result<(), ()> {
    let guard = create_window(Box::new(Context::new()))?;
    // 안전: 자기 창을 표시한 뒤 현재 스레드에서 Win32 메시지만 처리한다.
    unsafe {
        ShowWindow(guard.hwnd(), SW_SHOW);
        UpdateWindow(guard.hwnd());
    }
    let result = (|| {
        let mut msg = MSG::default();
        loop {
            // 안전: 유효 MSG이며 guard가 컨텍스트를 계속 소유한다.
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
            // 안전: live창만 dialog 탐색에 넘긴다. 프로브/runner/네트워크I/O0.
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
#[cfg(test)]
#[path = "native_gui_tests.rs"]
mod tests;
