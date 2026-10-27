//! Network Quick Check(Part B) 실제 검사 네이티브 GUI 진입점 모듈.
//!
//! 제품 단일 실행 파일(`NetworkQuickCheck`)의 명시적 실제 검사 GUI 진입점인
//! `--dev-gui-run-v1` 인자를 처리하며, caller 소유 슬롯과 전용 UI 스레드를 통해
//! Win32 실행 화면을 안전하게 격리 구동하고 세션 생명주기를 끝까지 drain합니다.
//!
//! ## 핵심 설계 및 불변식
//! - **정확한 단일 인자 진입**:
//!   인자는 정확히 1개(`--dev-gui-run-v1`)여야 하며, 인자 개수 불일치나 비유니코드 인자는 즉각 거부합니다 (Fail-Closed).
//!   미선택 시 백엔드, 세션, 스레드 등의 리소스를 일체 생성하지 않고 `None`을 반환합니다.
//! - **원문 반사 없는 정적 오류**:
//!   - 잘못된 인자 개수 시 `crate::INVALID_STDERR`를 출력하고 exit 2로 종료합니다.
//!   - Windows 이외 플랫폼에서는 정적 미지원 메시지를 출력하고 exit 1로 종료합니다.
//!   - GUI 초기화 또는 실행 실패 시 정적 오류 메시지를 출력하고 exit 1로 종료합니다.
//! - **단일 슬롯 소유권 및 UI 스레드 격리**:
//!   - `GuiRunSession`은 caller(non-UI)가 생성한 `GuiSessionSlot`에 단 하나만 소유됩니다.
//!   - UI thread에는 `Arc` 복제본만 전달하며, UI는 세션을 `Option::take`, 교체, 복제하지 않습니다.
//!   - `launch_run_gui_with`는 전용 UI thread를 생성하고 완료 및 패닉을 관측합니다.
//!   - thread spawn 실패 시에도 caller 슬롯이 원 세션을 보존하며, 새 스레드 spawn 없이 caller에서 직접 회수합니다.
//! - **Caller 최종 Drain 및 Fail-Closed 보존**:
//!   - UI 스레드 종료 후 caller가 슬롯에서 원 세션을 take하여 `begin_close` + `poll`로 `Closed` 또는 `Failed`까지 drain합니다.
//!   - UI 오류(`Err`), UI 패닉, 슬롯 poison 발생 시 원 세션을 안전하게 회수하되 결과를 결코 성공으로 위장하지 않고 `failed = true`를 반환합니다.
//!   - 슬롯이 비정상적으로 `None`인 경우 가짜 세션을 발명하지 않고 `failed = true`로 종료합니다.
//!   - Drain이 `Pending` 상태로 남은 채 무책임하게 종료하거나 세션을 Drop하지 않으며, 5초 상한 동안 실제 worker 및 채널 종료를 확인합니다.

use std::ffi::OsString;
use std::io::Write;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex};
use std::thread::{self, Builder, JoinHandle};
use std::time::{Duration, Instant};

use crate::gui_presenter::GuiPresenter;
use crate::gui_run_session::{GuiRunSession, SessionShutdown};

/// 네이티브 실제 검사 GUI 진입점 셀렉터 플래그 문자열.
pub(crate) const GUI_RUN_SELECTOR: &str = "--dev-gui-run-v1";

/// 비Windows 환경에서 GUI 실행 시도 시 출력되는 정적 한국어 메시지.
pub(crate) const GUI_UNSUPPORTED_STDERR: &str =
    "Network Quick Check: 네이티브 GUI는 Windows 환경에서만 지원됩니다.\n";

/// GUI 생성, 메시지 루프 또는 실행 중 오류 발생 시 출력되는 정적 한국어 메시지.
pub(crate) const GUI_RUNTIME_ERROR_STDERR: &str =
    "Network Quick Check: GUI 초기화 또는 실행 중 오류가 발생했습니다.\n";

/// caller가 소유하고 UI thread와 공유하는 단일 세션 슬롯.
pub(crate) type GuiSessionSlot = Arc<Mutex<Option<GuiRunSession>>>;

/// 실행 GUI 종료 결과.
pub(crate) struct GuiRunExit {
    pub(crate) session: Option<GuiRunSession>,
    pub(crate) failed: bool,
}

/// 주어진 정적 메시지를 stderr에 기록하고 플러시합니다.
fn write_static_stderr(stderr: &mut dyn Write, message: &str) -> bool {
    stderr
        .write_all(message.as_bytes())
        .and_then(|_| stderr.flush())
        .is_ok()
}

/// 전용 UI thread를 생성하고 세션을 drain하여 결과를 반환합니다.
pub(crate) fn launch_run_gui_with<F>(
    session: GuiRunSession,
    ui: F,
) -> GuiRunExit
where
    F: FnOnce(GuiSessionSlot) -> Result<(), ()> + Send + 'static,
{
    launch_run_gui_with_spawner(session, ui, |job| {
        Builder::new()
            .name("quick-gui-ui".into())
            .spawn(job)
    })
}

/// thread spawn 실패 시나리오 등을 모의할 수 있도록 spawner를 주입받는 내부 런처.
pub(crate) fn launch_run_gui_with_spawner<F, S>(
    session: GuiRunSession,
    ui: F,
    spawner: S,
) -> GuiRunExit
where
    F: FnOnce(GuiSessionSlot) -> Result<(), ()> + Send + 'static,
    S: FnOnce(Box<dyn FnOnce() -> Result<(), ()> + Send>) -> std::io::Result<JoinHandle<Result<(), ()>>>,
{
    // session은 caller(non-UI)가 만든 slot에 처음부터 한 개만 소유된다.
    let slot: GuiSessionSlot = Arc::new(Mutex::new(Some(session)));
    let ui_slot = Arc::clone(&slot);

    let job = Box::new(move || {
        let run_res = catch_unwind(AssertUnwindSafe(move || ui(ui_slot)));
        match run_res {
            Ok(res) => res,
            Err(_) => Err(()),
        }
    });

    let spawn_res = spawner(job);

    let mut ui_failed = false;
    match spawn_res {
        Ok(join_handle) => {
            // UI join은 caller에서만 수행 (UI thread나 callback은 recv/join/block_on 금지)
            match join_handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(())) => {
                    ui_failed = true;
                }
                Err(_) => {
                    // UI 스레드 패닉 관측
                    ui_failed = true;
                }
            }
        }
        Err(_) => {
            // thread spawn 실패: caller slot이 원 session을 보존하므로
            // 새 drain thread를 spawn하지 않고 caller에서 직접 회수
            ui_failed = true;
        }
    }

    // UI thread 종료 뒤 (또는 spawn 실패 뒤) caller는 같은 slot에서 원 session을 take하고
    // begin_close + poll로 실제 Closed/Failed까지 끝까지 drain한다.
    drain_and_exit(slot, ui_failed)
}

/// UI thread 종료 후 슬롯에서 원 세션을 회수하고 최종 drain을 수행합니다.
fn drain_and_exit(slot: GuiSessionSlot, ui_failed: bool) -> GuiRunExit {
    let mut poison_occurred = false;
    let session_opt = match slot.lock() {
        Ok(mut guard) => guard.take(),
        Err(poisoned) => {
            poison_occurred = true;
            // poison은 into_inner로 원 session을 회수하되 성공으로 위장하지 않음
            poisoned.into_inner().take()
        }
    };

    let Some(mut session) = session_opt else {
        // None이면 failed=true이며 대체 session/가짜 완료를 만들지 않는다.
        return GuiRunExit {
            session: None,
            failed: true,
        };
    };

    let mut failed = ui_failed || poison_occurred;

    // begin_close + poll로 실제 Closed/Failed까지 끝까지 drain한다.
    let _ = session.begin_close();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        session.poll();
        match session.shutdown_state() {
            SessionShutdown::Closed => {
                break;
            }
            SessionShutdown::Failed => {
                failed = true;
                break;
            }
            SessionShutdown::Pending => {
                if Instant::now() >= deadline {
                    // 타임아웃: caller drain이 Pending인데 성공 반환/원 session 무책임 Drop 금지
                    failed = true;
                    break;
                }
                thread::yield_now();
                thread::sleep(Duration::from_millis(1));
            }
            SessionShutdown::NotRequested => {
                let _ = session.begin_close();
            }
        }
    }

    GuiRunExit {
        session: Some(session),
        failed,
    }
}

/// 공통 실행 GUI 런처 디스패처.
///
/// 실제 프로덕션 진입과 모의 단위 테스트가 동일한 디스패처 로직을 공유합니다.
pub(crate) fn dispatch_launcher<F>(
    args: &[OsString],
    stderr: &mut dyn Write,
    is_windows: bool,
    launcher: F,
) -> Option<u8>
where
    F: FnOnce() -> Result<(), ()>,
{
    if args.is_empty() {
        return None;
    }

    // Unicode 손실 변환 금지: to_str()이 None이면 비Unicode이므로 셀렉터 불일치로 간주하여 None 반환
    let first = args[0].to_str()?;

    if first != GUI_RUN_SELECTOR {
        return None;
    }

    // 셀렉터는 일치하지만 arity가 정확히 1이 아닌 경우
    if args.len() != 1 {
        let code = if write_static_stderr(stderr, crate::INVALID_STDERR) {
            2
        } else {
            1
        };
        return Some(code);
    }

    // Windows가 아닌 환경인 경우
    if !is_windows {
        let _ = write_static_stderr(stderr, GUI_UNSUPPORTED_STDERR);
        return Some(1);
    }

    // 런처 실행 및 패닉 방어
    let run_res = catch_unwind(AssertUnwindSafe(launcher));
    match run_res {
        Ok(Ok(())) => Some(0),
        Ok(Err(())) | Err(_) => {
            let _ = write_static_stderr(stderr, GUI_RUNTIME_ERROR_STDERR);
            Some(1)
        }
    }
}

/// Network Quick Check 진입점에서 실제 검사 네이티브 GUI 실행을 시도합니다.
///
/// - `--dev-gui-run-v1` 단일 인자가 아니면 `None`을 반환하여 다음 진입점으로 위임합니다.
/// - 단일 인자가 일치하면 네이티브 GUI를 열고 정상 종료 시 `Some(0)`, 오류/미지원 시 `Some(1)`, 인자 오류 시 `Some(2)`를 반환합니다.
pub(crate) fn try_entry(args: &[OsString], stderr: &mut dyn Write) -> Option<u8> {
    #[cfg(windows)]
    {
        dispatch_launcher(args, stderr, true, || {
            let session = GuiRunSession::new(GuiPresenter::new());
            let exit = launch_run_gui_with(session, crate::native_gui::run_native_execution_gui);
            if exit.failed {
                Err(())
            } else {
                Ok(())
            }
        })
    }
    #[cfg(not(windows))]
    {
        dispatch_launcher(args, stderr, false, || Err(()))
    }
}

#[cfg(test)]
#[path = "gui_run_entry_tests.rs"]
mod tests;
