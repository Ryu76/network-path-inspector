//! Network Quick Check(Part B) 메인 실행 진입점.
//!
//! 제품 단일 실행 파일(`NetworkQuickCheck`)의 진입점으로, 명령행 인자를 수집하여
//! 라이브러리의 `entry` 함수로 전달하고 반환된 종료 코드를 OS에 전달합니다.
//! 자동 진단, 백그라운드 런타임, 네이티브 GUI, 서브시스템 속성 등의 임의 로직을 일체 포함하지 않습니다.

use std::process::ExitCode;

fn main() -> ExitCode {
    // argv0을 제외하고 최대 4개의 인자만 안전하게 수집합니다.
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).take(4).collect();
    let code = network_quick_check::entry(
        &args,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    );
    ExitCode::from(code)
}
