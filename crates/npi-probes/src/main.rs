//! G2-A 개발자용 루프백 전용 CLI 엔트리포인트 (`npi-probes <profile.json>`).
//!
//! - 최대 64KiB 이하의 프로필 JSON 파일만 읽는다.
//! - 비루프백 우회 플래그를 일절 제공하지 않는다.
//! - 단일 스레드(`current_thread`) Tokio 런타임을 구성하여 `run_profile`을 호출한다.
//! - 성공 시 측정 엔벨로프 JSON을 출력하고 종료 코드 0을 반환하며,
//!   거부된 입력이나 오류 발생 시 오류 JSON을 출력하고 0이 아닌 종료 코드를 반환한다.

use std::{
    env,
    fs::File,
    io::Read,
    process::ExitCode,
    sync::{Arc, atomic::AtomicBool},
};

use serde_json::{Value, json};

/// 프로필 JSON 파일 최대 허용 크기 (64KiB).
const MAX_PROFILE_BYTES: u64 = 64 * 1024;

fn emit_error_and_exit(errors: Vec<String>) -> ExitCode {
    let payload = json!({
        "errors": errors,
    });
    println!("{payload}");
    ExitCode::from(1)
}

fn main() -> ExitCode {
    let args: Vec<std::ffi::OsString> = env::args_os().collect();
    if args.len() != 2 {
        return emit_error_and_exit(vec![
            "사용법: npi-probes <profile.json> (단일 프로필 경로만 허용하며 우회 플래그는 지원하지 않습니다)"
                .to_string(),
        ]);
    }

    let path = &args[1];
    let file = match File::open(path) {
        Ok(f) => f,
        Err(err) => {
            return emit_error_and_exit(vec![format!("프로필 파일 열기 실패: {err}")]);
        }
    };

    let mut buffer = Vec::new();
    if let Err(err) = file.take(MAX_PROFILE_BYTES + 1).read_to_end(&mut buffer) {
        return emit_error_and_exit(vec![format!("프로필 파일 읽기 실패: {err}")]);
    }

    if (buffer.len() as u64) > MAX_PROFILE_BYTES {
        return emit_error_and_exit(vec![format!(
            "프로필 파일 크기가 64KiB({MAX_PROFILE_BYTES} 바이트) 상한을 초과했습니다"
        )]);
    }

    let profile: Value = match serde_json::from_slice(&buffer) {
        Ok(v) => v,
        Err(err) => {
            return emit_error_and_exit(vec![format!("프로필 JSON 파싱 실패: {err}")]);
        }
    };

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            return emit_error_and_exit(vec![format!("Tokio 런타임 생성 실패: {err}")]);
        }
    };

    let cancelled = Arc::new(AtomicBool::new(false));
    match runtime.block_on(npi_probes::engine::run_profile(&profile, cancelled)) {
        Ok(envelope) => match serde_json::to_string_pretty(&envelope) {
            Ok(rendered) => {
                println!("{rendered}");
                ExitCode::SUCCESS
            }
            Err(err) => emit_error_and_exit(vec![format!("결과 JSON 직렬화 실패: {err}")]),
        },
        Err(errors) => emit_error_and_exit(errors),
    }
}
