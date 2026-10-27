//! G2-A 개발자용 루프백 전용 CLI 엔트리포인트 (`npi-probes <profile.json>`) 및
//! G2-B DNS 개발 실험 진입점 (`--npi-dns-worker-v1`, `--dns-localhost`).
//!
//! 주의 및 제한사항:
//! - 본 구현은 개발/실험 단계의 진입점이며 전체 G2 수용, Session 1.1 또는 UI 연결이 아닙니다.
//! - 일반 프로필 CLI(`<profile.json>`)의 도메인 해석은 여전히 미지원 상태로 유지됩니다(G2-A 가드).
//! - `--npi-dns-worker-v1`: 동일 바이너리의 helper 프로세스 엔트리포인트로,
//!   대소문자 무관 "localhost" 또는 파싱 가능한 IPv4/IPv6 루프백 리터럴만 처리하며,
//!   OS resolver(getaddrinfo 계열)를 블로킹 호출하여 한 줄 JSON(`npi-dns-worker-1`)을 stdout으로 출력합니다.
//! - `--dns-localhost`: 부모 프로세스 명시 실험 진입점으로, 하드코딩된 "localhost"만 격리 실행합니다.
//! - 반환 주소는 OS 해석기 결과일 뿐이며, DNS 서버·RR·TTL·패킷·네트워크 정책은 관찰하지 않습니다.
//! - 최대 64KiB 이하의 프로필 JSON 파일만 읽으며, 비루프백 우회 플래그는 일절 제공하지 않습니다.

use std::{
    env,
    fs::File,
    io::Read,
    net::IpAddr,
    path::Path,
    process::ExitCode,
    sync::{
        Arc,
        atomic::AtomicBool,
    },
    time::Duration,
};

use serde_json::{Value, json};

/// 프로필 JSON 파일 최대 허용 크기 (64KiB).
const MAX_PROFILE_BYTES: u64 = 64 * 1024;

/// 기본 DNS 해석 대기 시한 (5000ms).
const DEFAULT_DNS_TIMEOUT: Duration = Duration::from_millis(5000);

fn emit_error_and_exit(errors: Vec<String>) -> ExitCode {
    let payload = json!({
        "errors": errors,
    });
    println!("{payload}");
    ExitCode::from(1)
}

/// worker 실행용 호스트가 대소문자 무관 "localhost" 또는 루프백 IP 리터럴인지 검증한다.
fn is_allowed_worker_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return ip.is_loopback();
    }
    false
}

/// CLI 시한 문자열을 엄격 검증(10진 숫자, 선행 0 금지, 1..=60000ms)하여 Duration으로 파싱한다.
fn parse_cli_timeout_ms(text: &str) -> Result<Duration, String> {
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err("시한 인자는 10진 숫자여야 합니다".to_string());
    }
    if text.len() > 1 && text.starts_with('0') {
        return Err("시한 인자에 선행 0은 허용되지 않습니다".to_string());
    }
    let millis: u64 = text
        .parse()
        .map_err(|_| "시한 숫자 파싱 실패".to_string())?;
    let duration = Duration::from_millis(millis);
    npi_probes::dns::validate_timeout(duration)?;
    Ok(duration)
}

/// 숨은 `--npi-dns-worker-v1 <host> <port>` 처리 (정확히 argc 4).
///
/// Tokio 런타임 및 프로필 파일 읽기 전에 동기적으로 실행되며,
/// stdout에 한 줄의 worker payload JSON만 출력하고 정상 protocol은 exit 0을 반환한다.
fn handle_dns_worker(args: &[std::ffi::OsString]) -> ExitCode {
    if args.len() != 4 {
        return emit_error_and_exit(vec![
            "--npi-dns-worker-v1 플래그는 정확히 2개의 인자(<host> <port>)가 필요합니다".to_string(),
        ]);
    }

    let host_str = match args[2].to_str() {
        Some(s) => s,
        None => {
            return emit_error_and_exit(vec!["worker 호스트 인자가 유효한 UTF-8이 아닙니다".to_string()]);
        }
    };

    let port_str = match args[3].to_str() {
        Some(s) => s,
        None => {
            return emit_error_and_exit(vec!["worker 포트 인자가 유효한 UTF-8이 아닙니다".to_string()]);
        }
    };

    // 보안 가드: 대소문자 무관 localhost 또는 루프백 IP 리터럴 ONLY.
    // "localhost." 및 임의 도메인/비루프백은 OS resolver 호출 전 거부.
    if !is_allowed_worker_host(host_str) {
        return emit_error_and_exit(vec![format!(
            "허용되지 않은 worker 호스트입니다: '{host_str}' (대소문자 무관 'localhost' 또는 루프백 IP 리터럴만 허용되며 우회 플래그는 없습니다)"
        )]);
    }

    // 포트 엄격 검증(1..=65535, 선행 0 금지).
    if let Err(err) = npi_probes::dns::parse_helper_port(port_str) {
        return emit_error_and_exit(vec![format!("worker 포트 오류: {err}")]);
    }

    let payload = npi_probes::dns::run_worker_from_args(host_str, port_str);
    // stdout에 정확히 worker_output_line 한 줄만 출력 (추가 로그 stdout 금지)
    print!("{}", npi_probes::dns::worker_output_line(&payload));
    ExitCode::SUCCESS
}

/// 명시 부모 실험 `--dns-localhost <port> [timeout_ms]` 처리 (argc 3 또는 4).
fn handle_dns_localhost(args: &[std::ffi::OsString]) -> ExitCode {
    if args.len() != 3 && args.len() != 4 {
        return emit_error_and_exit(vec![
            "사용법: npi-probes --dns-localhost <port> [timeout_ms]".to_string(),
        ]);
    }

    let port_str = match args[2].to_str() {
        Some(s) => s,
        None => {
            return emit_error_and_exit(vec!["포트 인자가 유효한 UTF-8이 아닙니다".to_string()]);
        }
    };

    let port = match npi_probes::dns::parse_helper_port(port_str) {
        Ok(p) => p,
        Err(err) => {
            return emit_error_and_exit(vec![format!("포트 오류: {err}")]);
        }
    };

    let timeout = if args.len() == 4 {
        let timeout_str = match args[3].to_str() {
            Some(s) => s,
            None => {
                return emit_error_and_exit(vec!["시한 인자가 유효한 UTF-8이 아닙니다".to_string()]);
            }
        };
        match parse_cli_timeout_ms(timeout_str) {
            Ok(t) => t,
            Err(err) => {
                return emit_error_and_exit(vec![format!("시한 오류: {err}")]);
            }
        }
    } else {
        DEFAULT_DNS_TIMEOUT
    };

    let exe_path = match env::current_exe() {
        Ok(p) => p,
        Err(err) => {
            return emit_error_and_exit(vec![format!("현재 실행 파일 경로 확인 실패: {err}")]);
        }
    };

    let cancelled = Arc::new(AtomicBool::new(false));
    // host는 하드코딩 localhost ONLY
    let measurement = npi_probes::dns::resolve_isolated(
        &exe_path,
        "localhost",
        port,
        timeout,
        cancelled,
    );

    // 측정 결과 자체는 DNS_ERROR/TIMED_OUT/LOCAL_ERROR이어도 완료 measurement=exit0
    match serde_json::to_string_pretty(&measurement) {
        Ok(rendered) => {
            println!("{rendered}");
            ExitCode::SUCCESS
        }
        Err(err) => emit_error_and_exit(vec![format!("결과 JSON 직렬화 실패: {err}")]),
    }
}

/// 기존 프로필 실행 모드 (`npi-probes <profile.json>`).
fn handle_profile_run(path: &Path) -> ExitCode {
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

fn main() -> ExitCode {
    let args: Vec<std::ffi::OsString> = env::args_os().collect();
    if args.len() < 2 {
        return emit_error_and_exit(vec![
            "사용법: npi-probes <profile.json> (단일 프로필 경로만 허용하며 우회 플래그는 지원하지 않습니다)"
                .to_string(),
        ]);
    }

    if let Some(flag) = args[1].to_str() {
        if flag == "--npi-dns-worker-v1" {
            return handle_dns_worker(&args);
        }
        if flag == "--dns-localhost" {
            return handle_dns_localhost(&args);
        }
    }

    if args.len() != 2 {
        return emit_error_and_exit(vec![
            "사용법: npi-probes <profile.json> (단일 프로필 경로만 허용하며 우회 플래그는 지원하지 않습니다)"
                .to_string(),
        ]);
    }

    let path = Path::new(&args[1]);
    handle_profile_run(path)
}
