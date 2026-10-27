//! G2-B DNS CLI 회귀 및 계약 테스트 (`npi-probes`).
//!
//! 주의 및 제한사항:
//! - 본 테스트 모음은 바이너리 CLI 진입점(`--npi-dns-worker-v1`, `--dns-localhost`)의 동작을 검증합니다.
//! - 개발 및 실험 단계의 검증이며 전체 G2 수용, Session 1.1 또는 UI 연결이 아닙니다.
//! - 기본 오프라인 테스트는 외부 DNS, 실제 소켓 연결, 네트워크 패킷 관찰 없이 순수 인자 파싱 및
//!   루프백 IP 리터럴 격리 동작만 검증합니다.
//! - OS resolver(getaddrinfo 계열)를 실제로 호출하는 `localhost` 해석 테스트는 부모 프로세스가 명시적으로
//!   실행할 수 있도록 `#[ignore = "부모 명시 실행: 실제 localhost helper"]`로 격리되어 있습니다.
//! - OS resolver가 반환하는 주소 외에 DNS 서버, RR, TTL, 패킷, 정책 등은 관찰하지 않습니다.

use std::process::Command;
use serde_json::Value;

/// `npi-probes` 바이너리를 주어진 인자로 실행하고 (ExitStatus, stdout, stderr)를 반환한다.
fn run_cli(args: &[&str]) -> (std::process::ExitStatus, String, String) {
    let bin_path = env!("CARGO_BIN_EXE_npi-probes");
    let output = Command::new(bin_path)
        .args(args)
        .output()
        .expect("npi-probes 바이너리 실행에 실패했습니다");
    let stdout = String::from_utf8(output.stdout).expect("stdout이 유효한 UTF-8이 아닙니다");
    let stderr = String::from_utf8(output.stderr).expect("stderr이 유효한 UTF-8이 아닙니다");
    (output.status, stdout, stderr)
}

/// 오류 입력에 대해 종료 코드가 비제로이고 `errors` 배열을 담은 JSON이 출력되었는지 검증한다.
fn assert_cli_error(status: std::process::ExitStatus, stdout: &str) -> Value {
    assert!(
        !status.success(),
        "오류 입력에 대해 비제로(non-zero) 종료 코드가 반환되어야 합니다. 실제: {:?}",
        status.code()
    );
    let parsed: Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|err| panic!("오류 출력이 올바른 JSON 형식이 아닙니다: {err}\n출력 내용: {stdout}"));
    assert!(
        parsed.get("errors").and_then(|v| v.as_array()).is_some(),
        "오류 JSON 출력에는 'errors' 배열 필드가 포함되어야 합니다: {stdout}"
    );
    parsed
}

/// worker 실행 성공 시 stdout에 정확히 한 줄의 JSON이 출력되고 exit 0인지 검증한다.
fn assert_worker_line_success(status: std::process::ExitStatus, stdout: &str) -> Value {
    assert!(
        status.success(),
        "정상 worker 호출 시 종료 코드는 0이어야 합니다. 실제: {:?}",
        status.code()
    );
    assert!(
        stdout.ends_with('\n'),
        "worker stdout 출력은 개행 문자(\\n)로 끝나야 합니다"
    );
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "worker stdout에는 정확히 한 줄의 JSON만 출력되어야 합니다 (추가 로그 금지): {stdout}"
    );
    let payload: Value = serde_json::from_str(lines[0])
        .unwrap_or_else(|err| panic!("worker 출력이 올바른 JSON이 아닙니다: {err}\n출력: {stdout}"));
    assert_eq!(
        payload["format"], "npi-dns-worker-1",
        "worker 페이로드 포맷 식별자는 'npi-dns-worker-1'이어야 합니다"
    );
    payload
}

// ============================================================================
// 1. 기본 인자 수(argc) 및 사용법 검증
// ============================================================================

#[test]
fn test_cli_no_args_shows_usage_error() {
    let (status, stdout, _stderr) = run_cli(&[]);
    let error_json = assert_cli_error(status, &stdout);
    let msg = error_json["errors"][0].as_str().unwrap_or_default();
    assert!(msg.contains("사용법: npi-probes <profile.json>"));
}

#[test]
fn test_cli_worker_invalid_argc() {
    // 인자 0개 (총 argc 2)
    let (status, stdout, _) = run_cli(&["--npi-dns-worker-v1"]);
    assert_cli_error(status, &stdout);

    // 인자 1개 (총 argc 3)
    let (status, stdout, _) = run_cli(&["--npi-dns-worker-v1", "127.0.0.1"]);
    assert_cli_error(status, &stdout);

    // 인자 3개 (총 argc 5)
    let (status, stdout, _) = run_cli(&["--npi-dns-worker-v1", "127.0.0.1", "80", "extra"]);
    assert_cli_error(status, &stdout);
}

#[test]
fn test_cli_dns_localhost_invalid_argc() {
    // 포트 누락 (총 argc 2)
    let (status, stdout, _) = run_cli(&["--dns-localhost"]);
    assert_cli_error(status, &stdout);

    // 인자 초과 (총 argc 5)
    let (status, stdout, _) = run_cli(&["--dns-localhost", "80", "5000", "extra"]);
    assert_cli_error(status, &stdout);
}

// ============================================================================
// 2. worker 호스트 가드 검증 (비루프백 / 미허용 도메인 / 잘못된 문자 거부)
// ============================================================================

#[test]
fn test_cli_worker_reject_disallowed_hosts() {
    let disallowed = [
        "localhost.",          // 후행 점이 있는 도메인은 엄격 거부
        "example.com",        // 외부 일반 도메인 거부
        "google.com",         // 외부 일반 도메인 거부
        "192.168.1.1",        // 비루프백 사설 IPv4 거부
        "10.0.0.1",           // 비루프백 사설 IPv4 거부
        "172.16.0.1",         // 비루프백 사설 IPv4 거부
        "8.8.8.8",            // 비루프백 공인 IPv4 거부
        "::2",                // 비루프백 IPv6 거부
        "2001:db8::1",        // 비루프백 문서용 IPv6 거부
        "fe80::1",            // 링크 로컬 비루프백 IPv6 거부
        "",                   // 빈 문자열 거부
        "localhost extra",    // 공백 포함 거부
        "localhost:80",       // 포트 포함 문자열 거부
    ];

    for host in disallowed {
        let (status, stdout, _) = run_cli(&["--npi-dns-worker-v1", host, "80"]);
        let error_json = assert_cli_error(status, &stdout);
        let errors = error_json["errors"].as_array().unwrap();
        assert!(
            !errors.is_empty(),
            "호스트 '{host}' 거부 시 오류 메시지가 포함되어야 합니다"
        );
    }
}

// ============================================================================
// 3. 포트 엄격 파싱 검증 (worker 및 dns-localhost)
// ============================================================================

#[test]
fn test_cli_worker_reject_invalid_ports() {
    let invalid_ports = [
        "0",       // 0 포트 금지
        "65536",   // 16비트 범위 초과
        "70000",   // 16비트 범위 초과
        "abc",     // 비숫자
        "080",     // 선행 0 금지
        "+80",     // 부호 금지
        "-1",      // 음수 금지
        "",        // 빈 문자열
        "80 80",   // 공백 포함
    ];

    for port in invalid_ports {
        let (status, stdout, _) = run_cli(&["--npi-dns-worker-v1", "127.0.0.1", port]);
        assert_cli_error(status, &stdout);
    }
}

#[test]
fn test_cli_dns_localhost_reject_invalid_ports() {
    let invalid_ports = ["0", "65536", "not_a_port", "080", "+80", "-10"];
    for port in invalid_ports {
        let (status, stdout, _) = run_cli(&["--dns-localhost", port]);
        assert_cli_error(status, &stdout);
    }
}

// ============================================================================
// 4. 시한(timeout) 엄격 검증 (--dns-localhost)
// ============================================================================

#[test]
fn test_cli_dns_localhost_reject_invalid_timeouts() {
    let invalid_timeouts = [
        "0",        // 1ms 미만
        "60001",    // 60000ms 초과
        "abc",      // 비숫자
        "05000",    // 선행 0 금지
        "+1000",    // 부호 금지
        "-500",     // 음수
        "",         // 빈 문자열
    ];

    for timeout in invalid_timeouts {
        let (status, stdout, _) = run_cli(&["--dns-localhost", "80", timeout]);
        assert_cli_error(status, &stdout);
    }
}

// ============================================================================
// 5. 순수 오프라인 IP 리터럴 루프백 worker 검증 (실제 DNS 호출 없음)
// ============================================================================

#[test]
fn test_cli_worker_offline_ipv4_loopback_literal() {
    let (status, stdout, stderr) = run_cli(&["--npi-dns-worker-v1", "127.0.0.1", "8080"]);
    assert!(stderr.is_empty(), "worker 정상 동작 시 stderr 출력이 없어야 함");
    let payload = assert_worker_line_success(status, &stdout);

    assert_eq!(payload["host"], "127.0.0.1");
    assert_eq!(payload["port"], 8080);
    assert_eq!(payload["addresses"], serde_json::json!(["127.0.0.1:8080"]));
    assert_eq!(payload["truncated"], false);
    assert!(payload["error_code"].is_null());
    assert!(payload["error_message"].is_null());
}

#[test]
fn test_cli_worker_offline_ipv4_other_loopback_literal() {
    let (status, stdout, stderr) = run_cli(&["--npi-dns-worker-v1", "127.0.0.2", "9000"]);
    assert!(stderr.is_empty(), "worker 정상 동작 시 stderr 출력이 없어야 함");
    let payload = assert_worker_line_success(status, &stdout);

    assert_eq!(payload["host"], "127.0.0.2");
    assert_eq!(payload["port"], 9000);
    assert_eq!(payload["addresses"], serde_json::json!(["127.0.0.2:9000"]));
    assert_eq!(payload["truncated"], false);
    assert!(payload["error_code"].is_null());
    assert!(payload["error_message"].is_null());
}

#[test]
fn test_cli_worker_offline_ipv6_loopback_literal() {
    let (status, stdout, stderr) = run_cli(&["--npi-dns-worker-v1", "::1", "53"]);
    assert!(stderr.is_empty(), "worker 정상 동작 시 stderr 출력이 없어야 함");
    let payload = assert_worker_line_success(status, &stdout);

    assert_eq!(payload["host"], "::1");
    assert_eq!(payload["port"], 53);
    assert_eq!(payload["addresses"], serde_json::json!(["[::1]:53"]));
    assert_eq!(payload["truncated"], false);
    assert!(payload["error_code"].is_null());
    assert!(payload["error_message"].is_null());
}

// ============================================================================
// 6. 기존 프로필 CLI 모드 회귀 검증
// ============================================================================

#[test]
fn test_cli_profile_mode_nonexistent_file_errors() {
    let (status, stdout, _) = run_cli(&["nonexistent_profile_definitely_missing.json"]);
    let error_json = assert_cli_error(status, &stdout);
    let errors = error_json["errors"].as_array().unwrap();
    let msg = errors[0].as_str().unwrap_or_default();
    assert!(
        msg.contains("프로필 파일 열기 실패"),
        "존재하지 않는 프로필 파일에 대해 열기 실패 오류를 출력해야 합니다: {msg}"
    );
}

// ============================================================================
// 7. 부모 명시 실행: 실제 localhost OS resolver 및 --dns-localhost 격리 실측
// ============================================================================

#[test]
#[ignore = "부모 명시 실행: 실제 localhost helper"]
fn test_cli_worker_real_localhost_resolver() {
    let (status, stdout, stderr) = run_cli(&["--npi-dns-worker-v1", "localhost", "80"]);
    assert!(stderr.is_empty(), "worker 정상 프로토콜 시 stderr 출력이 없어야 함");
    let payload = assert_worker_line_success(status, &stdout);

    assert_eq!(payload["host"], "localhost");
    assert_eq!(payload["port"], 80);

    // OS resolver가 성공하여 주소를 반환했거나 DNS_ERROR인 경우 둘 다 프로토콜 정상(exit 0)
    if payload["error_message"].is_null() {
        let addresses = payload["addresses"].as_array().expect("addresses 배열 필요");
        assert!(!addresses.is_empty(), "성공 시 최소 1개 이상의 주소가 반환되어야 함");
        for addr in addresses {
            let addr_str = addr.as_str().unwrap();
            assert!(
                addr_str.starts_with("127.") || addr_str.starts_with("[::1]"),
                "localhost 해석 주소는 루프백이어야 함: {addr_str}"
            );
            assert!(
                addr_str.ends_with(":80"),
                "주소의 포트는 요청 포트 80과 일치해야 함: {addr_str}"
            );
        }
    } else {
        // OS 환경에 따라 getaddrinfo가 실패한 경우에도 protocol exit 0이며 에러 메시지가 기록됨
        assert!(payload["error_message"].as_str().is_some());
    }
}

#[test]
#[ignore = "부모 명시 실행: 실제 localhost helper"]
fn test_cli_dns_localhost_real_execution_default_timeout() {
    let (status, stdout, _stderr) = run_cli(&["--dns-localhost", "80"]);
    assert!(
        status.success(),
        "--dns-localhost는 결과 상태(RESOLVED/DNS_ERROR 등)와 무관하게 정상 측정이면 exit 0이어야 함"
    );

    let measurement: Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|err| panic!("출력이 올바른 DnsMeasurement JSON이어야 함: {err}\n출력: {stdout}"));

    assert_eq!(measurement["host"], "localhost");
    assert_eq!(measurement["port"], 80);
    assert!(measurement["outcome"].is_string());
    assert!(measurement["limitations"].is_array());

    let limitations = measurement["limitations"].as_array().unwrap();
    assert!(
        limitations.iter().any(|v| v.as_str().unwrap_or("").contains("OS 해석기")),
        "limitations에 OS 해석기 제한사항이 포함되어야 함"
    );
}

#[test]
#[ignore = "부모 명시 실행: 실제 localhost helper"]
fn test_cli_dns_localhost_real_execution_custom_timeout() {
    let (status, stdout, _stderr) = run_cli(&["--dns-localhost", "80", "3000"]);
    assert!(
        status.success(),
        "--dns-localhost 3000ms 시한 지정 시 exit 0이어야 함"
    );

    let measurement: Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|err| panic!("출력이 올바른 DnsMeasurement JSON이어야 함: {err}\n출력: {stdout}"));

    assert_eq!(measurement["host"], "localhost");
    assert_eq!(measurement["port"], 80);
    assert!(measurement["outcome"].is_string());
}
