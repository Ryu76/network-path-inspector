//! G2-B DNS 순수 오프라인 단위 및 계약 테스트.
//!
//! 이 테스트 모음은 기본 실행 시 실제 소켓/하위 프로세스/네트워크/외부 DNS 호출을
//! 일절 발생시키지 않으며, 모든 검증을 메모리 내 단위 테스트 및 가짜 HelperHandle
//! 구현체로 수행한다. 실제 하위 프로세스 격리 검증은 부모가 main.rs에 helper를
//! 연결한 후 명시적으로 실행하는 `#[ignore]` 테스트로만 격리된다.

use network_resolver as dns;

use dns::*;
use std::io::{self, Cursor};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

// ============================================================================
// 테스트 전용 가짜 HelperHandle 구현체
// ============================================================================

struct TestFakeHelperHandle {
    exit_status: Option<bool>,
    overflowed: bool,
    finished: bool,
    terminate_count: usize,
    output_bytes: Option<Vec<u8>>,
    poll_error: Option<String>,
    on_poll: Option<Box<dyn FnMut()>>,
    on_terminate: Option<Box<dyn FnMut()>>,
}

impl TestFakeHelperHandle {
    fn new(exit_status: Option<bool>, finished: bool, output: Vec<u8>) -> Self {
        Self {
            exit_status,
            overflowed: false,
            finished,
            terminate_count: 0,
            output_bytes: Some(output),
            poll_error: None,
            on_poll: None,
            on_terminate: None,
        }
    }
}

impl HelperHandle for TestFakeHelperHandle {
    fn poll_exit(&mut self) -> io::Result<Option<bool>> {
        if let Some(ref mut action) = self.on_poll {
            action();
        }
        if let Some(ref err) = self.poll_error {
            return Err(io::Error::other(err.clone()));
        }
        Ok(self.exit_status)
    }

    fn output_overflowed(&self) -> bool {
        self.overflowed
    }

    fn output_finished(&self) -> bool {
        self.finished
    }

    fn terminate(&mut self) {
        self.terminate_count += 1;
        if let Some(ref mut action) = self.on_terminate {
            action();
        }
    }

    fn take_output(&mut self) -> io::Result<Vec<u8>> {
        self.output_bytes
            .take()
            .ok_or_else(|| io::Error::other("output already taken or none"))
    }
}

// ============================================================================
// 1. 엄격한 호스트/포트/시한 규칙 (Strict Host Rules & Port & Timeout)
// ============================================================================

#[test]
fn test_strict_host_rules_empty_and_length() {
    assert!(validate_host("").is_err(), "빈 호스트 거부");

    let too_long_no_dot = "a".repeat(254);
    assert!(
        validate_host(&too_long_no_dot).is_err(),
        "253자 초과 호스트 거부"
    );

    let max_len_with_dot = format!("{}.", "a".repeat(253));
    // 라벨 길이가 63자를 초과하므로 라벨 길이에서 거부
    assert!(validate_host(&max_len_with_dot).is_err());

    // 63자 이하 라벨들로 구성된 정확히 253자 도메인 (후행 점 포함 254자)
    // 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253자
    let label63_a = "a".repeat(63);
    let label63_b = "b".repeat(63);
    let label63_c = "c".repeat(63);
    let label61_d = "d".repeat(61);
    let max_valid_domain = format!("{label63_a}.{label63_b}.{label63_c}.{label61_d}");
    assert_eq!(max_valid_domain.len(), 253);
    assert_eq!(
        validate_host(&max_valid_domain),
        Ok(HostKind::DomainName),
        "253자 정상 도메인 허용"
    );

    let max_valid_domain_dot = format!("{max_valid_domain}.");
    assert_eq!(max_valid_domain_dot.len(), 254);
    assert_eq!(
        validate_host(&max_valid_domain_dot),
        Ok(HostKind::DomainName),
        "253자 도메인 + 후행 점 허용"
    );
}

#[test]
fn test_strict_host_rules_whitespace_and_control() {
    assert!(validate_host(" example.com").is_err(), "선행 공백 거부");
    assert!(validate_host("example.com ").is_err(), "후행 공백 거부");
    assert!(validate_host("exam ple.com").is_err(), "중간 공백 거부");
    assert!(validate_host("example\t.com").is_err(), "탭 문자 거부");
    assert!(validate_host("example\n.com").is_err(), "개행 문자 거부");
    assert!(validate_host("도메인.한국").is_err(), "비ASCII 한글 거부");
}

#[test]
fn test_strict_host_rules_prohibited_characters() {
    assert!(
        validate_host("http://example.com").is_err(),
        "URI 스키마 거부"
    );
    assert!(validate_host("example.com/path").is_err(), "URI 경로 거부");
    assert!(
        validate_host("user:pass@example.com").is_err(),
        "자격증명 거부"
    );
    assert!(validate_host("192.168.1.0/24").is_err(), "CIDR 표기 거부");
    assert!(validate_host("*.example.com").is_err(), "와일드카드 거부");
    assert!(validate_host("example_name.com").is_err(), "밑줄(_) 거부");
}

#[test]
fn test_strict_host_rules_valid_ipv4() {
    assert_eq!(
        validate_host("127.0.0.1"),
        Ok(HostKind::Ipv4(Ipv4Addr::new(127, 0, 0, 1)))
    );
    assert_eq!(
        validate_host("0.0.0.0"),
        Ok(HostKind::Ipv4(Ipv4Addr::new(0, 0, 0, 0)))
    );
    assert_eq!(
        validate_host("255.255.255.255"),
        Ok(HostKind::Ipv4(Ipv4Addr::new(255, 255, 255, 255)))
    );
}

#[test]
fn test_strict_host_rules_invalid_ipv4() {
    assert!(
        validate_host("127.0.0.1.").is_err(),
        "후행 점이 있는 IPv4 거부"
    );
    assert!(
        validate_host("127.0.0.01").is_err(),
        "선행 0이 있는 IPv4 거부"
    );
    assert!(
        validate_host("01.2.3.4").is_err(),
        "선행 0이 있는 IPv4 거부"
    );
    assert!(validate_host("127.1").is_err(), "4옥텟 미만 IPv4 거부");
    assert!(validate_host("1.2.3.4.5").is_err(), "4옥텟 초과 IPv4 거부");
    assert!(
        validate_host("256.0.0.1").is_err(),
        "255 초과 옥텟 IPv4 거부"
    );
    assert!(
        validate_host("0x7f000001").is_err(),
        "16진 정수형 주소 거부"
    );
    assert!(validate_host("0x7f.0.0.1").is_err(), "16진 라벨 주소 거부");
}

#[test]
fn test_strict_host_rules_valid_ipv6() {
    assert_eq!(
        validate_host("::1"),
        Ok(HostKind::Ipv6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))
    );
    assert_eq!(
        validate_host("::1:80"),
        Ok(HostKind::Ipv6("::1:80".parse::<Ipv6Addr>().unwrap())),
        "::1:80은 유효한 16진 그룹 IPv6 리터럴"
    );
    assert_eq!(
        validate_host("2001:db8::1"),
        Ok(HostKind::Ipv6("2001:db8::1".parse().unwrap()))
    );
    assert_eq!(
        validate_host("::"),
        Ok(HostKind::Ipv6(Ipv6Addr::UNSPECIFIED))
    );
}

#[test]
fn test_strict_host_rules_invalid_ipv6() {
    assert!(validate_host("[::1]").is_err(), "대괄호 포함 IPv6 거부");
    assert!(
        validate_host("[::1]:80").is_err(),
        "대괄호 및 포트 포함 IPv6 거부"
    );
    assert!(
        validate_host("fe80::1%eth0").is_err(),
        "영역 ID 포함 IPv6 거부"
    );
    assert!(validate_host("2001:::1").is_err(), "잘못된 IPv6 구문 거부");
}

#[test]
fn test_strict_host_rules_domain_names() {
    assert_eq!(validate_host("localhost"), Ok(HostKind::DomainName));
    assert_eq!(validate_host("localhost."), Ok(HostKind::DomainName));
    assert_eq!(validate_host("example.com"), Ok(HostKind::DomainName));
    assert_eq!(validate_host("example.com."), Ok(HostKind::DomainName));
    assert_eq!(
        validate_host("sub-host.example-domain.org"),
        Ok(HostKind::DomainName)
    );

    // 라벨 63자 초과
    let label64 = format!("{}.com", "a".repeat(64));
    assert!(validate_host(&label64).is_err(), "라벨 길이 63자 초과 거부");

    // 하이픈 시작/끝 라벨
    assert!(
        validate_host("-example.com").is_err(),
        "선행 하이픈 라벨 거부"
    );
    assert!(
        validate_host("example-.com").is_err(),
        "후행 하이픈 라벨 거부"
    );
    assert!(
        validate_host("sub.-test.com").is_err(),
        "중간 선행 하이픈 거부"
    );

    // 빈 라벨
    assert!(validate_host(".").is_err(), "단일 점 거부");
    assert!(validate_host("..").is_err(), "연속 점 거부");
    assert!(validate_host("example..com").is_err(), "빈 라벨 거부");
}

#[test]
fn test_validate_port_range() {
    assert!(validate_port(0).is_err(), "포트 0 거부");
    assert!(validate_port(1).is_ok(), "포트 1 허용");
    assert!(validate_port(80).is_ok(), "포트 80 허용");
    assert!(validate_port(65535).is_ok(), "포트 65535 허용");
}

#[test]
fn test_validate_timeout_range() {
    assert!(
        validate_timeout(Duration::from_millis(0)).is_err(),
        "시한 0ms 거부"
    );
    assert!(
        validate_timeout(Duration::from_millis(1)).is_ok(),
        "시한 1ms 허용"
    );
    assert!(
        validate_timeout(Duration::from_millis(60_000)).is_ok(),
        "시한 60000ms 허용"
    );
    assert!(
        validate_timeout(Duration::from_millis(60_001)).is_err(),
        "시한 60001ms 거부"
    );
}

#[test]
fn test_parse_helper_port_valid_and_invalid() {
    assert_eq!(parse_helper_port("80"), Ok(80));
    assert_eq!(parse_helper_port("53"), Ok(53));
    assert_eq!(parse_helper_port("65535"), Ok(65535));

    assert!(parse_helper_port("").is_err(), "빈 문자열 거부");
    assert!(parse_helper_port("0").is_err(), "0 거부");
    assert!(parse_helper_port("080").is_err(), "선행 0 거부");
    assert!(parse_helper_port("+80").is_err(), "부호 문자 거부");
    assert!(parse_helper_port("-80").is_err(), "음수 거부");
    assert!(parse_helper_port("80a").is_err(), "문자 혼합 거부");
    assert!(parse_helper_port("65536").is_err(), "65536 초과 거부");
    assert!(parse_helper_port("999999").is_err(), "5자리 초과 거부");
}

#[test]
fn test_helper_arguments_format() {
    let args = helper_arguments("example.com", 443);
    assert_eq!(args, ["--npi-dns-worker-v1", "example.com", "443"]);
}

// ============================================================================
// 2. 주소 수집, 포트 일치, 중복 제거 및 32개 상한 (collect_unique_addresses)
// ============================================================================

#[test]
fn test_collect_unique_addresses_filtering_and_dedup() {
    let target_port = 80;
    let addrs = vec![
        SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 80),
        SocketAddr::new(Ipv4Addr::new(127, 0, 0, 2).into(), 8080), // 포트 불일치
        SocketAddr::new(Ipv4Addr::new(127, 0, 0, 1).into(), 80),   // 중복
        SocketAddr::new(Ipv6Addr::LOCALHOST.into(), 80),
    ];

    let (collected, truncated) = collect_unique_addresses(addrs, target_port);
    assert!(!truncated);
    assert_eq!(collected.len(), 2);
    assert_eq!(collected[0], "127.0.0.1:80");
    assert_eq!(collected[1], "[::1]:80");
}

#[test]
fn test_collect_unique_addresses_max_32_and_truncation() {
    let target_port = 80;
    // 40개의 서로 다른 주소 생성
    let mut addrs = Vec::new();
    for i in 1..=40 {
        addrs.push(SocketAddr::new(
            Ipv4Addr::new(10, 0, 0, i).into(),
            target_port,
        ));
    }

    let (collected, truncated) = collect_unique_addresses(addrs, target_port);
    assert!(truncated, "32개 초과 시 truncated 플래그 설정");
    assert_eq!(collected.len(), MAX_ADDRESSES);
    assert_eq!(collected[0], "10.0.0.1:80");
    assert_eq!(collected[31], "10.0.0.32:80");
}

// ============================================================================
// 3. 페이로드 직렬화, 역직렬화, 상한 및 프로토콜 검증
// ============================================================================

#[test]
fn test_worker_output_line_roundtrip_success() {
    let payload = DnsWorkerPayload {
        format: WORKER_FORMAT.to_string(),
        host: "example.com".to_string(),
        port: 443,
        addresses: vec!["93.184.216.34:443".to_string()],
        truncated: false,
        error_code: None,
        error_message: None,
    };

    let line = worker_output_line(&payload);
    assert!(line.ends_with('\n'));
    assert!(!line[..line.len() - 1].contains('\n'));

    let decoded = decode_worker_payload(line.as_bytes(), "example.com", 443).unwrap();
    assert_eq!(decoded, payload);
}

#[test]
fn test_decode_payload_format_mismatch() {
    let payload = DnsWorkerPayload {
        format: "invalid-format-v2".to_string(),
        host: "example.com".to_string(),
        port: 80,
        addresses: vec!["93.184.216.34:80".to_string()],
        truncated: false,
        error_code: None,
        error_message: None,
    };
    let line = worker_output_line(&payload);
    let err = decode_worker_payload(line.as_bytes(), "example.com", 80).unwrap_err();
    assert!(err.contains("helper 페이로드 형식 불일치"), "에러: {err}");
}

#[test]
fn test_decode_payload_host_mismatch() {
    let payload = DnsWorkerPayload {
        format: WORKER_FORMAT.to_string(),
        host: "forged.com".to_string(),
        port: 80,
        addresses: vec!["93.184.216.34:80".to_string()],
        truncated: false,
        error_code: None,
        error_message: None,
    };
    let line = worker_output_line(&payload);
    let err = decode_worker_payload(line.as_bytes(), "example.com", 80).unwrap_err();
    assert!(err.contains("helper 페이로드 호스트 불일치"), "에러: {err}");
}

#[test]
fn test_decode_payload_port_mismatch() {
    let payload = DnsWorkerPayload {
        format: WORKER_FORMAT.to_string(),
        host: "example.com".to_string(),
        port: 8080,
        addresses: vec!["93.184.216.34:8080".to_string()],
        truncated: false,
        error_code: None,
        error_message: None,
    };
    let line = worker_output_line(&payload);
    let err = decode_worker_payload(line.as_bytes(), "example.com", 80).unwrap_err();
    assert!(err.contains("helper 페이로드 포트 불일치"), "에러: {err}");
}

#[test]
fn test_decode_payload_address_port_mismatch() {
    let payload = DnsWorkerPayload {
        format: WORKER_FORMAT.to_string(),
        host: "example.com".to_string(),
        port: 80,
        addresses: vec!["93.184.216.34:8080".to_string()], // 요청 포트와 다름
        truncated: false,
        error_code: None,
        error_message: None,
    };
    let line = worker_output_line(&payload);
    let err = decode_worker_payload(line.as_bytes(), "example.com", 80).unwrap_err();
    assert!(
        err.contains("helper 주소 포트가 요청 포트와 다름"),
        "에러: {err}"
    );
}

#[test]
fn test_decode_payload_duplicate_addresses() {
    let payload = DnsWorkerPayload {
        format: WORKER_FORMAT.to_string(),
        host: "example.com".to_string(),
        port: 80,
        addresses: vec![
            "93.184.216.34:80".to_string(),
            "93.184.216.34:80".to_string(), // 중복
        ],
        truncated: false,
        error_code: None,
        error_message: None,
    };
    let line = worker_output_line(&payload);
    let err = decode_worker_payload(line.as_bytes(), "example.com", 80).unwrap_err();
    assert!(err.contains("helper 주소 중복"), "에러: {err}");
}

#[test]
fn test_decode_payload_empty_bytes() {
    let err = decode_worker_payload(&[], "example.com", 80).unwrap_err();
    assert!(err.contains("helper stdout이 비어 있음"), "에러: {err}");
}

#[test]
fn test_decode_payload_empty_success_rejected() {
    let payload = DnsWorkerPayload {
        format: WORKER_FORMAT.to_string(),
        host: "example.com".to_string(),
        port: 80,
        addresses: Vec::new(), // 주소 없음
        truncated: false,
        error_code: None,
        error_message: None,
    };
    let line = worker_output_line(&payload);
    let err = decode_worker_payload(line.as_bytes(), "example.com", 80).unwrap_err();
    assert!(err.contains("주소 없는 성공 페이로드 거부"), "에러: {err}");
}

#[test]
fn test_decode_payload_error_with_addresses_rejected() {
    let payload = DnsWorkerPayload {
        format: WORKER_FORMAT.to_string(),
        host: "example.com".to_string(),
        port: 80,
        addresses: vec!["93.184.216.34:80".to_string()],
        truncated: false,
        error_code: Some(11001),
        error_message: Some("호스트를 찾을 수 없음".to_string()),
    };
    let line = worker_output_line(&payload);
    let err = decode_worker_payload(line.as_bytes(), "example.com", 80).unwrap_err();
    assert!(err.contains("오류와 주소가 동시에 존재"), "에러: {err}");
}

#[test]
fn test_decode_payload_error_code_without_message_rejected() {
    let payload = DnsWorkerPayload {
        format: WORKER_FORMAT.to_string(),
        host: "example.com".to_string(),
        port: 80,
        addresses: Vec::new(),
        truncated: false,
        error_code: Some(11001),
        error_message: None, // 메시지 없음
    };
    let line = worker_output_line(&payload);
    let err = decode_worker_payload(line.as_bytes(), "example.com", 80).unwrap_err();
    assert!(
        err.contains("오류 코드만 있고 메시지가 없음"),
        "에러: {err}"
    );
}

#[test]
fn test_decode_payload_error_message_length_limit() {
    let long_msg = "x".repeat(MAX_ERROR_MESSAGE_BYTES + 1);
    let payload = DnsWorkerPayload {
        format: WORKER_FORMAT.to_string(),
        host: "example.com".to_string(),
        port: 80,
        addresses: Vec::new(),
        truncated: false,
        error_code: Some(11001),
        error_message: Some(long_msg),
    };
    let line = worker_output_line(&payload);
    let err = decode_worker_payload(line.as_bytes(), "example.com", 80).unwrap_err();
    assert!(
        err.contains("helper 오류 메시지 길이 상한 초과"),
        "에러: {err}"
    );
}

#[test]
fn test_decode_payload_max_addresses_exceeded() {
    let mut addrs = Vec::new();
    for i in 1..=33 {
        addrs.push(format!("10.0.0.{i}:80"));
    }
    let payload = DnsWorkerPayload {
        format: WORKER_FORMAT.to_string(),
        host: "example.com".to_string(),
        port: 80,
        addresses: addrs,
        truncated: false,
        error_code: None,
        error_message: None,
    };
    let line = worker_output_line(&payload);
    let err = decode_worker_payload(line.as_bytes(), "example.com", 80).unwrap_err();
    assert!(err.contains("helper 주소 개수 32개 초과"), "에러: {err}");
}

#[test]
fn test_decode_payload_truncation_mismatch() {
    let payload = DnsWorkerPayload {
        format: WORKER_FORMAT.to_string(),
        host: "example.com".to_string(),
        port: 80,
        addresses: vec!["93.184.216.34:80".to_string()], // 1개뿐인데 truncated: true
        truncated: true,
        error_code: None,
        error_message: None,
    };
    let line = worker_output_line(&payload);
    let err = decode_worker_payload(line.as_bytes(), "example.com", 80).unwrap_err();
    assert!(err.contains("잘림 표시와 주소 개수 불일치"), "에러: {err}");
}

#[test]
fn test_decode_payload_16kib_limit_exceeded() {
    let oversized = vec![b'a'; MAX_PAYLOAD_BYTES + 1];
    let err = decode_worker_payload(&oversized, "example.com", 80).unwrap_err();
    assert!(err.contains("helper stdout 16KiB 상한 초과"), "에러: {err}");
}

#[test]
fn test_decode_payload_multiline_or_carriage_return_rejected() {
    let payload = DnsWorkerPayload {
        format: WORKER_FORMAT.to_string(),
        host: "example.com".to_string(),
        port: 80,
        addresses: vec!["93.184.216.34:80".to_string()],
        truncated: false,
        error_code: None,
        error_message: None,
    };
    let mut line = worker_output_line(&payload);
    line.push_str("extra second line\n");
    let err = decode_worker_payload(line.as_bytes(), "example.com", 80).unwrap_err();
    assert!(
        err.contains("helper stdout이 정확히 한 줄 JSON이 아님"),
        "에러: {err}"
    );
}

#[test]
fn test_decode_payload_unknown_fields_denied() {
    let json_with_unknown = r#"{"format":"npi-dns-worker-1","host":"example.com","port":80,"addresses":["93.184.216.34:80"],"truncated":false,"error_code":null,"error_message":null,"malicious_field":"injected"}"#;
    let mut line = json_with_unknown.to_string();
    line.push('\n');
    let err = decode_worker_payload(line.as_bytes(), "example.com", 80).unwrap_err();
    assert!(err.contains("helper JSON 파싱 실패"), "에러: {err}");
}

#[test]
fn test_decode_payload_invalid_utf8_rejected() {
    let bad_utf8 = vec![0xFF, 0xFE, 0xFD];
    let err = decode_worker_payload(&bad_utf8, "example.com", 80).unwrap_err();
    assert!(err.contains("helper stdout이 UTF-8이 아님"), "에러: {err}");
}

// ============================================================================
// 4. 바이트 제한 읽기 (read_bounded & 16KiB limit)
// ============================================================================

#[test]
fn test_read_bounded_within_16kib() {
    let input_data = vec![b'x'; 512];
    let overflow = AtomicBool::new(false);
    let cursor = Cursor::new(input_data.clone());
    let result = read_bounded(cursor, &overflow).unwrap();

    assert_eq!(result, input_data);
    assert!(!overflow.load(Ordering::SeqCst));
}

#[test]
fn test_read_bounded_overflow_sentinel_and_flag() {
    let total_size = MAX_PAYLOAD_BYTES + 100;
    let input_data = vec![b'z'; total_size];
    let overflow = AtomicBool::new(false);
    let cursor = Cursor::new(input_data);
    let result = read_bounded(cursor, &overflow).unwrap();

    // 16KiB + 1(sentinel)까지만 보관
    assert_eq!(result.len(), MAX_PAYLOAD_BYTES + 1);
    assert!(overflow.load(Ordering::SeqCst));
}

// ============================================================================
// 5. 프로세스 생성 전 판단 (plan_resolution)
// ============================================================================

#[test]
fn test_plan_resolution_pre_cancelled_no_process() {
    let exe = Path::new("C:/target/release/npi.exe");
    let cancelled = AtomicBool::new(true);
    let started = Instant::now();

    let plan = plan_resolution(
        exe,
        "example.com",
        80,
        Duration::from_millis(1000),
        &cancelled,
        started,
    );

    match plan {
        ResolutionPlan::Immediate(m) => {
            assert_eq!(m.outcome, OUTCOME_CANCELLED);
            assert!(m.limitations.iter().any(|l| l.contains(LIMIT_CANCEL)));
            assert!(m.limitations.iter().any(|l| l.contains(LIMIT_NO_PROCESS)));
        }
        ResolutionPlan::SpawnHelper => panic!("취소 시 helper를 생성해서는 안 됨"),
    }
}

#[test]
fn test_plan_resolution_ipv4_literal_no_dns() {
    let exe = Path::new("C:/target/release/npi.exe");
    let cancelled = AtomicBool::new(false);
    let started = Instant::now();

    let plan = plan_resolution(
        exe,
        "127.0.0.1",
        8080,
        Duration::from_millis(1000),
        &cancelled,
        started,
    );

    match plan {
        ResolutionPlan::Immediate(m) => {
            assert_eq!(m.outcome, OUTCOME_RESOLVED);
            assert_eq!(m.addresses, vec!["127.0.0.1:8080"]);
            assert!(m.limitations.iter().any(|l| l.contains(LIMIT_LITERAL)));
        }
        ResolutionPlan::SpawnHelper => panic!("IP 리터럴은 helper를 생성해서는 안 됨"),
    }
}

#[test]
fn test_plan_resolution_ipv6_literal_no_dns() {
    let exe = Path::new("C:/target/release/npi.exe");
    let cancelled = AtomicBool::new(false);
    let started = Instant::now();

    let plan = plan_resolution(
        exe,
        "::1",
        53,
        Duration::from_millis(1000),
        &cancelled,
        started,
    );

    match plan {
        ResolutionPlan::Immediate(m) => {
            assert_eq!(m.outcome, OUTCOME_RESOLVED);
            assert_eq!(m.addresses, vec!["[::1]:53"]);
            assert!(m.limitations.iter().any(|l| l.contains(LIMIT_LITERAL)));
        }
        ResolutionPlan::SpawnHelper => panic!("IPv6 리터럴은 helper를 생성해서는 안 됨"),
    }
}

#[test]
fn test_plan_resolution_invalid_port_no_process() {
    let exe = Path::new("C:/target/release/npi.exe");
    let cancelled = AtomicBool::new(false);
    let started = Instant::now();

    let plan = plan_resolution(
        exe,
        "example.com",
        0, // 잘못된 포트
        Duration::from_millis(1000),
        &cancelled,
        started,
    );

    match plan {
        ResolutionPlan::Immediate(m) => {
            assert_eq!(m.outcome, OUTCOME_LOCAL_ERROR);
            assert!(m.error_message.unwrap().contains("포트는 1..65535"));
            assert!(m.limitations.iter().any(|l| l.contains(LIMIT_NO_PROCESS)));
        }
        ResolutionPlan::SpawnHelper => panic!("입력 검증 실패 시 helper 생성 금지"),
    }
}

#[test]
fn test_plan_resolution_invalid_timeout_no_process() {
    let exe = Path::new("C:/target/release/npi.exe");
    let cancelled = AtomicBool::new(false);
    let started = Instant::now();

    let plan = plan_resolution(
        exe,
        "example.com",
        80,
        Duration::from_millis(0), // 잘못된 시한
        &cancelled,
        started,
    );

    match plan {
        ResolutionPlan::Immediate(m) => {
            assert_eq!(m.outcome, OUTCOME_LOCAL_ERROR);
            assert!(m.error_message.unwrap().contains("시한은 1..60000ms"));
            assert!(m.limitations.iter().any(|l| l.contains(LIMIT_NO_PROCESS)));
        }
        ResolutionPlan::SpawnHelper => panic!("입력 검증 실패 시 helper 생성 금지"),
    }
}

#[test]
fn test_plan_resolution_invalid_host_no_process() {
    let exe = Path::new("C:/target/release/npi.exe");
    let cancelled = AtomicBool::new(false);
    let started = Instant::now();

    let plan = plan_resolution(
        exe,
        "bad host name!",
        80,
        Duration::from_millis(1000),
        &cancelled,
        started,
    );

    match plan {
        ResolutionPlan::Immediate(m) => {
            assert_eq!(m.outcome, OUTCOME_LOCAL_ERROR);
            assert!(m.error_message.unwrap().contains("공백/제어/비ASCII"));
            assert!(m.limitations.iter().any(|l| l.contains(LIMIT_NO_PROCESS)));
        }
        ResolutionPlan::SpawnHelper => panic!("호스트 검증 실패 시 helper 생성 금지"),
    }
}

#[test]
fn test_plan_resolution_relative_executable_no_process() {
    let exe = Path::new("relative/path/helper.exe");
    let cancelled = AtomicBool::new(false);
    let started = Instant::now();

    let plan = plan_resolution(
        exe,
        "example.com",
        80,
        Duration::from_millis(1000),
        &cancelled,
        started,
    );

    match plan {
        ResolutionPlan::Immediate(m) => {
            assert_eq!(m.outcome, OUTCOME_LOCAL_ERROR);
            assert!(m.error_message.unwrap().contains("절대 경로"));
            assert!(m.limitations.iter().any(|l| l.contains(LIMIT_NO_PROCESS)));
        }
        ResolutionPlan::SpawnHelper => panic!("상대 경로 실행파일 거부"),
    }
}

#[test]
fn test_plan_resolution_bat_script_rejected_no_process() {
    let exe = Path::new("C:/Windows/System32/helper.bat");
    let cancelled = AtomicBool::new(false);
    let started = Instant::now();

    let plan = plan_resolution(
        exe,
        "example.com",
        80,
        Duration::from_millis(1000),
        &cancelled,
        started,
    );

    match plan {
        ResolutionPlan::Immediate(m) => {
            assert_eq!(m.outcome, OUTCOME_LOCAL_ERROR);
            assert!(m.error_message.unwrap().contains("배치 스크립트"));
            assert!(m.limitations.iter().any(|l| l.contains(LIMIT_NO_PROCESS)));
        }
        ResolutionPlan::SpawnHelper => panic!("배치 스크립트 helper 거부"),
    }
}

#[test]
fn test_plan_resolution_valid_domain_spawns_helper() {
    let exe = Path::new("C:/target/release/npi.exe");
    let cancelled = AtomicBool::new(false);
    let started = Instant::now();

    let plan = plan_resolution(
        exe,
        "example.com",
        80,
        Duration::from_millis(1000),
        &cancelled,
        started,
    );

    assert_eq!(plan, ResolutionPlan::SpawnHelper);
}

// ============================================================================
// 6. 가짜 HelperHandle을 통한 helper 감독 및 정리 (supervise_helper)
// ============================================================================

#[test]
fn test_supervise_helper_success_normal_exit() {
    let payload = DnsWorkerPayload {
        format: WORKER_FORMAT.to_string(),
        host: "example.com".to_string(),
        port: 80,
        addresses: vec!["93.184.216.34:80".to_string()],
        truncated: false,
        error_code: None,
        error_message: None,
    };
    let line = worker_output_line(&payload);
    let mut handle = TestFakeHelperHandle::new(Some(true), true, line.into_bytes());
    let cancelled = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_secs(1);

    let verdict = supervise_helper(&mut handle, "example.com", 80, deadline, &cancelled);

    assert_eq!(verdict, HelperVerdict::Payload(payload));
    assert_eq!(
        handle.terminate_count, 1,
        "정상 종료 후 terminate 호출 필수"
    );
}

#[test]
fn test_supervise_helper_dns_error_exit() {
    let payload = DnsWorkerPayload {
        format: WORKER_FORMAT.to_string(),
        host: "notfound.example.com".to_string(),
        port: 80,
        addresses: Vec::new(),
        truncated: false,
        error_code: Some(11001),
        error_message: Some("호스트를 찾을 수 없음".to_string()),
    };
    let line = worker_output_line(&payload);
    let mut handle = TestFakeHelperHandle::new(Some(true), true, line.into_bytes());
    let cancelled = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_secs(1);

    let verdict = supervise_helper(
        &mut handle,
        "notfound.example.com",
        80,
        deadline,
        &cancelled,
    );

    assert_eq!(verdict, HelperVerdict::Payload(payload));
    assert_eq!(handle.terminate_count, 1, "DNS 오류 종료 후 terminate 필수");
}

#[test]
fn test_supervise_helper_abnormal_exit_code() {
    let payload = DnsWorkerPayload {
        format: WORKER_FORMAT.to_string(),
        host: "example.com".to_string(),
        port: 80,
        addresses: vec!["93.184.216.34:80".to_string()],
        truncated: false,
        error_code: None,
        error_message: None,
    };
    let line = worker_output_line(&payload);
    // exit_status: Some(false) (0이 아닌 종료 코드)
    let mut handle = TestFakeHelperHandle::new(Some(false), true, line.into_bytes());
    let cancelled = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_secs(1);

    let verdict = supervise_helper(&mut handle, "example.com", 80, deadline, &cancelled);

    match verdict {
        HelperVerdict::LocalError(msg) => assert!(msg.contains("helper 비정상 종료")),
        _ => panic!("비정상 종료는 LocalError여야 함"),
    }
    assert_eq!(handle.terminate_count, 1, "비정상 종료 후 terminate 필수");
}

#[test]
fn test_supervise_helper_poll_io_error() {
    let mut handle = TestFakeHelperHandle::new(None, false, Vec::new());
    handle.poll_error = Some("자식 프로세스 핸들 폴링 실패".to_string());
    let cancelled = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_secs(1);

    let verdict = supervise_helper(&mut handle, "example.com", 80, deadline, &cancelled);

    match verdict {
        HelperVerdict::LocalError(msg) => assert!(msg.contains("helper 상태 확인 실패")),
        _ => panic!("상태 확인 실패는 LocalError여야 함"),
    }
    assert_eq!(handle.terminate_count, 1);
}

#[test]
fn test_supervise_helper_stdout_overflow_terminates() {
    let mut handle = TestFakeHelperHandle::new(Some(true), true, Vec::new());
    handle.overflowed = true; // 16KiB 초과
    let cancelled = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_secs(1);

    let verdict = supervise_helper(&mut handle, "example.com", 80, deadline, &cancelled);

    match verdict {
        HelperVerdict::LocalError(msg) => assert!(msg.contains("16KiB 상한 초과")),
        _ => panic!("16KiB 상한 초과는 LocalError여야 함"),
    }
    assert_eq!(handle.terminate_count, 1, "상한 초과 즉시 terminate 필수");
}

#[test]
fn test_supervise_helper_timeout_cancels_and_terminates() {
    // 종료되지 않고 계속 실행 중
    let mut handle = TestFakeHelperHandle::new(None, false, Vec::new());
    let cancelled = AtomicBool::new(false);
    // 매우 짧은 시한 (10ms 이하)
    let deadline = Instant::now() + Duration::from_millis(15);

    let verdict = supervise_helper(&mut handle, "example.com", 80, deadline, &cancelled);

    assert_eq!(verdict, HelperVerdict::TimedOut);
    assert_eq!(
        handle.terminate_count, 1,
        "시한 초과 시 terminate(kill+wait+reader join) 필수"
    );
}

#[test]
fn test_supervise_helper_in_flight_cancellation_terminates() {
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut handle = TestFakeHelperHandle::new(None, false, Vec::new());

    // 첫 폴링 시 취소 플래그 설정 시뮬레이션
    let cancelled_clone = Arc::clone(&cancelled);
    handle.on_poll = Some(Box::new(move || {
        cancelled_clone.store(true, Ordering::SeqCst);
    }));

    let deadline = Instant::now() + Duration::from_secs(2);
    let verdict = supervise_helper(&mut handle, "example.com", 80, deadline, &cancelled);

    assert_eq!(verdict, HelperVerdict::Cancelled);
    assert_eq!(handle.terminate_count, 1, "실행 중 취소 시 terminate 필수");
}

#[test]
fn test_supervise_helper_cancellation_wins_after_response() {
    let payload = DnsWorkerPayload {
        format: WORKER_FORMAT.to_string(),
        host: "example.com".to_string(),
        port: 80,
        addresses: vec!["93.184.216.34:80".to_string()],
        truncated: false,
        error_code: None,
        error_message: None,
    };
    let line = worker_output_line(&payload);
    // 종료 및 읽기 완료 상태이나 취소 플래그가 true
    let mut handle = TestFakeHelperHandle::new(Some(true), true, line.into_bytes());
    let cancelled = AtomicBool::new(true);
    let deadline = Instant::now() + Duration::from_secs(1);

    let verdict = supervise_helper(&mut handle, "example.com", 80, deadline, &cancelled);

    assert_eq!(
        verdict,
        HelperVerdict::Cancelled,
        "응답 수신 후에도 취소가 우선해야 함"
    );
    assert_eq!(handle.terminate_count, 1);
}

#[test]
fn test_supervise_helper_always_reaps_on_terminate() {
    // 다중 terminate 호출 시에도 안전한지 검증
    let mut handle = TestFakeHelperHandle::new(Some(true), true, b"{}".to_vec());
    handle.terminate();
    handle.terminate();
    assert_eq!(handle.terminate_count, 2);
}

#[test]
fn test_supervise_helper_expired_ready_prefers_deadline() {
    let payload = DnsWorkerPayload {
        format: WORKER_FORMAT.to_string(),
        host: "example.com".to_string(),
        port: 80,
        addresses: vec!["93.184.216.34:80".to_string()],
        truncated: false,
        error_code: None,
        error_message: None,
    };
    let line = worker_output_line(&payload);
    // 이미 완료된 상태이나 마감시간이 이미 만료된 경우
    let mut handle = TestFakeHelperHandle::new(Some(true), true, line.into_bytes());
    let cancelled = AtomicBool::new(false);
    let deadline = Instant::now() - Duration::from_millis(5);

    let verdict = supervise_helper(&mut handle, "example.com", 80, deadline, &cancelled);

    assert_eq!(
        verdict,
        HelperVerdict::TimedOut,
        "이미 완료된 상태라도 전체 마감시간이 만료되었으면 TimedOut이 우선해야 함"
    );
    assert_eq!(
        handle.terminate_count, 1,
        "만료 판정 시에도 terminate 호출 필수"
    );
}

#[test]
fn test_supervise_helper_late_poll_completion_loses_to_deadline() {
    let payload = DnsWorkerPayload {
        format: WORKER_FORMAT.to_string(),
        host: "localhost".to_string(),
        port: 80,
        addresses: vec!["127.0.0.1:80".to_string()],
        truncated: false,
        error_code: None,
        error_message: None,
    };
    let line = worker_output_line(&payload);
    // poll_exit에서 8ms 지연 후 성공을 반환하나, 전체 마감시간은 1ms 후 만료
    let mut handle = TestFakeHelperHandle::new(Some(true), true, line.into_bytes());
    handle.on_poll = Some(Box::new(|| {
        std::thread::sleep(Duration::from_millis(8));
    }));
    let cancelled = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_millis(1);

    let verdict = supervise_helper(&mut handle, "localhost", 80, deadline, &cancelled);

    assert_eq!(
        verdict,
        HelperVerdict::TimedOut,
        "poll 도중 마감시간이 만료되었으면 늦게 관찰된 완료보다 TimedOut이 우선해야 함"
    );
    assert_eq!(
        handle.terminate_count, 1,
        "만료 판정 시에도 terminate 호출 필수"
    );
}

#[test]
fn test_supervise_helper_cancellation_during_terminate_overrides_early_timeout() {
    // DNS-CANCEL-01 회귀 (A):
    // deadline 만료로 early TimedOut 경로에 진입했더라도,
    // terminate 정리 중 취소(cancel)가 발생하면 Cancelled가 TimedOut보다 우선해야 한다.
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut handle = TestFakeHelperHandle::new(None, false, Vec::new());
    let poll_called = Arc::new(AtomicBool::new(false));
    let poll_called_clone = Arc::clone(&poll_called);
    handle.on_poll = Some(Box::new(move || {
        poll_called_clone.store(true, Ordering::SeqCst);
    }));
    let cancelled_clone = Arc::clone(&cancelled);
    handle.on_terminate = Some(Box::new(move || {
        cancelled_clone.store(true, Ordering::SeqCst);
    }));

    // 이미 만료된 deadline
    let deadline = Instant::now();
    let verdict = supervise_helper(&mut handle, "example.com", 80, deadline, &cancelled);

    assert_eq!(
        verdict,
        HelperVerdict::Cancelled,
        "정리 중 발생한 취소는 early TimedOut보다 최우선이어야 함"
    );
    assert_eq!(
        handle.terminate_count, 1,
        "만료 판정 시에도 terminate는 반드시 1회 수행되어야 함"
    );
    assert!(
        !poll_called.load(Ordering::SeqCst),
        "만료 deadline 조건에서는 poll 호출 없이도 terminate가 반드시 수행되어야 함"
    );
}

#[test]
fn test_supervise_helper_cancellation_during_terminate_overrides_early_overflow() {
    // DNS-CANCEL-01 회귀 (B):
    // stdout 16KiB 상한 초과로 early LocalError 경로에 진입했더라도,
    // terminate 정리 중 취소(cancel)가 발생하면 Cancelled가 LocalError보다 우선해야 한다.
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut handle = TestFakeHelperHandle::new(Some(true), true, Vec::new());
    handle.overflowed = true;
    let cancelled_clone = Arc::clone(&cancelled);
    handle.on_terminate = Some(Box::new(move || {
        cancelled_clone.store(true, Ordering::SeqCst);
    }));

    let deadline = Instant::now() + Duration::from_secs(10);
    let verdict = supervise_helper(&mut handle, "example.com", 80, deadline, &cancelled);

    assert_eq!(
        verdict,
        HelperVerdict::Cancelled,
        "정리 중 발생한 취소는 early LocalError(stdout 상한 초과)보다 최우선이어야 함"
    );
    assert_eq!(
        handle.terminate_count, 1,
        "상한 초과 정리 시에도 terminate는 반드시 1회 수행되어야 함"
    );
}

// ============================================================================
// 7. 감독 결과 DTO 변환 (measurement_from_verdict)
// ============================================================================

#[test]
fn test_measurement_from_verdict_timed_out() {
    let m = measurement_from_verdict("example.com", 80, HelperVerdict::TimedOut, 150);
    assert_eq!(m.outcome, OUTCOME_TIMED_OUT);
    assert_eq!(m.elapsed_ms, 150);
    assert!(m.limitations.iter().any(|l| l.contains(LIMIT_TIMEOUT)));
}

#[test]
fn test_measurement_from_verdict_cancelled() {
    let m = measurement_from_verdict("example.com", 80, HelperVerdict::Cancelled, 50);
    assert_eq!(m.outcome, OUTCOME_CANCELLED);
    assert_eq!(m.elapsed_ms, 50);
    assert!(m.limitations.iter().any(|l| l.contains(LIMIT_CANCEL)));
}

#[test]
fn test_measurement_from_verdict_local_error() {
    let m = measurement_from_verdict(
        "example.com",
        80,
        HelperVerdict::LocalError("stdout 읽기 실패".to_string()),
        12,
    );
    assert_eq!(m.outcome, OUTCOME_LOCAL_ERROR);
    assert_eq!(m.error_message, Some("stdout 읽기 실패".to_string()));
    assert!(m.limitations.iter().any(|l| l.contains(LIMIT_LOCAL)));
}

#[test]
fn test_measurement_from_verdict_worker_input_rejected_prefix() {
    let payload = DnsWorkerPayload {
        format: WORKER_FORMAT.to_string(),
        host: "example.com".to_string(),
        port: 80,
        addresses: Vec::new(),
        truncated: false,
        error_code: None,
        error_message: Some(format!("{WORKER_INPUT_REJECTED_PREFIX} 포트 오류")),
    };
    let m = measurement_from_verdict("example.com", 80, HelperVerdict::Payload(payload), 5);
    assert_eq!(
        m.outcome, OUTCOME_LOCAL_ERROR,
        "WORKER_INPUT_REJECTED는 LOCAL_ERROR로 분류"
    );
    assert!(
        m.error_message
            .unwrap()
            .contains("WORKER_INPUT_REJECTED: 포트 오류")
    );
}

#[test]
fn test_measurement_from_verdict_dns_error_preserves_raw_code_and_message() {
    let payload = DnsWorkerPayload {
        format: WORKER_FORMAT.to_string(),
        host: "unknown-host.example".to_string(),
        port: 80,
        addresses: Vec::new(),
        truncated: false,
        error_code: Some(11001),
        error_message: Some("No such host is known".to_string()),
    };
    let m = measurement_from_verdict(
        "unknown-host.example",
        80,
        HelperVerdict::Payload(payload),
        35,
    );
    assert_eq!(m.outcome, OUTCOME_DNS_ERROR);
    assert_eq!(m.error_code, Some(11001), "원시 OS 에러 코드 보존");
    assert_eq!(
        m.error_message,
        Some("No such host is known".to_string()),
        "원시 OS 에러 메시지 보존"
    );
    assert!(m.limitations.iter().any(|l| l.contains(LIMIT_DNS_ERROR)));
}

#[test]
fn test_measurement_from_verdict_resolved_success() {
    let payload = DnsWorkerPayload {
        format: WORKER_FORMAT.to_string(),
        host: "example.com".to_string(),
        port: 80,
        addresses: vec!["93.184.216.34:80".to_string()],
        truncated: false,
        error_code: None,
        error_message: None,
    };
    let m = measurement_from_verdict("example.com", 80, HelperVerdict::Payload(payload), 42);
    assert_eq!(m.outcome, OUTCOME_RESOLVED);
    assert_eq!(m.addresses, vec!["93.184.216.34:80"]);
    assert_eq!(m.elapsed_ms, 42);
    assert!(m.limitations.iter().any(|l| l.contains(LIMIT_OS_RESOLVER)));
}

#[test]
fn test_measurement_from_verdict_resolved_truncated() {
    let mut addrs = Vec::new();
    for i in 1..=32 {
        addrs.push(format!("10.0.0.{i}:80"));
    }
    let payload = DnsWorkerPayload {
        format: WORKER_FORMAT.to_string(),
        host: "example.com".to_string(),
        port: 80,
        addresses: addrs,
        truncated: true,
        error_code: None,
        error_message: None,
    };
    let m = measurement_from_verdict("example.com", 80, HelperVerdict::Payload(payload), 45);
    assert_eq!(m.outcome, OUTCOME_RESOLVED);
    assert!(m.limitations.iter().any(|l| l.contains(LIMIT_TRUNCATED)));
}

// ============================================================================
// 8. resolver_worker 순수 입력 거부 및 리터럴 처리 검증
// ============================================================================

#[test]
fn test_resolver_worker_invalid_port_returns_rejected() {
    let payload = resolver_worker("example.com", 0);
    assert_eq!(payload.format, WORKER_FORMAT);
    assert!(payload.addresses.is_empty());
    assert!(
        payload
            .error_message
            .unwrap()
            .contains(WORKER_INPUT_REJECTED_PREFIX)
    );
}

#[test]
fn test_resolver_worker_invalid_host_returns_rejected() {
    let payload = resolver_worker("invalid:host:colon", 80);
    assert_eq!(payload.format, WORKER_FORMAT);
    assert!(payload.addresses.is_empty());
    assert!(
        payload
            .error_message
            .unwrap()
            .contains(WORKER_INPUT_REJECTED_PREFIX)
    );
}

#[test]
fn test_resolver_worker_ipv4_literal_without_os_resolver() {
    let payload = resolver_worker("127.0.0.1", 8080);
    assert_eq!(payload.format, WORKER_FORMAT);
    assert_eq!(payload.addresses, vec!["127.0.0.1:8080"]);
    assert_eq!(payload.error_code, None);
    assert_eq!(payload.error_message, None);
}

#[test]
fn test_resolver_worker_ipv6_literal_without_os_resolver() {
    let payload = resolver_worker("::1", 53);
    assert_eq!(payload.format, WORKER_FORMAT);
    assert_eq!(payload.addresses, vec!["[::1]:53"]);
    assert_eq!(payload.error_code, None);
    assert_eq!(payload.error_message, None);
}

#[test]
fn test_run_worker_from_args_invalid_port_string() {
    let payload = run_worker_from_args("example.com", "not_a_port");
    assert_eq!(payload.format, WORKER_FORMAT);
    assert!(
        payload
            .error_message
            .unwrap()
            .contains(WORKER_INPUT_REJECTED_PREFIX)
    );
}

// ============================================================================
// 9. IP 리터럴 부모 직접 처리(우회) 및 실제 helper 격리 시험
// ============================================================================

#[test]
fn test_literal_ip_bypasses_helper_process_offline() {
    // 127.0.0.1 같은 IP 리터럴은 helper 자식 프로세스를 스폰하지 않고 부모에서 즉시 해석(bypass)됨을
    // 검증하는 순수 오프라인 테스트이다. 자식 프로세스 격리 실행을 입증하는 시험이 아니다.
    let exe = std::env::current_exe().expect("현재 실행 파일 경로 획득");
    let cancelled = Arc::new(AtomicBool::new(false));
    let measurement = resolve_isolated(
        &exe,
        "127.0.0.1",
        80,
        Duration::from_millis(1000),
        cancelled,
    );
    // 리터럴은 프로세스 없이 즉시 반환되므로 안전
    assert_eq!(measurement.outcome, OUTCOME_RESOLVED);
    assert_eq!(measurement.addresses, vec!["127.0.0.1:80"]);
    assert!(
        measurement
            .limitations
            .iter()
            .any(|l| l.contains(LIMIT_LITERAL)),
        "IP 리터럴 우회 표시 포함 필수"
    );
}

#[test]
#[ignore = "부모 명시 실행: localhost helper 격리 시험"]
fn test_real_localhost_helper_process_isolation() {
    // 부모가 main.rs에 helper 실행 플래그를 연결한 후 NPI_TEST_HELPER_EXE 환경변수로
    // 지정한 실제 제품 바이너리 경로(테스트 실행 파일 아님)로 localhost의 하위 프로세스 격리를 시험한다.
    // 외부 도메인을 사용하지 않으며, 부모가 추후 main/helper를 연결하고 명시적으로 실행한다.
    let exe_var = std::env::var("NPI_TEST_HELPER_EXE").expect(
        "명시 real 시험에는 NPI_TEST_HELPER_EXE 절대 경로가 필요하며 미설정은 성공이 아니다",
    );
    let exe_path = Path::new(&exe_var);
    assert!(
        exe_path.is_absolute(),
        "NPI_TEST_HELPER_EXE 경로는 절대 경로여야 함"
    );
    let cancelled = Arc::new(AtomicBool::new(false));
    let measurement = resolve_isolated(
        exe_path,
        "localhost",
        80,
        Duration::from_millis(3000),
        cancelled,
    );
    assert_eq!(measurement.host, "localhost");
    assert_eq!(measurement.port, 80);
    assert!(
        measurement.outcome == OUTCOME_RESOLVED || measurement.outcome == OUTCOME_DNS_ERROR,
        "localhost helper 실행 결과는 RESOLVED 또는 DNS_ERROR여야 함"
    );
    assert!(
        measurement
            .limitations
            .iter()
            .any(|l| l.contains(LIMIT_OS_RESOLVER)),
        "helper 프로세스의 OS 해석기 제한사항 포함 필수"
    );
}
