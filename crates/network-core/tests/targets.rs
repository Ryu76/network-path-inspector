//! Network Quick Check(Part B) 진단 대상 입력 분석 및 계획 수립 단위/경계 테스트.
//!
//! ## 주의 및 안전 규칙
//! - 본 테스트 스위트는 소켓 연결, 패킷 송수신, DNS 쿼리, 프로세스 실행 또는 파일 쓰기 등
//!   실제 네트워크 및 OS I/O 작업을 일체 수행하지 않는 순수 메모리 단위 테스트입니다.
//! - `qg2a-contract.json` 및 PRD v1.2 요구사항의 모든 경계 조건을 철저히 검증합니다.

use network_core::quick::QuickFeature;
use network_core::targets::{
    DEFAULT_CONCURRENCY, DEFAULT_TCP_TIMEOUT_MS, MAX_INPUT_BYTES, QuickOptions, QuickTarget,
    build_quick_plan, parse_target_list, parse_target_pair,
};

/// 1. 유효한 IPv4, IPv6, 도메인, localhost 파싱 검증.
#[test]
fn test_valid_target_parsing() {
    // parse_target_pair 검증
    let t_ipv4 = parse_target_pair("127.0.0.1", "80").expect("유효한 IPv4 pair 파싱 실패");
    assert_eq!(t_ipv4.host, "127.0.0.1");
    assert_eq!(t_ipv4.port, 80);
    assert_eq!(t_ipv4.raw_input, "127.0.0.1:80");

    let t_ipv6 = parse_target_pair("::1", "443").expect("유효한 IPv6 pair 파싱 실패");
    assert_eq!(t_ipv6.host, "::1");
    assert_eq!(t_ipv6.port, 443);
    assert_eq!(t_ipv6.raw_input, "::1:443");

    let t_domain = parse_target_pair("example.com", "8080").expect("유효한 도메인 pair 파싱 실패");
    assert_eq!(t_domain.host, "example.com");
    assert_eq!(t_domain.port, 8080);
    assert_eq!(t_domain.raw_input, "example.com:8080");

    let t_localhost =
        parse_target_pair("localhost", "3000").expect("유효한 localhost pair 파싱 실패");
    assert_eq!(t_localhost.host, "localhost");
    assert_eq!(t_localhost.port, 3000);
    assert_eq!(t_localhost.raw_input, "localhost:3000");

    // parse_target_list 다중 행 검증
    let list_input = "127.0.0.1:80\n[::1]:443\nexample.com:8080\nlocalhost:3000\n";
    let list_res = parse_target_list(list_input).expect("다중 유효 대상 파싱 실패");
    assert_eq!(list_res.len(), 4);
    assert_eq!(list_res[0], t_ipv4);
    assert_eq!(list_res[1].host, "::1");
    assert_eq!(list_res[1].port, 443);
    assert_eq!(list_res[1].raw_input, "[::1]:443");
    assert_eq!(list_res[2], t_domain);
    assert_eq!(list_res[3], t_localhost);
}

/// 2. 포트 번호 경계값(1, 65535) 및 비정상 범위(0, 65536, 음수, 부호, 공백, 소수, 문자) 검증.
#[test]
fn test_port_boundary_and_range() {
    assert!(parse_target_pair("example.com", "1").is_ok());
    assert!(parse_target_pair("example.com", "65535").is_ok());

    // 포트 0 금지
    assert!(parse_target_pair("example.com", "0").is_err());
    // 65536 범위 초과 금지
    assert!(parse_target_pair("example.com", "65536").is_err());
    // 음수, 부호, 소수점, 범위, 공백 금지
    assert!(parse_target_pair("example.com", "-80").is_err());
    assert!(parse_target_pair("example.com", "+80").is_err());
    assert!(parse_target_pair("example.com", "80.0").is_err());
    assert!(parse_target_pair("example.com", "80-90").is_err());
    assert!(parse_target_pair("example.com", "80 ").is_err());
    assert!(parse_target_pair("example.com", " 80").is_err());
    assert!(parse_target_pair("example.com", "100000").is_err());
    assert!(parse_target_pair("example.com", "").is_err());
    assert!(parse_target_pair("example.com", "abc").is_err());
}

/// 3. 인라인 붙여넣기에서 bare IPv6:port 모호성 거부 및 [IPv6]:port 정상 허용 검증.
#[test]
fn test_ambiguous_bare_ipv6_rejected() {
    // bare IPv6:port는 콜론이 2개 이상이므로 모호성 방지를 위해 거부되어야 함
    let bare1 = "2001:db8::1:80\n";
    let res1 = parse_target_list(bare1);
    assert!(res1.is_err());
    let errs1 = res1.unwrap_err();
    assert!(errs1.iter().any(|e| e.message.contains("[IPv6]:port")));

    let bare2 = "::1:80\n";
    let res2 = parse_target_list(bare2);
    assert!(res2.is_err());

    // 대괄호 형태 [IPv6]:port는 정상 허용
    let bracketed = "[2001:db8::1]:80\n[::1]:443\n";
    let res_ok = parse_target_list(bracketed).expect("[IPv6]:port 파싱 실패");
    assert_eq!(res_ok.len(), 2);
    assert_eq!(res_ok[0].host, "2001:db8::1");
    assert_eq!(res_ok[0].port, 80);
    assert_eq!(res_ok[1].host, "::1");
    assert_eq!(res_ok[1].port, 443);
}

/// 4. 잘못된 숫자형 IPv4 주소가 도메인으로 수리되지 않고 거부되는지 검증.
#[test]
fn test_invalid_numeric_ipv4_rejected() {
    // 256 이상 옥텟
    assert!(parse_target_pair("192.168.1.999", "80").is_err());
    // 옥텟 초과
    assert!(parse_target_pair("999.999.999.999", "80").is_err());
    // 숫자로 시작하는 잘못된 라벨 패턴
    assert!(parse_target_pair("10.0.0.1a", "80").is_err());

    let list_err = parse_target_list("192.168.1.999:80\n");
    assert!(list_err.is_err());
}

/// 5. URL 자격증명(@) 입력 시 오류가 발생하고, 시크릿 토큰이 에러 메시지에 반사되지 않는지 검증.
#[test]
fn test_url_credential_no_secret_reflection() {
    let secret = "SuperSecretTokenPassword12345";
    let raw_line = format!("http://admin:{secret}@example.com:80");

    let list_res = parse_target_list(&raw_line);
    assert!(list_res.is_err());
    let list_errs = list_res.unwrap_err();
    for err in &list_errs {
        assert!(
            !err.message.contains(secret),
            "에러 메시지에 시크릿 토큰이 노출되었습니다: {}",
            err.message
        );
    }

    let pair_res = parse_target_pair(&format!("admin:{secret}@example.com"), "80");
    assert!(pair_res.is_err());
    for err in &pair_res.unwrap_err() {
        assert!(
            !err.message.contains(secret),
            "pair 에러 메시지에 시크릿 토큰이 노출되었습니다: {}",
            err.message
        );
    }
}

/// 6. 입력 문자열 32768 바이트 상한 검증 (문자열 분석 전 즉각 차단).
#[test]
fn test_max_input_bytes_limit() {
    // 정확히 32768 바이트 이하인 유효 입력은 검증 진행
    let single_line = "127.0.0.1:80\n";
    let repeat_count = MAX_INPUT_BYTES / single_line.len();
    let exact_input = single_line.repeat(repeat_count);
    assert!(exact_input.len() <= MAX_INPUT_BYTES);
    assert!(parse_target_list(&exact_input).is_ok());

    // 32768 바이트 초과 입력은 분석 전 즉시 에러 (line 0)
    let overflow_input = format!("{}\n", "a".repeat(MAX_INPUT_BYTES));
    assert!(overflow_input.len() > MAX_INPUT_BYTES);
    let errs = parse_target_list(&overflow_input).expect_err("32768 바이트 초과 입력이 허용됨");
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].line, 0);
    assert!(errs[0].message.contains("최대 허용 크기"));
}

/// 7. 고유 대상 수 100개 상한 검증 (101개 입력 시 조용히 자르지 않고 오류 반환).
#[test]
fn test_max_unique_targets_limit_exceeded() {
    let mut lines = String::new();
    for i in 1..=101 {
        lines.push_str(&format!("10.0.0.{i}:80\n"));
    }

    let res = parse_target_list(&lines);
    assert!(res.is_err(), "101개 고유 대상이 조용히 허용됨");
    let errs = res.unwrap_err();
    assert_eq!(errs.len(), 1);
    assert_eq!(errs[0].line, 0);
    assert!(errs[0].message.contains("최대 허용 한도"));
}

/// 8. 도메인 case-insensitive 및 IP canon 동치 키 중복 제거 (첫 등장 원문 보존).
#[test]
fn test_deduplication_domain_case_and_ip_canon() {
    let input = "example.com:80\nEXAMPLE.COM:80\nExample.Com:80\n[::1]:80\n[0:0:0:0:0:0:0:1]:80\n";
    let res = parse_target_list(input).expect("중복 제거 파싱 실패");
    assert_eq!(res.len(), 2);

    // 첫 등장 도메인 원문 및 포트 유지
    assert_eq!(res[0].host, "example.com");
    assert_eq!(res[0].port, 80);
    assert_eq!(res[0].raw_input, "example.com:80");

    // 첫 등장 IPv6 원문 및 포트 유지
    assert_eq!(res[1].host, "::1");
    assert_eq!(res[1].port, 80);
    assert_eq!(res[1].raw_input, "[::1]:80");
}

/// 9. 중복이 많아도 고유 한도(100개)를 적용하여 처리하는지 검증.
#[test]
fn test_deduplication_many_duplicates_within_unique_limit() {
    // 1개 대상을 200번 반복: 고유 대상은 1개이므로 정상 통과
    let single_line = "127.0.0.1:80\n";
    let duplicates_200 = single_line.repeat(200);
    let res_single = parse_target_list(&duplicates_200).expect("반복 중복 파싱 실패");
    assert_eq!(res_single.len(), 1);

    // 100개 고유 대상을 2번씩 반복 (총 200행): 고유 대상 100개로 정상 통과
    let mut double_100 = String::new();
    for i in 1..=100 {
        double_100.push_str(&format!("10.1.0.{i}:80\n10.1.0.{i}:80\n"));
    }
    let res_100 = parse_target_list(&double_100).expect("100개 고유 대상 2회 중복 파싱 실패");
    assert_eq!(res_100.len(), 100);

    // 101개 고유 대상을 2번씩 반복: 고유 대상 101개이므로 에러 발생
    let mut double_101 = String::new();
    for i in 1..=101 {
        double_101.push_str(&format!("10.2.0.{i}:80\n10.2.0.{i}:80\n"));
    }
    assert!(parse_target_list(&double_101).is_err());
}

/// 10. 한 행이라도 잘못되면 원자적(Atomic)으로 전체 Err를 반환하고 정확한 1-based 라인 번호를 제공하는지 검증.
#[test]
fn test_atomic_error_and_line_numbers() {
    let input = "127.0.0.1:80\n\
                 invalid_port:abc\n\
                 127.0.0.2:80\n\
                 bad_host..com:80\n\
                 127.0.0.3:80\n";

    let res = parse_target_list(input);
    assert!(res.is_err());
    let errs = res.unwrap_err();

    // 2행(포트 오류)과 4행(호스트 라벨 오류) 오류 수집 확인
    assert!(errs.iter().any(|e| e.line == 2));
    assert!(errs.iter().any(|e| e.line == 4));

    // 유효했던 1, 3, 5행이 일부만 반환되지 않고 전체가 실패 처리됨
    assert!(errs.len() >= 2);
}

/// 11. 기본 옵션(Default)으로 진단 계획 수립 검증 (TCP+Ping, 3000ms -> 2000ms ICMP 클램프).
#[test]
fn test_default_plan_construction() {
    let target = parse_target_pair("127.0.0.1", "80").expect("대상 생성 실패");
    let options = QuickOptions::default();

    let plan =
        build_quick_plan(std::slice::from_ref(&target), &options).expect("기본 계획 수립 실패");

    assert_eq!(plan.tcp_timeout_ms, DEFAULT_TCP_TIMEOUT_MS);
    // Ping 선택 시 min(3000, 2000) = 2000ms로 클램프
    assert_eq!(plan.icmp_timeout_ms, Some(2000));
    assert_eq!(plan.concurrency, DEFAULT_CONCURRENCY);
    assert_eq!(plan.targets.len(), 1);
    assert_eq!(
        plan.targets[0].features,
        vec![QuickFeature::TcpConnect, QuickFeature::IcmpPing]
    );
    // 대상이 IP 리터럴이므로 requires_resolution = false
    assert!(!plan.targets[0].requires_resolution);

    // 타임아웃 클램프 안내가 limitations에 명시되었는지 검증
    assert!(!plan.limitations.is_empty());
    assert!(plan.limitations.iter().any(|l| l.contains("2000ms")));
}

/// 12. 빈 기능 선택(selected_features가 빈 경우) 계획 수립 검증.
#[test]
fn test_empty_feature_selection_plan() {
    let target = parse_target_pair("example.com", "80").expect("대상 생성 실패");
    let options = QuickOptions {
        tcp_timeout_ms: 3000,
        concurrency: 4,
        selected_features: Vec::new(),
    };

    let plan = build_quick_plan(&[target], &options).expect("빈 기능 선택 계획 수립 실패");
    assert_eq!(plan.targets.len(), 1);
    // 대상별 features가 빈 목록이고 프로브 계획이 0이어야 함
    assert!(plan.targets[0].features.is_empty());
    assert_eq!(plan.icmp_timeout_ms, None);
    assert!(!plan.targets[0].requires_resolution);
}

/// 13. 개별 5개 기능 선택 검증 및 미선택 기능 자동 추가 없음/중복 기능 에러 검증.
#[test]
fn test_individual_features_selection_and_no_unselected_added() {
    let target = parse_target_pair("example.com", "80").expect("대상 생성 실패");
    let all_features = [
        QuickFeature::TcpConnect,
        QuickFeature::IcmpPing,
        QuickFeature::IcmpTraceroute,
        QuickFeature::DnsLookup,
        QuickFeature::LocalNetwork,
    ];

    for &feature in &all_features {
        let options = QuickOptions {
            tcp_timeout_ms: 1000,
            concurrency: 2,
            selected_features: vec![feature],
        };
        let plan = build_quick_plan(std::slice::from_ref(&target), &options)
            .expect("단일 기능 계획 수립 실패");
        assert_eq!(plan.targets[0].features.len(), 1);
        assert_eq!(plan.targets[0].features[0], feature);

        if feature == QuickFeature::IcmpPing {
            assert_eq!(plan.icmp_timeout_ms, Some(1000));
        } else {
            assert_eq!(plan.icmp_timeout_ms, None);
        }
    }

    // 기능 중복 선택 시 에러 반환 검증
    let dup_options = QuickOptions {
        tcp_timeout_ms: 3000,
        concurrency: 2,
        selected_features: vec![QuickFeature::TcpConnect, QuickFeature::TcpConnect],
    };
    let err = build_quick_plan(&[target], &dup_options).expect_err("중복 기능 선택이 허용됨");
    assert!(err.iter().any(|e| e.message.contains("중복")));
}

/// 14. 도메인 vs IP 대상에 대한 선행 주소 해석(requires_resolution) 계산 검증.
#[test]
fn test_implicit_vs_detailed_dns_resolution() {
    let domain_target = parse_target_pair("example.com", "80").unwrap();
    let ip_target = parse_target_pair("127.0.0.1", "80").unwrap();

    // 1) 도메인 대상 + TCP Connect -> requires_resolution: true
    let opt_tcp = QuickOptions {
        tcp_timeout_ms: 3000,
        concurrency: 4,
        selected_features: vec![QuickFeature::TcpConnect],
    };
    let plan_domain_tcp = build_quick_plan(std::slice::from_ref(&domain_target), &opt_tcp).unwrap();
    assert!(plan_domain_tcp.targets[0].requires_resolution);

    // 2) 도메인 대상 + DnsLookup만 선택 -> requires_resolution: false (상세 기능 자체 조회)
    let opt_dns = QuickOptions {
        tcp_timeout_ms: 3000,
        concurrency: 4,
        selected_features: vec![QuickFeature::DnsLookup],
    };
    let plan_domain_dns = build_quick_plan(std::slice::from_ref(&domain_target), &opt_dns).unwrap();
    assert!(!plan_domain_dns.targets[0].requires_resolution);

    // 3) 도메인 대상 + Traceroute -> requires_resolution: true
    let opt_trace = QuickOptions {
        tcp_timeout_ms: 3000,
        concurrency: 4,
        selected_features: vec![QuickFeature::IcmpTraceroute],
    };
    let plan_domain_trace = build_quick_plan(&[domain_target], &opt_trace).unwrap();
    assert!(plan_domain_trace.targets[0].requires_resolution);

    // 4) IP 대상 + TCP Connect -> requires_resolution: false
    let plan_ip_tcp = build_quick_plan(std::slice::from_ref(&ip_target), &opt_tcp).unwrap();
    assert!(!plan_ip_tcp.targets[0].requires_resolution);

    // 5) IP 대상 + DnsLookup -> requires_resolution: false
    let plan_ip_dns = build_quick_plan(&[ip_target], &opt_dns).unwrap();
    assert!(!plan_ip_dns.targets[0].requires_resolution);
}

/// 15. 안전하지 않은 주소(0.0.0.0, ::, 브로드캐스트, 멀티캐스트, IPv6 매핑) 거부 검증.
#[test]
fn test_unsafe_address_inputs_rejected() {
    let unsafe_addresses = [
        "0.0.0.0",
        "::",
        "255.255.255.255",
        "224.0.0.1",
        "ff02::1",
        "::ffff:0.0.0.0",
        "::ffff:255.255.255.255",
        "::ffff:224.0.0.1",
    ];

    for addr in unsafe_addresses {
        let pair_res = parse_target_pair(addr, "80");
        assert!(
            pair_res.is_err(),
            "안전하지 않은 주소({addr})가 pair에서 허용됨"
        );

        let list_entry = if addr.contains(':') {
            format!("[{addr}]:80\n")
        } else {
            format!("{addr}:80\n")
        };
        let list_res = parse_target_list(&list_entry);
        assert!(
            list_res.is_err(),
            "안전하지 않은 주소({addr})가 list에서 허용됨"
        );
    }
}

/// 16. 직접 위조된 QuickTarget 및 옵션에 대한 build_quick_plan 재검증 검증.
#[test]
fn test_forged_target_revalidation_in_build_plan() {
    let options = QuickOptions::default();

    // 포트 0 위조 대상
    let forged_port0 = QuickTarget {
        host: "127.0.0.1".to_string(),
        port: 0,
        raw_input: "127.0.0.1:0".to_string(),
    };
    assert!(build_quick_plan(&[forged_port0], &options).is_err());

    // 잘못된 호스트 위조 대상
    let forged_bad_host = QuickTarget {
        host: "invalid..host".to_string(),
        port: 80,
        raw_input: "invalid..host:80".to_string(),
    };
    assert!(build_quick_plan(&[forged_bad_host], &options).is_err());

    // 안전하지 않은 IP 위조 대상
    let forged_unsafe_ip = QuickTarget {
        host: "255.255.255.255".to_string(),
        port: 80,
        raw_input: "255.255.255.255:80".to_string(),
    };
    assert!(build_quick_plan(&[forged_unsafe_ip], &options).is_err());

    // 빈 대상 목록
    assert!(build_quick_plan(&[], &options).is_err());

    // 101개 대상 목록
    let valid_target = parse_target_pair("127.0.0.1", "80").unwrap();
    let targets_101 = vec![valid_target; 101];
    assert!(build_quick_plan(&targets_101, &options).is_err());

    // 타임아웃 범위 위조 (0ms 또는 60001ms)
    let bad_timeout_opt = QuickOptions {
        tcp_timeout_ms: 0,
        concurrency: 4,
        selected_features: vec![QuickFeature::TcpConnect],
    };
    let normal_target = parse_target_pair("127.0.0.1", "80").unwrap();
    assert!(build_quick_plan(std::slice::from_ref(&normal_target), &bad_timeout_opt).is_err());

    // 동시성 범위 위조 (0 또는 5)
    let bad_concurrency_opt = QuickOptions {
        tcp_timeout_ms: 3000,
        concurrency: 5,
        selected_features: vec![QuickFeature::TcpConnect],
    };
    assert!(build_quick_plan(&[normal_target], &bad_concurrency_opt).is_err());
}

/// 17. 옵션 변경 후에도 수립된 plan이 불변(deep clone snapshot)으로 유지되는지 검증.
#[test]
fn test_immutability_after_options_mutation() {
    let target = parse_target_pair("127.0.0.1", "80").unwrap();
    let mut options = QuickOptions::default();

    let plan = build_quick_plan(&[target], &options).expect("계획 수립 실패");

    // 원본 options 변조
    options.tcp_timeout_ms = 50000;
    options.concurrency = 1;
    options.selected_features.clear();

    // plan 내부 필드는 원본 스냅샷 그대로 불변 유지
    assert_eq!(plan.tcp_timeout_ms, DEFAULT_TCP_TIMEOUT_MS);
    assert_eq!(plan.concurrency, DEFAULT_CONCURRENCY);
    assert_eq!(plan.targets[0].features.len(), 2);
}

/// 18. 토큰 앞뒤 공백 수리 금지(에러 반환) 및 공백 전용 행 무시 검증.
#[test]
fn test_whitespace_repair_forbidden() {
    // 토큰 앞뒤 공백 수리 금지
    assert!(parse_target_list(" 127.0.0.1:80\n").is_err());
    assert!(parse_target_list("127.0.0.1:80 \n").is_err());
    assert!(parse_target_pair(" 127.0.0.1", "80").is_err());
    assert!(parse_target_pair("127.0.0.1", "80 ").is_err());

    // 공백 전용 빈 행은 무시하고 정상 행만 파싱
    let input_with_blanks = "   \n\n127.0.0.1:80\n  \t  \n127.0.0.2:80\n\n";
    let res = parse_target_list(input_with_blanks).expect("공백 행 무시 파싱 실패");
    assert_eq!(res.len(), 2);
    assert_eq!(res[0].host, "127.0.0.1");
    assert_eq!(res[1].host, "127.0.0.2");
}

/// 19. 도메인 마지막 마침표(FQDN 점) 거부 및 라벨 형식 검증.
#[test]
fn test_domain_trailing_dot_rejected() {
    assert!(parse_target_pair("example.com.", "80").is_err());
    assert!(parse_target_pair(".example.com", "80").is_err());
    assert!(parse_target_pair("example..com", "80").is_err());
    assert!(parse_target_pair("-example.com", "80").is_err());
    assert!(parse_target_pair("example-.com", "80").is_err());
}

/// 20. 직접 생성된 자격증명 포함 host(포트 443)의 build_quick_plan 검증 시 시크릿 미노출 및 순번 식별 검증.
#[test]
fn test_build_quick_plan_credential_in_host_no_secret_reflection_port_443() {
    let sentinel = "QG2_SYNTHETIC_CREDENTIAL_SENTINEL";
    let user = "admin";
    let forged_host = format!("{user}:{sentinel}@example.test");
    let raw = format!("{forged_host}:443");

    let target = QuickTarget {
        host: forged_host.clone(),
        port: 443,
        raw_input: raw.clone(),
    };

    let options = QuickOptions::default();

    // 1) 단일 대상 (#1 순번 식별 및 시크릿 미반사)
    let res = build_quick_plan(std::slice::from_ref(&target), &options);
    assert!(res.is_err(), "자격증명 포함 호스트가 허용됨");
    let errs = res.unwrap_err();
    assert!(!errs.is_empty());

    for err in &errs {
        assert_eq!(err.line, 0, "build_quick_plan 오류 line은 0이어야 함");
        assert!(
            !err.message.contains(sentinel),
            "에러 메시지에 합성 sentinel이 노출되었습니다: {}",
            err.message
        );
        assert!(
            !err.message.contains(user),
            "에러 메시지에 사용자명이 노출되었습니다: {}",
            err.message
        );
        assert!(
            !err.message.contains(&raw),
            "에러 메시지에 raw_input이 노출되었습니다: {}",
            err.message
        );
        assert!(
            err.message.contains("#1"),
            "에러 메시지에 1-based 대상 순번(#1)이 식별되지 않습니다: {}",
            err.message
        );
    }

    // 2) 다중 대상에서 2번째 대상 오류 시 #2 순번 식별 및 1번째 정상 대상에 영향 없음 검증
    let normal_target = parse_target_pair("127.0.0.1", "443").unwrap();
    let multi_res = build_quick_plan(&[normal_target.clone(), target.clone()], &options);
    assert!(multi_res.is_err());
    let multi_errs = multi_res.unwrap_err();
    assert!(
        multi_errs.iter().any(|e| e.message.contains("#2")),
        "다중 대상 중 2번째 대상 순번(#2)이 식별되지 않습니다"
    );
    for err in &multi_errs {
        assert!(!err.message.contains(sentinel));
        assert!(!err.message.contains(user));
    }

    // 3) URL scheme 포함 호스트(https://user:sentinel@host) 위조 검증
    let url_host = format!("https://{user}:{sentinel}@example.test");
    let url_raw = format!("{url_host}:443");
    let url_target = QuickTarget {
        host: url_host.clone(),
        port: 443,
        raw_input: url_raw.clone(),
    };
    let url_res = build_quick_plan(std::slice::from_ref(&url_target), &options);
    assert!(url_res.is_err());
    for err in &url_res.unwrap_err() {
        assert!(!err.message.contains(sentinel));
        assert!(!err.message.contains(user));
        assert!(!err.message.contains(&url_raw));
    }

    // 원본 target 객체들의 불변(no mutation) 검증
    assert_eq!(target.host, forged_host);
    assert_eq!(target.port, 443);
    assert_eq!(target.raw_input, raw);
    assert_eq!(url_target.host, url_host);
    assert_eq!(url_target.port, 443);
    assert_eq!(url_target.raw_input, url_raw);
    assert_eq!(normal_target.host, "127.0.0.1");
}

/// 21. 직접 생성된 자격증명 포함 host(포트 0)의 build_quick_plan 포트/호스트 오류 시 시크릿 미노출 및 순번 식별 검증.
#[test]
fn test_build_quick_plan_credential_in_host_no_secret_reflection_port_0() {
    let sentinel = "QG2_SYNTHETIC_CREDENTIAL_SENTINEL";
    let user = "admin";
    let forged_host = format!("{user}:{sentinel}@example.test");
    let raw = format!("{forged_host}:0");

    let target = QuickTarget {
        host: forged_host.clone(),
        port: 0,
        raw_input: raw.clone(),
    };

    let options = QuickOptions::default();

    let res = build_quick_plan(std::slice::from_ref(&target), &options);
    assert!(res.is_err(), "포트 0 및 자격증명 호스트가 허용됨");
    let errs = res.unwrap_err();
    assert!(
        errs.len() >= 2,
        "포트 범위 오류와 호스트 유효성 오류가 모두 수집되어야 함"
    );

    let mut found_port_err = false;
    let mut found_host_err = false;

    for err in &errs {
        assert_eq!(err.line, 0, "build_quick_plan 오류 line은 0이어야 함");
        assert!(
            !err.message.contains(sentinel),
            "에러 메시지에 합성 sentinel이 노출되었습니다: {}",
            err.message
        );
        assert!(
            !err.message.contains(user),
            "에러 메시지에 사용자명이 노출되었습니다: {}",
            err.message
        );
        assert!(
            !err.message.contains(&raw),
            "에러 메시지에 raw_input이 노출되었습니다: {}",
            err.message
        );
        assert!(
            err.message.contains("#1"),
            "에러 메시지에 대상 순번(#1)이 식별되지 않습니다: {}",
            err.message
        );

        if err.message.contains("포트 번호(0)가 유효 범위") {
            found_port_err = true;
        }
        if err.message.contains("호스트가 유효하지 않습니다") {
            found_host_err = true;
        }
    }

    assert!(found_port_err, "포트 0 범위 오류 메시지가 존재해야 함");
    assert!(found_host_err, "호스트 오류 메시지가 존재해야 함");

    // 원본 target 객체의 불변(no mutation) 검증
    assert_eq!(target.host, forged_host);
    assert_eq!(target.port, 0);
    assert_eq!(target.raw_input, raw);
}
