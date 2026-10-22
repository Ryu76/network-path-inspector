//! Network Quick Check(Part B) ICMP Traceroute 단위 및 통합 테스트 모듈.
//!
//! 이 모듈은 다음을 철저히 검증합니다:
//! 1. 합성 픽스처(Synthetic Fixtures) 기반 OS tracert 출력 파서 (`parse_trace_output`).
//!    - 영어 및 한국어 Windows 로케일 출력
//!    - 1ms 미만(`<1 ms`) 상한 표기 및 타임아웃(`*`) 처리
//!    - IPv4 및 IPv6 다중 홉 경로
//!    - TTL 순서/중복/범위 위반 및 불량 홉 파싱 거절
//!    - u8 범위 분리(256 오버플로우 에러) 및 RTT 필수 ms 단위, '+' 부호 거절
//! 2. 진단 결과 어댑터 (`trace_to_quick_result`) 및 스키마 검증.
//!    - REACHED, INCOMPLETE, TIMED_OUT, CANCELLED, LOCAL_ERROR, UNAVAILABLE 매핑
//!    - IP 일관성 및 컨텍스트 교차 오염 차단
//!    - raw_stdout 재파싱 정합성 및 절삭/비정상 exit 코드 승격 차단
//! 3. 실행 전 매개변수 및 안전하지 않은 IP 차단 (`trace_once`, spawn 0회 보장).
//! 4. 실제 소유 IPv4/IPv6 루프백 진단 (`#[ignore]`, 부모 전용 통합 실행).

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use network_core::quick::{
    EvidenceLevel, QuickContext, QuickFeature, QuickStatus, validate_quick_result,
};
use network_core::traceroute::{
    TraceHop, TraceMeasurement, TraceOptions, parse_trace_output, trace_once, trace_to_quick_result,
};

/// [합성 픽스처] Windows 영어 로케일 단일 홉 정상 도달 출력.
const SYNTHETIC_FIXTURE_IPV4_ENGLISH_REACHED: &str = "\
Tracing route to 127.0.0.1 over a maximum of 30 hops\r\n\
\r\n\
  1    <1 ms    <1 ms    <1 ms  127.0.0.1\r\n\
\r\n\
Trace complete.\r\n";

/// [합성 픽스처] Windows 한국어 로케일 단일 홉 정상 도달 출력.
const SYNTHETIC_FIXTURE_IPV4_KOREAN_REACHED: &str = "\
최대 30홉에서 127.0.0.1(으)로 가는 경로 추적\r\n\
\r\n\
  1    <1 ms    <1 ms    <1 ms  127.0.0.1\r\n\
\r\n\
추적을 완료했습니다.\r\n";

/// [합성 픽스처] 다중 홉 및 무응답 타임아웃 홉 포함 출력 (영어).
const SYNTHETIC_FIXTURE_MULTI_HOP_MIXED: &str = "\
Tracing route to 192.168.1.1 over a maximum of 30 hops\r\n\
\r\n\
  1     2 ms     1 ms     2 ms  10.0.0.1\r\n\
  2     *        *        *     Request timed out.\r\n\
  3     8 ms     *        9 ms  192.168.1.1\r\n\
\r\n\
Trace complete.\r\n";

/// [합성 픽스처] 한국어 로케일 무응답 타임아웃 홉 출력.
const SYNTHETIC_FIXTURE_KOREAN_TIMED_OUT_HOP: &str = "\
최대 30홉에서 8.8.8.8(으)로 가는 경로 추적\r\n\
\r\n\
  1     1 ms     1 ms     1 ms  192.168.0.1\r\n\
  2     *        *        *     요청 시간이 만료되었습니다.\r\n";

/// [합성 픽스처] Windows IPv6 루프백 정상 도달 출력.
const SYNTHETIC_FIXTURE_IPV6_REACHED: &str = "\
Tracing route to ::1 over a maximum of 30 hops\r\n\
\r\n\
  1    <1 ms    <1 ms    <1 ms  ::1\r\n\
\r\n\
Trace complete.\r\n";

/// 기본 테스트용 컨텍스트 생성 헬퍼.
fn create_test_context(target_host: &str) -> QuickContext {
    QuickContext {
        session_id: "test-traceroute-session-001".to_string(),
        timestamp_iso8601: Some("2026-10-21T18:00:00Z".to_string()),
        source_host: Some("client-node".to_string()),
        target_host: target_host.to_string(),
        target_port: 80,
    }
}

#[test]
fn test_synthetic_ipv4_reached_parse_english() {
    let target: IpAddr = "127.0.0.1".parse().unwrap();
    let hops = parse_trace_output(
        target,
        SYNTHETIC_FIXTURE_IPV4_ENGLISH_REACHED.as_bytes(),
        30,
    )
    .expect("영어 정상 출력 파싱 실패");

    assert_eq!(hops.len(), 1);
    assert_eq!(hops[0].ttl, 1);
    assert_eq!(hops[0].address.as_deref(), Some("127.0.0.1"));
    assert_eq!(hops[0].probe_times_ms, vec![Some(1), Some(1), Some(1)]);
    assert_eq!(hops[0].rtt_less_than, vec![true, true, true]);
    assert!(hops[0].raw_line.contains("127.0.0.1"));
}

#[test]
fn test_synthetic_ipv4_reached_parse_korean() {
    let target: IpAddr = "127.0.0.1".parse().unwrap();
    let hops = parse_trace_output(target, SYNTHETIC_FIXTURE_IPV4_KOREAN_REACHED.as_bytes(), 30)
        .expect("한국어 정상 출력 파싱 실패");

    assert_eq!(hops.len(), 1);
    assert_eq!(hops[0].ttl, 1);
    assert_eq!(hops[0].address.as_deref(), Some("127.0.0.1"));
    assert_eq!(hops[0].probe_times_ms, vec![Some(1), Some(1), Some(1)]);
    assert_eq!(hops[0].rtt_less_than, vec![true, true, true]);
}

#[test]
fn test_synthetic_multi_hop_with_timeout_parse() {
    let target: IpAddr = "192.168.1.1".parse().unwrap();
    let hops = parse_trace_output(target, SYNTHETIC_FIXTURE_MULTI_HOP_MIXED.as_bytes(), 30)
        .expect("다중 홉 파싱 실패");

    assert_eq!(hops.len(), 3);

    // 홉 1: 정상 응답
    assert_eq!(hops[0].ttl, 1);
    assert_eq!(hops[0].address.as_deref(), Some("10.0.0.1"));
    assert_eq!(hops[0].probe_times_ms, vec![Some(2), Some(1), Some(2)]);
    assert_eq!(hops[0].rtt_less_than, vec![false, false, false]);

    // 홉 2: 전면 타임아웃
    assert_eq!(hops[1].ttl, 2);
    assert_eq!(hops[1].address, None);
    assert_eq!(hops[1].probe_times_ms, vec![None, None, None]);
    assert_eq!(hops[1].rtt_less_than, vec![false, false, false]);

    // 홉 3: 일부 타임아웃 혼합
    assert_eq!(hops[2].ttl, 3);
    assert_eq!(hops[2].address.as_deref(), Some("192.168.1.1"));
    assert_eq!(hops[2].probe_times_ms, vec![Some(8), None, Some(9)]);
    assert_eq!(hops[2].rtt_less_than, vec![false, false, false]);
}

#[test]
fn test_synthetic_korean_timed_out_hop_parse() {
    let target: IpAddr = "8.8.8.8".parse().unwrap();
    let hops = parse_trace_output(
        target,
        SYNTHETIC_FIXTURE_KOREAN_TIMED_OUT_HOP.as_bytes(),
        30,
    )
    .expect("한국어 타임아웃 홉 파싱 실패");

    assert_eq!(hops.len(), 2);
    assert_eq!(hops[0].ttl, 1);
    assert_eq!(hops[0].address.as_deref(), Some("192.168.0.1"));

    assert_eq!(hops[1].ttl, 2);
    assert_eq!(hops[1].address, None);
    assert_eq!(hops[1].probe_times_ms, vec![None, None, None]);
}

#[test]
fn test_synthetic_ipv6_reached_parse() {
    let target: IpAddr = "::1".parse().unwrap();
    let hops = parse_trace_output(target, SYNTHETIC_FIXTURE_IPV6_REACHED.as_bytes(), 30)
        .expect("IPv6 정상 출력 파싱 실패");

    assert_eq!(hops.len(), 1);
    assert_eq!(hops[0].ttl, 1);
    assert_eq!(hops[0].address.as_deref(), Some("::1"));
    assert_eq!(hops[0].probe_times_ms, vec![Some(1), Some(1), Some(1)]);
    assert_eq!(hops[0].rtt_less_than, vec![true, true, true]);
}

#[test]
fn test_synthetic_parse_error_ttl_not_starting_at_one() {
    let target: IpAddr = "127.0.0.1".parse().unwrap();
    let bad_output = "  2    <1 ms    <1 ms    <1 ms  127.0.0.1\r\n";
    let res = parse_trace_output(target, bad_output.as_bytes(), 30);
    assert!(res.is_err(), "TTL이 1이 아닌 경우 파싱 거절되어야 함");
}

#[test]
fn test_synthetic_parse_error_ttl_duplicate() {
    let target: IpAddr = "127.0.0.1".parse().unwrap();
    let bad_output = "\
  1     1 ms     1 ms     1 ms  10.0.0.1\r\n\
  1     2 ms     2 ms     2 ms  127.0.0.1\r\n";
    let res = parse_trace_output(target, bad_output.as_bytes(), 30);
    assert!(res.is_err(), "중복된 TTL은 파싱 거절되어야 함");
}

#[test]
fn test_synthetic_parse_error_ttl_skip() {
    let target: IpAddr = "127.0.0.1".parse().unwrap();
    let bad_output = "\
  1     1 ms     1 ms     1 ms  10.0.0.1\r\n\
  3     2 ms     2 ms     2 ms  127.0.0.1\r\n";
    let res = parse_trace_output(target, bad_output.as_bytes(), 30);
    assert!(res.is_err(), "건너뛴 TTL 순서는 파싱 거절되어야 함");
}

#[test]
fn test_synthetic_parse_error_ttl_exceeds_max_hops() {
    let target: IpAddr = "127.0.0.1".parse().unwrap();
    let bad_output = "\
  1     1 ms     1 ms     1 ms  10.0.0.1\r\n\
  2     2 ms     2 ms     2 ms  127.0.0.1\r\n";
    let res = parse_trace_output(target, bad_output.as_bytes(), 1);
    assert!(res.is_err(), "max_hops를 초과한 TTL은 파싱 거절되어야 함");
}

#[test]
fn test_synthetic_parse_error_missing_probe_sample() {
    let target: IpAddr = "127.0.0.1".parse().unwrap();
    let bad_output = "  1     1 ms     1 ms  127.0.0.1\r\n";
    let res = parse_trace_output(target, bad_output.as_bytes(), 30);
    assert!(res.is_err(), "샘플 수가 3개 미만인 홉은 파싱 거절되어야 함");
}

#[test]
fn test_synthetic_parse_error_invalid_ip() {
    let target: IpAddr = "127.0.0.1".parse().unwrap();
    let bad_output = "  1     1 ms     1 ms     1 ms  999.999.999.999\r\n";
    let res = parse_trace_output(target, bad_output.as_bytes(), 30);
    assert!(res.is_err(), "유효하지 않은 IP 주소는 파싱 거절되어야 함");
}

#[test]
fn test_synthetic_parse_error_ip_version_mismatch() {
    let target_v4: IpAddr = "127.0.0.1".parse().unwrap();
    let v6_hop = "  1     1 ms     1 ms     1 ms  ::1\r\n";
    let res_v4 = parse_trace_output(target_v4, v6_hop.as_bytes(), 30);
    assert!(
        res_v4.is_err(),
        "IPv4 대상에 IPv6 홉이 등장하면 파싱 거절되어야 함"
    );

    let target_v6: IpAddr = "::1".parse().unwrap();
    let v4_hop = "  1     1 ms     1 ms     1 ms  10.0.0.1\r\n";
    let res_v6 = parse_trace_output(target_v6, v4_hop.as_bytes(), 30);
    assert!(
        res_v6.is_err(),
        "IPv6 대상에 IPv4 홉이 등장하면 파싱 거절되어야 함"
    );
}

#[test]
fn test_adapter_reached_to_quick_result() {
    let ctx = create_test_context("127.0.0.1");
    let raw = SYNTHETIC_FIXTURE_IPV4_ENGLISH_REACHED.as_bytes().to_vec();
    let hops =
        parse_trace_output("127.0.0.1".parse().unwrap(), &raw, 30).expect("합성 hop 파싱 실패");

    let measurement = TraceMeasurement {
        target: "127.0.0.1".to_string(),
        method: "ICMP_TRACERT".to_string(),
        outcome: "REACHED".to_string(),
        hops,
        elapsed_ms: 12,
        exit_code: Some(0),
        raw_stdout: raw,
        raw_stderr: Vec::new(),
        output_truncated: false,
        limitations: vec!["테스트 안내".to_string()],
    };

    let result = trace_to_quick_result(&ctx, &measurement).expect("어댑터 변환 실패");
    validate_quick_result(&result).expect("QuickResult 유효성 검증 실패");

    assert_eq!(result.status, QuickStatus::PASS);
    assert_eq!(result.evidence_level, EvidenceLevel::OBSERVED);
    assert_eq!(result.feature, QuickFeature::IcmpTraceroute);
    assert_eq!(result.resolved_ip.as_deref(), Some("127.0.0.1"));
    assert_eq!(result.elapsed_ms, Some(12));
    assert_eq!(result.os_error_code, None);
    assert_eq!(result.details["raw_measurement"]["exit_code"], 0);
    assert_eq!(result.details["outcome"], "REACHED");
}

#[test]
fn test_adapter_incomplete_with_valid_hops() {
    let ctx = create_test_context("192.168.1.1");
    let raw = SYNTHETIC_FIXTURE_MULTI_HOP_MIXED.as_bytes().to_vec();
    let hops =
        parse_trace_output("192.168.1.1".parse().unwrap(), &raw, 30).expect("다중 홉 파싱 실패");

    let measurement = TraceMeasurement {
        target: "192.168.1.1".to_string(),
        method: "ICMP_TRACERT".to_string(),
        outcome: "INCOMPLETE".to_string(),
        hops,
        elapsed_ms: 3000,
        exit_code: Some(0),
        raw_stdout: raw,
        raw_stderr: Vec::new(),
        output_truncated: false,
        limitations: Vec::new(),
    };

    let result = trace_to_quick_result(&ctx, &measurement).expect("어댑터 변환 실패");
    validate_quick_result(&result).expect("QuickResult 유효성 검증 실패");

    // 유효한 홉이 있으므로 WARN, OBSERVED
    assert_eq!(result.status, QuickStatus::WARN);
    assert_eq!(result.evidence_level, EvidenceLevel::OBSERVED);
}

#[test]
fn test_adapter_incomplete_without_valid_hops() {
    let ctx = create_test_context("192.168.1.1");
    let raw = b"  1     *        *        *     Request timed out.\r\n".to_vec();
    let hops = parse_trace_output("192.168.1.1".parse().unwrap(), &raw, 30)
        .expect("타임아웃 홉 파싱 실패");

    let measurement = TraceMeasurement {
        target: "192.168.1.1".to_string(),
        method: "ICMP_TRACERT".to_string(),
        outcome: "INCOMPLETE".to_string(),
        hops,
        elapsed_ms: 1000,
        exit_code: Some(0),
        raw_stdout: raw,
        raw_stderr: Vec::new(),
        output_truncated: false,
        limitations: Vec::new(),
    };

    let result = trace_to_quick_result(&ctx, &measurement).expect("어댑터 변환 실패");
    validate_quick_result(&result).expect("QuickResult 유효성 검증 실패");

    // 유효한 홉이 없으므로 UNKNOWN, UNKNOWN
    assert_eq!(result.status, QuickStatus::UNKNOWN);
    assert_eq!(result.evidence_level, EvidenceLevel::UNKNOWN);
}

#[test]
fn test_adapter_other_outcomes_mapping() {
    let other_outcomes = [
        "PARSE_ERROR",
        "TIMED_OUT",
        "CANCELLED",
        "LOCAL_ERROR",
        "UNAVAILABLE",
    ];

    for oc in other_outcomes {
        let ctx = create_test_context("127.0.0.1");
        let measurement = TraceMeasurement {
            target: "127.0.0.1".to_string(),
            method: "ICMP_TRACERT".to_string(),
            outcome: oc.to_string(),
            hops: Vec::new(),
            elapsed_ms: 50,
            exit_code: None,
            raw_stdout: Vec::new(),
            raw_stderr: Vec::new(),
            output_truncated: false,
            limitations: Vec::new(),
        };

        let result = trace_to_quick_result(&ctx, &measurement).expect("어댑터 변환 실패");
        assert_eq!(
            result.status,
            QuickStatus::UNKNOWN,
            "{oc} 상태는 UNKNOWN이어야 함"
        );
        assert_eq!(
            result.evidence_level,
            EvidenceLevel::UNKNOWN,
            "{oc} 근거수준은 UNKNOWN이어야 함"
        );
    }
}

#[test]
fn test_adapter_context_validation_failures() {
    let mut ctx = create_test_context("127.0.0.1");
    let measurement = TraceMeasurement {
        target: "127.0.0.1".to_string(),
        method: "ICMP_TRACERT".to_string(),
        outcome: "REACHED".to_string(),
        hops: Vec::new(),
        elapsed_ms: 10,
        exit_code: Some(0),
        raw_stdout: Vec::new(),
        raw_stderr: Vec::new(),
        output_truncated: false,
        limitations: Vec::new(),
    };

    // 포트 0 거절 검증
    ctx.target_port = 0;
    assert!(trace_to_quick_result(&ctx, &measurement).is_err());

    // 빈 session_id 거절 검증
    ctx.target_port = 80;
    ctx.session_id = "   ".to_string();
    assert!(trace_to_quick_result(&ctx, &measurement).is_err());

    // 대상 IP 불일치 거절 검증
    ctx.session_id = "test-session".to_string();
    ctx.target_host = "10.0.0.1".to_string(); // 측정 대상(127.0.0.1)과 불일치
    assert!(trace_to_quick_result(&ctx, &measurement).is_err());
}

#[test]
fn test_trace_once_parameter_validation_bounds() {
    let target: IpAddr = "127.0.0.1".parse().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));

    // max_hops 0 거절
    let opts1 = TraceOptions {
        max_hops: 0,
        ..Default::default()
    };
    let res1 = trace_once(target, &opts1, cancel.clone());
    assert_eq!(res1.outcome, "LOCAL_ERROR");

    // max_hops 31 거절 (상한 30)
    let opts2 = TraceOptions {
        max_hops: 31,
        ..Default::default()
    };
    let res2 = trace_once(target, &opts2, cancel.clone());
    assert_eq!(res2.outcome, "LOCAL_ERROR");

    // probe_timeout_ms 0 거절
    let opts3 = TraceOptions {
        probe_timeout_ms: 0,
        ..Default::default()
    };
    let res3 = trace_once(target, &opts3, cancel.clone());
    assert_eq!(res3.outcome, "LOCAL_ERROR");

    // probe_timeout_ms 2001 거절 (상한 2000)
    let opts4 = TraceOptions {
        probe_timeout_ms: 2001,
        ..Default::default()
    };
    let res4 = trace_once(target, &opts4, cancel.clone());
    assert_eq!(res4.outcome, "LOCAL_ERROR");

    // overall_timeout_ms 0 거절
    let opts5 = TraceOptions {
        overall_timeout_ms: 0,
        ..Default::default()
    };
    let res5 = trace_once(target, &opts5, cancel.clone());
    assert_eq!(res5.outcome, "LOCAL_ERROR");

    // overall_timeout_ms 60001 거절 (상한 60000)
    let opts6 = TraceOptions {
        overall_timeout_ms: 60001,
        ..Default::default()
    };
    let res6 = trace_once(target, &opts6, cancel.clone());
    assert_eq!(res6.outcome, "LOCAL_ERROR");
}

#[test]
fn test_trace_once_unsafe_ip_blocked() {
    let cancel = Arc::new(AtomicBool::new(false));
    let opts = TraceOptions::default();

    let unsafe_ips = [
        "0.0.0.0",         // IPv4 미지정
        "255.255.255.255", // IPv4 브로드캐스트
        "224.0.0.1",       // IPv4 멀티캐스트
        "169.254.1.1",     // IPv4 링크 로컬
        "::",              // IPv6 미지정
        "ff02::1",         // IPv6 멀티캐스트
        "fe80::1",         // IPv6 링크 로컬
    ];

    for ip_str in unsafe_ips {
        let ip: IpAddr = ip_str.parse().unwrap();
        let res = trace_once(ip, &opts, cancel.clone());
        assert_eq!(
            res.outcome, "LOCAL_ERROR",
            "안전하지 않은 IP({ip_str})는 LOCAL_ERROR로 거절되어야 함"
        );
        assert!(res.hops.is_empty());
    }
}

#[test]
fn test_trace_once_precancelled() {
    let target: IpAddr = "127.0.0.1".parse().unwrap();
    let cancel = Arc::new(AtomicBool::new(true)); // 사전 취소 상태
    let opts = TraceOptions::default();

    let res = trace_once(target, &opts, cancel);
    assert_eq!(res.outcome, "CANCELLED");
    assert_eq!(res.elapsed_ms, 0);
    assert!(res.hops.is_empty());
}

// =========================================================================
// QA 4P1+2P2 및 부모 경계 불변식 회귀 테스트 모음
// =========================================================================

#[test]
fn test_boundary_reached_without_target_hop_never_passes() {
    let ctx = create_test_context("127.0.0.1");
    let measurement = TraceMeasurement {
        target: "127.0.0.1".to_string(),
        method: "ICMP_TRACERT".to_string(),
        outcome: "REACHED".to_string(),
        hops: Vec::new(),
        elapsed_ms: 1,
        exit_code: Some(0),
        raw_stdout: Vec::new(),
        raw_stderr: Vec::new(),
        output_truncated: false,
        limitations: vec!["synthetic-only".to_string()],
    };
    let r = trace_to_quick_result(&ctx, &measurement);
    assert!(
        r.is_err() || r.unwrap().status != QuickStatus::PASS,
        "대상 응답 증거가 없는 REACHED를 PASS로 승격 금지"
    );
}

#[test]
fn test_boundary_invalid_raw_target_never_passes() {
    let ctx = create_test_context("127.0.0.1");
    let raw = SYNTHETIC_FIXTURE_IPV4_ENGLISH_REACHED.as_bytes().to_vec();
    let hops = parse_trace_output("127.0.0.1".parse().unwrap(), &raw, 30).unwrap();
    let measurement = TraceMeasurement {
        target: "not-an-ip".to_string(),
        method: "ICMP_TRACERT".to_string(),
        outcome: "REACHED".to_string(),
        hops,
        elapsed_ms: 12,
        exit_code: Some(0),
        raw_stdout: raw,
        raw_stderr: Vec::new(),
        output_truncated: false,
        limitations: Vec::new(),
    };
    let r = trace_to_quick_result(&ctx, &measurement);
    assert!(
        r.is_err() || r.unwrap().status != QuickStatus::PASS,
        "잘못된 대상 IP 문자열은 PASS로 승격 금지"
    );
}

#[test]
fn test_boundary_truncated_success_never_passes() {
    let ctx = create_test_context("127.0.0.1");
    let raw = SYNTHETIC_FIXTURE_IPV4_ENGLISH_REACHED.as_bytes().to_vec();
    let hops = parse_trace_output("127.0.0.1".parse().unwrap(), &raw, 30).unwrap();
    let measurement = TraceMeasurement {
        target: "127.0.0.1".to_string(),
        method: "ICMP_TRACERT".to_string(),
        outcome: "REACHED".to_string(),
        hops,
        elapsed_ms: 12,
        exit_code: Some(0),
        raw_stdout: raw,
        raw_stderr: Vec::new(),
        output_truncated: true,
        limitations: Vec::new(),
    };
    let r = trace_to_quick_result(&ctx, &measurement);
    assert!(
        r.is_err() || r.unwrap().status != QuickStatus::PASS,
        "출력이 절삭된 REACHED는 PASS로 승격 금지"
    );
}

#[test]
fn test_boundary_wrong_method_never_passes() {
    let ctx = create_test_context("127.0.0.1");
    let raw = SYNTHETIC_FIXTURE_IPV4_ENGLISH_REACHED.as_bytes().to_vec();
    let hops = parse_trace_output("127.0.0.1".parse().unwrap(), &raw, 30).unwrap();
    let measurement = TraceMeasurement {
        target: "127.0.0.1".to_string(),
        method: "TCP".to_string(),
        outcome: "REACHED".to_string(),
        hops,
        elapsed_ms: 12,
        exit_code: Some(0),
        raw_stdout: raw,
        raw_stderr: Vec::new(),
        output_truncated: false,
        limitations: Vec::new(),
    };
    let r = trace_to_quick_result(&ctx, &measurement);
    assert!(
        r.is_err() || r.unwrap().status != QuickStatus::PASS,
        "잘못된 method는 PASS로 승격 금지"
    );
}

#[test]
fn test_boundary_nonzero_exit_never_passes() {
    let ctx = create_test_context("127.0.0.1");
    let raw = SYNTHETIC_FIXTURE_IPV4_ENGLISH_REACHED.as_bytes().to_vec();
    let hops = parse_trace_output("127.0.0.1".parse().unwrap(), &raw, 30).unwrap();
    let measurement = TraceMeasurement {
        target: "127.0.0.1".to_string(),
        method: "ICMP_TRACERT".to_string(),
        outcome: "REACHED".to_string(),
        hops,
        elapsed_ms: 12,
        exit_code: Some(1),
        raw_stdout: raw,
        raw_stderr: Vec::new(),
        output_truncated: false,
        limitations: Vec::new(),
    };
    let r = trace_to_quick_result(&ctx, &measurement);
    assert!(
        r.is_err() || r.unwrap().status != QuickStatus::PASS,
        "비정상 종료 코드의 REACHED는 PASS로 승격 금지"
    );
}

#[test]
fn test_boundary_parser_missing_ms_units_is_rejected() {
    let target: IpAddr = "127.0.0.1".parse().unwrap();
    let res = parse_trace_output(target, b"1 1 2 3 127.0.0.1\r\n", 30);
    assert!(res.is_err(), "단위 없는 임의 숫자를 실측 RTT로 승격 금지");
}

#[test]
fn test_boundary_third_rtt_unit_is_required() {
    let target: IpAddr = "127.0.0.1".parse().unwrap();
    let res = parse_trace_output(target, b"1 10 ms 20 ms 30 127.0.0.1\n", 30);
    assert!(res.is_err(), "세 번째 RTT 단위가 누락되면 거절되어야 함");
}

#[test]
fn test_boundary_ttl_overflow_is_not_a_header() {
    let target: IpAddr = "127.0.0.1".parse().unwrap();
    let res = parse_trace_output(
        target,
        b"1 1 ms 1 ms 1 ms 127.0.0.1\n256 1 ms 1 ms 1 ms 10.0.0.1\n",
        30,
    );
    assert!(
        res.is_err(),
        "256 TTL 오버플로우는 헤더가 아니며 에러여야 함"
    );
}

#[test]
fn test_boundary_fourth_timeout_sample_is_rejected() {
    let target: IpAddr = "127.0.0.1".parse().unwrap();
    let res = parse_trace_output(target, b"1 * * * 1 ms 127.0.0.1\n", 30);
    assert!(
        res.is_err(),
        "전면 타임아웃 뒤 추가 샘플 및 IP는 거부되어야 함"
    );
}

#[test]
fn test_boundary_invalid_incomplete_hop_is_not_observed() {
    let ctx = create_test_context("127.0.0.1");
    let raw = SYNTHETIC_FIXTURE_IPV4_ENGLISH_REACHED.as_bytes().to_vec();
    let mut hops = parse_trace_output("127.0.0.1".parse().unwrap(), &raw, 30).unwrap();
    hops[0].address = Some(String::new()); // 빈 문자열 주소로 손상

    let measurement = TraceMeasurement {
        target: "127.0.0.1".to_string(),
        method: "ICMP_TRACERT".to_string(),
        outcome: "INCOMPLETE".to_string(),
        hops,
        elapsed_ms: 12,
        exit_code: Some(0),
        raw_stdout: raw,
        raw_stderr: Vec::new(),
        output_truncated: false,
        limitations: Vec::new(),
    };
    let r = trace_to_quick_result(&ctx, &measurement);
    assert!(
        r.is_err() || r.unwrap().evidence_level != EvidenceLevel::OBSERVED,
        "불량 주소를 가진 INCOMPLETE는 OBSERVED로 승격 금지"
    );
}

#[test]
fn test_boundary_ttl_plus_sign_rejected() {
    let target: IpAddr = "127.0.0.1".parse().unwrap();
    let res = parse_trace_output(target, b"+1 1 ms 1 ms 1 ms 127.0.0.1\n", 30);
    assert!(res.is_err(), "+ 부호가 포함된 TTL 토큰은 거부되어야 함");
}

#[test]
fn test_boundary_rtt_plus_sign_rejected() {
    let target: IpAddr = "127.0.0.1".parse().unwrap();
    let res = parse_trace_output(target, b"1 +1 ms 1 ms 1 ms 127.0.0.1\n", 30);
    assert!(res.is_err(), "+ 부호가 포함된 RTT 수치는 거부되어야 함");
}

#[test]
fn test_boundary_max_hops_range_validation() {
    let target: IpAddr = "127.0.0.1".parse().unwrap();
    assert!(parse_trace_output(target, b"1 1 ms 1 ms 1 ms 127.0.0.1\n", 0).is_err());
    assert!(parse_trace_output(target, b"1 1 ms 1 ms 1 ms 127.0.0.1\n", 31).is_err());
}

#[test]
fn test_boundary_raw_hops_mismatch_rejected() {
    let ctx = create_test_context("127.0.0.1");
    let measurement = TraceMeasurement {
        target: "127.0.0.1".to_string(),
        method: "ICMP_TRACERT".to_string(),
        outcome: "REACHED".to_string(),
        hops: vec![TraceHop {
            ttl: 1,
            address: Some("127.0.0.1".to_string()),
            probe_times_ms: vec![Some(1), Some(1), Some(1)],
            rtt_less_than: vec![true, true, true],
            raw_line: "1 1 ms 1 ms 1 ms 127.0.0.1".to_string(),
        }],
        elapsed_ms: 12,
        exit_code: Some(0),
        raw_stdout: b"Trace complete.".to_vec(), // 불일치 raw_stdout
        raw_stderr: Vec::new(),
        output_truncated: false,
        limitations: Vec::new(),
    };
    let r = trace_to_quick_result(&ctx, &measurement);
    assert!(
        r.is_err() || r.unwrap().status != QuickStatus::PASS,
        "raw_stdout과 hops가 불일치하는 REACHED는 PASS로 승격 금지"
    );
}

#[test]
fn test_boundary_negative_ttl_is_not_a_header() {
    let target: IpAddr = "127.0.0.1".parse().unwrap();
    let bad_output = b"1 1 ms 1 ms 1 ms 127.0.0.1\n-1 1 ms 1 ms 1 ms 10.0.0.1\n";
    let res = parse_trace_output(target, bad_output, 30);
    assert!(
        res.is_err(),
        "정상 도달 행 뒤에 붙은 음수 TTL(-1)은 안내문으로 무시되지 않고 거절되어야 함"
    );
}

#[test]
fn test_boundary_out_of_bound_negative_ttl_rejected() {
    let target: IpAddr = "127.0.0.1".parse().unwrap();
    let bad_output = b"1 1 ms 1 ms 1 ms 127.0.0.1\n-256 1 ms 1 ms 1 ms 10.0.0.1\n";
    let res = parse_trace_output(target, bad_output, 30);
    assert!(
        res.is_err(),
        "정상 도달 행 뒤에 붙은 범위 밖 음수 TTL(-256)은 안내문으로 무시되지 않고 거절되어야 함"
    );

    let bad_output_large = b"1 1 ms 1 ms 1 ms 127.0.0.1\n-99999 1 ms 1 ms 1 ms 10.0.0.1\n";
    let res_large = parse_trace_output(target, bad_output_large, 30);
    assert!(
        res_large.is_err(),
        "정상 도달 행 뒤에 붙은 큰 음수 TTL(-99999)은 안내문으로 무시되지 않고 거절되어야 함"
    );
}

#[test]
fn test_boundary_signed_positive_ttl_candidate_after_valid_hop_rejected() {
    let target: IpAddr = "127.0.0.1".parse().unwrap();
    let bad_output = b"1 1 ms 1 ms 1 ms 127.0.0.1\n+2 1 ms 1 ms 1 ms 10.0.0.1\n";
    let res = parse_trace_output(target, bad_output, 30);
    assert!(
        res.is_err(),
        "정상 도달 행 뒤에 붙은 +부호 TTL(+2)은 안내문으로 무시되지 않고 거절되어야 함"
    );

    let bad_output_overflow = b"1 1 ms 1 ms 1 ms 127.0.0.1\n+256 1 ms 1 ms 1 ms 10.0.0.1\n";
    let res_overflow = parse_trace_output(target, bad_output_overflow, 30);
    assert!(
        res_overflow.is_err(),
        "정상 도달 행 뒤에 붙은 +부호 오버플로우 TTL(+256)은 거절되어야 함"
    );
}

#[test]
fn test_boundary_terminal_drain_error_measurement_never_passes() {
    let ctx = create_test_context("127.0.0.1");
    let raw = SYNTHETIC_FIXTURE_IPV4_ENGLISH_REACHED.as_bytes().to_vec();
    let measurement = TraceMeasurement {
        target: "127.0.0.1".to_string(),
        method: "ICMP_TRACERT".to_string(),
        outcome: "LOCAL_ERROR".to_string(),
        hops: Vec::new(),
        elapsed_ms: 15,
        exit_code: Some(0),
        raw_stdout: raw,
        raw_stderr: Vec::new(),
        output_truncated: false,
        limitations: vec!["표준 출력 잔량 수집 중 오류 (코드 5): Access Denied".to_string()],
    };

    let r = trace_to_quick_result(&ctx, &measurement).expect("어댑터 변환은 유효한 결과 객체 생성");
    assert_ne!(
        r.status,
        QuickStatus::PASS,
        "최종 드레인 오류로 LOCAL_ERROR가 된 측정은 절대 PASS로 승격 금지"
    );
    assert_eq!(r.status, QuickStatus::UNKNOWN);
    assert_eq!(r.evidence_level, EvidenceLevel::UNKNOWN);
    assert_eq!(r.details["outcome"], "LOCAL_ERROR");
}

#[test]
fn test_boundary_job_assignment_failure_measurement_never_passes() {
    let ctx = create_test_context("127.0.0.1");
    let measurement = TraceMeasurement {
        target: "127.0.0.1".to_string(),
        method: "ICMP_TRACERT".to_string(),
        outcome: "LOCAL_ERROR".to_string(),
        hops: Vec::new(),
        elapsed_ms: 5,
        exit_code: None,
        raw_stdout: b"partial output".to_vec(),
        raw_stderr: b"partial err".to_vec(),
        output_truncated: false,
        limitations: vec!["자식 프로세스를 Job Object에 할당하는 데 실패했습니다.".to_string()],
    };

    let r = trace_to_quick_result(&ctx, &measurement).expect("어댑터 변환 성공");
    assert_ne!(r.status, QuickStatus::PASS);
    assert_eq!(r.status, QuickStatus::UNKNOWN);
    assert_eq!(r.evidence_level, EvidenceLevel::UNKNOWN);
}

/// 실제 소유 IPv4 루프백 통합 진단 시험.
///
/// 운영체제 기본 `tracert.exe` 프로세스를 실제로 실행하므로 기본 단위 시험에서는 무시(`#[ignore]`)되며,
/// 부모 통합 환경 검증 시에만 명시적으로 실행됩니다.
#[test]
#[ignore = "실제 OS tracert.exe 프로세스를 소유 실행하므로 부모 통합 검증에서만 수행됩니다."]
fn test_real_owned_loopback_ipv4() {
    let target: IpAddr = "127.0.0.1".parse().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let options = TraceOptions {
        max_hops: 1,
        probe_timeout_ms: 1000,
        overall_timeout_ms: 10000,
    };

    let measurement = trace_once(target, &options, cancel);

    #[cfg(windows)]
    {
        assert_eq!(measurement.method, "ICMP_TRACERT");
        assert_eq!(measurement.outcome, "REACHED");
        assert_eq!(measurement.hops.len(), 1);
        assert_eq!(measurement.hops[0].ttl, 1);
        assert_eq!(measurement.hops[0].address.as_deref(), Some("127.0.0.1"));
        assert!(!measurement.raw_stdout.is_empty());
    }

    #[cfg(not(windows))]
    {
        assert_eq!(measurement.outcome, "UNAVAILABLE");
    }
}

/// 실제 소유 IPv6 루프백 통합 진단 시험.
///
/// 운영체제 기본 `tracert.exe` 프로세스를 실제로 실행하므로 기본 단위 시험에서는 무시(`#[ignore]`)되며,
/// 부모 통합 환경 검증 시에만 명시적으로 실행됩니다.
#[test]
#[ignore = "실제 OS tracert.exe 프로세스를 소유 실행하므로 부모 통합 검증에서만 수행됩니다."]
fn test_real_owned_loopback_ipv6() {
    let target: IpAddr = "::1".parse().unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let options = TraceOptions {
        max_hops: 1,
        probe_timeout_ms: 1000,
        overall_timeout_ms: 10000,
    };

    let measurement = trace_once(target, &options, cancel);

    #[cfg(windows)]
    {
        assert_eq!(measurement.method, "ICMP_TRACERT");
        assert_eq!(measurement.outcome, "REACHED");
        assert_eq!(measurement.hops.len(), 1);
        assert_eq!(measurement.hops[0].ttl, 1);
        assert_eq!(measurement.hops[0].address.as_deref(), Some("::1"));
        assert!(!measurement.raw_stdout.is_empty());
    }

    #[cfg(not(windows))]
    {
        assert_eq!(measurement.outcome, "UNAVAILABLE");
    }
}
