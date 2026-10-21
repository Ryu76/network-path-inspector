//! Network Quick Check(Part B)를 위한 Windows native ICMP Traceroute 모듈.
//!
//! 이 모듈은 Windows 운영체제 기본 유틸리티인 `System32\tracert.exe`를 안전하게 소유 실행하고,
//! 표준 출력/표준 에러를 non-blocking 방식으로 수집하여 홉별 RTT 및 IP 경로를 파싱합니다.
//! 또한 진단 결과 DTO(`TraceMeasurement`)를 Quick Check 계약 결과(`QuickResult`)로 변환하는 순수 어댑터를 제공합니다.
//!
//! ## 핵심 안전 및 격리 원칙
//! - **절대 경로 단독 실행**: shell, cmd.exe, PowerShell, PATH 환경변수 탐색을 일체 배제하며,
//!   `GetSystemDirectoryW`를 통해 확인된 `System32\tracert.exe` 절대 경로만을 직접 실행합니다.
//! - **무창 및 프로세스 수명 관리 (Job Object)**:
//!   - `CREATE_NO_WINDOW` 플래그로 콘솔 창 생성을 억제합니다.
//!   - `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`가 설정된 전용 Win32 Job Object에 프로세스를 즉시 바인딩하여,
//!     타임아웃, 취소 또는 부모 비정상 종료 시 커널 레벨에서 자식 프로세스가 즉각 강제 종료(fail-closed)되도록 보장합니다.
//!   - Job Object 할당 실패 시 즉시 자식을 정리하고 `LOCAL_ERROR`를 반환하며 우회 재시도를 금지합니다.
//! - **버퍼 상한 및 비차단 폴링**:
//!   - 표준 출력 및 표준 에러는 각 32KiB(32768 바이트) 상한을 엄격히 적용하며 초과분은 절삭(truncated) 기록합니다.
//!   - `PeekNamedPipe`를 통한 비차단 가용량 검사 후 읽기를 수행하며, reader thread 무한 대기(join)를 배제합니다.
//! - **측정 사실·추론·확인 불가의 엄격한 분리**:
//!   - 패킷 캡처(PCAP) 근거 없는 SYN/RST 관찰 주장을 엄격히 금지합니다.
//!   - 응답 없는 홉(`* * *`)을 방화벽 차단 장비로 단정하지 않고 무응답 상태로만 기록합니다.
//! - **동결 계약(Frozen Contract) 준수**:
//!   - `quick-trace-contract.json` 및 PRD v1.2 요구사항을 정확히 준수합니다.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use serde::{Deserialize, Serialize};

use crate::quick::{
    EvidenceLevel, QUICK_PRODUCT_NAME, QUICK_SCHEMA_VERSION, QuickContext, QuickFeature,
    QuickResult, QuickStatus, validate_quick_result, validate_rfc3339_timestamp,
};

/// 표준 출력 및 표준 에러 버퍼 최대 상한 (각 32KiB = 32768 바이트).
pub const MAX_OUTPUT_BUFFER_BYTES: usize = 32768;

/// Traceroute 실행 옵션 DTO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceOptions {
    /// 최대 홉 수 (유효 범위: 1..=30).
    pub max_hops: u8,
    /// 홉당 프로브 대기 타임아웃 밀리초 (유효 범위: 1..=2000).
    pub probe_timeout_ms: u32,
    /// 전체 진단 상한 타임아웃 밀리초 (유효 범위: 1..=60000).
    pub overall_timeout_ms: u64,
}

impl Default for TraceOptions {
    fn default() -> Self {
        Self {
            max_hops: 30,
            probe_timeout_ms: 1000,
            overall_timeout_ms: 30000,
        }
    }
}

/// Traceroute 단일 홉 측정 결과 DTO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceHop {
    /// 홉 번호 (TTL, 1부터 순차 증가).
    pub ttl: u8,
    /// 관찰된 라우터/대상 IP 주소 문자열 (`None`인 경우 무응답).
    pub address: Option<String>,
    /// 3회 시도에 대한 RTT 측정값 밀리초 (`None`인 경우 타임아웃 `*`).
    pub probe_times_ms: Vec<Option<u32>>,
    /// 각 시도의 RTT가 1ms 미만(`<1 ms`)인지 여부 플래그.
    pub rtt_less_than: Vec<bool>,
    /// OS 유틸리티에서 출력된 원본 텍스트 행.
    pub raw_line: String,
}

/// Traceroute 전체 측정 결과 DTO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraceMeasurement {
    /// 검사 대상 IP 주소 문자열.
    pub target: String,
    /// 사용된 진단 방식 (고정: "ICMP_TRACERT").
    pub method: String,
    /// 측정 판정 결과 ("REACHED", "INCOMPLETE", "PARSE_ERROR", "TIMED_OUT", "CANCELLED", "LOCAL_ERROR", "UNAVAILABLE").
    pub outcome: String,
    /// 파싱된 홉별 결과 목록.
    pub hops: Vec<TraceHop>,
    /// 전체 측정 소요 시간 (밀리초, 실측치).
    pub elapsed_ms: u64,
    /// OS 프로세스 종료 코드 (`None`인 경우 미실행 또는 강제 종료).
    pub exit_code: Option<i32>,
    /// 원본 표준 출력 바이트 배열 (최대 32KiB).
    pub raw_stdout: Vec<u8>,
    /// 원본 표준 에러 바이트 배열 (최대 32KiB).
    pub raw_stderr: Vec<u8>,
    /// 출력 버퍼 한도 초과 절삭 발생 여부.
    pub output_truncated: bool,
    /// 측정상 한계 및 안전 안내 목록.
    pub limitations: Vec<String>,
}

/// 옵션 매개변수 유효성을 무보정 검증합니다.
fn validate_trace_options(options: &TraceOptions) -> Result<(), String> {
    if options.max_hops == 0 || options.max_hops > 30 {
        return Err(format!(
            "max_hops는 1..=30 범위여야 합니다 (현재: {}).",
            options.max_hops
        ));
    }
    if options.probe_timeout_ms == 0 || options.probe_timeout_ms > 2000 {
        return Err(format!(
            "probe_timeout_ms는 1..=2000 범위여야 합니다 (현재: {}).",
            options.probe_timeout_ms
        ));
    }
    if options.overall_timeout_ms == 0 || options.overall_timeout_ms > 60000 {
        return Err(format!(
            "overall_timeout_ms는 1..=60000 범위여야 합니다 (현재: {}).",
            options.overall_timeout_ms
        ));
    }
    Ok(())
}

/// 지정되지 않은 주소, 브로드캐스트, 멀티캐스트, 영역 없는 링크 로컬 등 안전하지 않은 대상을 차단합니다.
fn check_safe_ip(ip: IpAddr) -> Result<(), String> {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() {
                return Err("지정되지 않은 IPv4 주소(0.0.0.0)는 Traceroute 진단 대상으로 사용할 수 없습니다.".to_string());
            }
            if v4.is_broadcast() || v4.octets() == [255, 255, 255, 255] {
                return Err("브로드캐스트 IPv4 주소(255.255.255.255)는 Traceroute 진단 대상으로 사용할 수 없습니다.".to_string());
            }
            if v4.is_multicast() {
                return Err("멀티캐스트 IPv4 주소(224.0.0.0/4)는 Traceroute 진단 대상으로 사용할 수 없습니다.".to_string());
            }
            if v4.is_link_local() {
                return Err("영역 식별자가 없는 링크 로컬 IPv4 주소(169.254.0.0/16)는 Traceroute 진단 대상으로 사용할 수 없습니다.".to_string());
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() {
                return Err("지정되지 않은 IPv6 주소(::)는 Traceroute 진단 대상으로 사용할 수 없습니다.".to_string());
            }
            if v6.is_multicast() {
                return Err("멀티캐스트 IPv6 주소(ff00::/8)는 Traceroute 진단 대상으로 사용할 수 없습니다.".to_string());
            }
            // IPv6 링크 로컬 주소 (fe80::/10): std::net::IpAddr는 zone/scope id를 가질 수 없으므로 영역 없는 링크 로컬로 차단
            if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                return Err("영역 식별자(scope id)가 없는 링크 로컬 IPv6 주소(fe80::/10)는 Traceroute 진단 대상으로 사용할 수 없습니다.".to_string());
            }

            // IPv4 매핑된 IPv6 주소 (::ffff:a.b.c.d) 안전 검사
            let seg = v6.segments();
            if seg[0] == 0
                && seg[1] == 0
                && seg[2] == 0
                && seg[3] == 0
                && seg[4] == 0
                && seg[5] == 0xffff
            {
                let mapped_v4 = Ipv4Addr::new(
                    (seg[6] >> 8) as u8,
                    (seg[6] & 0xff) as u8,
                    (seg[7] >> 8) as u8,
                    (seg[7] & 0xff) as u8,
                );
                if mapped_v4.is_unspecified() {
                    return Err("IPv4 매핑된 IPv6의 미지정 주소(::ffff:0.0.0.0)는 Traceroute 진단 대상으로 사용할 수 없습니다.".to_string());
                }
                if mapped_v4.is_broadcast() || mapped_v4.octets() == [255, 255, 255, 255] {
                    return Err("IPv4 매핑된 IPv6의 브로드캐스트 주소(::ffff:255.255.255.255)는 Traceroute 진단 대상으로 사용할 수 없습니다.".to_string());
                }
                if mapped_v4.is_multicast() {
                    return Err("IPv4 매핑된 IPv6의 멀티캐스트 주소(::ffff:224.0.0.0/104)는 Traceroute 진단 대상으로 사용할 수 없습니다.".to_string());
                }
                if mapped_v4.is_link_local() {
                    return Err("IPv4 매핑된 IPv6의 링크 로컬 주소(::ffff:169.254.0.0/112)는 Traceroute 진단 대상으로 사용할 수 없습니다.".to_string());
                }
            }
        }
    }
    Ok(())
}

/// 토큰 시퀀스로부터 단일 RTT 샘플을 추출하는 헬퍼 함수.
///
/// `<1 ms`, `<1ms`, `< 1 ms`, `15 ms`, `15ms`, `*` 등 OS 유틸리티 출력의 다양한 공백 변종을 파싱합니다.
fn parse_rtt_sample(tokens: &[&str], idx: &mut usize) -> Result<(Option<u32>, bool), String> {
    if *idx >= tokens.len() {
        return Err("RTT 샘플 토큰이 부족합니다.".to_string());
    }
    let tok = tokens[*idx];
    if tok == "*" {
        *idx += 1;
        return Ok((None, false));
    }

    if tok == "<" {
        *idx += 1;
        if *idx >= tokens.len() {
            return Err("'<' 기호 뒤에 RTT 수치가 없습니다.".to_string());
        }
        let next_tok = tokens[*idx];
        let (num_str, has_ms) = if let Some(stripped) = next_tok.strip_suffix("ms") {
            (stripped, true)
        } else {
            (next_tok, false)
        };
        let val: u32 = num_str
            .parse()
            .map_err(|_| format!("'<' 뒤의 수치 파싱 실패: '{next_tok}'"))?;
        *idx += 1;
        if !has_ms && *idx < tokens.len() && tokens[*idx].eq_ignore_ascii_case("ms") {
            *idx += 1;
        }
        return Ok((Some(val), true));
    }

    if let Some(rest) = tok.strip_prefix('<') {
        let (num_str, has_ms) = if let Some(stripped) = rest.strip_suffix("ms") {
            (stripped, true)
        } else {
            (rest, false)
        };
        let val: u32 = num_str
            .parse()
            .map_err(|_| format!("'<' 뒤의 수치 파싱 실패: '{tok}'"))?;
        *idx += 1;
        if !has_ms && *idx < tokens.len() && tokens[*idx].eq_ignore_ascii_case("ms") {
            *idx += 1;
        }
        return Ok((Some(val), true));
    }

    let (num_str, has_ms) = if let Some(stripped) = tok.strip_suffix("ms") {
        (stripped, true)
    } else {
        (tok, false)
    };
    let val: u32 = num_str
        .parse()
        .map_err(|_| format!("RTT 수치 파싱 실패: '{tok}'"))?;
    *idx += 1;
    if !has_ms && *idx < tokens.len() && tokens[*idx].eq_ignore_ascii_case("ms") {
        *idx += 1;
    }
    Ok((Some(val), false))
}

/// OS tracert.exe의 표준 출력 바이트 배열을 파싱하여 홉별 측정 목록(`Vec<TraceHop>`)을 생성합니다.
///
/// ## 불변식 및 검증 규칙
/// 1. 로케일 독립적 숫자/IP 중심 파싱:
///    - 헤더 문구("Tracing route...", "최대 ... 경로 추적")나 완료 문자열("Trace complete", "추적을 완료했습니다")에
///      의존하여 성공 여부를 판정하지 않으며 비-숫자 헤더/안내문 행은 무시합니다.
/// 2. TTL 순서 및 유효성:
///    - TTL은 1부터 시작하여 1씩 순차적으로 증가해야 합니다.
///    - TTL 중복, 역전, 건너뜀, 0 또는 max_hops 초과 시 파싱 오류(`Err`)를 반환합니다.
/// 3. 샘플 및 RTT 상한:
///    - 각 홉 행은 정확히 3개의 RTT 샘플을 포함해야 합니다.
///    - `<1 ms`는 수치 `1`과 `rtt_less_than = true`로 표기하며, `*`는 `None`과 `rtt_less_than = false`로 표기합니다.
/// 4. 대상 IP 및 주소 일치:
///    - 응답이 있는 홉은 유효한 IP 주소를 포함해야 하며, 대상 IP(`target`)와 주소 체계(IPv4 vs IPv6)가 일치해야 합니다.
///    - IP 문자열 임의 trim/수리는 엄격히 금지됩니다.
/// 5. 부분 실패 격리:
///    - 오류 발생 시 부분 결과로 위장하지 않고 감지된 모든 파싱 에러를 반환합니다.
pub fn parse_trace_output(
    target: IpAddr,
    output: &[u8],
    max_hops: u8,
) -> Result<Vec<TraceHop>, Vec<String>> {
    let text = String::from_utf8_lossy(output);
    let mut hops: Vec<TraceHop> = Vec::new();
    let mut errors: Vec<String> = Vec::new();
    let mut expected_ttl: u8 = 1;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }

        // 첫 번째 토큰이 숫자가 아니면 헤더 또는 완료 안내 행이므로 건너뜁니다.
        let Ok(ttl) = tokens[0].parse::<u8>() else {
            continue;
        };

        // TTL 범위 검사
        if ttl == 0 || ttl > max_hops {
            errors.push(format!(
                "TTL({ttl})이 유효 범위(1..={max_hops})를 벗어났습니다."
            ));
            continue;
        }

        // TTL 순서 검사
        if ttl != expected_ttl {
            if ttl < expected_ttl {
                errors.push(format!("중복되거나 역전된 TTL({ttl})이 발견되었습니다."));
            } else {
                errors.push(format!(
                    "TTL 순서가 올바르지 않습니다 (기대치: {expected_ttl}, 관찰치: {ttl})."
                ));
            }
            continue;
        }

        // 3개의 RTT 샘플 파싱
        let mut idx = 1;
        let mut probe_times_ms = Vec::with_capacity(3);
        let mut rtt_less_than = Vec::with_capacity(3);
        let mut hop_err = false;

        for _ in 0..3 {
            match parse_rtt_sample(&tokens, &mut idx) {
                Ok((time_opt, less_than)) => {
                    probe_times_ms.push(time_opt);
                    rtt_less_than.push(less_than);
                }
                Err(err_msg) => {
                    errors.push(format!("TTL {ttl} 행 RTT 샘플 파싱 실패: {err_msg}"));
                    hop_err = true;
                    break;
                }
            }
        }

        if hop_err {
            continue;
        }

        // 주소 파싱
        let all_timed_out = probe_times_ms.iter().all(|t| t.is_none());
        let address = if all_timed_out {
            None
        } else {
            if idx >= tokens.len() {
                errors.push(format!(
                    "TTL {ttl} 행에 응답 샘플이 존재하나 대상 IP 주소가 누락되었습니다."
                ));
                continue;
            }
            let raw_addr = tokens[idx];
            match raw_addr.parse::<IpAddr>() {
                Ok(parsed_ip) => {
                    match (target, parsed_ip) {
                        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                            Some(parsed_ip.to_string())
                        }
                        _ => {
                            errors.push(format!(
                                "TTL {ttl} 행의 IP 버전({parsed_ip})이 대상 IP 버전({target})과 일치하지 않습니다."
                            ));
                            continue;
                        }
                    }
                }
                Err(_) => {
                    errors.push(format!(
                        "TTL {ttl} 행의 주소가 유효한 IP 형식이 아닙니다: '{raw_addr}'"
                    ));
                    continue;
                }
            }
        };

        hops.push(TraceHop {
            ttl,
            address,
            probe_times_ms,
            rtt_less_than,
            raw_line: line.to_string(),
        });

        expected_ttl = ttl + 1;
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    Ok(hops)
}

/// 공통 Traceroute 프로브 측정 결과(`TraceMeasurement`)를 Quick Check 계약 결과(`QuickResult`)로 변환합니다.
///
/// ## 매핑 규칙 및 불변식
/// 1. 컨텍스트 검증:
///    - session_id, target_host 필수값 및 포트(1..=65535), 타임스탬프 형식 검증.
/// 2. IP 일관성 검증 (교차 오염 방지):
///    - `measurement.target`의 IpAddr 파싱 성공 시 컨텍스트 `target_host`가 IP 리터럴인 경우 수치 비교 불일치를 차단합니다.
///    - 컨텍스트 `target_host`가 도메인인 경우 임의 DNS 조회 없이 실측 IP를 `resolved_ip`로 유도합니다.
/// 3. 상태 매핑:
///    - `REACHED` -> `(QuickStatus::PASS, EvidenceLevel::OBSERVED)`
///    - `INCOMPLETE` (유효 홉 존재 시) -> `(QuickStatus::WARN, EvidenceLevel::OBSERVED)`
///    - `INCOMPLETE` (유효 홉 부재 시) -> `(QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN)`
///    - `PARSE_ERROR` / `TIMED_OUT` / `CANCELLED` / `LOCAL_ERROR` / `UNAVAILABLE` -> `(QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN)`
///    - 알 수 없는 outcome -> `(QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN)`
/// 4. 세부 정보 보존:
///    - `details` 객체는 `outcome`, `limitations`, `raw_measurement`의 정확히 3개 필드로 구성합니다.
pub fn trace_to_quick_result(
    ctx: &QuickContext,
    measurement: &TraceMeasurement,
) -> Result<QuickResult, Vec<String>> {
    let mut errors = Vec::new();

    if ctx.session_id.trim().is_empty() {
        errors.push("session_id는 비어있을 수 없습니다.".to_string());
    }
    if ctx.target_host.trim().is_empty() {
        errors.push("target_host는 비어있을 수 없습니다.".to_string());
    }
    if ctx.target_port == 0 {
        errors.push("target_port는 0일 수 없습니다 (유효 범위: 1..=65535).".to_string());
    }
    if let Some(ts) = &ctx.timestamp_iso8601 {
        if ts.trim().is_empty() {
            errors.push("timestamp_iso8601는 비어있을 수 없습니다.".to_string());
        } else if let Err(err) = validate_rfc3339_timestamp(ts) {
            errors.push(format!("timestamp_iso8601 형식 오류: {err}"));
        }
    }
    if let Some(sh) = &ctx.source_host
        && sh.trim().is_empty()
    {
        errors.push("source_host는 비어있을 수 없습니다.".to_string());
    }

    let mut resolved_ip: Option<String> = None;
    if let Ok(parsed_ip) = measurement.target.parse::<IpAddr>() {
        resolved_ip = Some(parsed_ip.to_string());

        if let Ok(ctx_ip) = ctx.target_host.trim().parse::<IpAddr>()
            && parsed_ip != ctx_ip
        {
            errors.push(format!(
                "측정 대상 IP({parsed_ip})가 컨텍스트 대상 IP({ctx_ip})와 일치하지 않습니다 (IP 불일치 방지)."
            ));
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    let (status, evidence_level) = match measurement.outcome.as_str() {
        "REACHED" => (QuickStatus::PASS, EvidenceLevel::OBSERVED),
        "INCOMPLETE" => {
            let has_valid_hop = measurement.hops.iter().any(|h| h.address.is_some());
            if has_valid_hop {
                (QuickStatus::WARN, EvidenceLevel::OBSERVED)
            } else {
                (QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN)
            }
        }
        "PARSE_ERROR" | "TIMED_OUT" | "CANCELLED" | "LOCAL_ERROR" | "UNAVAILABLE" => {
            (QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN)
        }
        _ => (QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN),
    };

    let raw_measurement_val = serde_json::to_value(measurement)
        .map_err(|err| vec![format!("TraceMeasurement 직렬화 오류: {err}")])?;

    let details = serde_json::json!({
        "outcome": measurement.outcome,
        "limitations": measurement.limitations,
        "raw_measurement": raw_measurement_val,
    });

    let res = QuickResult {
        schema_version: QUICK_SCHEMA_VERSION.to_string(),
        product: QUICK_PRODUCT_NAME.to_string(),
        session_id: ctx.session_id.clone(),
        timestamp_iso8601: ctx.timestamp_iso8601.clone(),
        source_host: ctx.source_host.clone(),
        target_host: ctx.target_host.clone(),
        resolved_ip,
        target_port: ctx.target_port,
        feature: QuickFeature::IcmpTraceroute,
        status,
        elapsed_ms: Some(measurement.elapsed_ms),
        os_error_code: measurement.exit_code,
        details,
        evidence_level,
    };

    validate_quick_result(&res)?;
    Ok(res)
}

#[cfg(windows)]
mod native {
    use std::ffi::OsString;
    use std::io::Read;
    use std::net::IpAddr;
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::process::CommandExt;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::{
        CloseHandle, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

    use super::{
        MAX_OUTPUT_BUFFER_BYTES, TraceMeasurement, TraceOptions, parse_trace_output,
    };

    /// Win32 HANDLE에 대한 RAII 래퍼 구조체.
    struct SafeHandle(HANDLE);

    impl Drop for SafeHandle {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                unsafe {
                    CloseHandle(self.0);
                }
            }
        }
    }

    /// System32 디렉터리의 tracert.exe 절대 경로를 획득합니다.
    fn get_system32_tracert_path() -> Result<PathBuf, String> {
        let mut buf = [0u16; 260];
        let len = unsafe { GetSystemDirectoryW(buf.as_mut_ptr(), buf.len() as u32) };
        if len == 0 {
            return Err("GetSystemDirectoryW 호출 실패".to_string());
        }
        let sys_dir = if (len as usize) < buf.len() {
            OsString::from_wide(&buf[..len as usize])
        } else {
            let mut dyn_buf = vec![0u16; (len + 1) as usize];
            let dyn_len = unsafe { GetSystemDirectoryW(dyn_buf.as_mut_ptr(), dyn_buf.len() as u32) };
            if dyn_len == 0 || (dyn_len as usize) >= dyn_buf.len() {
                return Err("GetSystemDirectoryW 재시도 실패".to_string());
            }
            OsString::from_wide(&dyn_buf[..dyn_len as usize])
        };

        let path = PathBuf::from(sys_dir).join("tracert.exe");
        if !path.is_file() {
            return Err(format!("tracert.exe 파일을 찾을 수 없습니다: {}", path.display()));
        }
        Ok(path)
    }

    /// 프로세스 종료 시 커널 레벨에서 즉시 종료되는 Job Object를 생성합니다.
    fn create_kill_on_close_job() -> Result<SafeHandle, String> {
        let job = unsafe { CreateJobObjectW(std::ptr::null_mut(), std::ptr::null()) };
        if job.is_null() || job == INVALID_HANDLE_VALUE {
            return Err("CreateJobObjectW 호출 실패".to_string());
        }
        let safe_job = SafeHandle(job);

        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

        let res = unsafe {
            SetInformationJobObject(
                safe_job.0,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if res == 0 {
            return Err("SetInformationJobObject 호출 실패".to_string());
        }

        Ok(safe_job)
    }

    /// 파이프에서 현재 가용한 바이트 수를 확인합니다.
    fn peek_pipe_avail(handle: HANDLE) -> u32 {
        let mut avail: u32 = 0;
        let res = unsafe {
            PeekNamedPipe(
                handle,
                std::ptr::null_mut(),
                0,
                std::ptr::null_mut(),
                &mut avail,
                std::ptr::null_mut(),
            )
        };
        if res != 0 {
            avail
        } else {
            0
        }
    }

    /// 파이프에서 가용한 바이트를 읽어 버퍼에 추가합니다.
    fn drain_pipe_chunk<R: Read>(
        reader: &mut R,
        handle: HANDLE,
        buf: &mut Vec<u8>,
        max_bytes: usize,
        truncated: &mut bool,
    ) {
        let avail = peek_pipe_avail(handle);
        if avail > 0 {
            let to_read = (avail as usize).min(4096);
            let mut temp = vec![0u8; to_read];
            if let Ok(n) = reader.read(&mut temp)
                && n > 0
            {
                if buf.len() + n > max_bytes {
                    *truncated = true;
                    let remain = max_bytes.saturating_sub(buf.len());
                    if remain > 0 {
                        buf.extend_from_slice(&temp[..remain]);
                    }
                } else {
                    buf.extend_from_slice(&temp[..n]);
                }
            }
        }
    }

    /// 자식 프로세스 종료 후 남은 잔량 전체를 drain합니다.
    fn drain_pipe_all<R: Read>(
        reader: &mut R,
        buf: &mut Vec<u8>,
        max_bytes: usize,
        truncated: &mut bool,
    ) {
        let mut temp = [0u8; 4096];
        loop {
            match reader.read(&mut temp) {
                Ok(0) => break,
                Ok(n) => {
                    if buf.len() + n > max_bytes {
                        *truncated = true;
                        let remain = max_bytes.saturating_sub(buf.len());
                        if remain > 0 {
                            buf.extend_from_slice(&temp[..remain]);
                        }
                    } else {
                        buf.extend_from_slice(&temp[..n]);
                    }
                }
                Err(_) => break,
            }
        }
    }

    /// 자식 프로세스 kill 후 자원 회수를 상한 대기합니다.
    fn wait_child_cleanup(child: &mut Child, limitations: &mut Vec<String>) {
        let cleanup_start = Instant::now();
        let cleanup_timeout = Duration::from_millis(1000);
        while cleanup_start.elapsed() < cleanup_timeout {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(e) => {
                    limitations.push(format!("자식 프로세스 정리 확인 중 오류 발생: {e}"));
                    return;
                }
            }
        }
        limitations.push("프로세스 강제 종료 후 자식 프로세스 자원 회수 대기 시간이 초과되었습니다.".to_string());
    }

    /// Windows 환경에서 tracert.exe를 안전하게 소유 실행합니다.
    pub fn trace_native_windows(
        target: IpAddr,
        options: &TraceOptions,
        cancel: Arc<AtomicBool>,
    ) -> TraceMeasurement {
        let mut limitations = Vec::new();
        limitations.push("패킷 캡처 근거가 없으므로 무응답 홉을 차단 장비로 단정하지 않으며 SYN/RST 패킷 관찰을 주장하지 않습니다.".to_string());
        limitations.push("Windows anonymous pipe는 동기 핸들 특성상 엄격한 OS 하드 실시간 보장을 제공하지 않으며, PeekNamedPipe 기반 비차단 폴링으로 수집되었습니다.".to_string());

        let tracert_path = match get_system32_tracert_path() {
            Ok(p) => p,
            Err(e) => {
                limitations.push(e);
                return TraceMeasurement {
                    target: target.to_string(),
                    method: "ICMP_TRACERT".to_string(),
                    outcome: "UNAVAILABLE".to_string(),
                    hops: Vec::new(),
                    elapsed_ms: 0,
                    exit_code: None,
                    raw_stdout: Vec::new(),
                    raw_stderr: Vec::new(),
                    output_truncated: false,
                    limitations,
                };
            }
        };

        let job = match create_kill_on_close_job() {
            Ok(j) => j,
            Err(e) => {
                limitations.push(e);
                return TraceMeasurement {
                    target: target.to_string(),
                    method: "ICMP_TRACERT".to_string(),
                    outcome: "LOCAL_ERROR".to_string(),
                    hops: Vec::new(),
                    elapsed_ms: 0,
                    exit_code: None,
                    raw_stdout: Vec::new(),
                    raw_stderr: Vec::new(),
                    output_truncated: false,
                    limitations,
                };
            }
        };

        let mut cmd = Command::new(&tracert_path);
        cmd.creation_flags(CREATE_NO_WINDOW);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        cmd.arg("-d");
        match target {
            IpAddr::V4(_) => {
                cmd.arg("-4");
            }
            IpAddr::V6(_) => {
                cmd.arg("-6");
            }
        }
        cmd.arg("-h").arg(options.max_hops.to_string());
        cmd.arg("-w").arg(options.probe_timeout_ms.to_string());
        cmd.arg(target.to_string());

        let start = Instant::now();
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                limitations.push(format!("tracert.exe 프로세스 생성 실패: {e}"));
                return TraceMeasurement {
                    target: target.to_string(),
                    method: "ICMP_TRACERT".to_string(),
                    outcome: "LOCAL_ERROR".to_string(),
                    hops: Vec::new(),
                    elapsed_ms: start.elapsed().as_millis() as u64,
                    exit_code: None,
                    raw_stdout: Vec::new(),
                    raw_stderr: Vec::new(),
                    output_truncated: false,
                    limitations,
                };
            }
        };

        // 자식 프로세스를 즉시 Job Object에 할당 (fail-closed)
        let child_handle = child.as_raw_handle() as HANDLE;
        let assign_res = unsafe { AssignProcessToJobObject(job.0, child_handle) };
        if assign_res == 0 {
            let _ = child.kill();
            wait_child_cleanup(&mut child, &mut limitations);
            limitations.push("자식 프로세스를 Job Object에 할당하는 데 실패했습니다.".to_string());
            return TraceMeasurement {
                target: target.to_string(),
                method: "ICMP_TRACERT".to_string(),
                outcome: "LOCAL_ERROR".to_string(),
                hops: Vec::new(),
                elapsed_ms: start.elapsed().as_millis() as u64,
                exit_code: None,
                raw_stdout: Vec::new(),
                raw_stderr: Vec::new(),
                output_truncated: false,
                limitations,
            };
        }

        let mut child_stdout = child.stdout.take().expect("stdout pipe 확보 실패");
        let mut child_stderr = child.stderr.take().expect("stderr pipe 확보 실패");
        let stdout_h = child_stdout.as_raw_handle() as HANDLE;
        let stderr_h = child_stderr.as_raw_handle() as HANDLE;

        let mut raw_stdout = Vec::new();
        let mut raw_stderr = Vec::new();
        let mut output_truncated = false;
        let mut outcome_opt: Option<String> = None;
        let mut exit_code: Option<i32> = None;

        loop {
            let elapsed_ms = start.elapsed().as_millis() as u64;

            drain_pipe_chunk(
                &mut child_stdout,
                stdout_h,
                &mut raw_stdout,
                MAX_OUTPUT_BUFFER_BYTES,
                &mut output_truncated,
            );
            drain_pipe_chunk(
                &mut child_stderr,
                stderr_h,
                &mut raw_stderr,
                MAX_OUTPUT_BUFFER_BYTES,
                &mut output_truncated,
            );

            // 취소 확인
            if cancel.load(Ordering::Relaxed) {
                let _ = child.kill();
                wait_child_cleanup(&mut child, &mut limitations);
                outcome_opt = Some("CANCELLED".to_string());
                break;
            }

            // 전체 타임아웃 확인
            if elapsed_ms >= options.overall_timeout_ms {
                let _ = child.kill();
                wait_child_cleanup(&mut child, &mut limitations);
                outcome_opt = Some("TIMED_OUT".to_string());
                break;
            }

            // 자식 프로세스 상태 확인
            match child.try_wait() {
                Ok(Some(status)) => {
                    exit_code = status.code();
                    drain_pipe_all(
                        &mut child_stdout,
                        &mut raw_stdout,
                        MAX_OUTPUT_BUFFER_BYTES,
                        &mut output_truncated,
                    );
                    drain_pipe_all(
                        &mut child_stderr,
                        &mut raw_stderr,
                        MAX_OUTPUT_BUFFER_BYTES,
                        &mut output_truncated,
                    );
                    break;
                }
                Ok(None) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    let _ = child.kill();
                    wait_child_cleanup(&mut child, &mut limitations);
                    outcome_opt = Some("LOCAL_ERROR".to_string());
                    limitations.push(format!("자식 프로세스 상태 폴링 중 오류: {e}"));
                    break;
                }
            }
        }

        let elapsed_ms = start.elapsed().as_millis() as u64;

        if output_truncated {
            limitations.push("표준 출력 또는 표준 에러 버퍼가 32KiB 한도를 초과하여 절삭되었습니다.".to_string());
        }

        let (outcome, hops) = if let Some(preset_outcome) = outcome_opt {
            (preset_outcome, Vec::new())
        } else {
            match parse_trace_output(target, &raw_stdout, options.max_hops) {
                Ok(parsed_hops) => {
                    let reached = parsed_hops
                        .last()
                        .and_then(|h| h.address.as_deref())
                        .and_then(|s| s.parse::<IpAddr>().ok())
                        == Some(target);
                    let oc = if reached {
                        "REACHED".to_string()
                    } else {
                        "INCOMPLETE".to_string()
                    };
                    (oc, parsed_hops)
                }
                Err(parse_errors) => {
                    for pe in parse_errors {
                        limitations.push(format!("파싱 오류: {pe}"));
                    }
                    ("PARSE_ERROR".to_string(), Vec::new())
                }
            }
        };

        TraceMeasurement {
            target: target.to_string(),
            method: "ICMP_TRACERT".to_string(),
            outcome,
            hops,
            elapsed_ms,
            exit_code,
            raw_stdout,
            raw_stderr,
            output_truncated,
            limitations,
        }
    }
}

/// 단일 대상 IP에 대해 ICMP Traceroute 진단을 실행합니다.
///
/// ## 안전 및 거절 원칙
/// 1. 사전 취소 확인:
///    - 호출 시점에 이미 `cancel` 플래그가 설정되어 있다면 프로세스를 일체 생성하지 않고(`spawn0`)
///      `outcome = "CANCELLED"` 결과를 즉시 반환합니다.
/// 2. 옵션 범위 무보정 검증:
///    - max_hops(1..=30), probe_timeout_ms(1..=2000), overall_timeout_ms(1..=60000) 범위를
///      벗어나는 경우 자동 보정 없이 `outcome = "LOCAL_ERROR"`로 즉시 거절합니다.
/// 3. 위험한 대상 IP 차단:
///    - 지정되지 않은 주소(0.0.0.0, ::), 브로드캐스트, 멀티캐스트, 영역 없는 링크 로컬 주소는
///      프로세스 생성 없이 `outcome = "LOCAL_ERROR"`로 즉시 거절합니다.
/// 4. 운영체제 분기:
///    - Windows 환경에서는 네이티브 `tracert.exe`를 안전하게 소유 실행합니다.
///    - 비-Windows 환경에서는 프로세스 생성 없이 `outcome = "UNAVAILABLE"`로 명시 반환합니다.
pub fn trace_once(
    target: IpAddr,
    options: &TraceOptions,
    cancel: Arc<AtomicBool>,
) -> TraceMeasurement {
    // 1. 사전 취소 확인 (spawn0)
    if cancel.load(Ordering::Relaxed) {
        return TraceMeasurement {
            target: target.to_string(),
            method: "ICMP_TRACERT".to_string(),
            outcome: "CANCELLED".to_string(),
            hops: Vec::new(),
            elapsed_ms: 0,
            exit_code: None,
            raw_stdout: Vec::new(),
            raw_stderr: Vec::new(),
            output_truncated: false,
            limitations: vec!["진단 시작 전 취소 요청이 감지되었습니다.".to_string()],
        };
    }

    // 2. 옵션 검증 (spawn0)
    if let Err(opt_err) = validate_trace_options(options) {
        return TraceMeasurement {
            target: target.to_string(),
            method: "ICMP_TRACERT".to_string(),
            outcome: "LOCAL_ERROR".to_string(),
            hops: Vec::new(),
            elapsed_ms: 0,
            exit_code: None,
            raw_stdout: Vec::new(),
            raw_stderr: Vec::new(),
            output_truncated: false,
            limitations: vec![opt_err],
        };
    }

    // 3. 안전하지 않은 대상 IP 차단 (spawn0)
    if let Err(safe_err) = check_safe_ip(target) {
        return TraceMeasurement {
            target: target.to_string(),
            method: "ICMP_TRACERT".to_string(),
            outcome: "LOCAL_ERROR".to_string(),
            hops: Vec::new(),
            elapsed_ms: 0,
            exit_code: None,
            raw_stdout: Vec::new(),
            raw_stderr: Vec::new(),
            output_truncated: false,
            limitations: vec![safe_err],
        };
    }

    // 4. 운영체제별 실행
    #[cfg(windows)]
    {
        native::trace_native_windows(target, options, cancel)
    }

    #[cfg(not(windows))]
    {
        let _ = cancel;
        TraceMeasurement {
            target: target.to_string(),
            method: "ICMP_TRACERT".to_string(),
            outcome: "UNAVAILABLE".to_string(),
            hops: Vec::new(),
            elapsed_ms: 0,
            exit_code: None,
            raw_stdout: Vec::new(),
            raw_stderr: Vec::new(),
            output_truncated: false,
            limitations: vec!["비-Windows 운영체제에서는 네이티브 tracert.exe 유틸리티가 지원되지 않습니다.".to_string()],
        }
    }
}
