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
//!   - `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`를 설정하여 핸들 종료 시 커널 레벨에서 프로세스 종료를 요청합니다.
//!     단, OS 스케줄링 및 파이프 상태에 따라 즉각 종료가 완료되지 않을 수 있으므로 명시적 자원 회수 대기를 병행합니다.
//!   - Job Object 할당 실패 시 즉시 자식을 정리하고 `LOCAL_ERROR`를 반환하며 우회 재시도를 금지합니다.
//! - **버퍼 상한 및 비차단 폴링**:
//!   - 표준 출력 및 표준 에러는 각 32KiB(32768 바이트) 상한을 엄격히 적용하며 초과분은 절삭(truncated) 기록합니다.
//!   - Windows anonymous pipe는 동기 핸들 특성상 엄격한 하드 실시간 보장을 제공하지 않으며,
//!     `PeekNamedPipe` 가용량 검사 기반 비차단 폴링 방식으로 수집합니다. reader thread 무한 대기(join)를 배제합니다.
//! - **측정 사실·추론·확인 불가의 엄격한 분리**:
//!   - 패킷 캡처(PCAP) 근거 없는 SYN/RST 관찰 주장을 엄격히 금지합니다.
//!   - 응답 없는 홉(`* * *`)을 방화벽 차단 장비로 단정하지 않고 무응답 상태로만 기록합니다.
//! - **동결 계약(Frozen Contract) 준수**:
//!   - `quick-trace-contract.json` 및 PRD v1.2 요구사항을 정확히 준수합니다.

use std::net::{IpAddr, Ipv4Addr};
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
                return Err(
                    "지정되지 않은 IPv6 주소(::)는 Traceroute 진단 대상으로 사용할 수 없습니다."
                        .to_string(),
                );
            }
            if v6.is_multicast() {
                return Err(
                    "멀티캐스트 IPv6 주소(ff00::/8)는 Traceroute 진단 대상으로 사용할 수 없습니다."
                        .to_string(),
                );
            }
            if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                return Err("영역 식별자(scope id)가 없는 링크 로컬 IPv6 주소(fe80::/10)는 Traceroute 진단 대상으로 사용할 수 없습니다.".to_string());
            }

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

/// 파이프 폴링 및 읽기를 위한 내부 추상화 상태 열거형.
#[derive(Debug, PartialEq, Eq)]
enum PipeStatus {
    Data(usize),
    Eof,
    Error(u32, String),
}

/// 비차단 파이프 수집을 위한 내부 추상화 트레이트.
trait PipeCollector {
    fn check_avail(&mut self) -> PipeStatus;
    fn read_bytes(&mut self, buf: &mut [u8]) -> std::io::Result<usize>;
}

/// 파이프에서 가용한 바이트를 비차단으로 수집합니다.
fn collect_from_pipe<P: PipeCollector>(
    pipe: &mut P,
    buf: &mut Vec<u8>,
    max_bytes: usize,
    truncated: &mut bool,
) -> Result<(), (Option<i64>, String)> {
    match pipe.check_avail() {
        PipeStatus::Data(avail) => {
            if avail > 0 {
                let to_read = avail.min(4096);
                let mut temp = vec![0u8; to_read];
                match pipe.read_bytes(&mut temp) {
                    Ok(0) => Ok(()),
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
                        Ok(())
                    }
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::BrokenPipe {
                            Ok(())
                        } else {
                            Err((
                                e.raw_os_error().map(i64::from),
                                format!("파이프 읽기 오류: {e}"),
                            ))
                        }
                    }
                }
            } else {
                Ok(())
            }
        }
        PipeStatus::Eof => Ok(()),
        PipeStatus::Error(code, msg) => Err((Some(i64::from(code)), msg)),
    }
}

/// 파이프의 남은 가용 데이터를 상한 횟수 내에서 안전하게 수집합니다.
fn drain_pipe_limited<P: PipeCollector>(
    pipe: &mut P,
    buf: &mut Vec<u8>,
    max_bytes: usize,
    truncated: &mut bool,
    max_rounds: usize,
) -> Result<bool, (Option<i64>, String)> {
    for _ in 0..max_rounds {
        match pipe.check_avail() {
            PipeStatus::Data(avail) if avail > 0 => {
                let to_read = avail.min(4096);
                let mut temp = vec![0u8; to_read];
                match pipe.read_bytes(&mut temp) {
                    Ok(0) => return Ok(true),
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
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::BrokenPipe {
                            return Ok(true);
                        } else {
                            return Err((
                                e.raw_os_error().map(i64::from),
                                format!("잔량 파이프 읽기 오류: {e}"),
                            ));
                        }
                    }
                }
            }
            PipeStatus::Data(_) => return Ok(true),
            PipeStatus::Eof => return Ok(true),
            PipeStatus::Error(code, msg) => return Err((Some(i64::from(code)), msg)),
        }
    }
    Ok(false)
}

/// 양쪽 파이프의 남은 가용 데이터를 상한 내에서 드레인하고 발생한 오류나 상한 미수집을 outcome 및 limitations에 반영합니다.
fn drain_pipes_and_evaluate<P1: PipeCollector, P2: PipeCollector>(
    stdout_pipe: &mut P1,
    stderr_pipe: &mut P2,
    raw_stdout: &mut Vec<u8>,
    raw_stderr: &mut Vec<u8>,
    output_truncated: &mut bool,
    outcome_opt: &mut Option<String>,
    limitations: &mut Vec<String>,
) {
    match drain_pipe_limited(
        stdout_pipe,
        raw_stdout,
        MAX_OUTPUT_BUFFER_BYTES,
        output_truncated,
        10,
    ) {
        Ok(true) => {}
        Ok(false) => {
            limitations.push(
                "표준 출력 파이프 가용 잔량을 완전히 수집하지 못했습니다 (상한 도달).".to_string(),
            );
            if outcome_opt.is_none() {
                *outcome_opt = Some("LOCAL_ERROR".to_string());
            }
        }
        Err((code, msg)) => {
            limitations.push(format!(
                "표준 출력 잔량 수집 중 오류 (코드 {}): {msg}",
                code.map_or_else(|| "미확인".to_string(), |value| value.to_string())
            ));
            if outcome_opt.is_none() {
                *outcome_opt = Some("LOCAL_ERROR".to_string());
            }
        }
    }

    match drain_pipe_limited(
        stderr_pipe,
        raw_stderr,
        MAX_OUTPUT_BUFFER_BYTES,
        output_truncated,
        10,
    ) {
        Ok(true) => {}
        Ok(false) => {
            limitations.push(
                "표준 에러 파이프 가용 잔량을 완전히 수집하지 못했습니다 (상한 도달).".to_string(),
            );
            if outcome_opt.is_none() {
                *outcome_opt = Some("LOCAL_ERROR".to_string());
            }
        }
        Err((code, msg)) => {
            limitations.push(format!(
                "표준 에러 잔량 수집 중 오류 (코드 {}): {msg}",
                code.map_or_else(|| "미확인".to_string(), |value| value.to_string())
            ));
            if outcome_opt.is_none() {
                *outcome_opt = Some("LOCAL_ERROR".to_string());
            }
        }
    }
}

/// 양쪽 파이프 드레인과 상태 평가를 거쳐 최종 TraceMeasurement를 구성하는 공통 종결 헬퍼.
fn finalize_trace_measurement<P1: PipeCollector, P2: PipeCollector>(
    target: IpAddr,
    max_hops: u8,
    exit_code: Option<i32>,
    elapsed_ms: u64,
    pipes: (&mut P1, &mut P2),
    buffers: (&mut Vec<u8>, &mut Vec<u8>, &mut bool),
    state: (&mut Option<String>, &mut Vec<String>),
) -> TraceMeasurement {
    let (stdout_pipe, stderr_pipe) = pipes;
    let (raw_stdout, raw_stderr, output_truncated) = buffers;
    let (outcome_opt, limitations) = state;

    drain_pipes_and_evaluate(
        stdout_pipe,
        stderr_pipe,
        raw_stdout,
        raw_stderr,
        output_truncated,
        outcome_opt,
        limitations,
    );

    let (outcome, hops) = evaluate_trace_outcome(
        target,
        max_hops,
        exit_code,
        *output_truncated,
        outcome_opt.clone(),
        raw_stdout,
        limitations,
    );

    TraceMeasurement {
        target: target.to_string(),
        method: "ICMP_TRACERT".to_string(),
        outcome,
        hops,
        elapsed_ms,
        exit_code,
        raw_stdout: raw_stdout.clone(),
        raw_stderr: raw_stderr.clone(),
        output_truncated: *output_truncated,
        limitations: limitations.clone(),
    }
}

/// 토큰 시퀀스로부터 단일 RTT 샘플을 추출하는 헬퍼 함수.
///
/// `<1 ms`, `<1ms`, `< 1 ms`, `15 ms`, `15ms`, `*` 등 OS 유틸리티 출력의 공백 변종을 파싱합니다.
/// `ms` 단위가 없거나 `+` 부호가 포함된 경우 거부합니다.
fn parse_rtt_sample(tokens: &[&str], idx: &mut usize) -> Result<(Option<u32>, bool), String> {
    if *idx >= tokens.len() {
        return Err("RTT 샘플 토큰이 부족합니다.".to_string());
    }
    let tok = tokens[*idx];

    // 무응답 타임아웃 토큰
    if tok == "*" {
        *idx += 1;
        return Ok((None, false));
    }

    // 독립된 '<' 기호
    if tok == "<" {
        *idx += 1;
        if *idx >= tokens.len() {
            return Err("'<' 기호 뒤에 RTT 수치가 없습니다.".to_string());
        }
        let next_tok = tokens[*idx];
        if next_tok.starts_with('+') {
            return Err("RTT 수치에 '+' 부호는 허용되지 않습니다.".to_string());
        }

        if let Some(stripped) = next_tok.strip_suffix("ms") {
            if stripped.is_empty() || !stripped.chars().all(|c| c.is_ascii_digit()) {
                return Err(format!("'<' 뒤의 수치 파싱 실패: '{next_tok}'"));
            }
            let val: u32 = stripped
                .parse()
                .map_err(|_| format!("'<' 뒤의 수치 파싱 실패: '{next_tok}'"))?;
            *idx += 1;
            return Ok((Some(val), true));
        }

        if next_tok.is_empty() || !next_tok.chars().all(|c| c.is_ascii_digit()) {
            return Err(format!("'<' 뒤의 수치 파싱 실패: '{next_tok}'"));
        }
        let val: u32 = next_tok
            .parse()
            .map_err(|_| format!("'<' 뒤의 수치 파싱 실패: '{next_tok}'"))?;
        *idx += 1;

        if *idx >= tokens.len() || !tokens[*idx].eq_ignore_ascii_case("ms") {
            return Err("RTT 수치 뒤에 필수 'ms' 단위가 누락되었습니다.".to_string());
        }
        *idx += 1;
        return Ok((Some(val), true));
    }

    // 접두사 '<'가 결합된 형태
    if let Some(rest) = tok.strip_prefix('<') {
        if rest.starts_with('+') {
            return Err("RTT 수치에 '+' 부호는 허용되지 않습니다.".to_string());
        }

        if let Some(stripped) = rest.strip_suffix("ms") {
            if stripped.is_empty() || !stripped.chars().all(|c| c.is_ascii_digit()) {
                return Err(format!("'<' 뒤의 수치 파싱 실패: '{tok}'"));
            }
            let val: u32 = stripped
                .parse()
                .map_err(|_| format!("'<' 뒤의 수치 파싱 실패: '{tok}'"))?;
            *idx += 1;
            return Ok((Some(val), true));
        }

        if rest.is_empty() || !rest.chars().all(|c| c.is_ascii_digit()) {
            return Err(format!("'<' 뒤의 수치 파싱 실패: '{tok}'"));
        }
        let val: u32 = rest
            .parse()
            .map_err(|_| format!("'<' 뒤의 수치 파싱 실패: '{tok}'"))?;
        *idx += 1;

        if *idx >= tokens.len() || !tokens[*idx].eq_ignore_ascii_case("ms") {
            return Err("RTT 수치 뒤에 필수 'ms' 단위가 누락되었습니다.".to_string());
        }
        *idx += 1;
        return Ok((Some(val), true));
    }

    // 일반 숫자 RTT 형태
    if tok.starts_with('+') {
        return Err("RTT 수치에 '+' 부호는 허용되지 않습니다.".to_string());
    }

    if let Some(stripped) = tok.strip_suffix("ms") {
        if stripped.is_empty() || !stripped.chars().all(|c| c.is_ascii_digit()) {
            return Err(format!("RTT 수치 파싱 실패: '{tok}'"));
        }
        let val: u32 = stripped
            .parse()
            .map_err(|_| format!("RTT 수치 파싱 실패: '{tok}'"))?;
        *idx += 1;
        return Ok((Some(val), false));
    }

    if tok.is_empty() || !tok.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("RTT 수치 형식이 올바르지 않습니다: '{tok}'"));
    }
    let val: u32 = tok
        .parse()
        .map_err(|_| format!("RTT 수치 파싱 실패: '{tok}'"))?;
    *idx += 1;

    if *idx >= tokens.len() || !tokens[*idx].eq_ignore_ascii_case("ms") {
        return Err(format!(
            "RTT 수치('{tok}') 뒤에 필수 'ms' 단위가 누락되었습니다."
        ));
    }
    *idx += 1;
    Ok((Some(val), false))
}

/// OS tracert.exe의 표준 출력 바이트 배열을 파싱하여 홉별 측정 목록(`Vec<TraceHop>`)을 생성합니다.
///
/// ## 불변식 및 검증 규칙
/// 1. 첫 토큰의 숫자 형태와 u8 범위 분리:
///    - 첫 토큰이 ASCII 숫자인 경우 TTL 행으로 식별하며, 256 등 8비트 정수 범위를 초과하면
///      헤더로 건너뛰지 않고 명확한 파싱 오류(`Err`)로 거절합니다.
///    - `max_hops`(1..=30) 범위를 엄격히 검사합니다.
/// 2. RTT 단위 필수:
///    - 각 RTT는 `ms` 단위가 필수이며, `+` 부호 수리를 금지합니다.
/// 3. 정확히 3샘플 유지 및 후행 잉여 거부:
///    - 전면 타임아웃(`* * *`) 뒤 추가 RTT 샘플이나 IP 주소 출현을 거부합니다.
///    - 응답 홉 뒤 3개 초과의 샘플이나 임의 숫자 출현을 거부합니다.
pub fn parse_trace_output(
    target: IpAddr,
    output: &[u8],
    max_hops: u8,
) -> Result<Vec<TraceHop>, Vec<String>> {
    let mut errors: Vec<String> = Vec::new();

    if max_hops == 0 || max_hops > 30 {
        return Err(vec![format!(
            "max_hops는 1..=30 범위여야 합니다 (현재: {max_hops})."
        )]);
    }

    let text = String::from_utf8_lossy(output);
    let mut hops: Vec<TraceHop> = Vec::new();
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

        let first_tok = tokens[0];

        // 음수 및 부호 숫자 후보를 명백한 hop 오류로 감지하고 안내문으로 건너뛰지 않음
        if first_tok.starts_with('-')
            && first_tok.len() > 1
            && first_tok[1..].chars().all(|c| c.is_ascii_digit())
        {
            errors.push(format!(
                "TTL 수치에 음수는 허용되지 않습니다: '{first_tok}'"
            ));
            continue;
        }

        if first_tok.starts_with('+')
            && first_tok.len() > 1
            && first_tok[1..].chars().all(|c| c.is_ascii_digit())
        {
            errors.push(format!(
                "TTL 수치에 '+' 부호는 허용되지 않습니다: '{first_tok}'"
            ));
            continue;
        }

        let is_numeric = !first_tok.is_empty() && first_tok.chars().all(|c| c.is_ascii_digit());
        if !is_numeric {
            continue;
        }

        let ttl = match first_tok.parse::<u8>() {
            Ok(v) => v,
            Err(_) => {
                errors.push(format!(
                    "TTL 수치가 8비트 정수 범위를 초과했습니다: '{first_tok}'"
                ));
                continue;
            }
        };

        if ttl == 0 || ttl > max_hops {
            errors.push(format!(
                "TTL({ttl})이 유효 범위(1..={max_hops})를 벗어났습니다."
            ));
            continue;
        }

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

        let mut idx = 1;
        let mut probe_times_ms = Vec::with_capacity(3);
        let mut rtt_less_than = Vec::with_capacity(3);
        let mut sample_err = false;

        for _ in 0..3 {
            match parse_rtt_sample(&tokens, &mut idx) {
                Ok((val_opt, less_than)) => {
                    probe_times_ms.push(val_opt);
                    rtt_less_than.push(less_than);
                }
                Err(err_msg) => {
                    errors.push(format!("TTL {ttl} 행 RTT 샘플 파싱 실패: {err_msg}"));
                    sample_err = true;
                    break;
                }
            }
        }

        if sample_err {
            continue;
        }

        let all_timed_out = probe_times_ms.iter().all(|t| t.is_none());
        let rest_tokens = &tokens[idx..];

        let address = if all_timed_out {
            let mut invalid_tail = false;
            for &tok in rest_tokens {
                if tok == "*"
                    || tok == "<"
                    || tok.starts_with('<')
                    || tok.eq_ignore_ascii_case("ms")
                    || tok.parse::<IpAddr>().is_ok()
                    || tok.chars().any(|c| c.is_ascii_digit())
                {
                    errors.push(format!(
                        "TTL {ttl} 전면 타임아웃 홉 뒤에 부적절한 샘플/숫자/IP 토큰이 존재합니다: '{tok}'"
                    ));
                    invalid_tail = true;
                    break;
                }
            }
            if invalid_tail {
                continue;
            }
            None
        } else {
            if rest_tokens.is_empty() {
                errors.push(format!(
                    "TTL {ttl} 행에 응답 샘플이 존재하나 대상 IP 주소가 누락되었습니다."
                ));
                continue;
            }

            let mut found_ip: Option<IpAddr> = None;
            let mut hop_tail_err = false;

            for &tok in rest_tokens {
                if tok == "*"
                    || tok == "<"
                    || tok.starts_with('<')
                    || tok.eq_ignore_ascii_case("ms")
                {
                    errors.push(format!(
                        "TTL {ttl} 행에 3개 초과의 RTT 샘플 토큰이 존재합니다: '{tok}'"
                    ));
                    hop_tail_err = true;
                    break;
                }

                let clean_tok = tok.trim_matches(|c| c == '[' || c == ']');
                if let Ok(ip) = clean_tok.parse::<IpAddr>() {
                    if found_ip.is_some() {
                        errors.push(format!("TTL {ttl} 행에 다중 IP 주소가 존재합니다: '{tok}'"));
                        hop_tail_err = true;
                        break;
                    }
                    found_ip = Some(ip);
                } else if tok.chars().any(|c| c.is_ascii_digit()) {
                    errors.push(format!(
                        "TTL {ttl} 행의 주소 영역에 임의 숫자 토큰이 존재합니다: '{tok}'"
                    ));
                    hop_tail_err = true;
                    break;
                }
            }

            if hop_tail_err {
                continue;
            }

            let Some(parsed_ip) = found_ip else {
                errors.push(format!(
                    "TTL {ttl} 행에서 유효한 IP 주소를 찾을 수 없습니다: '{trimmed}'"
                ));
                continue;
            };

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

/// 홉 목록의 의미론적 무결성을 검증합니다.
fn validate_hops_consistency(target: IpAddr, hops: &[TraceHop]) -> Result<(), String> {
    for (expected_ttl, hop) in (1_u8..).zip(hops.iter()) {
        if hop.ttl != expected_ttl || hop.ttl == 0 || hop.ttl > 30 {
            return Err(format!(
                "홉 TTL({}번)이 순차적이지 않거나 범위를 벗어났습니다.",
                hop.ttl
            ));
        }
        if hop.probe_times_ms.len() != 3 || hop.rtt_less_than.len() != 3 {
            return Err(format!(
                "홉 TTL {}번의 샘플 배열 길이가 3이 아닙니다.",
                hop.ttl
            ));
        }

        let all_timed_out = hop.probe_times_ms.iter().all(|t| t.is_none());
        if all_timed_out {
            if hop.address.is_some() {
                return Err(format!(
                    "홉 TTL {}번에 전면 타임아웃 주소가 존재합니다.",
                    hop.ttl
                ));
            }
        } else {
            let Some(ref addr_str) = hop.address else {
                return Err(format!(
                    "홉 TTL {}번에 응답 샘플이 있으나 주소가 누락되었습니다.",
                    hop.ttl
                ));
            };
            let parsed_addr = addr_str
                .parse::<IpAddr>()
                .map_err(|_| format!("홉 주소가 유효한 IP 형식이 아닙니다: '{addr_str}'"))?;
            match (target, parsed_addr) {
                (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {}
                _ => return Err(format!("홉 IP 버전이 대상과 불일치합니다: '{addr_str}'")),
            }
        }
    }
    Ok(())
}

/// 원본 표준 출력 재파싱 결과와 홉 목록의 일치 여부를 검증합니다.
fn validate_raw_hops_match(
    target: IpAddr,
    raw_stdout: &[u8],
    hops: &[TraceHop],
) -> Result<(), String> {
    if raw_stdout.is_empty() {
        if hops.is_empty() {
            return Ok(());
        }
        return Err("raw_stdout이 비어있으나 홉 데이터가 존재합니다.".to_string());
    }

    let reparsed = parse_trace_output(target, raw_stdout, 30)
        .map_err(|errs| format!("raw_stdout 재파싱 실패: {}", errs.join("; ")))?;

    if reparsed.len() != hops.len() {
        return Err("raw_stdout 재파싱 결과와 홉 개수가 일치하지 않습니다.".to_string());
    }

    for (h1, h2) in hops.iter().zip(reparsed.iter()) {
        if h1.ttl != h2.ttl
            || h1.address != h2.address
            || h1.probe_times_ms != h2.probe_times_ms
            || h1.rtt_less_than != h2.rtt_less_than
        {
            return Err("raw_stdout 재파싱 결과와 제공된 홉 데이터가 불일치합니다.".to_string());
        }
    }
    Ok(())
}

/// 프로세스 실행 상태 및 파싱 결과를 평가하여 최종 outcome과 홉 목록을 결정합니다.
fn evaluate_trace_outcome(
    target: IpAddr,
    max_hops: u8,
    exit_code: Option<i32>,
    output_truncated: bool,
    preset_outcome: Option<String>,
    raw_stdout: &[u8],
    limitations: &mut Vec<String>,
) -> (String, Vec<TraceHop>) {
    if let Some(preset) = preset_outcome {
        return (preset, Vec::new());
    }

    if output_truncated {
        limitations.push(
            "표준 출력 또는 표준 에러 버퍼가 32KiB 한도를 초과하여 절삭되었습니다.".to_string(),
        );
        return ("LOCAL_ERROR".to_string(), Vec::new());
    }

    match exit_code {
        Some(0) => {}
        Some(code) => {
            limitations.push(format!(
                "tracert.exe가 비정상 종료 코드({code})로 종료되었습니다."
            ));
            return ("LOCAL_ERROR".to_string(), Vec::new());
        }
        None => {
            limitations.push("프로세스 종료 코드를 확인할 수 없습니다.".to_string());
            return ("LOCAL_ERROR".to_string(), Vec::new());
        }
    }

    match parse_trace_output(target, raw_stdout, max_hops) {
        Ok(parsed_hops) => {
            if parsed_hops.is_empty() {
                limitations.push("유효한 홉 관측 결과가 존재하지 않습니다.".to_string());
                return ("INCOMPLETE".to_string(), Vec::new());
            }

            let reached = parsed_hops
                .last()
                .and_then(|h| h.address.as_deref())
                .and_then(|s| s.parse::<IpAddr>().ok())
                == Some(target)
                && parsed_hops
                    .last()
                    .map(|h| h.probe_times_ms.iter().any(|t| t.is_some()))
                    .unwrap_or(false);

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
}

/// 공통 Traceroute 프로브 측정 결과(`TraceMeasurement`)를 Quick Check 계약 결과(`QuickResult`)로 변환합니다.
///
/// ## 매핑 규칙 및 불변식
/// 1. 컨텍스트 및 측정 대상 검증:
///    - session_id, target_host 필수값 및 포트(1..=65535), 타임스탬프 형식 검증.
///    - `measurement.target`을 trim 없이 `IpAddr`로 직접 파싱하며 유효하지 않은 경우 거부합니다.
///    - `measurement.method`는 "ICMP_TRACERT"로 고정 일치해야 합니다.
/// 2. 엄격한 승격 조건 (REACHED / INCOMPLETE):
///    - `output_truncated = true` 또는 `exit_code != Some(0)`인 경우 PASS/OBSERVED 승격을 금지합니다.
///    - `REACHED`는 마지막 홉의 대상 IP 일치 및 유효 숫자 RTT, raw_stdout 재파싱 일치를 모두 요구합니다.
///    - `INCOMPLETE`는 유효 홉이 관측되고 raw_stdout 정합성이 보장될 때만 WARN/OBSERVED로 매핑됩니다.
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

    if measurement.method != "ICMP_TRACERT" {
        errors.push(format!(
            "진단 방식('{}')이 지원되는 고정 방식('ICMP_TRACERT')과 일치하지 않습니다.",
            measurement.method
        ));
    }

    let parsed_target_ip = match measurement.target.parse::<IpAddr>() {
        Ok(ip) => {
            if let Ok(ctx_ip) = ctx.target_host.trim().parse::<IpAddr>()
                && ip != ctx_ip
            {
                errors.push(format!(
                    "측정 대상 IP({ip})가 컨텍스트 대상 IP({ctx_ip})와 일치하지 않습니다 (IP 불일치 방지)."
                ));
            }
            ip
        }
        Err(_) => {
            errors.push(format!(
                "측정 대상 IP('{}')가 유효한 IpAddr 형식이 아닙니다.",
                measurement.target
            ));
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        }
    };

    if !errors.is_empty() {
        return Err(errors);
    }

    let resolved_ip = Some(parsed_target_ip.to_string());

    let (status, evidence_level) = match measurement.outcome.as_str() {
        "REACHED" => {
            let reached_valid = !measurement.output_truncated
                && measurement.exit_code == Some(0)
                && !measurement.hops.is_empty()
                && validate_hops_consistency(parsed_target_ip, &measurement.hops).is_ok()
                && validate_raw_hops_match(
                    parsed_target_ip,
                    &measurement.raw_stdout,
                    &measurement.hops,
                )
                .is_ok()
                && measurement
                    .hops
                    .last()
                    .and_then(|h| h.address.as_deref())
                    .and_then(|s| s.parse::<IpAddr>().ok())
                    == Some(parsed_target_ip)
                && measurement
                    .hops
                    .last()
                    .map(|h| h.probe_times_ms.iter().any(|t| t.is_some()))
                    .unwrap_or(false);

            if reached_valid {
                (QuickStatus::PASS, EvidenceLevel::OBSERVED)
            } else {
                (QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN)
            }
        }
        "INCOMPLETE" => {
            let hops_consistent = !measurement.output_truncated
                && measurement.exit_code == Some(0)
                && validate_hops_consistency(parsed_target_ip, &measurement.hops).is_ok()
                && validate_raw_hops_match(
                    parsed_target_ip,
                    &measurement.raw_stdout,
                    &measurement.hops,
                )
                .is_ok();

            let has_valid_hop = hops_consistent
                && measurement.hops.iter().any(|h| {
                    h.address
                        .as_deref()
                        .and_then(|s| s.parse::<IpAddr>().ok())
                        .is_some()
                });

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

    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
    };
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
    use windows_sys::Win32::System::Threading::CREATE_NO_WINDOW;

    use super::{
        MAX_OUTPUT_BUFFER_BYTES, PipeCollector, PipeStatus, TraceMeasurement, TraceOptions,
        collect_from_pipe, finalize_trace_measurement,
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

    /// Windows 익명 파이프 수집을 위한 구현 구조체.
    struct NativeWindowsPipe<R: Read> {
        handle: HANDLE,
        reader: R,
    }

    impl<R: Read> NativeWindowsPipe<R> {
        fn new(handle: HANDLE, reader: R) -> Self {
            Self { handle, reader }
        }
    }

    impl<R: Read> PipeCollector for NativeWindowsPipe<R> {
        fn check_avail(&mut self) -> PipeStatus {
            let mut avail: u32 = 0;
            let res = unsafe {
                PeekNamedPipe(
                    self.handle,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut avail,
                    std::ptr::null_mut(),
                )
            };
            if res != 0 {
                PipeStatus::Data(avail as usize)
            } else {
                let err = unsafe { GetLastError() };
                if err == 109 || err == 232 || err == 233 {
                    PipeStatus::Eof
                } else {
                    PipeStatus::Error(err, format!("PeekNamedPipe 실패 (Win32 오류 코드: {err})"))
                }
            }
        }

        fn read_bytes(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reader.read(buf)
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
            let dyn_len =
                unsafe { GetSystemDirectoryW(dyn_buf.as_mut_ptr(), dyn_buf.len() as u32) };
            if dyn_len == 0 || (dyn_len as usize) >= dyn_buf.len() {
                return Err("GetSystemDirectoryW 재시도 실패".to_string());
            }
            OsString::from_wide(&dyn_buf[..dyn_len as usize])
        };

        let path = PathBuf::from(sys_dir).join("tracert.exe");
        if !path.is_file() {
            return Err(format!(
                "tracert.exe 파일을 찾을 수 없습니다: {}",
                path.display()
            ));
        }
        Ok(path)
    }

    /// 프로세스 종료 시 커널 레벨에서 종료 요청되는 Job Object를 생성합니다.
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

    /// 자식 프로세스 상태를 확인하고 필요 시 강제 종료 후 자원 회수를 대기합니다.
    fn terminate_and_cleanup_child(child: &mut Child, limitations: &mut Vec<String>) {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {
                if let Err(e) = child.kill() {
                    match child.try_wait() {
                        Ok(Some(_)) => {}
                        _ => limitations.push(format!("자식 프로세스 kill 호출 실패: {e}")),
                    }
                }
            }
            Err(e) => {
                limitations.push(format!("자식 프로세스 상태 확인 중 오류: {e}"));
            }
        }
        wait_child_cleanup(child, limitations);
    }

    /// 자식 프로세스 종료 후 자원 회수를 상한 대기합니다.
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
        limitations.push(
            "프로세스 강제 종료 후 자식 프로세스 자원 회수 대기 시간이 초과되었습니다.".to_string(),
        );
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
                limitations: vec!["spawn 직전 취소 요청이 감지되었습니다.".to_string()],
            };
        }

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

        // 파이프 소유권을 Job 할당 이전에 안전하게 확보하여 모든 종료 경로에서 가용 잔량 수집을 보장
        let child_stdout = child.stdout.take().expect("stdout pipe 확보 실패");
        let child_stderr = child.stderr.take().expect("stderr pipe 확보 실패");
        let stdout_h = child_stdout.as_raw_handle() as HANDLE;
        let stderr_h = child_stderr.as_raw_handle() as HANDLE;

        let mut stdout_pipe = NativeWindowsPipe::new(stdout_h, child_stdout);
        let mut stderr_pipe = NativeWindowsPipe::new(stderr_h, child_stderr);

        let mut raw_stdout = Vec::new();
        let mut raw_stderr = Vec::new();
        let mut output_truncated = false;
        let mut outcome_opt: Option<String> = None;
        let mut exit_code: Option<i32> = None;

        let child_handle = child.as_raw_handle() as HANDLE;
        let assign_res = unsafe { AssignProcessToJobObject(job.0, child_handle) };
        if assign_res == 0 {
            terminate_and_cleanup_child(&mut child, &mut limitations);
            limitations.push("자식 프로세스를 Job Object에 할당하는 데 실패했습니다.".to_string());
            outcome_opt = Some("LOCAL_ERROR".to_string());
            let elapsed_ms = start.elapsed().as_millis() as u64;
            return finalize_trace_measurement(
                target,
                options.max_hops,
                exit_code,
                elapsed_ms,
                (&mut stdout_pipe, &mut stderr_pipe),
                (&mut raw_stdout, &mut raw_stderr, &mut output_truncated),
                (&mut outcome_opt, &mut limitations),
            );
        }

        loop {
            let elapsed_ms = start.elapsed().as_millis() as u64;

            if let Err((code, msg)) = collect_from_pipe(
                &mut stdout_pipe,
                &mut raw_stdout,
                MAX_OUTPUT_BUFFER_BYTES,
                &mut output_truncated,
            ) {
                limitations.push(format!(
                    "표준 출력 파이프 오류 (코드 {}): {msg}",
                    code.map_or_else(|| "미확인".to_string(), |value| value.to_string())
                ));
                outcome_opt = Some("LOCAL_ERROR".to_string());
                terminate_and_cleanup_child(&mut child, &mut limitations);
                break;
            }

            if let Err((code, msg)) = collect_from_pipe(
                &mut stderr_pipe,
                &mut raw_stderr,
                MAX_OUTPUT_BUFFER_BYTES,
                &mut output_truncated,
            ) {
                limitations.push(format!(
                    "표준 에러 파이프 오류 (코드 {}): {msg}",
                    code.map_or_else(|| "미확인".to_string(), |value| value.to_string())
                ));
                outcome_opt = Some("LOCAL_ERROR".to_string());
                terminate_and_cleanup_child(&mut child, &mut limitations);
                break;
            }

            if output_truncated {
                outcome_opt = Some("LOCAL_ERROR".to_string());
                terminate_and_cleanup_child(&mut child, &mut limitations);
                break;
            }

            if cancel.load(Ordering::Relaxed) {
                outcome_opt = Some("CANCELLED".to_string());
                terminate_and_cleanup_child(&mut child, &mut limitations);
                break;
            }

            if elapsed_ms >= options.overall_timeout_ms {
                outcome_opt = Some("TIMED_OUT".to_string());
                terminate_and_cleanup_child(&mut child, &mut limitations);
                break;
            }

            match child.try_wait() {
                Ok(Some(status)) => {
                    exit_code = status.code();
                    break;
                }
                Ok(None) => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    limitations.push(format!("자식 프로세스 상태 폴링 중 오류: {e}"));
                    outcome_opt = Some("LOCAL_ERROR".to_string());
                    terminate_and_cleanup_child(&mut child, &mut limitations);
                    break;
                }
            }
        }

        wait_child_cleanup(&mut child, &mut limitations);
        if exit_code.is_none()
            && let Ok(Some(st)) = child.try_wait()
        {
            exit_code = st.code();
        }

        let elapsed_ms = start.elapsed().as_millis() as u64;

        finalize_trace_measurement(
            target,
            options.max_hops,
            exit_code,
            elapsed_ms,
            (&mut stdout_pipe, &mut stderr_pipe),
            (&mut raw_stdout, &mut raw_stderr, &mut output_truncated),
            (&mut outcome_opt, &mut limitations),
        )
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
            limitations: vec![
                "비-Windows 운영체제에서는 네이티브 tracert.exe 유틸리티가 지원되지 않습니다."
                    .to_string(),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockPipe {
        avail_queue: Vec<PipeStatus>,
        data: Vec<u8>,
        read_pos: usize,
        fail_read: bool,
        read_error_code: Option<i32>,
    }

    impl MockPipe {
        fn new(avail: Vec<PipeStatus>, data: Vec<u8>) -> Self {
            Self {
                avail_queue: avail,
                data,
                read_pos: 0,
                fail_read: false,
                read_error_code: None,
            }
        }
    }

    impl PipeCollector for MockPipe {
        fn check_avail(&mut self) -> PipeStatus {
            if self.avail_queue.is_empty() {
                PipeStatus::Eof
            } else {
                self.avail_queue.remove(0)
            }
        }

        fn read_bytes(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.fail_read {
                if let Some(code) = self.read_error_code {
                    return Err(std::io::Error::from_raw_os_error(code));
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "mock read error",
                ));
            }
            if self.read_pos >= self.data.len() {
                return Ok(0);
            }
            let remain = &self.data[self.read_pos..];
            let n = remain.len().min(buf.len());
            buf[..n].copy_from_slice(&remain[..n]);
            self.read_pos += n;
            Ok(n)
        }
    }

    #[test]
    fn test_evaluate_outcome_exit_none_is_local_error() {
        let mut limits = Vec::new();
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        let (outcome, hops) = evaluate_trace_outcome(
            target,
            30,
            None,
            false,
            None,
            b"1 1 ms 1 ms 1 ms 127.0.0.1\r\n",
            &mut limits,
        );
        assert_eq!(outcome, "LOCAL_ERROR");
        assert!(hops.is_empty());
        assert!(limits.iter().any(|l| l.contains("종료 코드를 확인")));
    }

    #[test]
    fn test_evaluate_outcome_exit_nonzero_is_local_error() {
        let mut limits = Vec::new();
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        let (outcome, hops) = evaluate_trace_outcome(
            target,
            30,
            Some(1),
            false,
            None,
            b"1 1 ms 1 ms 1 ms 127.0.0.1\r\n",
            &mut limits,
        );
        assert_eq!(outcome, "LOCAL_ERROR");
        assert!(hops.is_empty());
        assert!(limits.iter().any(|l| l.contains("비정상 종료 코드")));
    }

    #[test]
    fn test_evaluate_outcome_truncated_is_local_error() {
        let mut limits = Vec::new();
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        let (outcome, hops) = evaluate_trace_outcome(
            target,
            30,
            Some(0),
            true,
            None,
            b"1 1 ms 1 ms 1 ms 127.0.0.1\r\n",
            &mut limits,
        );
        assert_eq!(outcome, "LOCAL_ERROR");
        assert!(hops.is_empty());
        assert!(limits.iter().any(|l| l.contains("절삭")));
    }

    #[test]
    fn test_evaluate_outcome_truncated_line_is_parse_error() {
        let mut limits = Vec::new();
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        let (outcome, hops) = evaluate_trace_outcome(
            target,
            30,
            Some(0),
            false,
            None,
            b"1 1 ms 1 ms 1 ms 127.0.0.1\r\n2 1 ms",
            &mut limits,
        );
        assert_eq!(outcome, "PARSE_ERROR");
        assert!(hops.is_empty());
    }

    #[test]
    fn test_evaluate_outcome_reached_success() {
        let mut limits = Vec::new();
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        let (outcome, hops) = evaluate_trace_outcome(
            target,
            30,
            Some(0),
            false,
            None,
            b"1 1 ms 1 ms 1 ms 127.0.0.1\r\n",
            &mut limits,
        );
        assert_eq!(outcome, "REACHED");
        assert_eq!(hops.len(), 1);
        assert_eq!(hops[0].address.as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn test_mock_pipe_peek_error() {
        let mut pipe = MockPipe::new(
            vec![PipeStatus::Error(5, "Access Denied".to_string())],
            Vec::new(),
        );
        let mut buf = Vec::new();
        let mut truncated = false;
        let res = collect_from_pipe(&mut pipe, &mut buf, 32768, &mut truncated);
        assert!(res.is_err());
        let (code, msg) = res.unwrap_err();
        assert_eq!(code, Some(5));
        assert!(msg.contains("Access Denied"));
    }

    #[test]
    fn test_mock_pipe_read_error() {
        let mut pipe = MockPipe::new(vec![PipeStatus::Data(10)], vec![1; 10]);
        pipe.fail_read = true;
        let mut buf = Vec::new();
        let mut truncated = false;
        let res = collect_from_pipe(&mut pipe, &mut buf, 32768, &mut truncated);
        assert!(res.is_err());
    }

    #[test]
    fn test_mock_pipe_eof_broken_pipe() {
        let mut pipe = MockPipe::new(vec![PipeStatus::Eof], Vec::new());
        let mut buf = Vec::new();
        let mut truncated = false;
        let res = collect_from_pipe(&mut pipe, &mut buf, 32768, &mut truncated);
        assert!(res.is_ok());
        assert!(buf.is_empty());
    }

    #[test]
    fn test_mock_read_error_preserves_raw_code() {
        let mut pipe = MockPipe::new(vec![PipeStatus::Data(1)], vec![1]);
        pipe.fail_read = true;
        pipe.read_error_code = Some(5);
        let mut buf = Vec::new();
        let mut truncated = false;
        let error = collect_from_pipe(&mut pipe, &mut buf, 32768, &mut truncated)
            .expect_err("합성 read 오류");
        assert_eq!(error.0, Some(5));
    }

    #[test]
    fn test_mock_read_error_without_raw_code_stays_unknown() {
        let mut pipe = MockPipe::new(vec![PipeStatus::Data(1)], vec![1]);
        pipe.fail_read = true;
        let mut buf = Vec::new();
        let mut truncated = false;
        let error = collect_from_pipe(&mut pipe, &mut buf, 32768, &mut truncated)
            .expect_err("원시 코드 없는 합성 read 오류");
        assert_eq!(error.0, None);
    }

    #[test]
    fn test_mock_terminal_drain_preserves_available_tail() {
        let mut pipe = MockPipe::new(vec![PipeStatus::Data(4), PipeStatus::Eof], b"tail".to_vec());
        let mut buf = b"prefix".to_vec();
        let mut truncated = false;
        assert!(
            drain_pipe_limited(&mut pipe, &mut buf, 32768, &mut truncated, 4)
                .expect("합성 종료 후 잔량 수집")
        );
        assert_eq!(buf, b"prefixtail");
        assert!(!truncated);
    }

    #[test]
    fn test_mock_pipe_overflow_truncated() {
        let overflow_data = vec![b'A'; 40000];
        // production 수집기는 한 번에 최대 4096바이트만 읽는다.
        // 실제 남은 가용량과 반복 수집을 모의하여 상한의 의미를 검증한다.
        let mut remaining = overflow_data.len();
        let mut availability = Vec::new();
        while remaining > 0 {
            availability.push(PipeStatus::Data(remaining));
            remaining -= remaining.min(4096);
        }
        availability.push(PipeStatus::Eof);
        let mut pipe = MockPipe::new(availability, overflow_data);
        let mut buf = Vec::new();
        let mut truncated = false;
        let drained = drain_pipe_limited(&mut pipe, &mut buf, 32768, &mut truncated, 16)
            .expect("모의 잔량 수집");
        assert!(drained);
        assert!(truncated);
        assert_eq!(buf.len(), 32768);
        assert_eq!(pipe.read_pos, 40000);
    }

    #[test]
    fn test_terminal_stdout_drain_peek_error_prevents_reached() {
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        let valid_reached_stdout = b"1 1 ms 1 ms 1 ms 127.0.0.1\r\n".to_vec();

        // 이미 루프 중에 유효 도달 raw를 수집한 상태를 모의
        let mut raw_stdout = valid_reached_stdout.clone();
        let mut raw_stderr = Vec::new();
        let mut output_truncated = false;
        let mut outcome_opt: Option<String> = None;
        let mut limitations = vec!["초기 안내문".to_string()];

        // stdout 파이프의 최종 drain 시점에 Peek 오류(코드 5, Access Denied) 모의
        let mut stdout_pipe = MockPipe::new(
            vec![PipeStatus::Error(5, "PeekNamedPipe 실패".to_string())],
            Vec::new(),
        );
        let mut stderr_pipe = MockPipe::new(vec![PipeStatus::Eof], Vec::new());

        let measurement = finalize_trace_measurement(
            target,
            30,
            Some(0),
            50,
            (&mut stdout_pipe, &mut stderr_pipe),
            (&mut raw_stdout, &mut raw_stderr, &mut output_truncated),
            (&mut outcome_opt, &mut limitations),
        );

        // 정상 exit 0과 도달 raw가 있었음에도 terminal stdout drain 오류로 LOCAL_ERROR 강제
        assert_eq!(measurement.outcome, "LOCAL_ERROR");
        assert!(measurement.hops.is_empty());
        assert_eq!(measurement.exit_code, Some(0));
        assert_eq!(measurement.raw_stdout, valid_reached_stdout);
        assert!(
            measurement
                .limitations
                .iter()
                .any(|l| l.contains("표준 출력 잔량 수집 중 오류 (코드 5)"))
        );

        // trace_to_quick_result에 넘겨도 절대 PASS로 승격되지 않음을 증명
        let ctx = QuickContext {
            session_id: "test-sess".to_string(),
            timestamp_iso8601: None,
            source_host: None,
            target_host: "127.0.0.1".to_string(),
            target_port: 80,
        };
        let q_res = trace_to_quick_result(&ctx, &measurement).expect("어댑터 변환 성공");
        assert_eq!(q_res.status, QuickStatus::UNKNOWN);
        assert_eq!(q_res.evidence_level, EvidenceLevel::UNKNOWN);
    }

    #[test]
    fn test_terminal_stderr_drain_read_error_prevents_reached() {
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        let valid_reached_stdout = b"1 1 ms 1 ms 1 ms 127.0.0.1\r\n".to_vec();

        let mut raw_stdout = valid_reached_stdout.clone();
        let mut raw_stderr = Vec::new();
        let mut output_truncated = false;
        let mut outcome_opt: Option<String> = None;
        let mut limitations = Vec::new();

        let mut stdout_pipe = MockPipe::new(vec![PipeStatus::Eof], Vec::new());
        // stderr 파이프의 최종 drain 시점에 read 오류(코드 14) 모의
        let mut stderr_pipe = MockPipe::new(vec![PipeStatus::Data(4)], vec![1, 2, 3, 4]);
        stderr_pipe.fail_read = true;
        stderr_pipe.read_error_code = Some(14);

        let measurement = finalize_trace_measurement(
            target,
            30,
            Some(0),
            40,
            (&mut stdout_pipe, &mut stderr_pipe),
            (&mut raw_stdout, &mut raw_stderr, &mut output_truncated),
            (&mut outcome_opt, &mut limitations),
        );

        assert_eq!(measurement.outcome, "LOCAL_ERROR");
        assert!(measurement.hops.is_empty());
        assert_eq!(measurement.raw_stdout, valid_reached_stdout);
        assert!(
            measurement
                .limitations
                .iter()
                .any(|l| l.contains("표준 에러 잔량 수집 중 오류 (코드 14)"))
        );
    }

    #[test]
    fn test_terminal_drain_error_without_os_code_preserves_unknown_tag() {
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        let mut raw_stdout = b"1 1 ms 1 ms 1 ms 127.0.0.1\r\n".to_vec();
        let mut raw_stderr = Vec::new();
        let mut output_truncated = false;
        let mut outcome_opt: Option<String> = None;
        let mut limitations = Vec::new();

        // read_error_code가 None인 합성 오류
        let mut stdout_pipe = MockPipe::new(vec![PipeStatus::Data(2)], vec![1, 2]);
        stdout_pipe.fail_read = true;
        stdout_pipe.read_error_code = None;
        let mut stderr_pipe = MockPipe::new(vec![PipeStatus::Eof], Vec::new());

        let measurement = finalize_trace_measurement(
            target,
            30,
            Some(0),
            30,
            (&mut stdout_pipe, &mut stderr_pipe),
            (&mut raw_stdout, &mut raw_stderr, &mut output_truncated),
            (&mut outcome_opt, &mut limitations),
        );

        assert_eq!(measurement.outcome, "LOCAL_ERROR");
        assert!(
            measurement
                .limitations
                .iter()
                .any(|l| l.contains("표준 출력 잔량 수집 중 오류 (코드 미확인)"))
        );
    }

    #[test]
    fn test_terminal_drain_uncollected_bound_prevents_reached() {
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        let mut raw_stdout = b"1 1 ms 1 ms 1 ms 127.0.0.1\r\n".to_vec();
        let mut raw_stderr = Vec::new();
        let mut output_truncated = false;
        let mut outcome_opt: Option<String> = None;
        let mut limitations = Vec::new();

        // 10회 반복을 초과하여 계속 데이터가 남아있는 모의 파이프 (max_rounds 10 초과)
        let mut infinite_avail = Vec::new();
        for _ in 0..20 {
            infinite_avail.push(PipeStatus::Data(100));
        }
        let mut stdout_pipe = MockPipe::new(infinite_avail, vec![b'A'; 2000]);
        let mut stderr_pipe = MockPipe::new(vec![PipeStatus::Eof], Vec::new());

        let measurement = finalize_trace_measurement(
            target,
            30,
            Some(0),
            60,
            (&mut stdout_pipe, &mut stderr_pipe),
            (&mut raw_stdout, &mut raw_stderr, &mut output_truncated),
            (&mut outcome_opt, &mut limitations),
        );

        assert_eq!(measurement.outcome, "LOCAL_ERROR");
        assert!(
            measurement
                .limitations
                .iter()
                .any(|l| l.contains("가용 잔량을 완전히 수집하지 못했습니다 (상한 도달)"))
        );
    }

    #[test]
    fn test_terminal_drain_cancelled_and_timed_out_not_promoted_to_success() {
        let target: IpAddr = "127.0.0.1".parse().unwrap();

        // CANCELLED 케이스
        let mut raw_stdout = b"1 1 ms 1 ms 1 ms 127.0.0.1\r\n".to_vec();
        let mut raw_stderr = Vec::new();
        let mut output_truncated = false;
        let mut outcome_opt = Some("CANCELLED".to_string());
        let mut limitations = Vec::new();
        let mut stdout_pipe = MockPipe::new(vec![PipeStatus::Eof], Vec::new());
        let mut stderr_pipe = MockPipe::new(vec![PipeStatus::Eof], Vec::new());

        let measurement = finalize_trace_measurement(
            target,
            30,
            Some(0),
            10,
            (&mut stdout_pipe, &mut stderr_pipe),
            (&mut raw_stdout, &mut raw_stderr, &mut output_truncated),
            (&mut outcome_opt, &mut limitations),
        );
        assert_eq!(measurement.outcome, "CANCELLED");

        // TIMED_OUT 케이스
        let mut outcome_opt2 = Some("TIMED_OUT".to_string());
        let mut stdout_pipe2 = MockPipe::new(vec![PipeStatus::Eof], Vec::new());
        let mut stderr_pipe2 = MockPipe::new(vec![PipeStatus::Eof], Vec::new());
        let measurement2 = finalize_trace_measurement(
            target,
            30,
            Some(0),
            10000,
            (&mut stdout_pipe2, &mut stderr_pipe2),
            (&mut raw_stdout, &mut raw_stderr, &mut output_truncated),
            (&mut outcome_opt2, &mut limitations),
        );
        assert_eq!(measurement2.outcome, "TIMED_OUT");
    }

    #[test]
    fn test_job_assignment_failure_preserves_available_pipe_tail_and_local_error() {
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        let mut raw_stdout = Vec::new();
        let mut raw_stderr = Vec::new();
        let mut output_truncated = false;
        let mut outcome_opt = Some("LOCAL_ERROR".to_string());
        let mut limitations =
            vec!["자식 프로세스를 Job Object에 할당하는 데 실패했습니다.".to_string()];

        // Job 할당 직후 프로세스가 kill되기 전 이미 버퍼에 기록해둔 stdout 및 stderr 모의
        let mut stdout_pipe = MockPipe::new(
            vec![PipeStatus::Data(14), PipeStatus::Eof],
            b"partial stdout".to_vec(),
        );
        let mut stderr_pipe = MockPipe::new(
            vec![PipeStatus::Data(14), PipeStatus::Eof],
            b"partial stderr".to_vec(),
        );

        let measurement = finalize_trace_measurement(
            target,
            30,
            None,
            5,
            (&mut stdout_pipe, &mut stderr_pipe),
            (&mut raw_stdout, &mut raw_stderr, &mut output_truncated),
            (&mut outcome_opt, &mut limitations),
        );

        // fail-closed LOCAL_ERROR 확인
        assert_eq!(measurement.outcome, "LOCAL_ERROR");
        assert!(measurement.hops.is_empty());
        assert_eq!(measurement.exit_code, None);
        // 가용 잔량이 빈 벡터가 아니라 온전히 보존되었는지 검증 (고정 빈 raw 반환 제거)
        assert_eq!(measurement.raw_stdout, b"partial stdout");
        assert_eq!(measurement.raw_stderr, b"partial stderr");
        assert!(
            measurement
                .limitations
                .iter()
                .any(|l| l.contains("Job Object에 할당하는 데 실패"))
        );
    }
}
