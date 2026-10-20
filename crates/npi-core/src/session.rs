use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::models::{ExecutionMode, GroupId, Limits, Profile, Target};
use crate::validation::{
    SCHEMA_VERSION, expected_group_for_feature, validate_profile, validate_target_host_str,
};

/// 레거시 변환이 지원하는 입력 스키마 버전.
pub const LEGACY_SCHEMA_VERSION: &str = "1.0";

/// 계약에 정의된 7개 기능 실행 결과 상태.
pub const KNOWN_STATUSES: [&str; 7] = [
    "PASS",
    "FAIL",
    "WARN",
    "SKIPPED_BY_USER",
    "UNAVAILABLE",
    "ERROR",
    "CANCELLED",
];

/// 계약에 정의된 3개 판정 분류.
pub const KNOWN_CLASSIFICATIONS: [&str; 3] = ["OBSERVED", "INFERRED", "UNKNOWN"];

/// 계약에 정의된 3개 신뢰도 등급.
pub const KNOWN_CONFIDENCE: [&str; 3] = ["low", "medium", "high"];

/// 계약에 정의된 8개 증거 종류.
pub const KNOWN_EVIDENCE_KINDS: [&str; 8] = [
    "SOCKET",
    "ICMP",
    "DNS",
    "HOST_SNAPSHOT",
    "PACKET",
    "CAPTURE_METADATA",
    "POLICY_MEMO",
    "IMPORT",
];

/// 계약에 정의된 호스트 역할 (`client` | `server`).
pub const KNOWN_HOST_ROLES: [&str; 2] = ["client", "server"];

/// 패킷 증거(`PACKET`)가 필수인 기능 ID 목록.
const PACKET_REQUIRED_FEATURES: [&str; 3] = ["syn_rst_analysis", "packet_compare", "pcap_export"];

const SESSION_FIELDS: [&str; 14] = [
    "schema_version",
    "session_id",
    "mode",
    "host_role",
    "started_at_utc",
    "timezone_offset_minutes",
    "clock_offset_ms",
    "clock_uncertainty_ms",
    "profile",
    "evidence",
    "feature_results",
    "findings",
    "limitations",
    "resource_metrics",
];

const EVIDENCE_FIELDS: [&str; 4] = ["evidence_id", "kind", "artifact_path", "synthetic"];

const FINDING_FIELDS: [&str; 6] = [
    "classification",
    "statement",
    "evidence_ids",
    "confidence",
    "limitations",
    "next_checks",
];

const FEATURE_RESULT_FIELDS: [&str; 11] = [
    "feature_id",
    "group_id",
    "status",
    "classification",
    "evidence_ids",
    "started_at_utc",
    "ended_at_utc",
    "duration_ms",
    "error_code",
    "limitations",
    "next_checks",
];

const RESOURCE_METRICS_FIELDS: [&str; 3] = ["peak_rss_bytes", "avg_cpu_percent", "capture_drops"];

/// 진단 근거(Evidence) DTO.
/// 모든 필드는 필수이며 알 수 없는 필드를 거부한다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub evidence_id: String,
    pub kind: String,
    pub artifact_path: Option<String>,
    pub synthetic: bool,
}

/// 진단 판정(Finding) DTO.
/// `OBSERVED` 분류는 반드시 존재하는 증거 ID를 1개 이상 참조해야 한다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub classification: String,
    pub statement: String,
    pub evidence_ids: Vec<String>,
    pub confidence: String,
    pub limitations: Vec<String>,
    pub next_checks: Vec<String>,
}

/// 개별 기능 실행 결과(FeatureResult) DTO.
/// 모든 필드는 필수이며 알 수 없는 필드를 거부한다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureResult {
    pub feature_id: String,
    pub group_id: String,
    pub status: String,
    pub classification: Option<String>,
    pub evidence_ids: Vec<String>,
    pub started_at_utc: Option<String>,
    pub ended_at_utc: Option<String>,
    pub duration_ms: Option<u64>,
    pub error_code: Option<i64>,
    pub limitations: Vec<String>,
    pub next_checks: Vec<String>,
}

/// 세션 자원 사용 지표(ResourceMetrics) DTO.
/// 측정되지 않은 지표는 가짜 수치로 채우지 않고 `None`(`null`)으로 유지한다.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceMetrics {
    pub peak_rss_bytes: Option<u64>,
    pub avg_cpu_percent: Option<f64>,
    pub capture_drops: Option<u64>,
}

/// 진단 세션(Session) DTO (스키마 1.1).
/// 알 수 없는 호스트 역할(`host_role`)이나 타임존(`timezone_offset_minutes`)은 `None`(`null`)으로 유지한다.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub schema_version: String,
    pub session_id: String,
    pub mode: String,
    pub host_role: Option<String>,
    pub started_at_utc: String,
    pub timezone_offset_minutes: Option<i32>,
    pub clock_offset_ms: Option<i64>,
    pub clock_uncertainty_ms: Option<u64>,
    pub profile: Profile,
    pub evidence: Vec<Evidence>,
    pub feature_results: Vec<FeatureResult>,
    pub findings: Vec<Finding>,
    pub limitations: Vec<String>,
    pub resource_metrics: ResourceMetrics,
}

/// 8-4-4-4-12 형식의 16진수 UUID 문자열인지 검증한다.
fn is_valid_uuid(s: &str) -> bool {
    if !s.is_ascii() || s.len() != 36 {
        return false;
    }
    let bytes = s.as_bytes();
    for (idx, &b) in bytes.iter().enumerate() {
        if idx == 8 || idx == 13 || idx == 18 || idx == 23 {
            if b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// 윤년 여부를 계산한다.
const fn is_leap_year(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// 연도와 월에 따른 최대 일수를 반환한다.
const fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

fn parse_ascii_digits(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() {
        return None;
    }
    let mut val = 0u32;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        val = val.checked_mul(10)?.checked_add((b - b'0') as u32)?;
    }
    Some(val)
}

/// UTF-8 멀티바이트 패닉 없이 RFC3339 날짜·시각 문자열과 달력 유효성(윤년/월별 일수/타임존)을 검증한다.
fn validate_rfc3339(s: &str) -> Result<(), String> {
    if !s.is_ascii() {
        return Err("RFC3339 타임스탬프는 ASCII 문자만 허용합니다".to_string());
    }
    let bytes = s.as_bytes();
    if bytes.len() < 20 {
        return Err("RFC3339 타임스탬프 길이가 너무 짧습니다".to_string());
    }

    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || (bytes[10] != b'T' && bytes[10] != b't')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return Err("RFC3339 타임스탬프 구분자 형식이 올바르지 않습니다".to_string());
    }

    let Some(year) = parse_ascii_digits(&bytes[0..4]) else {
        return Err("RFC3339 연도 형식이 올바르지 않습니다".to_string());
    };
    let Some(month) = parse_ascii_digits(&bytes[5..7]) else {
        return Err("RFC3339 월 형식이 올바르지 않습니다".to_string());
    };
    let Some(day) = parse_ascii_digits(&bytes[8..10]) else {
        return Err("RFC3339 일 형식이 올바르지 않습니다".to_string());
    };
    let Some(hour) = parse_ascii_digits(&bytes[11..13]) else {
        return Err("RFC3339 시 형식이 올바르지 않습니다".to_string());
    };
    let Some(minute) = parse_ascii_digits(&bytes[14..16]) else {
        return Err("RFC3339 분 형식이 올바르지 않습니다".to_string());
    };
    let Some(second) = parse_ascii_digits(&bytes[17..19]) else {
        return Err("RFC3339 초 형식이 올바르지 않습니다".to_string());
    };

    if year == 0 {
        return Err("RFC3339 연도는 1 이상이어야 합니다".to_string());
    }
    if !(1..=12).contains(&month) {
        return Err(format!("RFC3339 월 범위 오류: {month}"));
    }
    let max_day = days_in_month(year, month);
    if day == 0 || day > max_day {
        return Err(format!(
            "RFC3339 달력 날짜 오류: {year:04}-{month:02}-{day:02}"
        ));
    }
    if hour > 23 {
        return Err(format!("RFC3339 시 범위 오류: {hour}"));
    }
    if minute > 59 {
        return Err(format!("RFC3339 분 범위 오류: {minute}"));
    }
    if second > 59 {
        return Err(format!("RFC3339 초 범위 오류: {second}"));
    }

    let mut pos = 19usize;
    if bytes[pos] == b'.' {
        pos += 1;
        let frac_start = pos;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            pos += 1;
        }
        if pos == frac_start {
            return Err("RFC3339 소수점 초 뒤에 숫자가 없습니다".to_string());
        }
    }

    let tz = &bytes[pos..];
    if tz == b"Z" || tz == b"z" {
        return Ok(());
    }

    if tz.len() != 6 || (tz[0] != b'+' && tz[0] != b'-') || tz[3] != b':' {
        return Err("RFC3339 타임존 오프셋 형식이 올바르지 않습니다".to_string());
    }

    let Some(tz_hour) = parse_ascii_digits(&tz[1..3]) else {
        return Err("RFC3339 타임존 시 형식이 올바르지 않습니다".to_string());
    };
    let Some(tz_min) = parse_ascii_digits(&tz[4..6]) else {
        return Err("RFC3339 타임존 분 형식이 올바르지 않습니다".to_string());
    };

    if tz_hour > 23 || tz_min > 59 {
        return Err("RFC3339 타임존 오프셋 범위가 올바르지 않습니다".to_string());
    }
    if tz[0] == b'-' && tz_hour == 0 && tz_min == 0 {
        return Err("RFC3339 타임존에 -00:00은 허용되지 않습니다".to_string());
    }
    let total_offset_mins = (tz_hour as i32) * 60 + (tz_min as i32);
    if total_offset_mins > 840 {
        return Err(format!(
            "RFC3339 타임존 오프셋이 허용 범위(+-840분)를 초과했습니다: {total_offset_mins}"
        ));
    }

    Ok(())
}

/// 아티팩트 경로가 안전한 상대 경로인지 검증한다.
/// 절대 경로, 드라이브 문자, 스킴, 상위 디렉터리(`..`) 탐색을 모두 거부한다.
fn validate_relative_artifact_path(path: &str) -> Result<(), String> {
    if path.trim().is_empty() {
        return Err("artifact_path는 빈 문자열일 수 없습니다".to_string());
    }
    if path.chars().any(|c| c.is_control()) {
        return Err("artifact_path에 제어 문자를 포함할 수 없습니다".to_string());
    }
    if path.starts_with('/') || path.starts_with('\\') {
        return Err("artifact_path는 절대 경로일 수 없습니다".to_string());
    }
    if path.contains(':') {
        return Err("artifact_path에 드라이브 문자나 스킴(:)을 포함할 수 없습니다".to_string());
    }
    if path.ends_with('/') || path.ends_with('\\') {
        return Err("artifact_path는 디렉터리 구분자로 끝날 수 없습니다".to_string());
    }

    for segment in path.split(['/', '\\']) {
        if segment.is_empty() {
            return Err("artifact_path에 빈 경로 세그먼트(연속 슬래시)가 있습니다".to_string());
        }
        if segment == "." || segment == ".." {
            return Err("artifact_path에 '.' 또는 '..' 경로 탐색을 포함할 수 없습니다".to_string());
        }
        if segment.trim().is_empty() {
            return Err("artifact_path 세그먼트는 공백만 있을 수 없습니다".to_string());
        }
    }

    Ok(())
}

/// 문장 내 금지 단정 표현 직후(같은 절 내부)에 즉각적인 부정 어미가 붙어 있는지 확인한다.
/// 다른 절이나 문장 끝에 있는 '미확인 사항 없음' 등은 부정으로 인정하지 않는다.
fn has_immediate_scoped_negation(after_match: &str) -> bool {
    let clause_tail = after_match
        .split(['.', ',', '!', '?', ';', '\n', '\r', '(', ')', '—', '-'])
        .next()
        .unwrap_or("");

    let trimmed = clause_tail.trim_start();
    let stripped = trimmed
        .strip_prefix("은 ")
        .or_else(|| trimmed.strip_prefix("는 "))
        .or_else(|| trimmed.strip_prefix("이 "))
        .or_else(|| trimmed.strip_prefix("가 "))
        .or_else(|| trimmed.strip_prefix("을 "))
        .or_else(|| trimmed.strip_prefix("를 "))
        .or_else(|| trimmed.strip_prefix("로 "))
        .or_else(|| trimmed.strip_prefix("으로 "))
        .unwrap_or(trimmed)
        .trim_start();

    let compact: String = stripped.chars().filter(|c| !c.is_whitespace()).collect();
    const IMMEDIATE_NEGATIONS: [&str; 12] = [
        "불가",
        "아님",
        "아닙니다",
        "아니며",
        "할수없",
        "단정할수없",
        "단정불가",
        "단정하지않",
        "하지않",
        "않음",
        "않습니다",
        "금지",
    ];

    IMMEDIATE_NEGATIONS
        .iter()
        .any(|neg| compact.starts_with(neg))
}

/// '방화벽 차단 확정' 또는 '마지막 응답 HOP=차단 장비' 무근거 단정 문구를 검출한다.
fn check_unsupported_blocking_claims(text: &str, context: &str, errors: &mut Vec<String>) {
    let normalized_fw = text
        .replace("방화벽차단", "방화벽 차단")
        .replace("방화벽에 의한 차단 확정", "방화벽 차단 확정")
        .replace("방화벽 차단으로 확정", "방화벽 차단 확정");

    let mut search_slice = normalized_fw.as_str();
    while let Some(idx) = search_slice.find("방화벽 차단 확정") {
        let after = search_slice
            .get(idx + "방화벽 차단 확정".len()..)
            .unwrap_or("");
        if !has_immediate_scoped_negation(after) {
            errors.push(format!(
                "{context}: 근거 없는 '방화벽 차단 확정' 단정 문구는 허용되지 않습니다"
            ));
            break;
        }
        search_slice = after;
    }

    let lower = text.to_ascii_lowercase();
    for clause in lower.split(['.', ',', '!', '?', ';', '\n', '\r']) {
        let compact: String = clause.chars().filter(|c| !c.is_whitespace()).collect();
        let hop_patterns = [
            "마지막응답hop=차단장비",
            "마지막응답홉=차단장비",
            "마지막hop=차단장비",
            "마지막홉=차단장비",
            "lasthop=차단장비",
            "마지막응답hop은차단장비",
            "마지막응답hop이차단장비",
            "마지막응답홉은차단장비",
            "마지막응답홉이차단장비",
            "마지막응답hop을차단장비",
            "마지막응답홉을차단장비",
        ];
        for pat in hop_patterns {
            if let Some(pos) = compact.find(pat) {
                let after = compact.get(pos + pat.len()..).unwrap_or("");
                let negated = [
                    "불가",
                    "아님",
                    "아닙니다",
                    "할수없",
                    "단정불가",
                    "단정할수없",
                    "단정하지않",
                    "간주하지않",
                    "않음",
                    "금지",
                ]
                .iter()
                .any(|neg| after.starts_with(neg));
                if !negated {
                    errors.push(format!(
                        "{context}: '마지막 응답 HOP=차단 장비' 단정 문구는 허용되지 않습니다"
                    ));
                    return;
                }
            }
        }
    }
}

/// ASCII 영문 약어(`SYN`, `RST`)가 독립된 토큰(앞뒤에 다른 영문자가 붙지 않음)으로 등장하는지 확인한다.
fn contains_ascii_token(clause_upper: &str, token: &str) -> Option<usize> {
    let bytes = clause_upper.as_bytes();
    let tok_bytes = token.as_bytes();
    if bytes.len() < tok_bytes.len() {
        return None;
    }
    for i in 0..=(bytes.len() - tok_bytes.len()) {
        if &bytes[i..i + tok_bytes.len()] == tok_bytes {
            let prev_alpha = i > 0 && bytes[i - 1].is_ascii_alphabetic();
            let next_alpha = i + tok_bytes.len() < bytes.len()
                && bytes[i + tok_bytes.len()].is_ascii_alphabetic();
            if !prev_alpha && !next_alpha {
                return Some(i);
            }
        }
    }
    None
}

/// SYN/RST 토큰 뒤의 절 꼬리가 긍정 주장 없이 직접적인 부정·미확인 서술로 이어지는지 확인한다.
fn is_scoped_packet_negation(tail_compact: &str) -> bool {
    const POSITIVE_ASSERTIONS: [&str; 14] = [
        "관찰됨",
        "관찰되었",
        "관찰함",
        "수신됨",
        "수신되었",
        "수신함",
        "수신확인",
        "관찰확인",
        "패킷확인",
        "포착됨",
        "포착되었",
        "검출됨",
        "발견됨",
        "확정",
    ];
    if POSITIVE_ASSERTIONS
        .iter()
        .any(|pos| tail_compact.contains(pos))
    {
        return false;
    }

    const DIRECT_PACKET_NEGATIONS: [&str; 14] = [
        "미확인",
        "확인불가",
        "관찰불가",
        "단정불가",
        "단정할수없",
        "확인할수없",
        "관찰할수없",
        "알수없",
        "관찰되지않",
        "수신되지않",
        "확인되지않",
        "의미하지않",
        "뜻하지않",
        "생성하지않",
    ];

    DIRECT_PACKET_NEGATIONS
        .iter()
        .any(|neg| tail_compact.contains(neg))
}

/// 패킷 증거 여부 및 소켓 오류 오인 방지 규칙에 따라 SYN/RST 관련 주장을 검증한다.
fn check_syn_rst_claims(
    text: &str,
    has_packet_evidence: bool,
    context: &str,
    errors: &mut Vec<String>,
) {
    for clause in text.split(['.', ',', '!', '?', ';', '\n', '\r', '(', ')']) {
        // 먼저 무관한 '미확인 사항 없음', '오류 없음' 등을 제거한 뒤 인덱스를 계산하여 UTF-8 경계와 우회를 모두 방어한다.
        let sanitized = clause
            .replace("미확인 사항 없음", "")
            .replace("미확인사항 없음", "")
            .replace("미확인사항없음", "")
            .replace("추가 오류 없음", "")
            .replace("오류 없음", "")
            .replace("문제 없음", "")
            .replace("이상 없음", "")
            .replace("누락 없음", "")
            .replace("손실 없음", "")
            .replace("드롭 없음", "");

        let upper = sanitized.to_ascii_uppercase();
        let syn_pos = contains_ascii_token(&upper, "SYN");
        let rst_pos = contains_ascii_token(&upper, "RST");

        let Some(first_pos) = (match (syn_pos, rst_pos) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        }) else {
            continue;
        };

        let tail = sanitized.get(first_pos..).unwrap_or("");
        let tail_compact: String = tail.chars().filter(|c| !c.is_whitespace()).collect();
        let is_negated_or_unknown = is_scoped_packet_negation(&tail_compact);

        let mentions_socket_refused = upper.contains("10061")
            || upper.contains("REFUSED")
            || sanitized.contains("연결 거부")
            || sanitized.contains("소켓 거부");

        if mentions_socket_refused && !is_negated_or_unknown {
            errors.push(format!(
                "{context}: 소켓 연결 거부(10061/REFUSED)를 RST 패킷 관찰로 단정할 수 없습니다"
            ));
            return;
        }

        if !has_packet_evidence && !is_negated_or_unknown {
            errors.push(format!(
                "{context}: PACKET 증거 없이 SYN/RST 패킷 관찰을 긍정 단정할 수 없습니다"
            ));
            return;
        }
    }
}

/// 문장 안전 규칙(방화벽/마지막 HOP 단정 금지 및 무근거 SYN/RST 관찰 단정 금지)을 검증한다.
fn validate_statement_safety(
    text: &str,
    has_packet_evidence: bool,
    context: &str,
    errors: &mut Vec<String>,
) {
    check_unsupported_blocking_claims(text, context, errors);
    check_syn_rst_claims(text, has_packet_evidence, context, errors);
}

/// 문자열 배열 필드를 검증하고 각 문자열 원소를 반환한다.
fn validate_string_array<'a>(
    val: Option<&'a Value>,
    field_name: &str,
    require_nonempty_items: bool,
    errors: &mut Vec<String>,
) -> Vec<&'a str> {
    let mut out = Vec::new();
    match val {
        None => errors.push(format!("{field_name} 필드가 누락되었습니다")),
        Some(v) => match v.as_array() {
            None => errors.push(format!("{field_name}는 문자열 배열이어야 합니다")),
            Some(arr) => {
                for (idx, item) in arr.iter().enumerate() {
                    match item.as_str() {
                        None => errors.push(format!("{field_name}[{idx}]는 문자열이어야 합니다")),
                        Some(s) if require_nonempty_items && s.trim().is_empty() => {
                            errors.push(format!("{field_name}[{idx}]는 비어 있을 수 없습니다"));
                        }
                        Some(s) => out.push(s),
                    }
                }
            }
        },
    }
    out
}

/// 세션 JSON 값을 G1 인터페이스 계약(스키마 1.1)에 따라 검증한다.
/// 누락된 필수 키, 잘못된 타입/범위, 미해결 증거 참조, 패킷 증거 없는 SYN/RST 단정 및
/// 무근거 방화벽/마지막 HOP 차단 단정을 모두 거부한다.
pub fn validate_session(value: &Value) -> Result<(), Vec<String>> {
    let Some(obj) = value.as_object() else {
        return Err(vec!["세션 최상위 값은 JSON 객체여야 합니다".to_string()]);
    };

    let mut errors = Vec::new();

    for key in obj.keys() {
        if !SESSION_FIELDS.contains(&key.as_str()) {
            errors.push(format!("세션에 알 수 없는 필드가 있습니다: {key}"));
        }
    }

    match obj.get("schema_version") {
        None => errors.push("schema_version 필드가 누락되었습니다".to_string()),
        Some(v) => match v.as_str() {
            Some(SCHEMA_VERSION) => {}
            Some(other) => errors.push(format!("지원하지 않는 세션 schema_version입니다: {other}")),
            None => errors.push("schema_version은 문자열이어야 합니다".to_string()),
        },
    }

    match obj.get("session_id") {
        None => errors.push("session_id 필드가 누락되었습니다".to_string()),
        Some(v) => match v.as_str() {
            Some(s) if is_valid_uuid(s) => {}
            Some(other) => {
                errors.push(format!("유효하지 않은 session_id UUID 형식입니다: {other}"))
            }
            None => errors.push("session_id는 문자열이어야 합니다".to_string()),
        },
    }

    let mut session_mode: Option<&str> = None;
    match obj.get("mode") {
        None => errors.push("mode 필드가 누락되었습니다".to_string()),
        Some(v) => match v.as_str() {
            Some(s) if ExecutionMode::parse(s).is_some() => {
                session_mode = Some(s);
            }
            Some(other) => errors.push(format!("허용되지 않는 세션 mode입니다: {other}")),
            None => errors.push("mode는 문자열이어야 합니다".to_string()),
        },
    }

    match obj.get("host_role") {
        None => errors.push("host_role 필드가 누락되었습니다".to_string()),
        Some(v) if v.is_null() => {}
        Some(v) => match v.as_str() {
            Some(role) if KNOWN_HOST_ROLES.contains(&role) => {}
            Some(other) => errors.push(format!("허용되지 않는 host_role입니다: {other}")),
            None => {
                errors.push("host_role은 'client', 'server' 또는 null이어야 합니다".to_string())
            }
        },
    }

    match obj.get("started_at_utc") {
        None => errors.push("started_at_utc 필드가 누락되었습니다".to_string()),
        Some(v) => match v.as_str() {
            Some(ts) => {
                if let Err(e) = validate_rfc3339(ts) {
                    errors.push(format!("started_at_utc 오류: {e}"));
                }
            }
            None => errors.push("started_at_utc는 RFC3339 문자열이어야 합니다".to_string()),
        },
    }

    match obj.get("timezone_offset_minutes") {
        None => errors.push("timezone_offset_minutes 필드가 누락되었습니다".to_string()),
        Some(v) if v.is_null() => {}
        Some(v) => match v.as_i64() {
            Some(offset) if (-840..=840).contains(&offset) => {}
            Some(offset) => errors.push(format!(
                "timezone_offset_minutes 범위(-840..=840) 오류: {offset}"
            )),
            None => errors.push(
                "timezone_offset_minutes는 -840..=840 범위의 정수 또는 null이어야 합니다"
                    .to_string(),
            ),
        },
    }

    match obj.get("clock_offset_ms") {
        None => errors.push("clock_offset_ms 필드가 누락되었습니다".to_string()),
        Some(v) if v.is_null() => {}
        Some(v) => {
            if v.as_i64().is_none() {
                errors.push("clock_offset_ms는 정수 또는 null이어야 합니다".to_string());
            }
        }
    }

    match obj.get("clock_uncertainty_ms") {
        None => errors.push("clock_uncertainty_ms 필드가 누락되었습니다".to_string()),
        Some(v) if v.is_null() => {}
        Some(v) => {
            if v.as_u64().is_none() {
                errors.push(
                    "clock_uncertainty_ms는 0 이상의 정수 또는 null이어야 합니다".to_string(),
                );
            }
        }
    }

    match obj.get("profile") {
        None => errors.push("profile 필드가 누락되었습니다".to_string()),
        Some(profile_val) => {
            if let Err(profile_errs) = validate_profile(profile_val) {
                for err in profile_errs {
                    errors.push(format!("profile 검증 실패: {err}"));
                }
            }
            if let Some(p_mode) = profile_val.get("mode").and_then(Value::as_str) {
                if let Some(s_mode) = session_mode {
                    if s_mode != p_mode {
                        errors.push(format!(
                            "세션 mode({s_mode})와 profile.mode({p_mode})가 일치하지 않습니다"
                        ));
                    }
                }
            }
        }
    }

    // Evidence 검증 및 ID -> kind 매핑 수집
    let mut evidence_kinds_by_id: BTreeMap<String, String> = BTreeMap::new();
    match obj.get("evidence") {
        None => errors.push("evidence 필드가 누락되었습니다".to_string()),
        Some(v) => match v.as_array() {
            None => errors.push("evidence는 배열이어야 합니다".to_string()),
            Some(arr) => {
                for (idx, item) in arr.iter().enumerate() {
                    let Some(ev_obj) = item.as_object() else {
                        errors.push(format!("evidence[{idx}] 항목은 JSON 객체여야 합니다"));
                        continue;
                    };

                    for key in ev_obj.keys() {
                        if !EVIDENCE_FIELDS.contains(&key.as_str()) {
                            errors.push(format!("evidence[{idx}]에 알 수 없는 필드: {key}"));
                        }
                    }

                    let mut ev_id: Option<String> = None;
                    match ev_obj.get("evidence_id") {
                        None => errors.push(format!("evidence[{idx}].evidence_id 누락")),
                        Some(id_val) => match id_val.as_str() {
                            None => {
                                errors.push(format!(
                                    "evidence[{idx}].evidence_id는 문자열이어야 합니다"
                                ));
                            }
                            Some(s) if s.trim().is_empty() => {
                                errors.push(format!(
                                    "evidence[{idx}].evidence_id는 비어 있을 수 없습니다"
                                ));
                            }
                            Some(s) => {
                                if evidence_kinds_by_id.contains_key(s) {
                                    errors.push(format!("중복된 evidence_id입니다: {s}"));
                                }
                                ev_id = Some(s.to_string());
                            }
                        },
                    }

                    let mut ev_kind: Option<String> = None;
                    match ev_obj.get("kind") {
                        None => errors.push(format!("evidence[{idx}].kind 누락")),
                        Some(k_val) => match k_val.as_str() {
                            Some(k) if KNOWN_EVIDENCE_KINDS.contains(&k) => {
                                ev_kind = Some(k.to_string());
                            }
                            Some(other) => {
                                errors.push(format!("허용되지 않는 evidence kind입니다: {other}"));
                            }
                            None => {
                                errors.push(format!("evidence[{idx}].kind는 문자열이어야 합니다"))
                            }
                        },
                    }

                    match ev_obj.get("artifact_path") {
                        None => errors.push(format!("evidence[{idx}].artifact_path 누락")),
                        Some(p_val) if p_val.is_null() => {}
                        Some(p_val) => match p_val.as_str() {
                            Some(path_str) => {
                                if let Err(e) = validate_relative_artifact_path(path_str) {
                                    errors.push(format!("evidence[{idx}].artifact_path 오류: {e}"));
                                }
                            }
                            None => errors.push(format!(
                                "evidence[{idx}].artifact_path는 상대 경로 문자열 또는 null이어야 합니다"
                            )),
                        },
                    }

                    match ev_obj.get("synthetic") {
                        None => errors.push(format!("evidence[{idx}].synthetic 누락")),
                        Some(s_val) => {
                            if !s_val.is_boolean() {
                                errors.push(format!(
                                    "evidence[{idx}].synthetic은 불리언이어야 합니다"
                                ));
                            }
                        }
                    }

                    if let Some(id) = ev_id {
                        let kind_str = ev_kind.unwrap_or_default();
                        evidence_kinds_by_id.insert(id, kind_str);
                    }
                }
            }
        },
    }

    // FeatureResult 검증
    match obj.get("feature_results") {
        None => errors.push("feature_results 필드가 누락되었습니다".to_string()),
        Some(v) => match v.as_array() {
            None => errors.push("feature_results는 배열이어야 합니다".to_string()),
            Some(arr) => {
                let mut seen_features = BTreeSet::new();
                for (idx, item) in arr.iter().enumerate() {
                    let Some(fr_obj) = item.as_object() else {
                        errors.push(format!(
                            "feature_results[{idx}] 항목은 JSON 객체여야 합니다"
                        ));
                        continue;
                    };

                    for key in fr_obj.keys() {
                        if !FEATURE_RESULT_FIELDS.contains(&key.as_str()) {
                            errors.push(format!("feature_results[{idx}]에 알 수 없는 필드: {key}"));
                        }
                    }

                    let mut expected_group: Option<&'static str> = None;
                    let mut current_fid: Option<&str> = None;
                    match fr_obj.get("feature_id") {
                        None => errors.push(format!("feature_results[{idx}].feature_id 누락")),
                        Some(f_val) => match f_val.as_str() {
                            None => errors.push(format!(
                                "feature_results[{idx}].feature_id는 문자열이어야 합니다"
                            )),
                            Some(fid) => {
                                current_fid = Some(fid);
                                expected_group = expected_group_for_feature(fid);
                                if expected_group.is_none() {
                                    errors.push(format!(
                                        "feature_results[{idx}] 알 수 없는 feature_id: {fid}"
                                    ));
                                }
                                if !seen_features.insert(fid.to_string()) {
                                    errors.push(format!(
                                        "feature_results에 중복된 feature_id가 있습니다: {fid}"
                                    ));
                                }
                            }
                        },
                    }

                    match fr_obj.get("group_id") {
                        None => errors.push(format!("feature_results[{idx}].group_id 누락")),
                        Some(g_val) => match g_val.as_str() {
                            None => errors.push(format!(
                                "feature_results[{idx}].group_id는 문자열이어야 합니다"
                            )),
                            Some(gid) => {
                                if GroupId::parse(gid).is_none() {
                                    errors.push(format!(
                                        "feature_results[{idx}] 허용되지 않는 group_id: {gid}"
                                    ));
                                } else if expected_group.is_some_and(|exp| exp != gid) {
                                    errors.push(format!(
                                        "feature_results[{idx}] feature_id와 group_id({gid}) 불일치"
                                    ));
                                }
                            }
                        },
                    }

                    let mut current_status: Option<&str> = None;
                    match fr_obj.get("status") {
                        None => errors.push(format!("feature_results[{idx}].status 누락")),
                        Some(st_val) => match st_val.as_str() {
                            Some(st) if KNOWN_STATUSES.contains(&st) => {
                                current_status = Some(st);
                            }
                            Some(other) => errors.push(format!(
                                "feature_results[{idx}] 허용되지 않는 status: {other}"
                            )),
                            None => errors.push(format!(
                                "feature_results[{idx}].status는 문자열이어야 합니다"
                            )),
                        },
                    }

                    let mut current_class: Option<&str> = None;
                    match fr_obj.get("classification") {
                        None => errors.push(format!("feature_results[{idx}].classification 누락")),
                        Some(c_val) if c_val.is_null() => {}
                        Some(c_val) => match c_val.as_str() {
                            Some(c) if KNOWN_CLASSIFICATIONS.contains(&c) => {
                                current_class = Some(c);
                            }
                            Some(other) => errors.push(format!(
                                "feature_results[{idx}] 허용되지 않는 classification: {other}"
                            )),
                            None => errors.push(format!(
                                "feature_results[{idx}].classification은 문자열 또는 null이어야 합니다"
                            )),
                        },
                    }

                    let ev_refs = validate_string_array(
                        fr_obj.get("evidence_ids"),
                        &format!("feature_results[{idx}].evidence_ids"),
                        true,
                        &mut errors,
                    );
                    let mut has_packet_ev = false;
                    for &ev_id in &ev_refs {
                        match evidence_kinds_by_id.get(ev_id) {
                            None => errors.push(format!(
                                "feature_results[{idx}] 존재하지 않는 evidence_id 참조: {ev_id}"
                            )),
                            Some(kind) if kind == "PACKET" => {
                                has_packet_ev = true;
                            }
                            Some(_) => {}
                        }
                    }

                    if current_class == Some("OBSERVED") && ev_refs.is_empty() {
                        errors.push(format!(
                            "feature_results[{idx}] OBSERVED 분류는 최소 1개 이상의 evidence_ids가 필요합니다"
                        ));
                    }

                    if let Some(fid) = current_fid {
                        if PACKET_REQUIRED_FEATURES.contains(&fid)
                            && (current_status == Some("PASS") || current_class == Some("OBSERVED"))
                            && !has_packet_ev
                        {
                            errors.push(format!(
                                "feature_results[{idx}] '{fid}'의 PASS/OBSERVED 판정에는 PACKET 증거가 필요합니다"
                            ));
                        }
                    }

                    for ts_field in ["started_at_utc", "ended_at_utc"] {
                        match fr_obj.get(ts_field) {
                            None => {
                                errors.push(format!("feature_results[{idx}].{ts_field} 누락"));
                            }
                            Some(ts_val) if ts_val.is_null() => {}
                            Some(ts_val) => match ts_val.as_str() {
                                Some(ts_str) => {
                                    if let Err(e) = validate_rfc3339(ts_str) {
                                        errors.push(format!(
                                            "feature_results[{idx}].{ts_field} 오류: {e}"
                                        ));
                                    }
                                }
                                None => errors.push(format!(
                                    "feature_results[{idx}].{ts_field}는 RFC3339 문자열 또는 null이어야 합니다"
                                )),
                            },
                        }
                    }

                    match fr_obj.get("duration_ms") {
                        None => errors.push(format!("feature_results[{idx}].duration_ms 누락")),
                        Some(d_val) if d_val.is_null() => {}
                        Some(d_val) => {
                            if d_val.as_u64().is_none() {
                                errors.push(format!(
                                    "feature_results[{idx}].duration_ms는 0 이상의 정수 또는 null이어야 합니다"
                                ));
                            }
                        }
                    }

                    match fr_obj.get("error_code") {
                        None => errors.push(format!("feature_results[{idx}].error_code 누락")),
                        Some(e_val) if e_val.is_null() => {}
                        Some(e_val) => {
                            if e_val.as_i64().is_none() {
                                errors.push(format!(
                                    "feature_results[{idx}].error_code는 정수 또는 null이어야 합니다"
                                ));
                            }
                        }
                    }

                    let lims = validate_string_array(
                        fr_obj.get("limitations"),
                        &format!("feature_results[{idx}].limitations"),
                        false,
                        &mut errors,
                    );
                    for lim in lims {
                        validate_statement_safety(
                            lim,
                            has_packet_ev,
                            &format!("feature_results[{idx}].limitations"),
                            &mut errors,
                        );
                    }

                    let checks = validate_string_array(
                        fr_obj.get("next_checks"),
                        &format!("feature_results[{idx}].next_checks"),
                        false,
                        &mut errors,
                    );
                    for chk in checks {
                        validate_statement_safety(
                            chk,
                            has_packet_ev,
                            &format!("feature_results[{idx}].next_checks"),
                            &mut errors,
                        );
                    }
                }
            }
        },
    }

    // Findings 검증
    match obj.get("findings") {
        None => errors.push("findings 필드가 누락되었습니다".to_string()),
        Some(v) => match v.as_array() {
            None => errors.push("findings는 배열이어야 합니다".to_string()),
            Some(arr) => {
                for (idx, item) in arr.iter().enumerate() {
                    let Some(f_obj) = item.as_object() else {
                        errors.push(format!("findings[{idx}] 항목은 JSON 객체여야 합니다"));
                        continue;
                    };

                    for key in f_obj.keys() {
                        if !FINDING_FIELDS.contains(&key.as_str()) {
                            errors.push(format!("findings[{idx}]에 알 수 없는 필드: {key}"));
                        }
                    }

                    let mut classification: Option<&str> = None;
                    match f_obj.get("classification") {
                        None => errors.push(format!("findings[{idx}].classification 누락")),
                        Some(c_val) => match c_val.as_str() {
                            Some(c) if KNOWN_CLASSIFICATIONS.contains(&c) => {
                                classification = Some(c);
                            }
                            Some(other) => errors.push(format!(
                                "findings[{idx}] 허용되지 않는 classification: {other}"
                            )),
                            None => errors.push(format!(
                                "findings[{idx}].classification은 문자열이어야 합니다"
                            )),
                        },
                    }

                    let ev_refs = validate_string_array(
                        f_obj.get("evidence_ids"),
                        &format!("findings[{idx}].evidence_ids"),
                        true,
                        &mut errors,
                    );
                    let mut has_packet_ev = false;
                    for &ev_id in &ev_refs {
                        match evidence_kinds_by_id.get(ev_id) {
                            None => errors.push(format!(
                                "findings[{idx}] 존재하지 않는 evidence_id 참조: {ev_id}"
                            )),
                            Some(kind) if kind == "PACKET" => {
                                has_packet_ev = true;
                            }
                            Some(_) => {}
                        }
                    }

                    if classification == Some("OBSERVED") && ev_refs.is_empty() {
                        errors.push(format!(
                            "findings[{idx}] OBSERVED 분류는 비어 있지 않은 evidence_ids가 필수입니다"
                        ));
                    }

                    match f_obj.get("statement") {
                        None => errors.push(format!("findings[{idx}].statement 누락")),
                        Some(s_val) => match s_val.as_str() {
                            None => {
                                errors.push(format!(
                                    "findings[{idx}].statement는 문자열이어야 합니다"
                                ));
                            }
                            Some(s) if s.trim().is_empty() => {
                                errors.push(format!(
                                    "findings[{idx}].statement는 비어 있을 수 없습니다"
                                ));
                            }
                            Some(s) => {
                                validate_statement_safety(
                                    s,
                                    has_packet_ev,
                                    &format!("findings[{idx}].statement"),
                                    &mut errors,
                                );
                            }
                        },
                    }

                    match f_obj.get("confidence") {
                        None => errors.push(format!("findings[{idx}].confidence 누락")),
                        Some(conf_val) => match conf_val.as_str() {
                            Some(c) if KNOWN_CONFIDENCE.contains(&c) => {}
                            Some(other) => errors
                                .push(format!("findings[{idx}] 허용되지 않는 confidence: {other}")),
                            None => errors
                                .push(format!("findings[{idx}].confidence는 문자열이어야 합니다")),
                        },
                    }

                    let lims = validate_string_array(
                        f_obj.get("limitations"),
                        &format!("findings[{idx}].limitations"),
                        false,
                        &mut errors,
                    );
                    for lim in lims {
                        validate_statement_safety(
                            lim,
                            has_packet_ev,
                            &format!("findings[{idx}].limitations"),
                            &mut errors,
                        );
                    }

                    let checks = validate_string_array(
                        f_obj.get("next_checks"),
                        &format!("findings[{idx}].next_checks"),
                        false,
                        &mut errors,
                    );
                    for chk in checks {
                        validate_statement_safety(
                            chk,
                            has_packet_ev,
                            &format!("findings[{idx}].next_checks"),
                            &mut errors,
                        );
                    }
                }
            }
        },
    }

    let session_has_any_packet_ev = evidence_kinds_by_id.values().any(|k| k == "PACKET");
    let top_lims = validate_string_array(obj.get("limitations"), "limitations", false, &mut errors);
    for lim in top_lims {
        validate_statement_safety(lim, session_has_any_packet_ev, "limitations", &mut errors);
    }

    match obj.get("resource_metrics") {
        None => errors.push("resource_metrics 필드가 누락되었습니다".to_string()),
        Some(v) => match v.as_object() {
            None => errors.push("resource_metrics는 JSON 객체여야 합니다".to_string()),
            Some(rm_obj) => {
                for key in rm_obj.keys() {
                    if !RESOURCE_METRICS_FIELDS.contains(&key.as_str()) {
                        errors.push(format!("resource_metrics에 알 수 없는 필드: {key}"));
                    }
                }

                match rm_obj.get("peak_rss_bytes") {
                    None => errors.push("resource_metrics.peak_rss_bytes 누락".to_string()),
                    Some(val) if val.is_null() => {}
                    Some(val) => {
                        if val.as_u64().is_none() {
                            errors.push(
                                "resource_metrics.peak_rss_bytes는 0 이상의 정수 또는 null이어야 합니다"
                                    .to_string(),
                            );
                        }
                    }
                }

                match rm_obj.get("avg_cpu_percent") {
                    None => errors.push("resource_metrics.avg_cpu_percent 누락".to_string()),
                    Some(val) if val.is_null() => {}
                    Some(val) => match val.as_f64() {
                        Some(cpu) if cpu.is_finite() && (0.0..=100.0).contains(&cpu) => {}
                        Some(cpu) => errors.push(format!(
                            "resource_metrics.avg_cpu_percent 범위(0..=100) 오류: {cpu}"
                        )),
                        None => errors.push(
                            "resource_metrics.avg_cpu_percent는 0..=100 숫자 또는 null이어야 합니다"
                                .to_string(),
                        ),
                    },
                }

                match rm_obj.get("capture_drops") {
                    None => errors.push("resource_metrics.capture_drops 누락".to_string()),
                    Some(val) if val.is_null() => {}
                    Some(val) => {
                        if val.as_u64().is_none() {
                            errors.push(
                                "resource_metrics.capture_drops는 0 이상의 정수 또는 null이어야 합니다"
                                    .to_string(),
                            );
                        }
                    }
                }
            }
        },
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    if let Err(err) = serde_json::from_value::<Session>(value.clone()) {
        return Err(vec![format!("세션 DTO 역직렬화 실패: {err}")]);
    }

    Ok(())
}

/// 레거시 1.0 세션 JSON을 무손실 래퍼(`{ original, converted, transformations }`)로 변환한다.
/// - `original`: 알 수 없는 추가 필드를 포함한 원본 입력 JSON 그대로 보존
/// - `converted`: G1 계약(스키마 1.1)을 준수하는 정규화된 `Session` JSON
/// - `transformations`: 수행된 정규화 및 미확인 처리 내역 목록
///
/// 주의: 원본에 없는 메타데이터(`host_role`, `timezone_offset_minutes` 등)나
/// 검증되지 않은 `PASS` 결과, 패킷 캡처 근거(`PACKET`), 아티팩트 경로를 절대 추측하거나 생성하지 않는다.
pub fn convert_legacy_session(value: &Value) -> Result<Value, Vec<String>> {
    let Some(obj) = value.as_object() else {
        return Err(vec![
            "레거시 세션 최상위 값은 JSON 객체여야 합니다".to_string(),
        ]);
    };

    let mut errors = Vec::new();

    match obj.get("schema_version") {
        None => errors.push("레거시 schema_version 필드가 누락되었습니다".to_string()),
        Some(v) => match v.as_str() {
            Some(LEGACY_SCHEMA_VERSION) => {}
            Some(other) => errors.push(format!(
                "레거시 변환은 schema_version '1.0'만 지원합니다: {other}"
            )),
            None => errors.push("레거시 schema_version은 문자열이어야 합니다".to_string()),
        },
    }

    let mut session_id = String::new();
    match obj.get("session_id") {
        None => errors.push("레거시 session_id 필드가 누락되었습니다".to_string()),
        Some(v) => match v.as_str() {
            Some(s) if is_valid_uuid(s) => {
                session_id = s.to_string();
            }
            Some(other) => errors.push(format!("레거시 session_id UUID 형식 오류: {other}")),
            None => errors.push("레거시 session_id는 문자열이어야 합니다".to_string()),
        },
    }

    let mut mode = String::new();
    match obj.get("mode") {
        None => errors.push("레거시 mode 필드가 누락되었습니다".to_string()),
        Some(v) => match v.as_str() {
            Some(s) if ExecutionMode::parse(s).is_some() => {
                mode = s.to_string();
            }
            Some(other) => errors.push(format!("레거시 허용되지 않는 mode입니다: {other}")),
            None => errors.push("레거시 mode는 문자열이어야 합니다".to_string()),
        },
    }

    let mut started_at_utc = String::new();
    match obj.get("started_at_utc") {
        None => errors.push("레거시 started_at_utc 필드가 누락되었습니다".to_string()),
        Some(v) => match v.as_str() {
            Some(ts) => match validate_rfc3339(ts) {
                Ok(()) => started_at_utc = ts.to_string(),
                Err(e) => errors.push(format!("레거시 started_at_utc 오류: {e}")),
            },
            None => errors.push("레거시 started_at_utc는 문자열이어야 합니다".to_string()),
        },
    }

    let mut host_role: Option<String> = None;
    if let Some(hr_val) = obj.get("host_role") {
        if !hr_val.is_null() {
            match hr_val.as_str() {
                Some(r) if KNOWN_HOST_ROLES.contains(&r) => {
                    host_role = Some(r.to_string());
                }
                Some(other) => errors.push(format!("레거시 허용되지 않는 host_role: {other}")),
                None => errors.push("레거시 host_role은 문자열 또는 null이어야 합니다".to_string()),
            }
        }
    }

    let mut timezone_offset_minutes: Option<i32> = None;
    if let Some(tz_val) = obj.get("timezone_offset_minutes") {
        if !tz_val.is_null() {
            match tz_val.as_i64() {
                Some(offset) if (-840..=840).contains(&offset) => {
                    timezone_offset_minutes = Some(offset as i32);
                }
                Some(offset) => errors.push(format!(
                    "레거시 timezone_offset_minutes 범위 오류: {offset}"
                )),
                None => errors.push(
                    "레거시 timezone_offset_minutes는 정수 또는 null이어야 합니다".to_string(),
                ),
            }
        }
    }

    let mut target_host = String::new();
    let mut target_port = 0u16;
    let mut used_ip_key = false;

    match obj.get("target") {
        None => errors.push("레거시 target 필드가 누락되었습니다".to_string()),
        Some(t_val) => match t_val.as_object() {
            None => errors.push("레거시 target은 JSON 객체여야 합니다".to_string()),
            Some(t_obj) => {
                let ip_opt = t_obj.get("ip");
                let host_opt = t_obj.get("host");

                match (ip_opt, host_opt) {
                    (None, None) => {
                        errors
                            .push("레거시 target.ip 또는 target.host가 누락되었습니다".to_string());
                    }
                    (Some(ip_v), None) => match ip_v.as_str() {
                        None => errors.push("레거시 target.ip는 문자열이어야 합니다".to_string()),
                        Some(s) => match validate_target_host_str(s) {
                            Ok(()) => {
                                target_host = s.to_string();
                                used_ip_key = true;
                            }
                            Err(e) => errors.push(e),
                        },
                    },
                    (None, Some(host_v)) => match host_v.as_str() {
                        None => errors.push("레거시 target.host는 문자열이어야 합니다".to_string()),
                        Some(s) => match validate_target_host_str(s) {
                            Ok(()) => {
                                target_host = s.to_string();
                            }
                            Err(e) => errors.push(e),
                        },
                    },
                    (Some(ip_v), Some(host_v)) => {
                        let ip_s = ip_v.as_str();
                        let host_s = host_v.as_str();
                        match (ip_s, host_s) {
                            (Some(a), Some(b)) if a == b => match validate_target_host_str(a) {
                                Ok(()) => target_host = a.to_string(),
                                Err(e) => errors.push(e),
                            },
                            (Some(_), Some(_)) => errors.push(
                                "레거시 target.ip와 target.host 값이 서로 불일치합니다".to_string(),
                            ),
                            _ => errors.push(
                                "레거시 target.ip 및 target.host는 문자열이어야 합니다".to_string(),
                            ),
                        }
                    }
                }

                match t_obj.get("port") {
                    None => errors.push("레거시 target.port 필드가 누락되었습니다".to_string()),
                    Some(p_val) => match p_val.as_u64() {
                        Some(p) if (1..=65535).contains(&p) => {
                            target_port = p as u16;
                        }
                        Some(p) => errors.push(format!("레거시 target.port 범위 오류: {p}")),
                        None => errors
                            .push("레거시 target.port는 1..=65535 정수여야 합니다".to_string()),
                    },
                }

                match t_obj.get("protocol") {
                    None => errors.push("레거시 target.protocol 필드가 누락되었습니다".to_string()),
                    Some(proto_val) => match proto_val.as_str() {
                        Some("TCP") => {}
                        Some(other) => errors.push(format!(
                            "레거시 target.protocol은 'TCP'여야 합니다: {other}"
                        )),
                        None => {
                            errors.push("레거시 target.protocol은 문자열이어야 합니다".to_string());
                        }
                    },
                }
            }
        },
    }

    if let Some(tests_val) = obj.get("tests") {
        if !tests_val.is_array() {
            errors.push("레거시 tests 필드는 배열이어야 합니다".to_string());
        }
    }

    if let Some(artifacts_val) = obj.get("artifacts") {
        if !artifacts_val.is_array() {
            errors.push("레거시 artifacts 필드는 배열이어야 합니다".to_string());
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    let mut transformations = vec![
        "schema_version을 '1.0'에서 '1.1'로 변환하고 원본 JSON을 original 필드에 무손실 보존함"
            .to_string(),
    ];

    if used_ip_key {
        transformations
            .push("target.ip 리터럴 값을 변경 없이 profile.target.host로 매핑함".to_string());
    } else {
        transformations
            .push("target.host 리터럴 값을 변경 없이 profile.target.host로 보존함".to_string());
    }

    if host_role.is_none() {
        transformations.push(
            "원본에 host_role 정보가 없어 추측('client' 등)하지 않고 null로 유지함".to_string(),
        );
    }

    if timezone_offset_minutes.is_none() {
        transformations.push(
            "원본에 timezone_offset_minutes가 없어 started_at_utc가 Z로 끝나도 0으로 가정하지 않고 null로 유지함"
                .to_string(),
        );
    }

    transformations.push(
        "profile.selected_features는 빈 배열([]), capture_approved는 false로 설정하고 limits는 계약 정책 기본값(과거 측정치 아님)으로 정규화함"
            .to_string(),
    );
    transformations.push(
        "검증되지 않은 레거시 시험·아티팩트로부터 가짜 PASS 결과나 PACKET/IMPORT 증거를 생성하지 않고 UNKNOWN 판정으로 기록함"
            .to_string(),
    );

    let mut finding_limitations = vec![
        "레거시 1.0 데이터에는 G1 1.1 계약이 요구하는 구조화된 증거(Evidence)가 없어 PASS/FAIL을 단정하지 않음"
            .to_string(),
        "패킷 캡처 증거가 없으므로 SYN/RST 패킷 관찰 여부 미확인".to_string(),
    ];

    if obj
        .get("capture")
        .and_then(Value::as_object)
        .and_then(|c| c.get("enabled"))
        .and_then(Value::as_bool)
        == Some(true)
    {
        finding_limitations.push(
            "원본 capture.enabled=true 설정만으로는 실제 패킷 캡처 수행이나 패킷 증거 존재를 입증할 수 없음"
                .to_string(),
        );
        transformations.push(
            "원본 capture.enabled=true를 패킷 캡처 증거로 간주하지 않고 capture_approved=false 및 evidence=[]로 유지함"
                .to_string(),
        );
    }

    let profile = Profile {
        schema_version: SCHEMA_VERSION.to_string(),
        profile_id: format!("legacy-{session_id}"),
        label: "레거시 1.0 변환 프로필".to_string(),
        mode: mode.clone(),
        selected_features: Vec::new(),
        capture_approved: false,
        target: Target {
            host: target_host,
            port: target_port,
            protocol: "TCP".to_string(),
        },
        limits: Limits {
            tcp_timeout_ms: 5000,
            max_hops: 30,
            retries: 0,
            max_concurrent_tcp: 4,
            capture_duration_secs: 30,
            capture_max_bytes: 52_428_800,
            log_retention_days: 30,
            ui_updates_per_second: 4,
        },
    };

    let converted_session = Session {
        schema_version: SCHEMA_VERSION.to_string(),
        session_id,
        mode,
        host_role,
        started_at_utc,
        timezone_offset_minutes,
        clock_offset_ms: None,
        clock_uncertainty_ms: None,
        profile,
        evidence: Vec::new(),
        feature_results: Vec::new(),
        findings: vec![Finding {
            classification: "UNKNOWN".to_string(),
            statement: "레거시 1.0 세션에서 변환되었으며 검증된 1.1 증거가 없어 실행 결과를 미확인(UNKNOWN)으로 보존함"
                .to_string(),
            evidence_ids: Vec::new(),
            confidence: "low".to_string(),
            limitations: finding_limitations,
            next_checks: vec![
                "G1 1.1 스키마 환경에서 필요한 기능을 명시적으로 선택하여 재진단 수행".to_string(),
            ],
        }],
        limitations: vec![
            "레거시 1.0 무손실 변환 세션: 출처가 불명확한 메타데이터와 자원 지표는 null로 유지함"
                .to_string(),
        ],
        resource_metrics: ResourceMetrics {
            peak_rss_bytes: None,
            avg_cpu_percent: None,
            capture_drops: None,
        },
    };

    let converted_value = serde_json::to_value(&converted_session)
        .map_err(|e| vec![format!("변환된 세션 직렬화 실패: {e}")])?;

    validate_session(&converted_value)?;

    Ok(json!({
        "original": value.clone(),
        "converted": converted_value,
        "transformations": transformations,
    }))
}
