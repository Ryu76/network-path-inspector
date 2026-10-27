//! Network Quick Check 전용 DTO 및 어댑터 모듈.
//!
//! 이 모듈은 Part B(Network Quick Check)의 계약(qg1-contract.json)에 정의된
//! 단일 진단 측정 결과 DTO(`QuickResult`), 컨텍스트(`QuickContext`),
//! 그리고 공통 프로브 결과(`TcpMeasurement`)를 Quick 결과로 변환하는 어댑터를 제공합니다.

use std::net::{IpAddr, SocketAddr};

use npi_probes::tcp::TcpMeasurement;
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize};

/// Quick Check 고정 스키마 버전 ("1.0").
pub const QUICK_SCHEMA_VERSION: &str = "1.0";

/// Quick Check 고정 제품 식별자 ("network-quick-check").
pub const QUICK_PRODUCT_NAME: &str = "network-quick-check";

/// 계약에 정의된 허용 상태 목록.
pub const STATUS_VALUES: [&str; 5] = ["PASS", "FAIL", "WARN", "SKIPPED", "UNKNOWN"];
pub const STATUS_VALUES_COUNT: usize = 5;

/// 계약에 정의된 허용 근거 수준 목록.
pub const EVIDENCE_VALUES: [&str; 3] = ["OBSERVED", "INFERRED", "UNKNOWN"];
pub const EVIDENCE_VALUES_COUNT: usize = 3;

/// 계약에 정의된 허용 기능 식별자 목록.
pub const FEATURE_VALUES: [&str; 5] = [
    "tcp_connect",
    "icmp_ping",
    "icmp_traceroute",
    "dns_lookup",
    "local_network",
];
pub const FEATURE_VALUES_COUNT: usize = 5;

/// Quick Check 진단 결과 상태 열거형.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum QuickStatus {
    PASS,
    FAIL,
    WARN,
    SKIPPED,
    UNKNOWN,
}

impl QuickStatus {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::PASS => "PASS",
            Self::FAIL => "FAIL",
            Self::WARN => "WARN",
            Self::SKIPPED => "SKIPPED",
            Self::UNKNOWN => "UNKNOWN",
        }
    }
}

/// Quick Check 진단 근거 수준 열거형.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum EvidenceLevel {
    OBSERVED,
    INFERRED,
    UNKNOWN,
}

impl EvidenceLevel {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::OBSERVED => "OBSERVED",
            Self::INFERRED => "INFERRED",
            Self::UNKNOWN => "UNKNOWN",
        }
    }
}

/// Quick Check 지원 기능 식별자 열거형.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuickFeature {
    TcpConnect,
    IcmpPing,
    IcmpTraceroute,
    DnsLookup,
    LocalNetwork,
}

impl QuickFeature {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::TcpConnect => "tcp_connect",
            Self::IcmpPing => "icmp_ping",
            Self::IcmpTraceroute => "icmp_traceroute",
            Self::DnsLookup => "dns_lookup",
            Self::LocalNetwork => "local_network",
        }
    }
}

/// RFC3339 호환 ISO8601 부분집합 일시 문자열 검증 함수.
///
/// 형식: `YYYY-MM-DDTHH:MM:SS[.fraction](Z|+HH:MM|-HH:MM)`
/// 윤년, 월별 일수(1..=28/29/30/31), 시(0..=23), 분(0..=59), 초(0..=59) 및 offset을 검사합니다.
/// 지원하지 않는 윤초(60)는 명확한 Err로 처리됩니다.
pub fn validate_rfc3339_timestamp(s: &str) -> Result<(), String> {
    if !s.is_ascii() {
        return Err("타임스탬프는 ASCII 문자열이어야 합니다.".to_string());
    }
    if s.len() < 20 {
        return Err(
            "타임스탬프 길이가 너무 짧습니다 (최소 YYYY-MM-DDTHH:MM:SSZ 형식 필요).".to_string(),
        );
    }

    let bytes = s.as_bytes();
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return Err("날짜 구분자('-')가 올바르지 않습니다.".to_string());
    }

    if !bytes[0..4].iter().all(|b| b.is_ascii_digit()) {
        return Err("연도는 4자리 숫자여야 합니다.".to_string());
    }
    let year: u32 = s[0..4]
        .parse()
        .map_err(|_| "연도는 4자리 숫자여야 합니다.".to_string())?;
    if !(1..=9999).contains(&year) {
        return Err("연도는 0001..=9999 범위여야 합니다.".to_string());
    }

    if !bytes[5..7].iter().all(|b| b.is_ascii_digit()) {
        return Err("월은 2자리 숫자여야 합니다.".to_string());
    }
    let month: u32 = s[5..7]
        .parse()
        .map_err(|_| "월은 2자리 숫자여야 합니다.".to_string())?;
    if !(1..=12).contains(&month) {
        return Err("월은 01..=12 범위여야 합니다.".to_string());
    }

    if !bytes[8..10].iter().all(|b| b.is_ascii_digit()) {
        return Err("일은 2자리 숫자여야 합니다.".to_string());
    }
    let day: u32 = s[8..10]
        .parse()
        .map_err(|_| "일은 2자리 숫자여야 합니다.".to_string())?;

    let is_leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap {
                29
            } else {
                28
            }
        }
        _ => unreachable!(),
    };

    if day == 0 || day > max_day {
        return Err(format!(
            "해당 월({month}월)의 유효한 일자가 아닙니다 (1..={max_day})."
        ));
    }

    let sep = bytes[10];
    if sep != b'T' && sep != b't' {
        return Err("날짜와 시간 구분자는 'T'여야 합니다.".to_string());
    }

    if bytes[13] != b':' || bytes[16] != b':' {
        return Err("시간 구분자(':')가 올바르지 않습니다.".to_string());
    }

    if !bytes[11..13].iter().all(|b| b.is_ascii_digit()) {
        return Err("시는 2자리 숫자여야 합니다.".to_string());
    }
    let hour: u32 = s[11..13]
        .parse()
        .map_err(|_| "시는 2자리 숫자여야 합니다.".to_string())?;
    if hour > 23 {
        return Err("시는 00..=23 범위여야 합니다.".to_string());
    }

    if !bytes[14..16].iter().all(|b| b.is_ascii_digit()) {
        return Err("분은 2자리 숫자여야 합니다.".to_string());
    }
    let minute: u32 = s[14..16]
        .parse()
        .map_err(|_| "분은 2자리 숫자여야 합니다.".to_string())?;
    if minute > 59 {
        return Err("분은 00..=59 범위여야 합니다.".to_string());
    }

    if !bytes[17..19].iter().all(|b| b.is_ascii_digit()) {
        return Err("초는 2자리 숫자여야 합니다.".to_string());
    }
    let second: u32 = s[17..19]
        .parse()
        .map_err(|_| "초는 2자리 숫자여야 합니다.".to_string())?;
    if second == 60 {
        return Err("지원하지 않는 윤초(60)입니다.".to_string());
    }
    if second > 59 {
        return Err("초는 00..=59 범위여야 합니다.".to_string());
    }

    let mut rest = &s[19..];
    if rest.starts_with('.') {
        rest = &rest[1..];
        let frac_len = rest.bytes().take_while(|b| b.is_ascii_digit()).count();
        if frac_len == 0 {
            return Err("분수초('.') 뒤에는 최소 1자리 이상의 숫자가 필요합니다.".to_string());
        }
        rest = &rest[frac_len..];
    }

    if rest == "Z" || rest == "z" {
        Ok(())
    } else if rest.starts_with('+') || rest.starts_with('-') {
        if rest.len() != 6 || rest.as_bytes()[3] != b':' {
            return Err("시간대 오프셋은 ±HH:MM 형식이어야 합니다.".to_string());
        }
        let rest_bytes = rest.as_bytes();
        if !rest_bytes[1..3].iter().all(|b| b.is_ascii_digit()) {
            return Err("시간대 오프셋 시는 2자리 숫자여야 합니다.".to_string());
        }
        if !rest_bytes[4..6].iter().all(|b| b.is_ascii_digit()) {
            return Err("시간대 오프셋 분은 2자리 숫자여야 합니다.".to_string());
        }
        let tz_h: u32 = rest[1..3]
            .parse()
            .map_err(|_| "시간대 오프셋 시는 2자리 숫자여야 합니다.".to_string())?;
        let tz_m: u32 = rest[4..6]
            .parse()
            .map_err(|_| "시간대 오프셋 분은 2자리 숫자여야 합니다.".to_string())?;
        if tz_h > 23 || tz_m > 59 {
            return Err("시간대 오프셋은 00:00..=23:59 범위여야 합니다.".to_string());
        }
        Ok(())
    } else {
        Err("유효한 시간대 오프셋('Z' 또는 '±HH:MM')이 필요합니다.".to_string())
    }
}

/// Quick Check 진단 실행 컨텍스트.
///
/// 사용자가 입력한 원래의 대상 호스트명(`target_host`)과 포트, 세션 정보 등을 보존합니다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuickContext {
    pub session_id: String,
    pub timestamp_iso8601: Option<String>,
    pub source_host: Option<String>,
    pub target_host: String,
    pub target_port: u16,
}

/// Quick Check 단일 측정 결과 계약 DTO (14개 필드 고정).
///
/// - `schema_version`: 고정 "1.0"
/// - `product`: 고정 "network-quick-check"
/// - 모든 14개 필드는 필수 키로 직렬화되며, 미확인 nullable 필드는 `null`로 유지됩니다.
/// - 역직렬화 시 필수 키 부재는 거부되며, 명시적 null만 None으로 허용됩니다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QuickResult {
    pub schema_version: String,
    pub product: String,
    pub session_id: String,
    pub timestamp_iso8601: Option<String>,
    pub source_host: Option<String>,
    pub target_host: String,
    pub resolved_ip: Option<String>,
    pub target_port: u16,
    pub feature: QuickFeature,
    pub status: QuickStatus,
    pub elapsed_ms: Option<u64>,
    pub os_error_code: Option<i32>,
    pub details: serde_json::Value,
    pub evidence_level: EvidenceLevel,
}

impl<'de> Deserialize<'de> for QuickResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let obj = value
            .as_object()
            .ok_or_else(|| DeError::custom("QuickResult는 JSON 객체여야 합니다."))?;

        const REQUIRED_KEYS: [&str; 14] = [
            "schema_version",
            "product",
            "session_id",
            "timestamp_iso8601",
            "source_host",
            "target_host",
            "resolved_ip",
            "target_port",
            "feature",
            "status",
            "elapsed_ms",
            "os_error_code",
            "details",
            "evidence_level",
        ];

        // 알 수 없는 필드 거부 (deny_unknown_fields)
        for key in obj.keys() {
            if !REQUIRED_KEYS.contains(&key.as_str()) {
                return Err(DeError::custom(format!(
                    "알 수 없는 필드가 존재합니다: '{key}'"
                )));
            }
        }

        // 필수 필드 존재 확인 (nullable 필드 포함: 키 부재 거부, explicit null은 허용)
        for &key in &REQUIRED_KEYS {
            if !obj.contains_key(key) {
                return Err(DeError::custom(format!(
                    "필수 필드가 누락되었습니다: '{key}'"
                )));
            }
        }

        let schema_version_str = obj["schema_version"]
            .as_str()
            .ok_or_else(|| DeError::custom("schema_version은 문자열이어야 합니다."))?;
        if schema_version_str != QUICK_SCHEMA_VERSION {
            return Err(DeError::custom(format!(
                "schema_version은 고정값 '{QUICK_SCHEMA_VERSION}'이어야 합니다."
            )));
        }

        let product_str = obj["product"]
            .as_str()
            .ok_or_else(|| DeError::custom("product는 문자열이어야 합니다."))?;
        if product_str != QUICK_PRODUCT_NAME {
            return Err(DeError::custom(format!(
                "product는 고정값 '{QUICK_PRODUCT_NAME}'이어야 합니다."
            )));
        }

        let session_id_str = obj["session_id"]
            .as_str()
            .ok_or_else(|| DeError::custom("session_id는 문자열이어야 합니다."))?;
        if session_id_str.trim().is_empty() {
            return Err(DeError::custom("session_id는 비어있을 수 없습니다."));
        }

        let timestamp_iso8601 = match &obj["timestamp_iso8601"] {
            serde_json::Value::Null => None,
            serde_json::Value::String(s) => {
                validate_rfc3339_timestamp(s).map_err(DeError::custom)?;
                Some(s.clone())
            }
            _ => {
                return Err(DeError::custom(
                    "timestamp_iso8601는 문자열 또는 null이어야 합니다.",
                ));
            }
        };

        let source_host = match &obj["source_host"] {
            serde_json::Value::Null => None,
            serde_json::Value::String(s) => {
                if s.trim().is_empty() {
                    return Err(DeError::custom("source_host는 비어있을 수 없습니다."));
                }
                Some(s.clone())
            }
            _ => {
                return Err(DeError::custom(
                    "source_host는 문자열 또는 null이어야 합니다.",
                ));
            }
        };

        let target_host_str = obj["target_host"]
            .as_str()
            .ok_or_else(|| DeError::custom("target_host는 문자열이어야 합니다."))?;
        if target_host_str.trim().is_empty() {
            return Err(DeError::custom("target_host는 비어있을 수 없습니다."));
        }

        let resolved_ip = match &obj["resolved_ip"] {
            serde_json::Value::Null => None,
            serde_json::Value::String(s) => {
                if s.trim().is_empty() {
                    return Err(DeError::custom("resolved_ip는 비어있을 수 없습니다."));
                }
                s.parse::<IpAddr>().map_err(|_| {
                    DeError::custom("resolved_ip는 유효한 IPv4 또는 IPv6 주소여야 합니다.")
                })?;
                Some(s.clone())
            }
            _ => {
                return Err(DeError::custom(
                    "resolved_ip는 문자열 또는 null이어야 합니다.",
                ));
            }
        };

        let target_port_val = obj["target_port"]
            .as_u64()
            .ok_or_else(|| DeError::custom("target_port는 1..=65535 범위의 정수여야 합니다."))?;
        if !(1..=65535).contains(&target_port_val) {
            return Err(DeError::custom(
                "target_port는 1..=65535 범위여야 합니다 (포트 0 금지).",
            ));
        }
        let target_port = target_port_val as u16;

        let feature_str = obj["feature"]
            .as_str()
            .ok_or_else(|| DeError::custom("feature는 문자열이어야 합니다."))?;
        let feature: QuickFeature =
            serde_json::from_value(serde_json::Value::String(feature_str.to_string()))
                .map_err(|err| DeError::custom(format!("feature 역직렬화 실패: {err}")))?;

        let status_str = obj["status"]
            .as_str()
            .ok_or_else(|| DeError::custom("status는 문자열이어야 합니다."))?;
        let status: QuickStatus =
            serde_json::from_value(serde_json::Value::String(status_str.to_string()))
                .map_err(|err| DeError::custom(format!("status 역직렬화 실패: {err}")))?;

        let elapsed_ms = match &obj["elapsed_ms"] {
            serde_json::Value::Null => None,
            serde_json::Value::Number(n) => {
                let ms = n.as_u64().ok_or_else(|| {
                    DeError::custom("elapsed_ms는 0 이상의 정수(u64)여야 합니다.")
                })?;
                Some(ms)
            }
            _ => return Err(DeError::custom("elapsed_ms는 정수 또는 null이어야 합니다.")),
        };

        let os_error_code = match &obj["os_error_code"] {
            serde_json::Value::Null => None,
            serde_json::Value::Number(n) => {
                let code_i64 = n
                    .as_i64()
                    .ok_or_else(|| DeError::custom("os_error_code는 정수(i32)여야 합니다."))?;
                if code_i64 < (i32::MIN as i64) || code_i64 > (i32::MAX as i64) {
                    return Err(DeError::custom(
                        "os_error_code는 32비트 부호 있는 정수(i32) 범위여야 합니다.",
                    ));
                }
                Some(code_i64 as i32)
            }
            _ => {
                return Err(DeError::custom(
                    "os_error_code는 정수 또는 null이어야 합니다.",
                ));
            }
        };

        let details_obj = obj["details"]
            .as_object()
            .ok_or_else(|| DeError::custom("details는 객체여야 합니다."))?;
        const DETAILS_REQUIRED: [&str; 3] = ["outcome", "limitations", "raw_measurement"];
        for k in details_obj.keys() {
            if !DETAILS_REQUIRED.contains(&k.as_str()) {
                return Err(DeError::custom(format!(
                    "details에 알 수 없는 필드가 존재합니다: '{k}'"
                )));
            }
        }
        for &k in &DETAILS_REQUIRED {
            if !details_obj.contains_key(k) {
                return Err(DeError::custom(format!(
                    "details에 필수 필드가 누락되었습니다: '{k}'"
                )));
            }
        }
        if !details_obj["outcome"].is_string() {
            return Err(DeError::custom("details.outcome은 문자열이어야 합니다."));
        }
        let limitations_arr = details_obj["limitations"]
            .as_array()
            .ok_or_else(|| DeError::custom("details.limitations는 문자열 배열이어야 합니다."))?;
        for elem in limitations_arr {
            if !elem.is_string() {
                return Err(DeError::custom(
                    "details.limitations의 모든 요소는 문자열이어야 합니다.",
                ));
            }
        }
        if !details_obj["raw_measurement"].is_object() {
            return Err(DeError::custom(
                "details.raw_measurement는 객체여야 합니다.",
            ));
        }

        let evidence_str = obj["evidence_level"]
            .as_str()
            .ok_or_else(|| DeError::custom("evidence_level은 문자열이어야 합니다."))?;
        let evidence_level: EvidenceLevel =
            serde_json::from_value(serde_json::Value::String(evidence_str.to_string()))
                .map_err(|err| DeError::custom(format!("evidence_level 역직렬화 실패: {err}")))?;

        Ok(QuickResult {
            schema_version: schema_version_str.to_string(),
            product: product_str.to_string(),
            session_id: session_id_str.to_string(),
            timestamp_iso8601,
            source_host,
            target_host: target_host_str.to_string(),
            resolved_ip,
            target_port,
            feature,
            status,
            elapsed_ms,
            os_error_code,
            details: obj["details"].clone(),
            evidence_level,
        })
    }
}

/// QuickResult 구조체의 의미론적 유효성을 계약(qg1-contract.json) 및 스키마에 따라 검증합니다.
///
/// 수동 생성 DTO나 런타임 결과 객체에 대해 schema_version, product, target_port(1..=65535),
/// timestamp_iso8601(RFC3339), resolved_ip(IPv4/IPv6), details 객체 구조 등을 엄격히 검사합니다.
pub fn validate_quick_result(result: &QuickResult) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    if result.schema_version != QUICK_SCHEMA_VERSION {
        errors.push(format!(
            "schema_version은 고정값 '{QUICK_SCHEMA_VERSION}'이어야 합니다."
        ));
    }
    if result.product != QUICK_PRODUCT_NAME {
        errors.push(format!(
            "product는 고정값 '{QUICK_PRODUCT_NAME}'이어야 합니다."
        ));
    }
    if result.session_id.trim().is_empty() {
        errors.push("session_id는 비어있을 수 없습니다.".to_string());
    }
    if result.target_host.trim().is_empty() {
        errors.push("target_host는 비어있을 수 없습니다.".to_string());
    }
    if result.target_port == 0 {
        errors.push("target_port는 0일 수 없습니다 (유효 범위: 1..=65535).".to_string());
    }
    if let Some(ref ts) = result.timestamp_iso8601 {
        if ts.trim().is_empty() {
            errors.push("timestamp_iso8601는 비어있을 수 없습니다.".to_string());
        } else if let Err(err) = validate_rfc3339_timestamp(ts) {
            errors.push(format!("timestamp_iso8601 형식 오류: {err}"));
        }
    }
    if let Some(ref sh) = result.source_host
        && sh.trim().is_empty()
    {
        errors.push("source_host는 비어있을 수 없습니다.".to_string());
    }
    if let Some(ref ip_str) = result.resolved_ip {
        if ip_str.trim().is_empty() {
            errors.push("resolved_ip는 비어있을 수 없습니다.".to_string());
        } else if ip_str.parse::<IpAddr>().is_err() {
            errors.push("resolved_ip는 유효한 IPv4 또는 IPv6 주소여야 합니다.".to_string());
        }
    }

    if let Some(details_obj) = result.details.as_object() {
        const DETAILS_REQUIRED: [&str; 3] = ["outcome", "limitations", "raw_measurement"];
        for k in details_obj.keys() {
            if !DETAILS_REQUIRED.contains(&k.as_str()) {
                errors.push(format!("details에 알 수 없는 필드가 존재합니다: '{k}'"));
            }
        }
        for &k in &DETAILS_REQUIRED {
            if !details_obj.contains_key(k) {
                errors.push(format!("details 필수 필드가 누락되었습니다: '{k}'"));
            }
        }
        if let Some(outcome) = details_obj.get("outcome")
            && !outcome.is_string()
        {
            errors.push("details.outcome은 문자열이어야 합니다.".to_string());
        }
        if let Some(limitations) = details_obj.get("limitations") {
            if let Some(arr) = limitations.as_array() {
                for item in arr {
                    if !item.is_string() {
                        errors.push(
                            "details.limitations의 모든 항목은 문자열이어야 합니다.".to_string(),
                        );
                        break;
                    }
                }
            } else {
                errors.push("details.limitations는 배열이어야 합니다.".to_string());
            }
        }
        if let Some(raw) = details_obj.get("raw_measurement")
            && !raw.is_object()
        {
            errors.push("details.raw_measurement는 객체여야 합니다.".to_string());
        }
    } else {
        errors.push("details는 객체여야 합니다.".to_string());
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// 공통 TCP 프로브 측정 결과(`TcpMeasurement`)를 Quick Check 계약 결과(`QuickResult`)로 변환하는 어댑터 함수.
///
/// ## 규칙 및 불변식
/// 1. 컨텍스트 검증: 포트 0, 빈 세션 ID, 빈 대상 호스트, 유효하지 않은 타임스탬프 등은 거부합니다.
/// 2. IP 및 포트 일관성 검증 (교차 오염 방지):
///    - `measurement.target`의 SocketAddr 파싱 성공 시 컨텍스트 대상 포트(`ctx.target_port`)와 일치해야 합니다.
///    - 컨텍스트 `target_host`가 IP 리터럴인 경우 해당 IP와 측정 peer의 IP가 일치해야 하며, 불일치 시 거부합니다.
///    - 컨텍스트 `target_host`가 도메인인 경우 임의 DNS 조회를 하지 않고 실측 peer IP를 `resolved_ip`로 유도합니다.
/// 3. 임의 해석 금지: `measurement.target` 파싱 실패 시 `resolved_ip`는 미확인(`None` -> `null`)으로 유지하며
///    임의의 네트워크 조회나 DNS 해석 결과를 발명하지 않습니다.
/// 4. TCP 상태 매핑 (frozen contract 준수):
///    - `CONNECTED` -> `PASS`, `OBSERVED`
///    - `REFUSED` / `RESET` / `TIMED_OUT` / `UNREACHABLE` / `DNS_ERROR` -> `FAIL`, `OBSERVED`
///    - `LOCAL_ERROR` -> `UNKNOWN`, `OBSERVED` (로컬 OS 관찰 결과이나 원격 판정 미확정)
///    - `CANCELLED` -> `UNKNOWN`, `UNKNOWN` (FAIL로 위장 금지!)
///    - 알 수 없는 outcome -> `UNKNOWN`, `UNKNOWN` (절대 PASS로 분류 금지)
/// 5. details 보존: `outcome`, `limitations`, `raw_measurement`를 원형 그대로 보존합니다.
pub fn tcp_to_quick_result(
    ctx: &QuickContext,
    measurement: &TcpMeasurement,
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
    if let Some(ts) = &ctx.timestamp_iso8601
        && ts.trim().is_empty()
    {
        errors.push("timestamp_iso8601는 비어있을 수 없습니다.".to_string());
    } else if let Some(ts) = &ctx.timestamp_iso8601 {
        match validate_rfc3339_timestamp(ts) {
            Ok(()) => {}
            Err(err) => errors.push(format!("timestamp_iso8601 형식 오류: {err}")),
        }
    }
    if let Some(sh) = &ctx.source_host
        && sh.trim().is_empty()
    {
        errors.push("source_host는 비어있을 수 없습니다.".to_string());
    }

    let mut resolved_ip: Option<String> = None;
    if let Ok(socket_addr) = measurement.target.parse::<SocketAddr>() {
        if socket_addr.port() != ctx.target_port {
            errors.push(format!(
                "측정 대상 포트({})가 컨텍스트 대상 포트({})와 일치하지 않습니다 (포트 교차 오염 방지).",
                socket_addr.port(),
                ctx.target_port
            ));
        } else {
            resolved_ip = Some(socket_addr.ip().to_string());
        }

        // 컨텍스트 target_host가 IP literal인 경우 numeric IpAddr와 측정 peer IP 일치 검증
        if let Ok(ctx_ip) = ctx.target_host.trim().parse::<IpAddr>()
            && ctx_ip != socket_addr.ip()
        {
            errors.push(format!(
                "측정 대상 IP({})가 컨텍스트 대상 IP({})와 일치하지 않습니다 (IP 불일치 방지).",
                socket_addr.ip(),
                ctx_ip
            ));
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    let (status, evidence_level) = match measurement.outcome.as_str() {
        "CONNECTED" => (QuickStatus::PASS, EvidenceLevel::OBSERVED),
        "REFUSED" => (QuickStatus::FAIL, EvidenceLevel::OBSERVED),
        "RESET" => (QuickStatus::FAIL, EvidenceLevel::OBSERVED),
        "TIMED_OUT" => (QuickStatus::FAIL, EvidenceLevel::OBSERVED),
        "UNREACHABLE" => (QuickStatus::FAIL, EvidenceLevel::OBSERVED),
        "DNS_ERROR" => (QuickStatus::FAIL, EvidenceLevel::OBSERVED),
        "LOCAL_ERROR" => (QuickStatus::UNKNOWN, EvidenceLevel::OBSERVED),
        "CANCELLED" => (QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN),
        _ => (QuickStatus::UNKNOWN, EvidenceLevel::UNKNOWN),
    };

    let raw_measurement_val = serde_json::to_value(measurement)
        .map_err(|err| vec![format!("TcpMeasurement 직렬화 오류: {err}")])?;

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
        feature: QuickFeature::TcpConnect,
        status,
        elapsed_ms: Some(measurement.elapsed_ms),
        os_error_code: measurement.error_code,
        details,
        evidence_level,
    };

    validate_quick_result(&res)?;
    Ok(res)
}
