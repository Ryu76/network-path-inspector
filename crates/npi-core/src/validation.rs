use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use serde_json::Value;

use crate::models::{
    CostClass, ExecutionMode, FeatureDefinition, GroupId, PermissionLevel, Profile,
};

/// 계약에 정의된 스키마 버전.
pub const SCHEMA_VERSION: &str = "1.1";

/// 계약에 정의된 23개 기능 ID와 고정 그룹 ID 매핑.
pub const CANONICAL_FEATURE_GROUPS: [(&str, &str); 23] = [
    ("tcp_connect", "G-NET"),
    ("icmp_ping", "G-NET"),
    ("dns_lookup", "G-NET"),
    ("icmp_traceroute", "G-PATH"),
    ("tcp_traceroute", "G-PATH"),
    ("route_table", "G-PATH"),
    ("nic_inventory", "G-PATH"),
    ("packet_capture", "G-PKT"),
    ("syn_rst_analysis", "G-PKT"),
    ("firewall_log", "G-PKT"),
    ("listening_check", "G-PKT"),
    ("agent_session", "G-PAIR"),
    ("import_bundle", "G-PAIR"),
    ("packet_compare", "G-PAIR"),
    ("clock_skew", "G-PAIR"),
    ("tcp_monitor", "G-OPS"),
    ("config_change", "G-OPS"),
    ("history_query", "G-OPS"),
    ("result_json", "G-EVID"),
    ("pdf_report", "G-EVID"),
    ("pcap_export", "G-EVID"),
    ("hash_verify", "G-EVID"),
    ("policy_check", "G-EVID"),
];

/// 계약에 정의된 알려진 요구사항(requirements) 식별자 목록.
pub const KNOWN_REQUIREMENTS: [&str; 5] = [
    "validated_tcp_ttl_backend",
    "capture_consent",
    "npcap",
    "capture_privilege",
    "packet_evidence",
];

const PROFILE_FIELDS: [&str; 8] = [
    "schema_version",
    "profile_id",
    "label",
    "mode",
    "selected_features",
    "capture_approved",
    "target",
    "limits",
];

const TARGET_FIELDS: [&str; 3] = ["host", "port", "protocol"];

const LIMIT_BOUNDS: [(&str, u64, u64); 8] = [
    ("tcp_timeout_ms", 1, 120_000),
    ("max_hops", 1, 64),
    ("retries", 0, 3),
    ("max_concurrent_tcp", 1, 4),
    ("capture_duration_secs", 1, 300),
    ("capture_max_bytes", 1, 52_428_800),
    ("log_retention_days", 1, 365),
    ("ui_updates_per_second", 1, 4),
];

const FEATURE_FIELDS: [&str; 10] = [
    "feature_id",
    "group_id",
    "label",
    "description",
    "default_selected",
    "requirements",
    "dependencies",
    "cost_class",
    "permission_level",
    "supported_modes",
];

/// 기능 ID에 대응하는 계약상의 고정 그룹 ID를 조회한다.
pub fn expected_group_for_feature(feature_id: &str) -> Option<&'static str> {
    for (id, group) in CANONICAL_FEATURE_GROUPS {
        if id == feature_id {
            return Some(group);
        }
    }
    None
}

fn is_valid_limit_field(key: &str) -> bool {
    for (name, _, _) in LIMIT_BOUNDS {
        if name == key {
            return true;
        }
    }
    false
}

fn is_numeric_label(label: &str) -> bool {
    !label.is_empty() && label.chars().all(|c| c.is_ascii_digit())
}

/// 순수 문자열 및 `std::net::IpAddr` 파싱만을 사용하여 대상 호스트를 검증한다.
/// DNS 조회나 소켓 생성을 절대 수행하지 않는다.
pub(crate) fn validate_target_host_str(host: &str) -> Result<(), String> {
    validate_target_host(host)
}

fn validate_target_host(host: &str) -> Result<(), String> {
    if host.trim().is_empty() {
        return Err("target.host는 비어 있을 수 없습니다".to_string());
    }
    if host.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("target.host에 공백이나 제어 문자를 포함할 수 없습니다".to_string());
    }
    if host.contains("://") {
        return Err("target.host에 URI 스킴을 포함할 수 없습니다".to_string());
    }
    if host.contains('/') || host.contains('\\') {
        return Err("target.host에 경로 또는 CIDR 표기를 포함할 수 없습니다".to_string());
    }
    if host.contains('@') {
        return Err("target.host에 자격증명(@)을 포함할 수 없습니다".to_string());
    }
    if host.contains(',') || host.contains(';') {
        return Err("target.host에 호스트 목록 구분자를 포함할 수 없습니다".to_string());
    }
    if host.contains('[') || host.contains(']') || host.contains('?') || host.contains('#') {
        return Err("target.host에 허용되지 않는 구분 문자가 있습니다".to_string());
    }

    // IPv4 및 IPv6(::1, 2001:db8::1, ::ffff:192.0.2.1 등) 순수 구문 파싱
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }

    // 유효한 IpAddr가 아닌데 콜론(:)이 있으면 잘못된 IPv6이거나 포트가 결합된 형태임
    if host.contains(':') {
        return Err("target.host에 잘못된 IPv6 또는 포트가 포함되어 있습니다".to_string());
    }

    // ASCII 도메인 이름 검증 (전체 1..=253자, 각 라벨 1..=63자)
    if !host.is_ascii() {
        return Err("target.host 도메인은 ASCII 문자만 허용합니다".to_string());
    }
    if host.len() > 253 {
        return Err("target.host 도메인 길이는 최대 253자여야 합니다".to_string());
    }
    if host.starts_with('.') || host.ends_with('.') {
        return Err("target.host 도메인은 점(.)으로 시작하거나 끝날 수 없습니다".to_string());
    }

    let labels: Vec<&str> = host.split('.').collect();
    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return Err("target.host 도메인 라벨 길이는 1..=63자여야 합니다".to_string());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err("target.host 라벨은 하이픈(-)으로 시작/끝날 수 없습니다".to_string());
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return Err("target.host 라벨은 영숫자와 하이픈(-)만 허용합니다".to_string());
        }
    }

    // 잘못된 숫자형 IPv4를 유효한 도메인으로 오인하지 않도록 차단
    let all_numeric = labels.iter().all(|l| is_numeric_label(l));
    let last_digit = labels
        .last()
        .is_some_and(|l| l.starts_with(|c: char| c.is_ascii_digit()));
    if all_numeric || last_digit {
        return Err("target.host는 잘못된 숫자형 IPv4를 허용하지 않습니다".to_string());
    }

    Ok(())
}

/// 프로필 JSON 값을 G1 인터페이스 계약에 따라 검증한다.
/// 입력 JSON을 변경하지 않으며, 캡처가 선택되어도 `capture_approved`를 자동 부여하지 않는다.
pub fn validate_profile(value: &Value) -> Result<(), Vec<String>> {
    let Some(obj) = value.as_object() else {
        return Err(vec!["프로필 최상위 값은 JSON 객체여야 합니다".to_string()]);
    };

    let mut errors = Vec::new();

    for key in obj.keys() {
        if !PROFILE_FIELDS.contains(&key.as_str()) {
            errors.push(format!("프로필에 알 수 없는 필드가 있습니다: {key}"));
        }
    }

    match obj.get("schema_version") {
        None => errors.push("schema_version 필드가 누락되었습니다".to_string()),
        Some(v) => match v.as_str() {
            Some(SCHEMA_VERSION) => {}
            Some(other) => {
                errors.push(format!("지원하지 않는 schema_version입니다: {other}"));
            }
            None => errors.push("schema_version은 문자열이어야 합니다".to_string()),
        },
    }

    match obj.get("profile_id") {
        None => errors.push("profile_id 필드가 누락되었습니다".to_string()),
        Some(v) => match v.as_str() {
            Some(s) if !s.trim().is_empty() => {}
            Some(_) => errors.push("profile_id는 비어 있을 수 없습니다".to_string()),
            None => errors.push("profile_id는 문자열이어야 합니다".to_string()),
        },
    }

    match obj.get("label") {
        None => errors.push("label 필드가 누락되었습니다".to_string()),
        Some(v) => match v.as_str() {
            Some(s) if !s.trim().is_empty() => {}
            Some(_) => errors.push("label은 비어 있을 수 없습니다".to_string()),
            None => errors.push("label은 문자열이어야 합니다".to_string()),
        },
    }

    match obj.get("mode") {
        None => errors.push("mode 필드가 누락되었습니다".to_string()),
        Some(v) => match v.as_str() {
            Some(s) if ExecutionMode::parse(s).is_some() => {}
            Some(other) => errors.push(format!("허용되지 않는 mode입니다: {other}")),
            None => errors.push("mode는 문자열이어야 합니다".to_string()),
        },
    }

    match obj.get("selected_features") {
        None => errors.push("selected_features 필드가 누락되었습니다".to_string()),
        Some(v) => match v.as_array() {
            None => errors.push("selected_features는 배열이어야 합니다".to_string()),
            Some(arr) => {
                let mut seen = BTreeSet::new();
                for (idx, item) in arr.iter().enumerate() {
                    match item.as_str() {
                        None => {
                            errors.push(format!("selected_features[{idx}]는 문자열이어야 합니다"));
                        }
                        Some(fid) => {
                            if expected_group_for_feature(fid).is_none() {
                                errors.push(format!("알 수 없는 feature_id입니다: {fid}"));
                            }
                            if !seen.insert(fid) {
                                errors.push(format!("중복된 feature_id입니다: {fid}"));
                            }
                        }
                    }
                }
            }
        },
    }

    match obj.get("capture_approved") {
        None => errors.push("capture_approved 필드가 누락되었습니다".to_string()),
        Some(v) => {
            if !v.is_boolean() {
                errors.push("capture_approved는 불리언이어야 합니다".to_string());
            }
        }
    }

    match obj.get("target") {
        None => errors.push("target 필드가 누락되었습니다".to_string()),
        Some(v) => match v.as_object() {
            None => errors.push("target은 JSON 객체여야 합니다".to_string()),
            Some(target_obj) => {
                for key in target_obj.keys() {
                    if !TARGET_FIELDS.contains(&key.as_str()) {
                        errors.push(format!("target에 알 수 없는 필드가 있습니다: {key}"));
                    }
                }

                match target_obj.get("host") {
                    None => errors.push("target.host 필드가 누락되었습니다".to_string()),
                    Some(host_val) => match host_val.as_str() {
                        None => errors.push("target.host는 문자열이어야 합니다".to_string()),
                        Some(host_str) => {
                            if let Err(err) = validate_target_host(host_str) {
                                errors.push(err);
                            }
                        }
                    },
                }

                match target_obj.get("port") {
                    None => errors.push("target.port 필드가 누락되었습니다".to_string()),
                    Some(port_val) => match port_val.as_u64() {
                        Some(port) if (1..=65535).contains(&port) => {}
                        Some(port) => {
                            errors.push(format!("target.port 범위 오류입니다: {port}"));
                        }
                        None => {
                            errors.push("target.port는 1..=65535 정수여야 합니다".to_string());
                        }
                    },
                }

                match target_obj.get("protocol") {
                    None => errors.push("target.protocol 필드가 누락되었습니다".to_string()),
                    Some(proto_val) => match proto_val.as_str() {
                        Some("TCP") => {}
                        Some(other) => {
                            errors.push(format!("target.protocol은 'TCP'여야 합니다: {other}"));
                        }
                        None => errors.push("target.protocol은 문자열이어야 합니다".to_string()),
                    },
                }
            }
        },
    }

    match obj.get("limits") {
        None => errors.push("limits 필드가 누락되었습니다".to_string()),
        Some(v) => match v.as_object() {
            None => errors.push("limits는 JSON 객체여야 합니다".to_string()),
            Some(limits_obj) => {
                for key in limits_obj.keys() {
                    if !is_valid_limit_field(key.as_str()) {
                        errors.push(format!("limits에 알 수 없는 필드가 있습니다: {key}"));
                    }
                }

                for (field, min_val, max_val) in LIMIT_BOUNDS {
                    match limits_obj.get(field) {
                        None => errors.push(format!("limits.{field} 필드가 누락되었습니다")),
                        Some(limit_val) => match limit_val.as_u64() {
                            Some(num) if (min_val..=max_val).contains(&num) => {}
                            Some(num) => {
                                errors.push(format!("limits.{field} 범위 초과: {num}"));
                            }
                            None => {
                                errors.push(format!("limits.{field}는 유효한 정수여야 합니다"));
                            }
                        },
                    }
                }
            }
        },
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    if let Err(err) = serde_json::from_value::<Profile>(value.clone()) {
        return Err(vec![format!("프로필 DTO 역직렬화 실패: {err}")]);
    }

    Ok(())
}

/// 기능 레지스트리 JSON 배열을 G1 인터페이스 계약에 따라 검증한다.
/// 23개 고정 기능, 6개 그룹 소속, 필수 필드, 의존성 및 순환 참조를 비재귀적으로 검증한다.
pub fn validate_registry(value: &Value) -> Result<(), Vec<String>> {
    let Some(arr) = value.as_array() else {
        return Err(vec!["레지스트리 최상위 값은 배열이어야 합니다".to_string()]);
    };

    let mut errors = Vec::new();
    let len = arr.len();

    if len != CANONICAL_FEATURE_GROUPS.len() {
        errors.push(format!("레지스트리 기능 수는 23개여야 합니다: {len}"));
    }

    let mut seen_ids = BTreeSet::new();
    let mut deps_by_feature: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for (idx, item) in arr.iter().enumerate() {
        let Some(obj) = item.as_object() else {
            errors.push(format!("레지스트리[{idx}] 항목은 객체여야 합니다"));
            continue;
        };

        for key in obj.keys() {
            if !FEATURE_FIELDS.contains(&key.as_str()) {
                errors.push(format!("레지스트리[{idx}] 알 수 없는 필드: {key}"));
            }
        }

        let mut current_feature_id: Option<String> = None;
        let mut expected_group: Option<&'static str> = None;
        match obj.get("feature_id") {
            None => errors.push(format!("레지스트리[{idx}].feature_id 누락")),
            Some(v) => match v.as_str() {
                None => errors.push(format!("레지스트리[{idx}].feature_id 타입 오류")),
                Some(s) if s.trim().is_empty() => {
                    errors.push(format!("레지스트리[{idx}].feature_id 공백 오류"));
                }
                Some(s) => {
                    expected_group = expected_group_for_feature(s);
                    if expected_group.is_none() {
                        errors.push(format!("알 수 없는 feature_id: {s}"));
                    }
                    if !seen_ids.insert(s.to_string()) {
                        errors.push(format!("중복된 feature_id: {s}"));
                    }
                    current_feature_id = Some(s.to_string());
                }
            },
        }

        match obj.get("group_id") {
            None => errors.push(format!("레지스트리[{idx}].group_id 누락")),
            Some(v) => match v.as_str() {
                None => errors.push(format!("레지스트리[{idx}].group_id 타입 오류")),
                Some(g) => {
                    if GroupId::parse(g).is_none() {
                        errors.push(format!("허용되지 않는 group_id: {g}"));
                    } else if expected_group.is_some_and(|exp| exp != g) {
                        errors.push(format!("잘못된 group_id 소속: {g}"));
                    }
                }
            },
        }

        match obj.get("label") {
            None => errors.push(format!("레지스트리[{idx}].label 누락")),
            Some(v) => match v.as_str() {
                Some(s) if !s.trim().is_empty() => {}
                Some(_) => errors.push(format!("레지스트리[{idx}].label 공백 오류")),
                None => errors.push(format!("레지스트리[{idx}].label 타입 오류")),
            },
        }

        match obj.get("description") {
            None => errors.push(format!("레지스트리[{idx}].description 누락")),
            Some(v) => match v.as_str() {
                Some(s) if !s.trim().is_empty() => {}
                Some(_) => errors.push(format!("레지스트리[{idx}].description 공백 오류")),
                None => errors.push(format!("레지스트리[{idx}].description 타입 오류")),
            },
        }

        match obj.get("default_selected") {
            None => errors.push(format!("레지스트리[{idx}].default_selected 누락")),
            Some(v) => {
                if !v.is_boolean() {
                    errors.push(format!("레지스트리[{idx}].default_selected 타입 오류"));
                }
            }
        }

        match obj.get("requirements") {
            None => errors.push(format!("레지스트리[{idx}].requirements 누락")),
            Some(v) => match v.as_array() {
                None => errors.push(format!("레지스트리[{idx}].requirements 타입 오류")),
                Some(req_arr) => {
                    let mut seen_reqs = BTreeSet::new();
                    for (r_idx, req_val) in req_arr.iter().enumerate() {
                        match req_val.as_str() {
                            None => {
                                errors.push(format!("requirements[{r_idx}] 타입 오류"));
                            }
                            Some(req_str) => {
                                if !KNOWN_REQUIREMENTS.contains(&req_str) {
                                    errors.push(format!("알 수 없는 requirement: {req_str}"));
                                }
                                if !seen_reqs.insert(req_str) {
                                    errors.push(format!("중복된 requirement: {req_str}"));
                                }
                            }
                        }
                    }
                }
            },
        }

        match obj.get("dependencies") {
            None => errors.push(format!("레지스트리[{idx}].dependencies 누락")),
            Some(v) => match v.as_array() {
                None => errors.push(format!("레지스트리[{idx}].dependencies 타입 오류")),
                Some(dep_arr) => {
                    let mut seen_deps = BTreeSet::new();
                    let mut dep_list = Vec::new();
                    for (d_idx, dep_val) in dep_arr.iter().enumerate() {
                        match dep_val.as_str() {
                            None => {
                                errors.push(format!("dependencies[{d_idx}] 타입 오류"));
                            }
                            Some(dep_str) if dep_str.trim().is_empty() => {
                                errors.push(format!("dependencies[{d_idx}] 공백 오류"));
                            }
                            Some(dep_str) => {
                                if expected_group_for_feature(dep_str).is_none() {
                                    errors.push(format!("알 수 없는 의존성 ID: {dep_str}"));
                                }
                                if !seen_deps.insert(dep_str) {
                                    errors.push(format!("중복된 의존성 ID: {dep_str}"));
                                }
                                if current_feature_id.as_deref() == Some(dep_str) {
                                    errors.push(format!("자기 참조 순환 의존성: {dep_str}"));
                                }
                                dep_list.push(dep_str.to_string());
                            }
                        }
                    }
                    if let Some(ref fid) = current_feature_id {
                        let entry = deps_by_feature.entry(fid.clone()).or_default();
                        entry.extend(dep_list);
                    }
                }
            },
        }

        match obj.get("cost_class") {
            None => errors.push(format!("레지스트리[{idx}].cost_class 누락")),
            Some(v) => match v.as_str() {
                Some(s) if CostClass::parse(s).is_some() => {}
                Some(other) => errors.push(format!("허용되지 않는 cost_class: {other}")),
                None => errors.push(format!("레지스트리[{idx}].cost_class 타입 오류")),
            },
        }

        match obj.get("permission_level") {
            None => errors.push(format!("레지스트리[{idx}].permission_level 누락")),
            Some(v) => match v.as_str() {
                Some(s) if PermissionLevel::parse(s).is_some() => {}
                Some(other) => errors.push(format!("허용되지 않는 permission_level: {other}")),
                None => errors.push(format!("레지스트리[{idx}].permission_level 타입 오류")),
            },
        }

        match obj.get("supported_modes") {
            None => errors.push(format!("레지스트리[{idx}].supported_modes 누락")),
            Some(v) => match v.as_array() {
                None => errors.push(format!("레지스트리[{idx}].supported_modes 타입 오류")),
                Some(modes_arr) => {
                    if modes_arr.is_empty() {
                        errors.push(format!("레지스트리[{idx}].supported_modes 빈 배열 오류"));
                    }
                    let mut seen_modes = BTreeSet::new();
                    for (m_idx, mode_val) in modes_arr.iter().enumerate() {
                        match mode_val.as_str() {
                            None => {
                                errors.push(format!("supported_modes[{m_idx}] 타입 오류"));
                            }
                            Some(mode_str) => {
                                if ExecutionMode::parse(mode_str).is_none() {
                                    errors.push(format!("허용되지 않는 모드: {mode_str}"));
                                }
                                if !seen_modes.insert(mode_str) {
                                    errors.push(format!("중복된 지원 모드: {mode_str}"));
                                }
                            }
                        }
                    }
                }
            },
        }
    }

    for (canonical_id, _) in CANONICAL_FEATURE_GROUPS {
        if !seen_ids.contains(canonical_id) {
            errors.push(format!("필수 feature_id 누락: {canonical_id}"));
        }
    }

    for (fid, deps) in &deps_by_feature {
        for dep in deps {
            if !seen_ids.contains(dep) {
                errors.push(format!("'{fid}'의 의존성 '{dep}'이 레지스트리에 없습니다"));
            }
        }
    }

    detect_dependency_cycles_iterative(&deps_by_feature, &mut errors);

    if !errors.is_empty() {
        return Err(errors);
    }

    if let Err(err) = serde_json::from_value::<Vec<FeatureDefinition>>(value.clone()) {
        return Err(vec![format!("레지스트리 DTO 역직렬화 실패: {err}")]);
    }

    Ok(())
}

/// 반복적(Iterative) 위상 정렬(Kahn 알고리즘)로 직·간접 순환 의존성을 검출한다.
fn detect_dependency_cycles_iterative(
    deps_by_feature: &BTreeMap<String, Vec<String>>,
    errors: &mut Vec<String>,
) {
    let mut remaining_deps: BTreeMap<&str, usize> = BTreeMap::new();
    let mut dependents: BTreeMap<&str, Vec<&str>> = BTreeMap::new();

    for fid in deps_by_feature.keys() {
        remaining_deps.insert(fid.as_str(), 0);
        dependents.insert(fid.as_str(), Vec::new());
    }

    for (fid, deps) in deps_by_feature {
        let mut unique_valid_deps = BTreeSet::new();
        for dep in deps {
            if deps_by_feature.contains_key(dep.as_str()) {
                unique_valid_deps.insert(dep.as_str());
            }
        }
        if let Some(count) = remaining_deps.get_mut(fid.as_str()) {
            *count = unique_valid_deps.len();
        }
        for dep in unique_valid_deps {
            if let Some(list) = dependents.get_mut(dep) {
                list.push(fid.as_str());
            }
        }
    }

    let mut queue = Vec::new();
    for (&fid, &deg) in &remaining_deps {
        if deg == 0 {
            queue.push(fid);
        }
    }

    let mut resolved_count = 0usize;
    let mut head = 0usize;

    while head < queue.len() {
        let current = queue[head];
        head += 1;
        resolved_count += 1;

        if let Some(next_nodes) = dependents.get(current) {
            for &dependent in next_nodes {
                if let Some(deg) = remaining_deps.get_mut(dependent) {
                    *deg = deg.saturating_sub(1);
                    if *deg == 0 {
                        queue.push(dependent);
                    }
                }
            }
        }
    }

    if resolved_count < remaining_deps.len() {
        let mut unresolved = Vec::new();
        for (&fid, &deg) in &remaining_deps {
            if deg > 0 {
                unresolved.push(fid);
            }
        }
        errors.push(format!("순환 의존성 감지: {}", unresolved.join(", ")));
    }
}
