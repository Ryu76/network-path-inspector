use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::models::{CostClass, FeatureDefinition, PermissionLevel, Profile};
use crate::validation::{validate_profile, validate_registry};

/// 호스트 네트워크 스냅샷(`nic_inventory`, `route_table`) 공유 내부 수집기 식별자.
pub const SHARED_HOST_NETWORK_SNAPSHOT_COLLECTOR: &str = "host_network_snapshot";

/// 프로필 복원 시 재확인 전까지 자동 실행을 차단해야 하는 위험 기능 ID 목록.
pub const RISKY_RESTORE_FEATURE_IDS: [&str; 3] = ["tcp_monitor", "config_change", "pdf_report"];

/// G1 인터페이스 계약에 따른 단일 기능 실행 계획/결과 항목.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PlannedFeatureResult {
    feature_id: String,
    group_id: String,
    status: String,
    classification: Option<String>,
    evidence_ids: Vec<String>,
    started_at_utc: Option<String>,
    ended_at_utc: Option<String>,
    duration_ms: Option<u64>,
    error_code: Option<i32>,
    limitations: Vec<String>,
    next_checks: Vec<String>,
}

/// 프로필, 기능 레지스트리, 호스트 가용 요구사항(`capabilities`)을 바탕으로
/// 부작용 없는 순수 G1 기능 실행 계획을 수립한다.
///
/// - 소켓/OS/프로브/패킷 캡처/파일 쓰기 등 어떠한 런타임 동작도 수행하지 않는다.
/// - 전체 입력 및 의존성 그래프를 먼저 검증하고 비재귀적 위상 정렬로 순서를 계산한다.
/// - 선택되지 않은 기능은 `SKIPPED_BY_USER`(`classification: null`)로 유지하며 암묵적으로 실행하지 않는다.
/// - 선택되었으나 조건이 충족되지 않은 기능은 `UNAVAILABLE`(`classification: "UNKNOWN"`)로 분류한다.
/// - 실행 가능한 선택 기능은 계획 단계이므로 `WARN`(`classification: "UNKNOWN"`) 및 미실행 한계 설명을 부여한다.
pub fn plan_features(
    profile: &Value,
    registry: &Value,
    capabilities: &BTreeSet<String>,
) -> Result<Value, Vec<String>> {
    let (parsed_profile, parsed_registry) = validate_inputs(profile, registry)?;

    let mut feature_map: BTreeMap<&str, &FeatureDefinition> = BTreeMap::new();
    for feature in &parsed_registry {
        feature_map.insert(feature.feature_id.as_str(), feature);
    }

    let topo_all = topological_order_all(&parsed_registry)?;

    let mut selected_index: BTreeMap<&str, usize> = BTreeMap::new();
    for (idx, fid) in parsed_profile.selected_features.iter().enumerate() {
        selected_index.insert(fid.as_str(), idx);
    }

    let mut available_set: BTreeSet<&str> = BTreeSet::new();
    let mut limitations_by_feature: BTreeMap<&str, Vec<String>> = BTreeMap::new();

    for &fid in &topo_all {
        if !selected_index.contains_key(fid) {
            continue;
        }

        let feature = feature_map[fid];
        let mut reasons = Vec::new();

        let mode_ok = feature.supported_modes.contains(&parsed_profile.mode);
        if !mode_ok {
            let mode = &parsed_profile.mode;
            let msg = format!("실행 모드('{mode}') 미지원 (unsupported mode)");
            reasons.push(msg);
        }

        let has_consent_req = feature.requirements.iter().any(|r| r == "capture_consent");
        let requires_consent = feature.feature_id == "packet_capture" || has_consent_req;
        if requires_consent && !parsed_profile.capture_approved {
            let msg = "프로필 캡처 동의(capture_approved) 없음 (missing capture_consent)";
            reasons.push(msg.to_string());
        }

        for req in &feature.requirements {
            if req == "capture_consent" {
                continue;
            }
            if !capabilities.contains(req.as_str()) {
                if req == "validated_tcp_ttl_backend" {
                    let msg =
                        "TCP TTL 백엔드 없음, ICMP 대체 불가 (missing validated_tcp_ttl_backend)";
                    reasons.push(msg.to_string());
                } else {
                    let msg = format!("필수 요구사항('{req}') 미충족 (missing capability)");
                    reasons.push(msg);
                }
            }
        }

        for dep in &feature.dependencies {
            let dep_str = dep.as_str();
            if !selected_index.contains_key(dep_str) {
                let msg = format!("필수 의존성('{dep_str}') 미선택 (deselected dependency)");
                reasons.push(msg);
            } else if !available_set.contains(dep_str) {
                let msg = format!("필수 의존성('{dep_str}') 미가용 (unavailable dependency)");
                reasons.push(msg);
            }
        }

        if reasons.is_empty() {
            available_set.insert(fid);
        } else {
            limitations_by_feature.insert(fid, reasons);
        }
    }

    let execution_order =
        stable_available_execution_order(&feature_map, &selected_index, &available_set)?;

    let mut shared_collectors = Vec::new();
    if available_set.contains("nic_inventory") || available_set.contains("route_table") {
        shared_collectors.push(SHARED_HOST_NETWORK_SNAPSHOT_COLLECTOR.to_string());
    }

    let not_executed_msg = "G1 실행 계획 단계이며 아직 실행되지 않았습니다 (not executed)";
    let next_exec_msg = "G2 실행 단계에서 프로브를 실행하여 실제 측정 근거를 수집하세요";
    let next_unavail_msg = "실행 모드, 요구사항, 캡처 동의 및 의존성 선택 여부를 확인하세요";
    let fallback_unavail_msg = "실행 전제 조건이 충족되지 않았습니다 (unavailable)";

    let mut feature_results = Vec::with_capacity(parsed_registry.len());
    for feature in &parsed_registry {
        let fid = feature.feature_id.as_str();
        let result = if !selected_index.contains_key(fid) {
            PlannedFeatureResult {
                feature_id: feature.feature_id.clone(),
                group_id: feature.group_id.clone(),
                status: "SKIPPED_BY_USER".to_string(),
                classification: None,
                evidence_ids: Vec::new(),
                started_at_utc: None,
                ended_at_utc: None,
                duration_ms: None,
                error_code: None,
                limitations: Vec::new(),
                next_checks: Vec::new(),
            }
        } else if available_set.contains(fid) {
            PlannedFeatureResult {
                feature_id: feature.feature_id.clone(),
                group_id: feature.group_id.clone(),
                status: "WARN".to_string(),
                classification: Some("UNKNOWN".to_string()),
                evidence_ids: Vec::new(),
                started_at_utc: None,
                ended_at_utc: None,
                duration_ms: None,
                error_code: None,
                limitations: vec![not_executed_msg.to_string()],
                next_checks: vec![next_exec_msg.to_string()],
            }
        } else {
            let limitations = match limitations_by_feature.remove(fid) {
                Some(lims) => lims,
                None => vec![fallback_unavail_msg.to_string()],
            };
            PlannedFeatureResult {
                feature_id: feature.feature_id.clone(),
                group_id: feature.group_id.clone(),
                status: "UNAVAILABLE".to_string(),
                classification: Some("UNKNOWN".to_string()),
                evidence_ids: Vec::new(),
                started_at_utc: None,
                ended_at_utc: None,
                duration_ms: None,
                error_code: None,
                limitations,
                next_checks: vec![next_unavail_msg.to_string()],
            }
        };
        feature_results.push(result);
    }

    Ok(json!({
        "selected_features": parsed_profile.selected_features,
        "execution_order": execution_order,
        "feature_results": feature_results,
        "shared_collectors": shared_collectors,
    }))
}

/// 저장된 프로필을 안전하게 복원한다.
///
/// - 입력 프로필과 레지스트리를 먼저 검증하고 원본 입력을 절대 수정하지 않는다.
/// - `capture_approved`를 항상 `false`로 초기화한다.
/// - `HIGH` 비용 등급, `CONDITIONAL` 권한 수준, 위험 기능(`tcp_monitor`, `config_change`, `pdf_report`)을 제거한다.
/// - 안전한 기능 선택 목록은 원래 순서를 유지하며, 추가 UI 메타데이터 없이 정규 `Profile` JSON만 반환한다.
pub fn restore_profile(profile: &Value, registry: &Value) -> Result<Value, Vec<String>> {
    let (mut restored_profile, parsed_registry) = validate_inputs(profile, registry)?;

    let mut feature_map: BTreeMap<&str, &FeatureDefinition> = BTreeMap::new();
    for feature in &parsed_registry {
        feature_map.insert(feature.feature_id.as_str(), feature);
    }

    restored_profile.capture_approved = false;
    restored_profile.selected_features.retain(|fid| {
        let Some(def) = feature_map.get(fid.as_str()) else {
            return false;
        };
        !should_strip_on_restore(def)
    });

    match serde_json::to_value(restored_profile) {
        Ok(val) => Ok(val),
        Err(err) => Err(vec![format!("복원된 프로필 직렬화 실패: {err}")]),
    }
}

/// 프로필 복원 시 재확인이 필요한 고비용·조건부 권한·위험 기능 여부를 판정한다.
fn should_strip_on_restore(feature: &FeatureDefinition) -> bool {
    let is_high_cost = CostClass::parse(&feature.cost_class) == Some(CostClass::High);
    let is_conditional_perm =
        PermissionLevel::parse(&feature.permission_level) == Some(PermissionLevel::Conditional);
    let is_risky_id = RISKY_RESTORE_FEATURE_IDS.contains(&feature.feature_id.as_str());

    is_high_cost || is_conditional_perm || is_risky_id
}

/// 입력 프로필과 레지스트리를 검증한 뒤 역직렬화된 구조체 쌍을 반환한다.
fn validate_inputs(
    profile: &Value,
    registry: &Value,
) -> Result<(Profile, Vec<FeatureDefinition>), Vec<String>> {
    let mut errors = Vec::new();
    if let Err(profile_errs) = validate_profile(profile) {
        errors.extend(profile_errs);
    }
    if let Err(registry_errs) = validate_registry(registry) {
        errors.extend(registry_errs);
    }
    if !errors.is_empty() {
        return Err(errors);
    }

    let parsed_profile: Profile = match serde_json::from_value(profile.clone()) {
        Ok(p) => p,
        Err(err) => return Err(vec![format!("프로필 역직렬화 실패: {err}")]),
    };
    let parsed_registry: Vec<FeatureDefinition> = match serde_json::from_value(registry.clone()) {
        Ok(r) => r,
        Err(err) => return Err(vec![format!("레지스트리 역직렬화 실패: {err}")]),
    };

    Ok((parsed_profile, parsed_registry))
}

/// 전체 레지스트리 기능 그래프에 대해 비재귀적(Iterative) Kahn 알고리즘으로 위상 순서를 반환한다.
fn topological_order_all<'a>(
    registry: &'a [FeatureDefinition],
) -> Result<Vec<&'a str>, Vec<String>> {
    let mut reg_index: BTreeMap<&'a str, usize> = BTreeMap::new();
    let mut remaining_deps: BTreeMap<&'a str, usize> = BTreeMap::new();
    let mut dependents: BTreeMap<&'a str, Vec<&'a str>> = BTreeMap::new();

    for (idx, feature) in registry.iter().enumerate() {
        let fid = feature.feature_id.as_str();
        reg_index.insert(fid, idx);
        remaining_deps.insert(fid, 0);
        dependents.insert(fid, Vec::new());
    }

    for feature in registry {
        let fid = feature.feature_id.as_str();
        let mut unique_deps = BTreeSet::new();
        for dep in &feature.dependencies {
            if let Some((&dep_key, _)) = reg_index.get_key_value(dep.as_str()) {
                unique_deps.insert(dep_key);
            }
        }
        if let Some(deg) = remaining_deps.get_mut(fid) {
            *deg = unique_deps.len();
        }
        for dep_key in unique_deps {
            if let Some(children) = dependents.get_mut(dep_key) {
                children.push(fid);
            }
        }
    }

    // (registry_index, feature_id) 순서로 안정적인 반복 처리 수행
    let mut ready: BTreeSet<(usize, &'a str)> = BTreeSet::new();
    for (&fid, &deg) in &remaining_deps {
        if deg == 0 {
            ready.insert((reg_index[fid], fid));
        }
    }

    let mut ordered = Vec::with_capacity(registry.len());
    while let Some((_, current)) = ready.pop_first() {
        ordered.push(current);
        if let Some(children) = dependents.get(current) {
            for &child in children {
                if let Some(deg) = remaining_deps.get_mut(child) {
                    *deg = deg.saturating_sub(1);
                    if *deg == 0 {
                        ready.insert((reg_index[child], child));
                    }
                }
            }
        }
    }

    if ordered.len() != registry.len() {
        return Err(vec!["의존성 그래프에 순환 참조가 존재합니다".to_string()]);
    }

    Ok(ordered)
}

/// 선택되고 가용한(`AVAILABLE`) 기능들에 대해서만 사용자의 원래 선택 순서를 보존하는
/// 비재귀적(Iterative) 위상 정렬 실행 순서를 계산한다.
fn stable_available_execution_order<'a>(
    feature_map: &BTreeMap<&'a str, &'a FeatureDefinition>,
    selected_index: &BTreeMap<&'a str, usize>,
    available_set: &BTreeSet<&'a str>,
) -> Result<Vec<String>, Vec<String>> {
    let mut remaining_deps: BTreeMap<&'a str, usize> = BTreeMap::new();
    let mut dependents: BTreeMap<&'a str, Vec<&'a str>> = BTreeMap::new();

    for &fid in available_set {
        remaining_deps.insert(fid, 0);
        dependents.insert(fid, Vec::new());
    }

    for &fid in available_set {
        let feature = feature_map[fid];
        let mut unique_deps = BTreeSet::new();
        for dep in &feature.dependencies {
            if let Some(&dep_key) = available_set.get(dep.as_str()) {
                unique_deps.insert(dep_key);
            }
        }
        if let Some(deg) = remaining_deps.get_mut(fid) {
            *deg = unique_deps.len();
        }
        for dep_key in unique_deps {
            if let Some(children) = dependents.get_mut(dep_key) {
                children.push(fid);
            }
        }
    }

    // (selected_features_index, feature_id)를 키로 사용하여 원래 선택 순서를 유지
    let mut ready: BTreeSet<(usize, &'a str)> = BTreeSet::new();
    for (&fid, &deg) in &remaining_deps {
        if deg == 0 {
            let sel_idx = selected_index.get(fid).copied().unwrap_or(usize::MAX);
            ready.insert((sel_idx, fid));
        }
    }

    let mut execution_order = Vec::with_capacity(available_set.len());
    while let Some((_, current)) = ready.pop_first() {
        execution_order.push(current.to_string());
        if let Some(children) = dependents.get(current) {
            for &child in children {
                if let Some(deg) = remaining_deps.get_mut(child) {
                    *deg = deg.saturating_sub(1);
                    if *deg == 0 {
                        let sel_idx = selected_index.get(child).copied().unwrap_or(usize::MAX);
                        ready.insert((sel_idx, child));
                    }
                }
            }
        }
    }

    if execution_order.len() != available_set.len() {
        let msg = "실행 계획 생성 중 순환 의존성이 감지되었습니다";
        return Err(vec![msg.to_string()]);
    }

    Ok(execution_order)
}
