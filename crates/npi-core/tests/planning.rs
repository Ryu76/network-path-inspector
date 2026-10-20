use std::collections::BTreeSet;

use npi_core::{
    canonical_registry, plan_features, restore_profile, validate_profile, validate_registry,
};
use serde_json::{Value, json};

fn sample_profile(selected: &[&str], capture_approved: bool, mode: &str) -> Value {
    json!({
        "schema_version": "1.1",
        "profile_id": "prof-g1-plan-test",
        "label": "G1 플래너 검증 프로필",
        "mode": mode,
        "selected_features": selected,
        "capture_approved": capture_approved,
        "target": {
            "host": "127.0.0.1",
            "port": 443,
            "protocol": "TCP"
        },
        "limits": {
            "tcp_timeout_ms": 5000,
            "max_hops": 30,
            "retries": 0,
            "max_concurrent_tcp": 4,
            "capture_duration_secs": 30,
            "capture_max_bytes": 52428800,
            "log_retention_days": 30,
            "ui_updates_per_second": 4
        }
    })
}

fn caps(items: &[&str]) -> BTreeSet<String> {
    items.iter().map(|s| (*s).to_string()).collect()
}

fn find_result<'a>(plan: &'a Value, feature_id: &str) -> &'a Value {
    let arr = plan["feature_results"].as_array().unwrap();
    arr.iter()
        .find(|item| item["feature_id"] == feature_id)
        .unwrap()
}

fn set_feature_dependencies(registry: &mut Value, feature_id: &str, deps: &[&str]) {
    let arr = registry.as_array_mut().unwrap();
    for item in arr {
        if item["feature_id"] == feature_id {
            item["dependencies"] = json!(deps);
            return;
        }
    }
    panic!("레지스트리에서 '{feature_id}'를 찾을 수 없습니다");
}

fn set_feature_modes(registry: &mut Value, feature_id: &str, modes: &[&str]) {
    let arr = registry.as_array_mut().unwrap();
    for item in arr {
        if item["feature_id"] == feature_id {
            item["supported_modes"] = json!(modes);
            return;
        }
    }
    panic!("레지스트리에서 '{feature_id}'를 찾을 수 없습니다");
}

/// 1. quick-default 5개 기능 계획 시 가짜 PASS 없이 5개 WARN+UNKNOWN, 18개 SKIPPED_BY_USER,
///
/// 실행 순서 5개, 공유 수집기 1회 생성을 검증한다.
#[test]
fn plan_quick_default_exact_5_no_pass_and_shared_collector_once() {
    let quick = [
        "tcp_connect",
        "icmp_ping",
        "nic_inventory",
        "route_table",
        "result_json",
    ];
    let profile = sample_profile(&quick, false, "standalone");
    let registry = canonical_registry();
    let plan = plan_features(&profile, &registry, &BTreeSet::new()).unwrap();

    assert_eq!(plan["selected_features"], json!(quick));
    assert_eq!(plan["execution_order"], json!(quick));
    assert_eq!(plan["shared_collectors"], json!(["host_network_snapshot"]));

    let results = plan["feature_results"].as_array().unwrap();
    assert_eq!(results.len(), 23);

    let mut warn_count = 0;
    let mut skipped_count = 0;
    for res in results {
        let status = res["status"].as_str().unwrap();
        assert_ne!(status, "PASS");
        assert_eq!(res["evidence_ids"], json!([]));
        assert!(res["started_at_utc"].is_null());
        assert!(res["ended_at_utc"].is_null());
        assert!(res["duration_ms"].is_null());
        assert!(res["error_code"].is_null());

        if quick.contains(&res["feature_id"].as_str().unwrap()) {
            warn_count += 1;
            assert_eq!(status, "WARN");
            assert_eq!(res["classification"], json!("UNKNOWN"));
            let lims = res["limitations"].as_array().unwrap();
            assert!(!lims.is_empty());
        } else {
            skipped_count += 1;
            assert_eq!(status, "SKIPPED_BY_USER");
            assert!(res["classification"].is_null());
            assert_eq!(res["limitations"], json!([]));
            assert_eq!(res["next_checks"], json!([]));
        }
    }
    assert_eq!(warn_count, 5);
    assert_eq!(skipped_count, 18);
}

/// 2. 선택된 기능이 0개일 때 23개 모두 SKIPPED_BY_USER이고 실행 순서가 비어 있는지 검증한다.
#[test]
fn plan_zero_selected_features_all_23_skipped_and_zero_order() {
    let profile = sample_profile(&[], false, "standalone");
    let registry = canonical_registry();
    let plan = plan_features(&profile, &registry, &BTreeSet::new()).unwrap();

    assert_eq!(plan["selected_features"], json!([]));
    assert_eq!(plan["execution_order"], json!([]));
    assert_eq!(plan["shared_collectors"], json!([]));

    let results = plan["feature_results"].as_array().unwrap();
    assert_eq!(results.len(), 23);
    for res in results {
        assert_eq!(res["status"], json!("SKIPPED_BY_USER"));
        assert!(res["classification"].is_null());
    }
}

/// 3. feature_results 배열이 레지스트리 23개 순서와 계약된 11개 필드를 정확히 준수하는지 검증한다.
#[test]
fn plan_feature_results_preserve_exact_registry_order_and_contract_fields() {
    let profile = sample_profile(&["result_json", "tcp_connect"], false, "standalone");
    let registry = canonical_registry();
    let plan = plan_features(&profile, &registry, &BTreeSet::new()).unwrap();

    let reg_arr = registry.as_array().unwrap();
    let res_arr = plan["feature_results"].as_array().unwrap();
    assert_eq!(reg_arr.len(), res_arr.len());

    let expected_keys: BTreeSet<&str> = [
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
    ]
    .into_iter()
    .collect();

    for (reg_item, res_item) in reg_arr.iter().zip(res_arr.iter()) {
        assert_eq!(res_item["feature_id"], reg_item["feature_id"]);
        assert_eq!(res_item["group_id"], reg_item["group_id"]);
        let obj = res_item.as_object().unwrap();
        let actual_keys: BTreeSet<&str> = obj.keys().map(String::as_str).collect();
        assert_eq!(actual_keys, expected_keys);
    }
}

/// 4. tcp_traceroute는 validated_tcp_ttl_backend가 없으면 UNAVAILABLE이며 ICMP로 대체하지 않는다.
#[test]
fn plan_tcp_traceroute_unavailable_without_backend_and_never_replaced_by_icmp() {
    let profile = sample_profile(&["tcp_traceroute"], false, "standalone");
    let registry = canonical_registry();
    let plan = plan_features(&profile, &registry, &BTreeSet::new()).unwrap();

    assert_eq!(plan["execution_order"], json!([]));
    let tcp_res = find_result(&plan, "tcp_traceroute");
    assert_eq!(tcp_res["status"], json!("UNAVAILABLE"));
    assert_eq!(tcp_res["classification"], json!("UNKNOWN"));
    assert!(!tcp_res["limitations"].as_array().unwrap().is_empty());

    let icmp_res = find_result(&plan, "icmp_traceroute");
    assert_eq!(icmp_res["status"], json!("SKIPPED_BY_USER"));
    assert!(icmp_res["classification"].is_null());
}

/// 5. validated_tcp_ttl_backend capability가 주어지면 tcp_traceroute가 계획에 포함된다.
#[test]
fn plan_tcp_traceroute_available_when_backend_capability_present() {
    let profile = sample_profile(&["tcp_traceroute"], false, "standalone");
    let registry = canonical_registry();
    let capabilities = caps(&["validated_tcp_ttl_backend"]);
    let plan = plan_features(&profile, &registry, &capabilities).unwrap();

    assert_eq!(plan["execution_order"], json!(["tcp_traceroute"]));
    let tcp_res = find_result(&plan, "tcp_traceroute");
    assert_eq!(tcp_res["status"], json!("WARN"));
    assert_eq!(tcp_res["classification"], json!("UNKNOWN"));
}

/// 6. capabilities에 capture_consent가 위조 주입되어도 profile.capture_approved=false이면 차단한다.
#[test]
fn plan_forged_capture_consent_in_capabilities_blocked_when_profile_unapproved() {
    let profile = sample_profile(&["packet_capture"], false, "standalone");
    let registry = canonical_registry();
    let forged_caps = caps(&["capture_consent", "npcap", "capture_privilege"]);
    let plan = plan_features(&profile, &registry, &forged_caps).unwrap();

    assert_eq!(plan["execution_order"], json!([]));
    let pkt_res = find_result(&plan, "packet_capture");
    assert_eq!(pkt_res["status"], json!("UNAVAILABLE"));
    assert_eq!(pkt_res["classification"], json!("UNKNOWN"));
}

/// 7. 프리셋 기능 목록이나 하위 분석 기능이 선택되어도 캡처 동의를 암묵적으로 추론하지 않는다.
#[test]
fn plan_never_infers_capture_consent_from_preset_or_dependent_selection() {
    let precise = [
        "tcp_connect",
        "icmp_ping",
        "nic_inventory",
        "route_table",
        "icmp_traceroute",
        "tcp_traceroute",
        "packet_capture",
        "syn_rst_analysis",
        "firewall_log",
        "listening_check",
        "result_json",
    ];
    let profile = sample_profile(&precise, false, "standalone");
    let registry = canonical_registry();
    let all_caps = caps(&[
        "validated_tcp_ttl_backend",
        "capture_consent",
        "npcap",
        "capture_privilege",
        "packet_evidence",
    ]);
    let plan = plan_features(&profile, &registry, &all_caps).unwrap();

    let pkt_res = find_result(&plan, "packet_capture");
    assert_eq!(pkt_res["status"], json!("UNAVAILABLE"));
    let exec_order = plan["execution_order"].as_array().unwrap();
    assert!(!exec_order.contains(&json!("packet_capture")));
}

/// 8. profile.capture_approved=true이고 npcap 및 capture_privilege가 모두 있을 때만 가용하다.
#[test]
fn plan_packet_capture_requires_both_profile_approval_and_host_capabilities() {
    let registry = canonical_registry();
    let approved = sample_profile(&["packet_capture"], true, "standalone");

    let missing_npcap = caps(&["capture_consent", "capture_privilege"]);
    let plan_no_npcap = plan_features(&approved, &registry, &missing_npcap).unwrap();
    let res_no_npcap = find_result(&plan_no_npcap, "packet_capture");
    assert_eq!(res_no_npcap["status"], json!("UNAVAILABLE"));

    let missing_priv = caps(&["capture_consent", "npcap"]);
    let plan_no_priv = plan_features(&approved, &registry, &missing_priv).unwrap();
    let res_no_priv = find_result(&plan_no_priv, "packet_capture");
    assert_eq!(res_no_priv["status"], json!("UNAVAILABLE"));

    let full_caps = caps(&["capture_consent", "npcap", "capture_privilege"]);
    let plan_ok = plan_features(&approved, &registry, &full_caps).unwrap();
    let res_ok = find_result(&plan_ok, "packet_capture");
    assert_eq!(res_ok["status"], json!("WARN"));
    assert_eq!(plan_ok["execution_order"], json!(["packet_capture"]));
}

/// 9. packet_evidence 요구사항이 있는 기능들의 capability 제어를 검증한다.
#[test]
fn plan_packet_evidence_requirement_controls_dependent_features() {
    let selected = ["syn_rst_analysis", "packet_compare", "pcap_export"];
    let profile = sample_profile(&selected, false, "standalone");
    let registry = canonical_registry();

    let plan_without = plan_features(&profile, &registry, &BTreeSet::new()).unwrap();
    assert_eq!(plan_without["execution_order"], json!([]));
    for fid in selected {
        let res = find_result(&plan_without, fid);
        assert_eq!(res["status"], json!("UNAVAILABLE"));
        assert_eq!(res["classification"], json!("UNKNOWN"));
    }

    let with_caps = caps(&["packet_evidence"]);
    let plan_with = plan_features(&profile, &registry, &with_caps).unwrap();
    assert_eq!(plan_with["execution_order"], json!(selected));
    for fid in selected {
        let res = find_result(&plan_with, fid);
        assert_eq!(res["status"], json!("WARN"));
        assert_eq!(res["classification"], json!("UNKNOWN"));
    }
}

/// 10. 기능의 supported_modes와 프로필 mode 불일치 시 UNAVAILABLE 처리되는지 검증한다.
#[test]
fn plan_mode_support_controls_feature_availability() {
    let mut registry = canonical_registry();
    set_feature_modes(&mut registry, "agent_session", &["paired_offline"]);
    set_feature_modes(&mut registry, "clock_skew", &["paired_offline"]);

    let items = ["tcp_connect", "agent_session", "clock_skew"];
    let standalone_prof = sample_profile(&items, false, "standalone");
    let plan_standalone = plan_features(&standalone_prof, &registry, &BTreeSet::new()).unwrap();
    assert_eq!(plan_standalone["execution_order"], json!(["tcp_connect"]));

    let agent_res = find_result(&plan_standalone, "agent_session");
    assert_eq!(agent_res["status"], json!("UNAVAILABLE"));
    let clock_res = find_result(&plan_standalone, "clock_skew");
    assert_eq!(clock_res["status"], json!("UNAVAILABLE"));

    let paired_prof = sample_profile(&items, false, "paired_offline");
    let plan_paired = plan_features(&paired_prof, &registry, &BTreeSet::new()).unwrap();
    assert_eq!(plan_paired["execution_order"], json!(items));
}

/// 11. DAG 의존성이 있을 때 selected_features는 원본을 유지하고 execution_order만 위상 정렬된다.
#[test]
fn plan_dag_topological_order_reorders_execution_without_mutating_selected_features() {
    let mut registry = canonical_registry();
    set_feature_dependencies(&mut registry, "result_json", &["tcp_connect"]);
    set_feature_dependencies(&mut registry, "pdf_report", &["result_json"]);

    let reverse_selection = ["pdf_report", "result_json", "tcp_connect"];
    let profile = sample_profile(&reverse_selection, false, "standalone");
    let plan = plan_features(&profile, &registry, &BTreeSet::new()).unwrap();

    assert_eq!(plan["selected_features"], json!(reverse_selection));
    let expected_order = ["tcp_connect", "result_json", "pdf_report"];
    assert_eq!(plan["execution_order"], json!(expected_order));
}

/// 12. 다이아몬드 DAG에서 의존성 제약을 지키면서 원래 선택 순서(stable order)를 유지한다.
#[test]
fn plan_diamond_dag_preserves_stable_relative_order_among_ready_features() {
    let mut registry = canonical_registry();
    set_feature_dependencies(&mut registry, "icmp_ping", &["tcp_connect"]);
    set_feature_dependencies(&mut registry, "dns_lookup", &["tcp_connect"]);
    set_feature_dependencies(&mut registry, "result_json", &["icmp_ping", "dns_lookup"]);

    let selected = ["result_json", "dns_lookup", "icmp_ping", "tcp_connect"];
    let profile = sample_profile(&selected, false, "standalone");
    let plan = plan_features(&profile, &registry, &BTreeSet::new()).unwrap();

    let expected_order = ["tcp_connect", "dns_lookup", "icmp_ping", "result_json"];
    assert_eq!(plan["execution_order"], json!(expected_order));
}

/// 13. 필수 의존성이 사용자에 의해 선택 해제된 경우 암묵적 실행 없이 부모만 UNAVAILABLE 처리한다.
#[test]
fn plan_deselected_dependency_makes_parent_unavailable_without_implicit_execution() {
    let mut registry = canonical_registry();
    set_feature_dependencies(&mut registry, "syn_rst_analysis", &["packet_capture"]);

    let selected = ["syn_rst_analysis", "tcp_connect"];
    let profile = sample_profile(&selected, true, "standalone");
    let all_caps = caps(&[
        "capture_consent",
        "npcap",
        "capture_privilege",
        "packet_evidence",
    ]);
    let plan = plan_features(&profile, &registry, &all_caps).unwrap();

    assert_eq!(plan["selected_features"], json!(selected));
    assert_eq!(plan["execution_order"], json!(["tcp_connect"]));

    let syn_res = find_result(&plan, "syn_rst_analysis");
    assert_eq!(syn_res["status"], json!("UNAVAILABLE"));
    assert_eq!(syn_res["classification"], json!("UNKNOWN"));

    let pkt_res = find_result(&plan, "packet_capture");
    assert_eq!(pkt_res["status"], json!("SKIPPED_BY_USER"));
    assert!(pkt_res["classification"].is_null());
}

/// 14. 선행 의존성이 UNAVAILABLE일 때 다단계 하위 의존 기능들로 UNAVAILABLE 상태가 전파된다.
#[test]
fn plan_unavailable_dependency_propagates_transitively() {
    let mut registry = canonical_registry();
    set_feature_dependencies(&mut registry, "syn_rst_analysis", &["packet_capture"]);
    set_feature_dependencies(&mut registry, "pcap_export", &["syn_rst_analysis"]);
    set_feature_dependencies(&mut registry, "hash_verify", &["pcap_export"]);

    let selected = [
        "packet_capture",
        "syn_rst_analysis",
        "pcap_export",
        "hash_verify",
        "tcp_connect",
    ];
    let profile = sample_profile(&selected, false, "standalone");
    let all_caps = caps(&[
        "capture_consent",
        "npcap",
        "capture_privilege",
        "packet_evidence",
    ]);
    let plan = plan_features(&profile, &registry, &all_caps).unwrap();

    assert_eq!(plan["execution_order"], json!(["tcp_connect"]));
    let chain = [
        "packet_capture",
        "syn_rst_analysis",
        "pcap_export",
        "hash_verify",
    ];
    for fid in chain {
        let res = find_result(&plan, fid);
        assert_eq!(res["status"], json!("UNAVAILABLE"));
        assert_eq!(res["classification"], json!("UNKNOWN"));
    }
}

/// 15. nic_inventory와 route_table의 선택/가용 조합에 따라 shared_collectors가 정확히 1회만 계획되고
///
/// 미선택 상대 기능의 상태(SKIPPED_BY_USER)를 절대 바꾸지 않는지 검증한다.
#[test]
fn plan_shared_host_network_snapshot_collector_planned_once_and_never_mutates_unselected() {
    let mut registry = canonical_registry();

    let p_nic_only = sample_profile(&["nic_inventory"], false, "standalone");
    let plan_nic = plan_features(&p_nic_only, &registry, &BTreeSet::new()).unwrap();
    assert_eq!(
        plan_nic["shared_collectors"],
        json!(["host_network_snapshot"])
    );
    assert_eq!(
        find_result(&plan_nic, "nic_inventory")["status"],
        json!("WARN")
    );
    assert_eq!(
        find_result(&plan_nic, "route_table")["status"],
        json!("SKIPPED_BY_USER")
    );

    let p_route_only = sample_profile(&["route_table"], false, "standalone");
    let plan_route = plan_features(&p_route_only, &registry, &BTreeSet::new()).unwrap();
    assert_eq!(
        plan_route["shared_collectors"],
        json!(["host_network_snapshot"])
    );
    assert_eq!(
        find_result(&plan_route, "route_table")["status"],
        json!("WARN")
    );
    assert_eq!(
        find_result(&plan_route, "nic_inventory")["status"],
        json!("SKIPPED_BY_USER")
    );

    set_feature_modes(&mut registry, "nic_inventory", &["paired_offline"]);
    set_feature_modes(&mut registry, "route_table", &["paired_offline"]);
    let p_unavail = sample_profile(&["nic_inventory", "route_table"], false, "standalone");
    let plan_unavail = plan_features(&p_unavail, &registry, &BTreeSet::new()).unwrap();
    assert_eq!(plan_unavail["shared_collectors"], json!([]));
}

/// 16. 순환 의존성(자기 참조 및 다중 노드 사이클)이 있는 레지스트리는 계획 수립 전에 거부한다.
#[test]
fn plan_rejects_self_and_multi_node_dependency_cycles() {
    let profile = sample_profile(&["tcp_connect"], false, "standalone");

    let mut self_cycle_reg = canonical_registry();
    set_feature_dependencies(&mut self_cycle_reg, "tcp_connect", &["tcp_connect"]);
    assert!(plan_features(&profile, &self_cycle_reg, &BTreeSet::new()).is_err());

    let mut multi_cycle_reg = canonical_registry();
    set_feature_dependencies(&mut multi_cycle_reg, "tcp_connect", &["icmp_ping"]);
    set_feature_dependencies(&mut multi_cycle_reg, "icmp_ping", &["dns_lookup"]);
    set_feature_dependencies(&mut multi_cycle_reg, "dns_lookup", &["tcp_connect"]);
    assert!(plan_features(&profile, &multi_cycle_reg, &BTreeSet::new()).is_err());
}

/// 17. 프로필의 중복된 기능 ID, 알 수 없는 기능 ID, 잘못된 레지스트리 의존성을 거부한다.
#[test]
fn plan_rejects_duplicate_or_unknown_features_in_profile_and_registry() {
    let registry = canonical_registry();

    let dup_profile = sample_profile(&["tcp_connect", "tcp_connect"], false, "standalone");
    assert!(plan_features(&dup_profile, &registry, &BTreeSet::new()).is_err());

    let unknown_profile = sample_profile(&["tcp_connect", "unknown_probe"], false, "standalone");
    assert!(plan_features(&unknown_profile, &registry, &BTreeSet::new()).is_err());

    let mut bad_dep_reg = canonical_registry();
    set_feature_dependencies(&mut bad_dep_reg, "tcp_connect", &["non_existent_feature"]);
    let valid_profile = sample_profile(&["tcp_connect"], false, "standalone");
    assert!(plan_features(&valid_profile, &bad_dep_reg, &BTreeSet::new()).is_err());
}

/// 18. plan_features 호출이 원본 profile과 registry JSON을 절대 변형하지 않는지 검증한다.
#[test]
fn plan_does_not_mutate_input_profile_or_registry() {
    let items = [
        "result_json",
        "packet_capture",
        "tcp_connect",
        "nic_inventory",
    ];
    let profile = sample_profile(&items, true, "standalone");
    let registry = canonical_registry();
    let profile_before = profile.clone();
    let registry_before = registry.clone();

    let _ = plan_features(&profile, &registry, &caps(&["npcap"])).unwrap();

    assert_eq!(profile, profile_before);
    assert_eq!(registry, registry_before);
}

/// 19. restore_profile이 capture_approved를 false로 강제하고 HIGH 비용, CONDITIONAL 권한,
///
/// 위험 자동시작 기능(tcp_monitor, config_change, pdf_report)을 모두 제거하며 안전 기능 순서를 유지한다.
#[test]
fn restore_profile_strips_high_cost_conditional_and_risky_ids_preserving_safe_order() {
    let selected = [
        "result_json",
        "tcp_traceroute",
        "dns_lookup",
        "packet_capture",
        "firewall_log",
        "tcp_monitor",
        "nic_inventory",
        "config_change",
        "pdf_report",
        "tcp_connect",
        "listening_check",
    ];
    let profile = sample_profile(&selected, true, "standalone");
    let registry = canonical_registry();

    let restored = restore_profile(&profile, &registry).unwrap();

    assert_eq!(restored["capture_approved"], json!(false));
    let expected_safe = [
        "result_json",
        "dns_lookup",
        "nic_inventory",
        "tcp_connect",
        "listening_check",
    ];
    assert_eq!(restored["selected_features"], json!(expected_safe));
}

/// 20. 커스텀 레지스트리에서 비용 등급이 HIGH이거나 권한 수준이 CONDITIONAL로 지정된 기능도 제거한다.
#[test]
fn restore_profile_strips_custom_high_cost_and_conditional_permission_features() {
    let mut registry = canonical_registry();
    for item in registry.as_array_mut().unwrap() {
        if item["feature_id"] == "dns_lookup" {
            item["cost_class"] = json!("HIGH");
        }
        if item["feature_id"] == "clock_skew" {
            item["permission_level"] = json!("CONDITIONAL");
        }
    }
    assert!(validate_registry(&registry).is_ok());

    let items = ["tcp_connect", "dns_lookup", "clock_skew", "icmp_ping"];
    let profile = sample_profile(&items, true, "paired_offline");
    let restored = restore_profile(&profile, &registry).unwrap();

    assert_eq!(restored["capture_approved"], json!(false));
    assert_eq!(
        restored["selected_features"],
        json!(["tcp_connect", "icmp_ping"])
    );
}

/// 21. restore_profile이 추가 UI 메타데이터 없이 정규 Profile만 반환하며 원본 입력을 변경하지 않는다.
#[test]
fn restore_profile_returns_canonical_profile_only_and_keeps_inputs_unchanged() {
    let items = ["tcp_connect", "packet_capture", "pdf_report", "route_table"];
    let profile = sample_profile(&items, true, "standalone");
    let registry = canonical_registry();
    let profile_snapshot = profile.clone();
    let registry_snapshot = registry.clone();

    let restored = restore_profile(&profile, &registry).unwrap();

    validate_profile(&restored).unwrap();
    assert_eq!(restored.as_object().unwrap().len(), 8);
    assert_eq!(restored["schema_version"], profile["schema_version"]);
    assert_eq!(restored["profile_id"], profile["profile_id"]);
    assert_eq!(restored["label"], profile["label"]);
    assert_eq!(restored["mode"], profile["mode"]);
    assert_eq!(restored["target"], profile["target"]);
    assert_eq!(restored["limits"], profile["limits"]);

    assert_eq!(profile, profile_snapshot);
    assert_eq!(registry, registry_snapshot);
}

/// 22. restore_profile은 잘못된 프로필이나 잘못된 레지스트리를 먼저 검증하여 거부한다.
#[test]
fn restore_profile_validates_inputs_before_restoring() {
    let registry = canonical_registry();
    let mut bad_profile = sample_profile(&["tcp_connect"], true, "standalone");
    bad_profile["target"]["host"] = json!("https://bad.example.com/path");
    assert!(restore_profile(&bad_profile, &registry).is_err());

    let valid_profile = sample_profile(&["tcp_connect"], true, "standalone");
    let mut bad_registry = canonical_registry();
    set_feature_dependencies(&mut bad_registry, "tcp_connect", &["tcp_connect"]);
    assert!(restore_profile(&valid_profile, &bad_registry).is_err());
}

/// 23. 복합 선택 시나리오에서 23개 전체 상태 분포(WARN, UNAVAILABLE, SKIPPED_BY_USER)와
///
/// execution_order 수가 정확히 일치하는지 검증한다.
#[test]
fn plan_all_status_counts_match_across_mixed_availability_states() {
    let mut registry = canonical_registry();
    set_feature_modes(&mut registry, "agent_session", &["paired_offline"]);
    set_feature_dependencies(&mut registry, "hash_verify", &["pcap_export"]);

    let selected = [
        "tcp_connect",
        "tcp_traceroute",
        "icmp_ping",
        "packet_capture",
        "agent_session",
        "pcap_export",
        "hash_verify",
        "result_json",
    ];
    let profile = sample_profile(&selected, false, "standalone");
    let c = caps(&["capture_consent", "npcap", "capture_privilege"]);
    let plan = plan_features(&profile, &registry, &c).unwrap();

    let expected_order = ["tcp_connect", "icmp_ping", "result_json"];
    assert_eq!(plan["execution_order"], json!(expected_order));
    assert_eq!(plan["shared_collectors"], json!([]));

    let results = plan["feature_results"].as_array().unwrap();
    let warn_cnt = results.iter().filter(|r| r["status"] == "WARN").count();
    let unavail_cnt = results
        .iter()
        .filter(|r| r["status"] == "UNAVAILABLE")
        .count();
    let skipped_cnt = results
        .iter()
        .filter(|r| r["status"] == "SKIPPED_BY_USER")
        .count();

    assert_eq!(warn_cnt, 3);
    assert_eq!(unavail_cnt, 5);
    assert_eq!(skipped_cnt, 15);
    assert_eq!(warn_cnt + unavail_cnt + skipped_cnt, 23);
}
