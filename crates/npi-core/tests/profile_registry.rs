use npi_core::*;
use serde_json::{Value, json};

/// 테스트용 기본 유효 프로필 JSON을 생성한다.
fn valid_profile_json() -> Value {
    json!({
        "schema_version": "1.1",
        "profile_id": "quick-default",
        "label": "빠른 기본 진단",
        "mode": "standalone",
        "selected_features": [
            "tcp_connect",
            "icmp_ping",
            "nic_inventory",
            "route_table",
            "result_json"
        ],
        "capture_approved": false,
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

#[test]
fn canonical_registry_is_valid_and_has_five_defaults() {
    let registry = canonical_registry();
    assert!(validate_registry(&registry).is_ok());

    let defs: Vec<FeatureDefinition> = serde_json::from_value(registry).unwrap();
    assert_eq!(defs.len(), 23);

    let mut default_ids = Vec::new();
    for def in &defs {
        if def.default_selected {
            default_ids.push(def.feature_id.as_str());
        }
    }
    let expected = [
        "tcp_connect",
        "icmp_ping",
        "route_table",
        "nic_inventory",
        "result_json",
    ];
    assert_eq!(default_ids, expected);
}

#[test]
fn valid_profile_passes_and_roundtrips_dto() {
    let raw = valid_profile_json();
    assert!(validate_profile(&raw).is_ok());

    let profile: Profile = serde_json::from_value(raw.clone()).unwrap();
    assert_eq!(profile.schema_version, "1.1");
    assert_eq!(profile.target.port, 443);
    assert!(!profile.capture_approved);

    let reserialized = serde_json::to_value(&profile).unwrap();
    assert_eq!(reserialized, raw);
}

#[test]
fn paired_offline_mode_profile_is_accepted() {
    let mut profile = valid_profile_json();
    profile["mode"] = json!("paired_offline");
    assert!(validate_profile(&profile).is_ok());
}

#[test]
fn valid_ipv6_hosts_are_accepted() {
    for host in ["::1", "2001:db8::1", "::ffff:192.0.2.1"] {
        let mut profile = valid_profile_json();
        profile["target"]["host"] = json!(host);
        assert!(validate_profile(&profile).is_ok());
    }
}

#[test]
fn valid_ascii_domains_and_label_bounds_are_accepted() {
    let label_63 = "a".repeat(63);
    let part_a = "a".repeat(63);
    let part_b = "b".repeat(63);
    let part_c = "c".repeat(63);
    let part_d = "d".repeat(61);
    let max_253 = format!("{part_a}.{part_b}.{part_c}.{part_d}");
    assert_eq!(max_253.len(), 253);

    for host in ["localhost", "example.com", "sub-1.test.local"] {
        let mut profile = valid_profile_json();
        profile["target"]["host"] = json!(host);
        assert!(validate_profile(&profile).is_ok());
    }

    let mut p63 = valid_profile_json();
    p63["target"]["host"] = json!(label_63);
    assert!(validate_profile(&p63).is_ok());

    let mut p253 = valid_profile_json();
    p253["target"]["host"] = json!(max_253);
    assert!(validate_profile(&p253).is_ok());
}

#[test]
fn invalid_target_hosts_uri_path_cidr_credentials_whitespace_rejected() {
    let bad_hosts = [
        "",
        "   ",
        "http://example.com",
        "https://127.0.0.1",
        "example.com/path",
        "user@example.com",
        "127.0.0.1/24",
        "127.0.0.1,127.0.0.2",
        "127.0.0.1 80",
        "example.com:443",
        "[::1]",
        "-bad.example.com",
        "bad-.example.com",
        ".example.com",
        "example.com.",
        "example..com",
    ];

    for host in bad_hosts {
        let mut profile = valid_profile_json();
        profile["target"]["host"] = json!(host);
        assert!(validate_profile(&profile).is_err());
    }
}

#[test]
fn invalid_numeric_ipv4_and_overlong_domains_rejected() {
    let part_64 = "a".repeat(64);
    let label_64 = format!("{part_64}.com");
    let part_63 = "a".repeat(63);
    let part_190 = "b".repeat(190);
    let domain_254 = format!("{part_63}.{part_190}");

    let bad_numeric = [
        "999.999.999.999",
        "256.0.0.1",
        "192.168.1",
        "127.0.0.1.2",
        "10.0.0.999",
        "12345",
    ];

    for host in bad_numeric {
        let mut profile = valid_profile_json();
        profile["target"]["host"] = json!(host);
        assert!(validate_profile(&profile).is_err());
    }

    let mut p64 = valid_profile_json();
    p64["target"]["host"] = json!(label_64);
    assert!(validate_profile(&p64).is_err());

    let mut p254 = valid_profile_json();
    p254["target"]["host"] = json!(domain_254);
    assert!(validate_profile(&p254).is_err());
}

#[test]
fn invalid_ports_zero_huge_fractional_bool_and_non_tcp_rejected() {
    let bad_ports = [
        json!(0),
        json!(65536),
        json!(-1),
        json!(443.5),
        json!(80.0),
        json!(true),
        json!(false),
        json!("443"),
    ];

    for bad_port in bad_ports {
        let mut profile = valid_profile_json();
        profile["target"]["port"] = bad_port;
        assert!(validate_profile(&profile).is_err());
    }

    for valid_edge_port in [1, 65535] {
        let mut profile = valid_profile_json();
        profile["target"]["port"] = json!(valid_edge_port);
        assert!(validate_profile(&profile).is_ok());
    }

    for bad_proto in ["UDP", "ICMP", "tcp", ""] {
        let mut profile = valid_profile_json();
        profile["target"]["protocol"] = json!(bad_proto);
        assert!(validate_profile(&profile).is_err());
    }
}

#[test]
fn missing_required_profile_fields_rejected_without_fake_defaults() {
    let required = [
        "schema_version",
        "profile_id",
        "label",
        "mode",
        "selected_features",
        "capture_approved",
        "target",
        "limits",
    ];

    for field in required {
        let mut profile = valid_profile_json();
        profile.as_object_mut().unwrap().remove(field);
        assert!(validate_profile(&profile).is_err());
        assert!(serde_json::from_value::<Profile>(profile).is_err());
    }
}

#[test]
fn missing_required_target_and_limits_fields_rejected() {
    for target_field in ["host", "port", "protocol"] {
        let mut profile = valid_profile_json();
        profile["target"]
            .as_object_mut()
            .unwrap()
            .remove(target_field);
        assert!(validate_profile(&profile).is_err());
        assert!(serde_json::from_value::<Profile>(profile).is_err());
    }

    let limit_fields = [
        "tcp_timeout_ms",
        "max_hops",
        "retries",
        "max_concurrent_tcp",
        "capture_duration_secs",
        "capture_max_bytes",
        "log_retention_days",
        "ui_updates_per_second",
    ];

    for limit_field in limit_fields {
        let mut profile = valid_profile_json();
        profile["limits"]
            .as_object_mut()
            .unwrap()
            .remove(limit_field);
        assert!(validate_profile(&profile).is_err());
        assert!(serde_json::from_value::<Profile>(profile).is_err());
    }
}

#[test]
fn unknown_properties_rejected_across_dtos() {
    let mut profile = valid_profile_json();
    profile["extra_root"] = json!(true);
    assert!(validate_profile(&profile).is_err());
    assert!(serde_json::from_value::<Profile>(profile).is_err());

    let mut p_target = valid_profile_json();
    p_target["target"]["extra_target"] = json!("nope");
    assert!(validate_profile(&p_target).is_err());
    let target_val = p_target["target"].clone();
    assert!(serde_json::from_value::<Target>(target_val).is_err());

    let mut p_limits = valid_profile_json();
    p_limits["limits"]["extra_limit"] = json!(10);
    assert!(validate_profile(&p_limits).is_err());
    let limits_val = p_limits["limits"].clone();
    assert!(serde_json::from_value::<Limits>(limits_val).is_err());

    let mut reg = canonical_registry();
    reg[0]["unknown_field"] = json!(123);
    assert!(validate_registry(&reg).is_err());
    let feat_val = reg[0].clone();
    assert!(serde_json::from_value::<FeatureDefinition>(feat_val).is_err());
}

#[test]
fn unknown_schema_version_blank_strings_and_bools_as_numbers_rejected() {
    for bad_ver in ["1.0", "2.0", "", "v1.1"] {
        let mut profile = valid_profile_json();
        profile["schema_version"] = json!(bad_ver);
        assert!(validate_profile(&profile).is_err());
    }

    for blank in ["", "   ", "\t\n"] {
        let mut p1 = valid_profile_json();
        p1["profile_id"] = json!(blank);
        assert!(validate_profile(&p1).is_err());

        let mut p2 = valid_profile_json();
        p2["label"] = json!(blank);
        assert!(validate_profile(&p2).is_err());
    }

    for bad_mode in ["online", "STANDALONE", ""] {
        let mut profile = valid_profile_json();
        profile["mode"] = json!(bad_mode);
        assert!(validate_profile(&profile).is_err());
    }

    let bad_bools = [json!(0), json!(1), json!("false"), json!(null)];
    for bad_bool in bad_bools {
        let mut profile = valid_profile_json();
        profile["capture_approved"] = bad_bool;
        assert!(validate_profile(&profile).is_err());
    }
}

#[test]
fn limits_exact_lower_and_upper_bounds_accepted() {
    let mut min_profile = valid_profile_json();
    min_profile["limits"] = json!({
        "tcp_timeout_ms": 1,
        "max_hops": 1,
        "retries": 0,
        "max_concurrent_tcp": 1,
        "capture_duration_secs": 1,
        "capture_max_bytes": 1,
        "log_retention_days": 1,
        "ui_updates_per_second": 1
    });
    assert!(validate_profile(&min_profile).is_ok());

    let mut max_profile = valid_profile_json();
    max_profile["limits"] = json!({
        "tcp_timeout_ms": 120000,
        "max_hops": 64,
        "retries": 3,
        "max_concurrent_tcp": 4,
        "capture_duration_secs": 300,
        "capture_max_bytes": 52428800,
        "log_retention_days": 365,
        "ui_updates_per_second": 4
    });
    assert!(validate_profile(&max_profile).is_ok());
}

#[test]
fn every_limit_below_lower_bound_rejected() {
    let cases = [
        ("tcp_timeout_ms", json!(0)),
        ("max_hops", json!(0)),
        ("retries", json!(-1)),
        ("max_concurrent_tcp", json!(0)),
        ("capture_duration_secs", json!(0)),
        ("capture_max_bytes", json!(0)),
        ("log_retention_days", json!(0)),
        ("ui_updates_per_second", json!(0)),
    ];

    for (field, bad_val) in cases {
        let mut profile = valid_profile_json();
        profile["limits"][field] = bad_val;
        assert!(validate_profile(&profile).is_err());
    }
}

#[test]
fn every_limit_above_upper_bound_and_malformed_types_rejected() {
    let cases = [
        ("tcp_timeout_ms", json!(120001)),
        ("max_hops", json!(65)),
        ("retries", json!(4)),
        ("max_concurrent_tcp", json!(5)),
        ("capture_duration_secs", json!(301)),
        ("capture_max_bytes", json!(52428801)),
        ("log_retention_days", json!(366)),
        ("ui_updates_per_second", json!(5)),
    ];

    for (field, bad_val) in cases {
        let mut profile = valid_profile_json();
        profile["limits"][field] = bad_val;
        assert!(validate_profile(&profile).is_err());

        let mut float_profile = valid_profile_json();
        float_profile["limits"][field] = json!(1.5);
        assert!(validate_profile(&float_profile).is_err());

        let mut bool_profile = valid_profile_json();
        bool_profile["limits"][field] = json!(true);
        assert!(validate_profile(&bool_profile).is_err());
    }
}

#[test]
fn duplicate_and_unknown_selected_features_rejected() {
    let mut dup_profile = valid_profile_json();
    dup_profile["selected_features"] = json!(["tcp_connect", "icmp_ping", "tcp_connect"]);
    assert!(validate_profile(&dup_profile).is_err());

    let mut unknown_profile = valid_profile_json();
    unknown_profile["selected_features"] = json!(["tcp_connect", "nonexistent_probe"]);
    assert!(validate_profile(&unknown_profile).is_err());
}

#[test]
fn capture_selected_with_consent_false_is_valid_and_keeps_false() {
    let mut profile = valid_profile_json();
    profile["selected_features"] = json!([
        "tcp_connect",
        "packet_capture",
        "syn_rst_analysis",
        "pcap_export",
        "result_json",
    ]);
    profile["capture_approved"] = json!(false);

    let snapshot = profile.clone();
    assert!(validate_profile(&profile).is_ok());
    assert_eq!(profile, snapshot);
    assert_eq!(profile["capture_approved"], json!(false));

    let dto: Profile = serde_json::from_value(profile).unwrap();
    assert!(!dto.capture_approved);
}

#[test]
fn raw_input_remains_unchanged_on_validation_failure() {
    let mut bad_profile = valid_profile_json();
    bad_profile["target"]["port"] = json!(0);
    let profile_snapshot = bad_profile.clone();
    assert!(validate_profile(&bad_profile).is_err());
    assert_eq!(bad_profile, profile_snapshot);

    let mut bad_reg = canonical_registry();
    bad_reg[0]["group_id"] = json!("G-WRONG");
    let reg_snapshot = bad_reg.clone();
    assert!(validate_registry(&bad_reg).is_err());
    assert_eq!(bad_reg, reg_snapshot);
}

#[test]
fn registry_incorrect_group_membership_rejected() {
    let mut reg = canonical_registry();
    reg[0]["group_id"] = json!("G-PATH");
    assert!(validate_registry(&reg).is_err());

    let mut reg_unknown_group = canonical_registry();
    reg_unknown_group[0]["group_id"] = json!("G-INVALID");
    assert!(validate_registry(&reg_unknown_group).is_err());
}

#[test]
fn registry_duplicate_feature_id_and_wrong_length_rejected() {
    let mut dup_reg = canonical_registry();
    dup_reg[1]["feature_id"] = json!("tcp_connect");
    assert!(validate_registry(&dup_reg).is_err());

    let mut short_reg = canonical_registry();
    short_reg.as_array_mut().unwrap().pop();
    assert!(validate_registry(&short_reg).is_err());
}

#[test]
fn registry_missing_dependency_rejected_even_when_unselected() {
    let mut reg = canonical_registry();
    reg[2]["dependencies"] = json!(["missing_feature_id"]);
    assert!(validate_registry(&reg).is_err());

    let mut reg_missing_target = canonical_registry();
    reg_missing_target[2]["dependencies"] = json!(["policy_check"]);
    reg_missing_target.as_array_mut().unwrap().pop();
    assert!(validate_registry(&reg_missing_target).is_err());
}

#[test]
fn registry_self_dependency_cycle_rejected_even_when_unselected() {
    let mut reg = canonical_registry();
    assert_eq!(reg[2]["default_selected"], json!(false));
    reg[2]["dependencies"] = json!(["dns_lookup"]);
    assert!(validate_registry(&reg).is_err());
}

#[test]
fn registry_indirect_dependency_cycle_rejected_even_when_unselected() {
    let mut reg = canonical_registry();
    reg[2]["dependencies"] = json!(["icmp_traceroute"]);
    reg[3]["dependencies"] = json!(["tcp_traceroute"]);
    reg[4]["dependencies"] = json!(["dns_lookup"]);
    assert!(validate_registry(&reg).is_err());
}

#[test]
fn registry_valid_dag_dependencies_and_localized_labels_accepted() {
    let mut reg = canonical_registry();
    reg[0]["label"] = json!("TCP Connection (Localized)");
    reg[0]["description"] = json!("Localized TCP description");
    reg[8]["dependencies"] = json!(["packet_capture"]);

    let snapshot = reg.clone();
    assert!(validate_registry(&reg).is_ok());
    assert_eq!(reg, snapshot);
}

#[test]
fn registry_invalid_fields_modes_requirements_and_cost_permission_rejected() {
    let mut empty_modes = canonical_registry();
    empty_modes[0]["supported_modes"] = json!([]);
    assert!(validate_registry(&empty_modes).is_err());

    let mut dup_modes = canonical_registry();
    dup_modes[0]["supported_modes"] = json!(["standalone", "standalone"]);
    assert!(validate_registry(&dup_modes).is_err());

    let mut bad_cost = canonical_registry();
    bad_cost[0]["cost_class"] = json!("EXTREME");
    assert!(validate_registry(&bad_cost).is_err());

    let mut bad_perm = canonical_registry();
    bad_perm[0]["permission_level"] = json!("ADMIN");
    assert!(validate_registry(&bad_perm).is_err());

    let mut bad_req = canonical_registry();
    bad_req[0]["requirements"] = json!(["unknown_req"]);
    assert!(validate_registry(&bad_req).is_err());

    let mut dup_req = canonical_registry();
    dup_req[7]["requirements"] = json!(["npcap", "npcap"]);
    assert!(validate_registry(&dup_req).is_err());
}
