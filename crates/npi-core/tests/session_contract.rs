use npi_core::{
    Evidence, FeatureResult, Finding, ResourceMetrics, Session, convert_legacy_session,
    validate_session,
};
use serde_json::{Value, json};

/// 테스트용 유효한 최소 스키마 1.1 프로필 JSON을 생성한다 (네트워크 호출 없음).
fn sample_valid_profile_json() -> Value {
    json!({
        "schema_version": "1.1",
        "profile_id": "prof-minimal-01",
        "label": "최소 검증 프로필",
        "mode": "standalone",
        "selected_features": ["tcp_connect", "result_json"],
        "capture_approved": false,
        "target": {
            "host": "127.0.0.1",
            "port": 1526,
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

/// 테스트용 유효한 최소 스키마 1.1 세션 JSON을 생성한다.
/// 미확인 메타데이터(host_role, timezone_offset_minutes, clock, resource_metrics)는 모두 null이다.
fn sample_valid_minimal_session_json() -> Value {
    json!({
        "schema_version": "1.1",
        "session_id": "11111111-1111-4111-8111-111111111101",
        "mode": "standalone",
        "host_role": null,
        "started_at_utc": "2026-10-20T02:30:00Z",
        "timezone_offset_minutes": null,
        "clock_offset_ms": null,
        "clock_uncertainty_ms": null,
        "profile": sample_valid_profile_json(),
        "evidence": [],
        "feature_results": [],
        "findings": [],
        "limitations": [],
        "resource_metrics": {
            "peak_rss_bytes": null,
            "avg_cpu_percent": null,
            "capture_drops": null
        }
    })
}

#[test]
fn test_01_valid_minimal_session_with_nullable_unknowns() {
    let session_val = sample_valid_minimal_session_json();
    assert!(
        validate_session(&session_val).is_ok(),
        "유효한 최소 세션은 검증을 통과해야 합니다"
    );

    let parsed: Session =
        serde_json::from_value(session_val.clone()).expect("Session 역직렬화가 성공해야 합니다");
    assert_eq!(parsed.host_role, None);
    assert_eq!(parsed.timezone_offset_minutes, None);
    assert_eq!(parsed.clock_offset_ms, None);
    assert_eq!(parsed.clock_uncertainty_ms, None);
    assert_eq!(parsed.resource_metrics.peak_rss_bytes, None);
    assert_eq!(parsed.resource_metrics.avg_cpu_percent, None);
    assert_eq!(parsed.resource_metrics.capture_drops, None);

    let reserialized = serde_json::to_value(&parsed).expect("Session 재직렬화가 성공해야 합니다");
    assert_eq!(reserialized, session_val);
}

#[test]
fn test_02_valid_full_session_with_packet_evidence_and_results() {
    let mut s = sample_valid_minimal_session_json();
    s["host_role"] = json!("client");
    s["timezone_offset_minutes"] = json!(540);
    s["clock_offset_ms"] = json!(-12);
    s["clock_uncertainty_ms"] = json!(5);
    s["evidence"] = json!([
        {
            "evidence_id": "ev-sock-1",
            "kind": "SOCKET",
            "artifact_path": null,
            "synthetic": true
        },
        {
            "evidence_id": "ev-pkt-1",
            "kind": "PACKET",
            "artifact_path": "captures/test_trace.pcapng",
            "synthetic": true
        }
    ]);
    s["feature_results"] = json!([
        {
            "feature_id": "tcp_connect",
            "group_id": "G-NET",
            "status": "FAIL",
            "classification": "OBSERVED",
            "evidence_ids": ["ev-sock-1"],
            "started_at_utc": "2026-10-20T02:30:01.125+09:00",
            "ended_at_utc": "2026-10-20T02:30:02.500+09:00",
            "duration_ms": 1375,
            "error_code": 10061,
            "limitations": ["소켓 10061 응답만으로는 RST 패킷 수신을 단정할 수 없음"],
            "next_checks": ["패킷 캡처 증거와 대조"]
        },
        {
            "feature_id": "syn_rst_analysis",
            "group_id": "G-PKT",
            "status": "PASS",
            "classification": "OBSERVED",
            "evidence_ids": ["ev-pkt-1"],
            "started_at_utc": null,
            "ended_at_utc": null,
            "duration_ms": 0,
            "error_code": null,
            "limitations": [],
            "next_checks": []
        }
    ]);
    s["findings"] = json!([
        {
            "classification": "OBSERVED",
            "statement": "패킷 캡처 증거(ev-pkt-1)에서 SYN 전송 후 RST 패킷 수신됨",
            "evidence_ids": ["ev-pkt-1"],
            "confidence": "high",
            "limitations": ["마지막 응답 HOP=차단 장비 단정 불가"],
            "next_checks": ["서버 측 리스닝 상태 확인"]
        }
    ]);
    s["limitations"] = json!(["합성 픽스처 기반 검증 세션"]);
    s["resource_metrics"] = json!({
        "peak_rss_bytes": 1048576,
        "avg_cpu_percent": 12.5,
        "capture_drops": 0
    });

    assert!(
        validate_session(&s).is_ok(),
        "PACKET 증거가 연결된 정당한 세션은 통과해야 합니다: {:?}",
        validate_session(&s)
    );
}

#[test]
fn test_03_missing_mandatory_nullable_keys_and_unknown_fields_rejected() {
    for required_key in [
        "host_role",
        "timezone_offset_minutes",
        "clock_offset_ms",
        "clock_uncertainty_ms",
        "resource_metrics",
    ] {
        let mut s = sample_valid_minimal_session_json();
        s.as_object_mut().unwrap().remove(required_key);
        assert!(
            validate_session(&s).is_err(),
            "nullable 필드라도 키({required_key}) 자체가 누락되면 거부해야 합니다"
        );
    }

    let mut s_unknown = sample_valid_minimal_session_json();
    s_unknown["unexpected_field"] = json!(true);
    assert!(validate_session(&s_unknown).is_err());

    let mut s_rm_missing = sample_valid_minimal_session_json();
    s_rm_missing["resource_metrics"]
        .as_object_mut()
        .unwrap()
        .remove("capture_drops");
    assert!(validate_session(&s_rm_missing).is_err());
}

#[test]
fn test_04_host_role_and_timezone_bounds_validation() {
    let mut s = sample_valid_minimal_session_json();
    s["host_role"] = json!("server");
    s["timezone_offset_minutes"] = json!(-840);
    assert!(validate_session(&s).is_ok());

    s["timezone_offset_minutes"] = json!(840);
    assert!(validate_session(&s).is_ok());

    for bad_role in [json!("agent"), json!("unknown"), json!(123), json!(false)] {
        let mut bad = sample_valid_minimal_session_json();
        bad["host_role"] = bad_role;
        assert!(validate_session(&bad).is_err());
    }

    for bad_tz in [
        json!(-841),
        json!(841),
        json!(900),
        json!(540.5),
        json!("UTC+9"),
        json!(true),
    ] {
        let mut bad = sample_valid_minimal_session_json();
        bad["timezone_offset_minutes"] = bad_tz;
        assert!(validate_session(&bad).is_err());
    }
}

#[test]
fn test_05_session_mode_must_match_profile_mode() {
    let mut s = sample_valid_minimal_session_json();
    s["mode"] = json!("paired_offline");
    // profile.mode는 "standalone"인 상태
    let err = validate_session(&s).unwrap_err();
    assert!(
        err.iter().any(|m| m.contains("일치하지 않습니다")),
        "세션 mode와 profile.mode 불일치를 검출해야 합니다: {err:?}"
    );
}

#[test]
fn test_06_uuid_format_validation() {
    for invalid_uuid in [
        "",
        "11111111-1111-4111-8111-11111111110",
        "11111111-1111-4111-8111-1111111111011",
        "11111111_1111_4111_8111_111111111101",
        "11111111-1111-4111-8111-11111111110g",
        "111111111111-4111-8111-1111-11111101",
        "한글문자열이포함된-uuid-형식-오류-테스트입니다",
    ] {
        let mut s = sample_valid_minimal_session_json();
        s["session_id"] = json!(invalid_uuid);
        assert!(
            validate_session(&s).is_err(),
            "잘못된 UUID({invalid_uuid})는 거부되어야 합니다"
        );
    }
}

#[test]
fn test_07_rfc3339_calendar_leap_year_and_utf8_no_panic() {
    // 윤년 2월 29일은 유효
    let mut leap_ok = sample_valid_minimal_session_json();
    leap_ok["started_at_utc"] = json!("2024-02-29T23:59:59.999+09:00");
    assert!(validate_session(&leap_ok).is_ok());

    // 잘못된 날짜·시각 및 멀티바이트 UTF-8 입력이 패닉 없이 거부되는지 검증
    for bad_ts in [
        "2026-02-30T02:30:00Z",         // 2월 30일
        "2026-02-29T02:30:00Z",         // 평년 2월 29일
        "2100-02-29T02:30:00Z",         // 100배수 평년 2월 29일
        "2026-04-31T02:30:00Z",         // 4월 31일
        "2026-13-01T00:00:00Z",         // 13월
        "2026-00-10T00:00:00Z",         // 0월
        "2026-10-00T00:00:00Z",         // 0일
        "2026-10-20T24:00:00Z",         // 24시
        "2026-10-20T02:60:00Z",         // 60분
        "2026-10-20T02:30:60Z",         // 60초
        "2026-10-20T02:30:00.Z",        // 소수점 뒤 숫자 없음
        "2026-10-20T02:30:00+0900",     // 타임존 콜론 누락
        "2026-10-20T02:30:00-00:00",    // -00:00 불허
        "2026-10-20T02:30:00+14:30",    // +840분 초과
        "2026-10-20T02:30:00",          // 타임존 누락
        "2026년10월20일오후두시삼십분", // 멀티바이트 UTF-8 (콜론 없음, 슬라이스 패닉 방지)
        "가나다라마바사아자차카타파하", // 멀티바이트 UTF-8
    ] {
        let mut s = sample_valid_minimal_session_json();
        s["started_at_utc"] = json!(bad_ts);
        assert!(
            validate_session(&s).is_err(),
            "잘못된 타임스탬프({bad_ts})는 패닉 없이 거부되어야 합니다"
        );
    }
}

#[test]
fn test_08_resource_metrics_and_clock_bounds() {
    for bad_metrics in [
        json!({"peak_rss_bytes": -1, "avg_cpu_percent": null, "capture_drops": null}),
        json!({"peak_rss_bytes": null, "avg_cpu_percent": -0.1, "capture_drops": null}),
        json!({"peak_rss_bytes": null, "avg_cpu_percent": 100.1, "capture_drops": null}),
        json!({"peak_rss_bytes": null, "avg_cpu_percent": "50%", "capture_drops": null}),
        json!({"peak_rss_bytes": null, "avg_cpu_percent": null, "capture_drops": -5}),
        json!({"peak_rss_bytes": true, "avg_cpu_percent": null, "capture_drops": null}),
    ] {
        let mut s = sample_valid_minimal_session_json();
        s["resource_metrics"] = bad_metrics;
        assert!(validate_session(&s).is_err());
    }

    let mut bad_clock = sample_valid_minimal_session_json();
    bad_clock["clock_uncertainty_ms"] = json!(-1);
    assert!(validate_session(&bad_clock).is_err());
}

#[test]
fn test_09_evidence_kinds_unique_id_synthetic_bool_and_safe_relative_path() {
    // 8개 계약 kind 모두 허용 확인
    let kinds = [
        "SOCKET",
        "ICMP",
        "DNS",
        "HOST_SNAPSHOT",
        "PACKET",
        "CAPTURE_METADATA",
        "POLICY_MEMO",
        "IMPORT",
    ];
    let mut s = sample_valid_minimal_session_json();
    let ev_list: Vec<Value> = kinds
        .iter()
        .enumerate()
        .map(|(i, k)| {
            json!({
                "evidence_id": format!("ev-{i}"),
                "kind": k,
                "artifact_path": format!("artifacts/item_{i}.json"),
                "synthetic": false
            })
        })
        .collect();
    s["evidence"] = Value::Array(ev_list);
    assert!(validate_session(&s).is_ok());

    // 중복 evidence_id 거부
    let mut dup_ev = sample_valid_minimal_session_json();
    dup_ev["evidence"] = json!([
        {"evidence_id": "dup-1", "kind": "SOCKET", "artifact_path": null, "synthetic": true},
        {"evidence_id": "dup-1", "kind": "ICMP", "artifact_path": null, "synthetic": true}
    ]);
    assert!(validate_session(&dup_ev).is_err());

    // synthetic에 숫자가 들어오면 거부
    let mut bad_syn = sample_valid_minimal_session_json();
    bad_syn["evidence"] = json!([
        {"evidence_id": "ev-1", "kind": "SOCKET", "artifact_path": null, "synthetic": 1}
    ]);
    assert!(validate_session(&bad_syn).is_err());

    // 안전하지 않은 artifact_path 거부
    for unsafe_path in [
        "",
        "   ",
        "/etc/passwd",
        "\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\temp\\capture.pcap",
        "C:capture.pcap",
        "../secret.pcap",
        "captures/../../secret.pcap",
        "./capture.pcap",
        "captures//double.pcap",
        "captures/trailing/",
        "file://captures/test.pcap",
    ] {
        let mut bad_path = sample_valid_minimal_session_json();
        bad_path["evidence"] = json!([
            {"evidence_id": "ev-1", "kind": "PACKET", "artifact_path": unsafe_path, "synthetic": true}
        ]);
        assert!(
            validate_session(&bad_path).is_err(),
            "안전하지 않은 경로({unsafe_path})는 거부되어야 합니다"
        );
    }
}

#[test]
fn test_10_feature_results_duplicates_group_mismatch_and_bounds() {
    let mut s = sample_valid_minimal_session_json();
    let fr = json!({
        "feature_id": "tcp_connect",
        "group_id": "G-NET",
        "status": "SKIPPED_BY_USER",
        "classification": null,
        "evidence_ids": [],
        "started_at_utc": null,
        "ended_at_utc": null,
        "duration_ms": null,
        "error_code": null,
        "limitations": [],
        "next_checks": []
    });
    // 중복된 feature_id 거부
    s["feature_results"] = json!([fr.clone(), fr.clone()]);
    assert!(validate_session(&s).is_err());

    // 잘못된 group_id 매핑 거부
    let mut bad_grp = fr.clone();
    bad_grp["group_id"] = json!("G-PATH");
    s["feature_results"] = json!([bad_grp]);
    assert!(validate_session(&s).is_err());

    // 음수 duration_ms 거부
    let mut neg_dur = fr.clone();
    neg_dur["duration_ms"] = json!(-10);
    s["feature_results"] = json!([neg_dur]);
    assert!(validate_session(&s).is_err());

    // 소수점 error_code 거부
    let mut bad_err = fr;
    bad_err["error_code"] = json!(10061.5);
    s["feature_results"] = json!([bad_err]);
    assert!(validate_session(&s).is_err());
}

#[test]
fn test_11_dangling_evidence_refs_and_observed_empty_refs_rejected() {
    // 존재하지 않는 evidence_id 참조 거부
    let mut s = sample_valid_minimal_session_json();
    s["findings"] = json!([
        {
            "classification": "INFERRED",
            "statement": "경로 상 지연 가능성 추론",
            "evidence_ids": ["non-existent-ev"],
            "confidence": "medium",
            "limitations": [],
            "next_checks": []
        }
    ]);
    assert!(validate_session(&s).is_err());

    // OBSERVED finding인데 evidence_ids가 비어 있으면 거부
    s["findings"] = json!([
        {
            "classification": "OBSERVED",
            "statement": "TCP 연결 응답 확인",
            "evidence_ids": [],
            "confidence": "high",
            "limitations": [],
            "next_checks": []
        }
    ]);
    assert!(validate_session(&s).is_err());
}

#[test]
fn test_12_syn_rst_positive_claim_without_packet_evidence_rejected() {
    let mut s = sample_valid_minimal_session_json();
    s["evidence"] = json!([
        {
            "evidence_id": "ev-sock-only",
            "kind": "SOCKET",
            "artifact_path": null,
            "synthetic": true
        }
    ]);

    for bad_statement in [
        "SYN 패킷 전송 후 RST 패킷 수신 확인",
        "SYN/RST 패킷 관찰됨",
        "Winsock 10061(REFUSED) 발생으로 RST 패킷 수신됨",
        "대상 포트에서 RST 응답이 포착되었습니다",
    ] {
        s["findings"] = json!([
            {
                "classification": "OBSERVED",
                "statement": bad_statement,
                "evidence_ids": ["ev-sock-only"],
                "confidence": "high",
                "limitations": [],
                "next_checks": []
            }
        ]);
        assert!(
            validate_session(&s).is_err(),
            "PACKET 증거 없는 SYN/RST 긍정 주장({bad_statement})은 거부되어야 합니다"
        );
    }
}

#[test]
fn test_13_unrelated_negation_anywhere_else_does_not_bypass_guard() {
    let mut s = sample_valid_minimal_session_json();
    s["evidence"] = json!([
        {
            "evidence_id": "ev-pkt-1",
            "kind": "PACKET",
            "artifact_path": "captures/trace.pcapng",
            "synthetic": true
        }
    ]);

    // 다른 절이나 문장 끝에 '미확인 사항 없음', '오류 없음', '불가 항목 없음'을 붙여도 우회 불가
    for bypass_attempt in [
        "방화벽 차단 확정. 미확인 사항 없음.",
        "방화벽 차단 확정, 추가 오류 없음",
        "방화벽 차단 확정 (불가 항목 없음)",
        "마지막 응답 HOP=차단 장비. 미확인 사항 없음.",
        "마지막 응답 HOP = 차단 장비, 추가 확인 불가 항목 없음",
        "last hop=차단장비. 이상 없음.",
    ] {
        s["findings"] = json!([
            {
                "classification": "OBSERVED",
                "statement": bypass_attempt,
                "evidence_ids": ["ev-pkt-1"],
                "confidence": "high",
                "limitations": [],
                "next_checks": []
            }
        ]);
        assert!(
            validate_session(&s).is_err(),
            "무관한 부정어를 포함한 금지 단정 우회 문구({bypass_attempt})는 반드시 거부되어야 합니다"
        );
    }

    // PACKET 증거가 없을 때 무관한 부정어를 붙인 SYN/RST 긍정 주장도 우회 불가
    let mut s_no_pkt = sample_valid_minimal_session_json();
    for syn_rst_bypass in [
        "SYN/RST 패킷 관찰됨. 미확인 사항 없음.",
        "RST 패킷 수신 확인, 추가 오류 없음",
        "미확인 사항 없음. SYN/RST 패킷이 관찰되었습니다.",
        "RST 패킷이 수신되었으나 다른 항목은 확인 불가",
    ] {
        s_no_pkt["findings"] = json!([
            {
                "classification": "UNKNOWN",
                "statement": syn_rst_bypass,
                "evidence_ids": [],
                "confidence": "low",
                "limitations": [],
                "next_checks": []
            }
        ]);
        assert!(
            validate_session(&s_no_pkt).is_err(),
            "무관한 부정어를 포함한 무근거 SYN/RST 주장({syn_rst_bypass})은 거부되어야 합니다"
        );
    }
}

#[test]
fn test_14_scoped_immediate_negation_is_allowed() {
    let mut s = sample_valid_minimal_session_json();
    s["findings"] = json!([
        {
            "classification": "UNKNOWN",
            "statement": "패킷 캡처 근거가 없으므로 SYN/RST 패킷 관찰 여부 미확인",
            "evidence_ids": [],
            "confidence": "low",
            "limitations": [
                "방화벽 차단 확정 불가",
                "마지막 응답 HOP=차단 장비 단정 불가",
                "소켓 연결 거부(10061)는 RST 패킷 관찰을 의미하지 않음"
            ],
            "next_checks": []
        }
    ]);
    assert!(
        validate_session(&s).is_ok(),
        "직접적인 국소 부정·미확인 고지 문구는 허용되어야 합니다: {:?}",
        validate_session(&s)
    );
}

#[test]
fn test_15_malformed_arrays_and_objects_return_err_without_panic() {
    for non_obj in [
        json!(null),
        json!(true),
        json!(42),
        json!("session"),
        json!([]),
    ] {
        assert!(validate_session(&non_obj).is_err());
        assert!(convert_legacy_session(&non_obj).is_err());
    }

    for array_field in ["evidence", "feature_results", "findings", "limitations"] {
        let mut s = sample_valid_minimal_session_json();
        s[array_field] = json!({"not": "an_array"});
        assert!(validate_session(&s).is_err());

        s[array_field] = json!([12345]);
        assert!(validate_session(&s).is_err());
    }
}

#[test]
fn test_16_legacy_conversion_canonical_example_lossless() {
    let legacy_input = json!({
        "schema_version": "1.0",
        "session_id": "11111111-1111-4111-8111-111111111109",
        "mode": "standalone",
        "started_at_utc": "2026-10-20T02:30:00Z",
        "target": {
            "ip": "192.168.10.100",
            "port": 1526,
            "protocol": "TCP"
        },
        "tests": [],
        "artifacts": []
    });

    let wrapped = convert_legacy_session(&legacy_input)
        .expect("표준 레거시 1.0 예시 입력은 변환에 성공해야 합니다");

    assert_eq!(wrapped["original"], legacy_input);
    assert!(
        wrapped["transformations"]
            .as_array()
            .is_some_and(|arr| !arr.is_empty())
    );

    let converted = &wrapped["converted"];
    assert!(
        validate_session(converted).is_ok(),
        "변환된 1.1 세션은 validate_session을 통과해야 합니다: {:?}",
        validate_session(converted)
    );

    // Z로 끝나는 started_at_utc라도 원본 타임존 오프셋이 없으면 반드시 null 유지
    assert_eq!(converted["host_role"], Value::Null);
    assert_eq!(converted["timezone_offset_minutes"], Value::Null);
    assert_eq!(converted["clock_offset_ms"], Value::Null);
    assert_eq!(converted["clock_uncertainty_ms"], Value::Null);
    assert_eq!(
        converted["profile"]["target"]["host"],
        json!("192.168.10.100")
    );
    assert_eq!(converted["profile"]["target"]["port"], json!(1526));
    assert_eq!(converted["profile"]["target"]["protocol"], json!("TCP"));
    assert_eq!(converted["profile"]["selected_features"], json!([]));
    assert_eq!(converted["profile"]["capture_approved"], json!(false));
    assert_eq!(converted["evidence"], json!([]));
    assert_eq!(converted["feature_results"], json!([]));
}

#[test]
fn test_17_legacy_preserves_unknown_fields_and_never_invents_pass_or_capture() {
    let legacy_with_extras = json!({
        "schema_version": "1.0",
        "session_id": "11111111-1111-4111-8111-111111111109",
        "mode": "standalone",
        "started_at_utc": "2026-10-20T02:30:00Z",
        "target": {
            "ip": "192.168.10.100",
            "port": 1526,
            "protocol": "TCP",
            "legacy_zone": "dmz-alpha"
        },
        "capture": {
            "enabled": true,
            "driver": "npcap"
        },
        "tests": [
            {"id": "tcp_connect", "result": "PASS", "rtt_ms": 4}
        ],
        "artifacts": ["raw_dump.pcap"],
        "custom_operator_memo": "임의 레거시 메타데이터 보존 확인"
    });

    let wrapped = convert_legacy_session(&legacy_with_extras).expect("레거시 변환 성공");
    // 원본 JSON이 알 수 없는 모든 필드와 함께 그대로 보존되었는지 검증
    assert_eq!(wrapped["original"], legacy_with_extras);

    let converted = &wrapped["converted"];
    assert!(validate_session(converted).is_ok());
    // 원본 capture.enabled=true나 tests의 PASS가 있어도 가짜 증거/PASS/캡처 승인을 만들지 않음
    assert_eq!(converted["profile"]["capture_approved"], json!(false));
    assert_eq!(converted["evidence"], json!([]));
    assert_eq!(converted["feature_results"], json!([]));
    assert_eq!(converted["findings"][0]["classification"], json!("UNKNOWN"));
}

#[test]
fn test_18_legacy_known_role_and_timezone_preserved_when_valid() {
    let legacy_with_meta = json!({
        "schema_version": "1.0",
        "session_id": "11111111-1111-4111-8111-111111111109",
        "mode": "paired_offline",
        "host_role": "server",
        "started_at_utc": "2026-10-20T11:30:00+09:00",
        "timezone_offset_minutes": 540,
        "target": {
            "host": "example.internal",
            "port": 443,
            "protocol": "TCP"
        },
        "tests": [],
        "artifacts": []
    });

    let wrapped = convert_legacy_session(&legacy_with_meta).expect("레거시 변환 성공");
    let converted = &wrapped["converted"];
    assert!(validate_session(converted).is_ok());
    assert_eq!(converted["host_role"], json!("server"));
    assert_eq!(converted["timezone_offset_minutes"], json!(540));
    assert_eq!(
        converted["profile"]["target"]["host"],
        json!("example.internal")
    );
}

#[test]
fn test_19_legacy_rejects_unsupported_schema_versions() {
    for ver in ["1.1", "1.2", "2.0", "0.9", ""] {
        let mut legacy = json!({
            "schema_version": ver,
            "session_id": "11111111-1111-4111-8111-111111111109",
            "mode": "standalone",
            "started_at_utc": "2026-10-20T02:30:00Z",
            "target": {"ip": "192.168.10.100", "port": 1526, "protocol": "TCP"}
        });
        assert!(
            convert_legacy_session(&legacy).is_err(),
            "지원하지 않는 레거시 버전({ver})은 거부해야 합니다"
        );
        legacy["schema_version"] = json!(1.0);
        assert!(convert_legacy_session(&legacy).is_err());
    }
}

#[test]
fn test_20_legacy_rejects_missing_or_invalid_critical_fields() {
    let base = json!({
        "schema_version": "1.0",
        "session_id": "11111111-1111-4111-8111-111111111109",
        "mode": "standalone",
        "started_at_utc": "2026-10-20T02:30:00Z",
        "target": {"ip": "192.168.10.100", "port": 1526, "protocol": "TCP"}
    });

    for key in ["session_id", "mode", "started_at_utc", "target"] {
        let mut missing = base.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert!(
            convert_legacy_session(&missing).is_err(),
            "필수 키({key}) 누락 시 추측하지 않고 에러를 반환해야 합니다"
        );
    }

    // target 내부 필수 정보 누락 또는 UDP 프로토콜 거부
    let mut no_ip = base.clone();
    no_ip["target"].as_object_mut().unwrap().remove("ip");
    assert!(convert_legacy_session(&no_ip).is_err());

    let mut udp_proto = base.clone();
    udp_proto["target"]["protocol"] = json!("UDP");
    assert!(convert_legacy_session(&udp_proto).is_err());

    let mut conflicting_hosts = base;
    conflicting_hosts["target"]["host"] = json!("10.0.0.1");
    assert!(convert_legacy_session(&conflicting_hosts).is_err());
}

#[test]
fn test_21_dto_strict_deny_unknown_fields_on_deserialization() {
    let bad_ev = json!({
        "evidence_id": "ev-1",
        "kind": "SOCKET",
        "artifact_path": null,
        "synthetic": true,
        "extra": 1
    });
    assert!(serde_json::from_value::<Evidence>(bad_ev).is_err());

    let bad_finding = json!({
        "classification": "UNKNOWN",
        "statement": "테스트",
        "evidence_ids": [],
        "confidence": "low",
        "limitations": [],
        "next_checks": [],
        "extra": 1
    });
    assert!(serde_json::from_value::<Finding>(bad_finding).is_err());

    let bad_fr = json!({
        "feature_id": "tcp_connect",
        "group_id": "G-NET",
        "status": "UNAVAILABLE",
        "classification": null,
        "evidence_ids": [],
        "started_at_utc": null,
        "ended_at_utc": null,
        "duration_ms": null,
        "error_code": null,
        "limitations": [],
        "next_checks": [],
        "extra": 1
    });
    assert!(serde_json::from_value::<FeatureResult>(bad_fr).is_err());

    let bad_rm = json!({
        "peak_rss_bytes": null,
        "avg_cpu_percent": null,
        "capture_drops": null,
        "extra": 1
    });
    assert!(serde_json::from_value::<ResourceMetrics>(bad_rm).is_err());
}

#[test]
fn test_22_packet_required_feature_cannot_pass_without_packet_evidence() {
    let mut s = sample_valid_minimal_session_json();
    s["evidence"] = json!([
        {
            "evidence_id": "ev-sock-1",
            "kind": "SOCKET",
            "artifact_path": null,
            "synthetic": true
        }
    ]);
    s["feature_results"] = json!([
        {
            "feature_id": "syn_rst_analysis",
            "group_id": "G-PKT",
            "status": "PASS",
            "classification": "OBSERVED",
            "evidence_ids": ["ev-sock-1"],
            "started_at_utc": null,
            "ended_at_utc": null,
            "duration_ms": 10,
            "error_code": null,
            "limitations": [],
            "next_checks": []
        }
    ]);
    assert!(
        validate_session(&s).is_err(),
        "syn_rst_analysis가 PACKET 증거 없이 SOCKET 증거만으로 PASS/OBSERVED가 되면 거부해야 합니다"
    );
}
