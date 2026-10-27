//! Network Quick Check 순수 GUI 상태 모델 단위 테스트 모듈.
//!
//! 네트워크 I/O, 소켓, DNS, 프로세스, 스레드, 시계 조회가 일체 없는 완전한 순수 단위 테스트입니다.

use super::*;
use network_core::quick::{
    EvidenceLevel, QUICK_PRODUCT_NAME, QUICK_SCHEMA_VERSION, QuickFeature, QuickResult, QuickStatus,
};
use network_core::runner::ProbeCounts;
use network_core::targets::{
    DEFAULT_CONCURRENCY, DEFAULT_TCP_TIMEOUT_MS, MAX_INPUT_BYTES, MAX_TARGETS, QuickOptions,
};

/// 유효한 구문으로 정확한 UTF-8 바이트 크기를 갖는 대상 목록 문자열을 생성하는 순수 테스트 헬퍼.
///
/// 중복 제거 후 고유 대상 수가 MAX_TARGETS(100)를 초과하지 않도록 소수의 도메인을 반복합니다.
fn make_valid_input_exact_bytes(len: usize) -> String {
    assert!(len >= 16, "최소 16바이트 이상의 길이가 필요합니다.");
    let base_line = "example.com:80\n";
    let base_len = base_line.len(); // 15바이트
    let count = len / base_len;
    let rem = len % base_len;

    let mut s = String::with_capacity(len);
    if rem == 0 {
        for _ in 0..count {
            s.push_str(base_line);
        }
    } else {
        // 첫 줄의 라벨 길이를 조정하여 정확히 base_len + rem 바이트를 맞춤
        let first_len = base_len + rem;
        let padding_len = first_len - 9; // "a".len() + ".com:80\n".len() = 1 + 8 = 9
        s.push('a');
        for _ in 0..padding_len {
            s.push('a');
        }
        s.push_str(".com:80\n");
        for _ in 0..(count - 1) {
            s.push_str(base_line);
        }
    }
    assert_eq!(s.len(), len);
    s
}

/// 테스트용 표준 QuickRunReport 생성 헬퍼.
fn make_test_report(cancelled: bool, errors: Vec<String>) -> QuickRunReport {
    QuickRunReport {
        results: vec![QuickResult {
            schema_version: QUICK_SCHEMA_VERSION.to_string(),
            product: QUICK_PRODUCT_NAME.to_string(),
            session_id: "gui-run-1".to_string(),
            timestamp_iso8601: None,
            source_host: None,
            target_host: "127.0.0.1".to_string(),
            resolved_ip: Some("127.0.0.1".to_string()),
            target_port: 80,
            feature: QuickFeature::TcpConnect,
            status: QuickStatus::PASS,
            elapsed_ms: Some(5),
            os_error_code: None,
            details: serde_json::json!({
                "outcome": "CONNECTED",
                "limitations": [],
                "raw_measurement": {}
            }),
            evidence_level: EvidenceLevel::OBSERVED,
        }],
        cancelled,
        limit_reached: false,
        omitted_results: 0,
        errors,
        invocations: ProbeCounts {
            tcp_connect: 1,
            icmp_ping: 0,
            local_network: 0,
            dns_lookup: 0,
            icmp_traceroute: 0,
        },
        max_active_targets: 1,
        targets_started: 1,
        targets_completed: 1,
        serialized_result_bytes: 512,
    }
}

#[test]
fn test_default_and_empty_startup() {
    let state = GuiState::new();
    assert_eq!(state.phase(), RunPhase::Ready);
    assert!(state.targets().is_empty());
    assert_eq!(state.options(), &QuickOptions::default());
    assert_eq!(state.active_run_id(), None);
    assert_eq!(state.active_snapshot(), None);
    assert_eq!(state.last_result(), None);

    // Default 트레이트 동등성
    let default_state = GuiState::default();
    assert_eq!(state, default_state);

    // 빈 대상 상태에서 begin_run 시도 -> 계획 검증 실패 거부
    let mut state_mut = state;
    let res = state_mut.begin_run();
    match res {
        Err(GuiStateError::InvalidInput(errors)) => {
            assert!(!errors.is_empty());
            assert!(errors.iter().any(|e| e.message.contains("비어 있습니다")));
        }
        other => panic!("빈 대상에서 InvalidInput 오류가 예상되었으나 {other:?} 반환됨"),
    }

    // 실패 후 상태 불변성 검증
    assert_eq!(state_mut.phase(), RunPhase::Ready);
    assert!(state_mut.targets().is_empty());
    assert_eq!(state_mut.active_run_id(), None);
    assert_eq!(state_mut.active_snapshot(), None);
    assert_eq!(state_mut.last_result(), None);
    assert_eq!(state_mut.next_run_counter, 0);
}

#[test]
fn test_target_ordering_and_raw_inputs() {
    let mut state = GuiState::new();
    let input = "192.168.1.1:80\n[2001:db8::1]:8080\nexample.com:443";
    state.replace_targets(input).expect("정상 대상 교체");

    let targets = state.targets();
    assert_eq!(targets.len(), 3);

    assert_eq!(targets[0].host, "192.168.1.1");
    assert_eq!(targets[0].port, 80);
    assert_eq!(targets[0].raw_input, "192.168.1.1:80");

    assert_eq!(targets[1].host, "2001:db8::1");
    assert_eq!(targets[1].port, 8080);
    assert_eq!(targets[1].raw_input, "[2001:db8::1]:8080");

    assert_eq!(targets[2].host, "example.com");
    assert_eq!(targets[2].port, 443);
    assert_eq!(targets[2].raw_input, "example.com:443");
}

#[test]
fn test_deduplication_policies() {
    let mut state = GuiState::new();

    // 1. 도메인 대소문자 중복: 최초 등장 원문 유지
    state
        .replace_targets("example.com:80\nEXAMPLE.COM:80")
        .expect("도메인 파싱 성공");
    assert_eq!(state.targets().len(), 1);
    assert_eq!(state.targets()[0].host, "example.com");
    assert_eq!(state.targets()[0].raw_input, "example.com:80");

    // 2. 도메인 같으나 포트 다름 -> 별개 유지
    state
        .replace_targets("example.com:80\nexample.com:443")
        .expect("도메인 다른 포트 파싱 성공");
    assert_eq!(state.targets().len(), 2);
    assert_eq!(state.targets()[0].port, 80);
    assert_eq!(state.targets()[1].port, 443);

    // 3. IPv6 동치 중복 -> 최초 등장 원문 유지
    state
        .replace_targets("[2001:db8::1]:80\n[2001:0db8:0000:0000:0000:0000:0000:0001]:80")
        .expect("IPv6 동치 파싱 성공");
    assert_eq!(state.targets().len(), 1);
    assert_eq!(state.targets()[0].host, "2001:db8::1");
    assert_eq!(state.targets()[0].raw_input, "[2001:db8::1]:80");

    // 4. IPv6 동치이나 포트 다름 -> 별개 유지
    state
        .replace_targets("[::1]:80\n[0:0:0:0:0:0:0:1]:8080")
        .expect("IPv6 다른 포트 파싱 성공");
    assert_eq!(state.targets().len(), 2);
    assert_eq!(state.targets()[0].port, 80);
    assert_eq!(state.targets()[1].port, 8080);

    // 5. IPv4 동치 및 다른 포트
    state
        .replace_targets("127.0.0.1:80\n127.0.0.1:80")
        .expect("IPv4 동일 포트 파싱 성공");
    assert_eq!(state.targets().len(), 1);

    state
        .replace_targets("127.0.0.1:80\n127.0.0.1:8080")
        .expect("IPv4 다른 포트 파싱 성공");
    assert_eq!(state.targets().len(), 2);
}

#[test]
fn test_target_limits_atomic_failure() {
    let mut state = GuiState::new();

    // 100개 고유 대상 (MAX_TARGETS 허용)
    let mut targets_100 = String::new();
    for i in 1..=100 {
        targets_100.push_str(&format!("10.0.0.1:{i}\n"));
    }
    state
        .replace_targets(&targets_100)
        .expect("100개 대상 허용");
    assert_eq!(state.targets().len(), MAX_TARGETS);

    // 101개 고유 대상 (101개 원자적 거부 및 상태 불변)
    let mut targets_101 = String::new();
    for i in 1..=101 {
        targets_101.push_str(&format!("10.0.0.1:{i}\n"));
    }
    let err = state
        .replace_targets(&targets_101)
        .expect_err("101개 대상은 거부되어야 함");
    match err {
        GuiStateError::InvalidInput(errors) => {
            assert!(errors.iter().any(|e| e.message.contains("최대 허용 한도")));
        }
        other => panic!("InvalidInput이 예상되었으나 {other:?} 반환됨"),
    }
    // 기존 100개 대상이 완전히 보존되었는지 검증
    assert_eq!(state.targets().len(), MAX_TARGETS);

    // 중복 포함 105개이지만 고유 100개인 경우 -> 성공
    let mut targets_with_dups = targets_100.clone();
    for i in 1..=5 {
        targets_with_dups.push_str(&format!("10.0.0.1:{i}\n"));
    }
    state
        .replace_targets(&targets_with_dups)
        .expect("중복 제거 후 100개 대상 허용");
    assert_eq!(state.targets().len(), MAX_TARGETS);
}

#[test]
fn test_max_input_bytes_boundaries() {
    let mut state = GuiState::new();

    // 1. 정확히 32768 바이트 유효 입력 -> 성공
    let exact_32768 = make_valid_input_exact_bytes(MAX_INPUT_BYTES);
    assert_eq!(exact_32768.len(), MAX_INPUT_BYTES);
    state
        .replace_targets(&exact_32768)
        .expect("정확히 32768 바이트 입력은 허용되어야 함");
    assert!(!state.targets().is_empty());
    let saved_targets = state.targets().to_vec();

    // 2. 32769 바이트 입력 -> 거부 및 상태 불변
    let exceed_32769 = make_valid_input_exact_bytes(MAX_INPUT_BYTES + 1);
    assert_eq!(exceed_32769.len(), MAX_INPUT_BYTES + 1);
    let err = state
        .replace_targets(&exceed_32769)
        .expect_err("32769 바이트 입력은 거부되어야 함");
    match err {
        GuiStateError::InvalidInput(errors) => {
            assert!(errors.iter().any(|e| e.message.contains("최대 허용 크기")));
        }
        other => panic!("InvalidInput이 예상되었으나 {other:?} 반환됨"),
    }
    assert_eq!(state.targets(), &saved_targets);

    // MAX와 MAX+1은 같은 초기 대상 목록에서 독립적으로 시작한다.
    let mut initial_append = GuiState::new();
    initial_append
        .replace_targets("127.0.0.1:80")
        .expect("초기 대상 설정");
    let existing_bytes: usize = initial_append
        .targets()
        .iter()
        .map(|t| t.raw_input.len())
        .sum();
    let separator_bytes = initial_append.targets().len();
    let remaining = MAX_INPUT_BYTES - existing_bytes - separator_bytes;
    let exact_append = make_valid_input_exact_bytes(remaining);
    let exceed_append = make_valid_input_exact_bytes(remaining + 1);
    assert_eq!(
        existing_bytes + separator_bytes + exact_append.len(),
        MAX_INPUT_BYTES
    );
    assert_eq!(
        existing_bytes + separator_bytes + exceed_append.len(),
        MAX_INPUT_BYTES + 1
    );

    let mut state_append = initial_append.clone();
    state_append
        .append_targets(&exact_append)
        .expect("합산 정확히 32768 바이트 append 허용");
    let mut failed_append = initial_append.clone();
    let append_err = failed_append
        .append_targets(&exceed_append)
        .expect_err("합산 정확히 MAX+1 후보 거부");
    match append_err {
        GuiStateError::InvalidInput(errors) => {
            assert!(errors.iter().any(|e| e.message.contains("최대 허용 크기")));
        }
        other => panic!("InvalidInput이 예상되었으나 {other:?} 반환됨"),
    }
    assert_eq!(failed_append, initial_append);
}

#[test]
fn test_invalid_inputs_and_no_repair() {
    let mut state = GuiState::new();
    state
        .replace_targets("127.0.0.1:80")
        .expect("기준 대상 설정");
    let baseline = state.targets().to_vec();

    // 불량 행 fixture 목록 (원문 트림이나 수리 없이 즉시 거부되어야 함)
    let bad_inputs = [
        " 127.0.0.1:80",              // 앞 공백
        "127.0.0.1:80 ",              // 뒤 공백
        "127.0.0.1:0",                // 포트 0
        "127.0.0.1:65536",            // 포트 상한 초과
        "127.0.0.1:http",             // 영문 포트
        "::1:80",                     // 대괄호 없는 bare IPv6
        "user:secret@127.0.0.1:80",   // 자격증명
        "0.0.0.0:80",                 // 미지정 IPv4
        "224.0.0.1:80",               // 멀티캐스트 IPv4
        "255.255.255.255:80",         // 브로드캐스트 IPv4
        "http://example.com:80",      // URI 스킴
        "example.com:80/path",        // URL 경로
        "192.168.1.1:80,10.0.0.1:80", // 콤마 구분자
    ];

    for bad in bad_inputs {
        let err = state.replace_targets(bad).unwrap_err();
        assert!(
            matches!(err, GuiStateError::InvalidInput(_)),
            "불량 입력 '{bad}'에 대해 InvalidInput 예상"
        );
        assert_eq!(state.targets(), &baseline, "실패 후 상태는 불변이어야 함");
    }

    // 빈 문자열 replace는 파서 오류
    let empty_err = state.replace_targets("").unwrap_err();
    assert!(matches!(empty_err, GuiStateError::InvalidInput(_)));
    assert_eq!(state.targets(), &baseline);

    // 공백 행만 포함된 append는 코어 파서 정책에 따라 유효 대상 유지
    let space_append_res = state.append_targets("   \n\n\t  \n");
    assert!(space_append_res.is_ok());
    assert_eq!(state.targets(), &baseline);
}

#[test]
fn test_remove_target_indices() {
    let mut state = GuiState::new();
    state
        .replace_targets("10.0.0.1:80\n10.0.0.2:80\n10.0.0.3:80")
        .expect("3개 대상 추가");
    assert_eq!(state.targets().len(), 3);

    // 중간 대상 삭제 (인덱스 1)
    state.remove_target(1).expect("중간 인덱스 1 삭제");
    assert_eq!(state.targets().len(), 2);
    assert_eq!(state.targets()[0].host, "10.0.0.1");
    assert_eq!(state.targets()[1].host, "10.0.0.3");

    // 마지막 대상 삭제 (현재 인덱스 1)
    state.remove_target(1).expect("마지막 인덱스 1 삭제");
    assert_eq!(state.targets().len(), 1);
    assert_eq!(state.targets()[0].host, "10.0.0.1");

    // 단일 남은 대상 삭제 (인덱스 0) -> 빈 목록 정상 전이
    state.remove_target(0).expect("첫 번째 인덱스 0 삭제");
    assert!(state.targets().is_empty());

    // 빈 상태에서 삭제 시도 -> InvalidIndex 거부
    let err = state.remove_target(0).unwrap_err();
    assert_eq!(err, GuiStateError::InvalidIndex);

    // 다시 대상 추가 후 범위 초과 삭제 시도
    state.replace_targets("10.0.0.1:80").expect("1개 추가");
    let out_of_bounds_err = state.remove_target(1).unwrap_err();
    assert_eq!(out_of_bounds_err, GuiStateError::InvalidIndex);
    assert_eq!(state.targets().len(), 1);
}

#[test]
fn test_options_validation_on_begin_run() {
    let mut state = GuiState::new();
    state
        .replace_targets("127.0.0.1:80")
        .expect("유효 대상 설정");

    // 1. NoFeatures: 기능이 하나도 선택되지 않은 경우
    state
        .set_options(QuickOptions {
            selected_features: vec![],
            ..QuickOptions::default()
        })
        .expect("옵션 draft 설정");
    let no_feat_err = state.begin_run().unwrap_err();
    assert_eq!(no_feat_err, GuiStateError::NoFeatures);
    assert_eq!(state.phase(), RunPhase::Ready);

    // 2. 중복 기능 선택
    state
        .set_options(QuickOptions {
            selected_features: vec![QuickFeature::TcpConnect, QuickFeature::TcpConnect],
            ..QuickOptions::default()
        })
        .expect("옵션 draft 설정");
    let dup_feat_err = state.begin_run().unwrap_err();
    match dup_feat_err {
        GuiStateError::InvalidInput(errors) => {
            assert!(errors.iter().any(|e| e.message.contains("중복")));
        }
        other => panic!("InvalidInput이 예상되었으나 {other:?} 반환됨"),
    }
    assert_eq!(state.phase(), RunPhase::Ready);

    // 3. TCP 타임아웃 경계 (0ms, 60001ms 거부 / 1ms, 60000ms 허용)
    state
        .set_options(QuickOptions {
            tcp_timeout_ms: 0,
            ..QuickOptions::default()
        })
        .expect("옵션 설정");
    assert!(matches!(
        state.begin_run().unwrap_err(),
        GuiStateError::InvalidInput(_)
    ));

    state
        .set_options(QuickOptions {
            tcp_timeout_ms: 60001,
            ..QuickOptions::default()
        })
        .expect("옵션 설정");
    assert!(matches!(
        state.begin_run().unwrap_err(),
        GuiStateError::InvalidInput(_)
    ));

    // 4. 동시성 경계 (0, 5 거부 / 1..=4 허용)
    state
        .set_options(QuickOptions {
            concurrency: 0,
            ..QuickOptions::default()
        })
        .expect("옵션 설정");
    assert!(matches!(
        state.begin_run().unwrap_err(),
        GuiStateError::InvalidInput(_)
    ));

    state
        .set_options(QuickOptions {
            concurrency: 5,
            ..QuickOptions::default()
        })
        .expect("옵션 설정");
    assert!(matches!(
        state.begin_run().unwrap_err(),
        GuiStateError::InvalidInput(_)
    ));
}

#[test]
fn test_plan_equality_and_dns_resolution_flag() {
    let mut state = GuiState::new();
    state
        .replace_targets("127.0.0.1:80\nexample.com:443")
        .expect("대상 설정");

    let options = QuickOptions {
        tcp_timeout_ms: 5000,
        concurrency: 2,
        selected_features: vec![QuickFeature::TcpConnect, QuickFeature::IcmpPing],
    };
    state.set_options(options).expect("옵션 설정");

    // begin_run 스냅샷의 계획과 실제 코어 build_quick_plan의 전체 동등성 비교
    let snapshot = state.begin_run().expect("begin_run 성공");
    let expected_plan = build_quick_plan(state.targets(), state.options()).unwrap();
    assert_eq!(snapshot.plan(), &expected_plan);

    // 요청 DTO 무결성 검증
    let req = snapshot.request();
    assert_eq!(req.session_id, "gui-run-1");
    assert_eq!(req.timestamp_iso8601, None);
    assert_eq!(req.source_host, None);
    assert_eq!(req.max_result_bytes, DEFAULT_MAX_RESULT_BYTES);
    assert_eq!(req.targets, state.targets());
    assert_eq!(req.options, *state.options());

    // requires_resolution 플래그 검증:
    // targets[0]은 IP(127.0.0.1)이므로 false
    assert!(!snapshot.plan().targets[0].requires_resolution);
    // targets[1]은 도메인(example.com)이고 TcpConnect가 선택되었으므로 true
    assert!(snapshot.plan().targets[1].requires_resolution);

    // 상세 DNS(DnsLookup)만 단독 선택된 경우 requires_resolution == false 검증
    state
        .finish_run(snapshot.run_id(), Ok(make_test_report(false, vec![])))
        .expect("완료");
    state
        .set_options(QuickOptions {
            selected_features: vec![QuickFeature::DnsLookup],
            ..QuickOptions::default()
        })
        .expect("옵션 갱신");
    let dns_only_snapshot = state.begin_run().expect("DnsLookup 단독 시작");
    assert!(!dns_only_snapshot.plan().targets[1].requires_resolution);
}

#[test]
fn test_id_increment_and_overflow() {
    let mut state = GuiState::new();
    state.replace_targets("127.0.0.1:80").expect("대상 설정");

    // 첫 실행 성공 -> RunId(1), session_id == "gui-run-1"
    let snap1 = state.begin_run().expect("첫 실행");
    assert_eq!(snap1.run_id().as_u64(), 1);
    assert_eq!(snap1.request().session_id, "gui-run-1");
    assert_eq!(state.active_run_id(), Some(RunId(1)));

    // 완료 처리
    state
        .finish_run(snap1.run_id(), Ok(make_test_report(false, vec![])))
        .expect("첫 완료");
    assert_eq!(state.phase(), RunPhase::Finished);
    assert_eq!(state.active_run_id(), None);

    // 두 번째 실행 성공 -> RunId(2), session_id == "gui-run-2"
    let snap2 = state.begin_run().expect("두 번째 실행");
    assert_eq!(snap2.run_id().as_u64(), 2);
    assert_eq!(snap2.request().session_id, "gui-run-2");

    state
        .finish_run(snap2.run_id(), Ok(make_test_report(false, vec![])))
        .expect("두 번째 완료");

    // 카운터 오버플로 검증 (자식 test 모듈에서 private 카운터 경계 직접 설정)
    state.next_run_counter = u64::MAX;
    let overflow_err = state.begin_run().unwrap_err();
    assert_eq!(overflow_err, GuiStateError::IdExhausted);
    // 상태 및 카운터 불변 확인
    assert_eq!(state.phase(), RunPhase::Finished);
    assert_eq!(state.next_run_counter, u64::MAX);
    assert_eq!(state.active_run_id(), None);
}

#[test]
fn test_busy_locking_and_isolation() {
    let mut state = GuiState::new();
    state.replace_targets("127.0.0.1:80").expect("대상 설정");

    let snapshot = state.begin_run().expect("실행 시작");
    assert_eq!(state.phase(), RunPhase::Running);

    // 1. Running 상태에서 모든 편집 및 재시작 시도 -> Busy 거부
    assert_eq!(
        state.replace_targets("10.0.0.1:80"),
        Err(GuiStateError::Busy)
    );
    assert_eq!(
        state.append_targets("10.0.0.1:80"),
        Err(GuiStateError::Busy)
    );
    assert_eq!(state.remove_target(0), Err(GuiStateError::Busy));
    assert_eq!(
        state.set_options(QuickOptions::default()),
        Err(GuiStateError::Busy)
    );
    assert_eq!(state.begin_run().map(|_| ()), Err(GuiStateError::Busy));

    // 2. Cancelling 상태 전이 후에도 모든 편집 및 재시작 시도 -> Busy 거부
    let cancel_res = state.request_cancel();
    assert_eq!(cancel_res, Some(snapshot.run_id()));
    assert_eq!(state.phase(), RunPhase::Cancelling);

    assert_eq!(
        state.replace_targets("10.0.0.1:80"),
        Err(GuiStateError::Busy)
    );
    assert_eq!(
        state.append_targets("10.0.0.1:80"),
        Err(GuiStateError::Busy)
    );
    assert_eq!(state.remove_target(0), Err(GuiStateError::Busy));
    assert_eq!(
        state.set_options(QuickOptions::default()),
        Err(GuiStateError::Busy)
    );
    assert_eq!(state.begin_run().map(|_| ()), Err(GuiStateError::Busy));

    // 3. 외부 clone 수정 격리 검증
    let mut req_clone = snapshot.request().clone();
    req_clone.session_id = "mutated-session".to_string();
    assert_eq!(
        state.active_snapshot().unwrap().request().session_id,
        "gui-run-1"
    );
}

#[test]
fn test_cancellation_flow_and_race_acceptance() {
    let mut state = GuiState::new();
    state.replace_targets("127.0.0.1:80").expect("대상 설정");

    // Ready 상태에서 취소 요청 -> None
    assert_eq!(state.request_cancel(), None);

    let snapshot = state.begin_run().expect("실행 시작");
    let run_id = snapshot.run_id();

    // 최초 취소 요청 -> Some(RunId), Cancelling 전이
    assert_eq!(state.request_cancel(), Some(run_id));
    assert_eq!(state.phase(), RunPhase::Cancelling);

    // 반복 취소 요청 -> None 반환 및 Cancelling 유지
    assert_eq!(state.request_cancel(), None);
    assert_eq!(state.phase(), RunPhase::Cancelling);

    // 취소 요청 후 정상 완료 보고서(cancelled = false) 도착 (레이스 상태 허용)
    let normal_report = make_test_report(false, vec![]);
    state
        .finish_run(run_id, Ok(normal_report))
        .expect("취소 상태에서 정상 보고서 접수 성공");

    assert_eq!(state.phase(), RunPhase::Finished);
    let last = state.last_result().expect("결과 존재").as_ref().unwrap();
    // UI 취소 요청이 있었다고 해서 report.cancelled를 임의로 true로 조작하지 않고 원문(false) 보존
    assert!(!last.cancelled);
}

#[test]
fn test_finish_run_stale_and_duplicate_rejection() {
    let mut state = GuiState::new();
    state.replace_targets("127.0.0.1:80").expect("대상 설정");

    // 1. 비활성(Ready) 상태에서 finish_run -> InvalidCompletion
    let res = state.finish_run(RunId(1), Ok(make_test_report(false, vec![])));
    assert_eq!(res, Err(GuiStateError::InvalidCompletion));

    // 2. 활성 실행 중 다른 RunId로 완료 시도 -> InvalidCompletion 및 상태 불변
    let snapshot = state.begin_run().expect("실행 시작");
    let active_id = snapshot.run_id();
    let stale_id = RunId(active_id.as_u64() + 99);

    let stale_res = state.finish_run(stale_id, Ok(make_test_report(false, vec![])));
    assert_eq!(stale_res, Err(GuiStateError::InvalidCompletion));
    assert_eq!(state.phase(), RunPhase::Running);
    assert_eq!(state.active_run_id(), Some(active_id));

    // 3. 정상 완료
    state
        .finish_run(active_id, Ok(make_test_report(false, vec![])))
        .expect("정상 완료");
    assert_eq!(state.phase(), RunPhase::Finished);

    // 4. 완료 후 동일 RunId로 중복 완료 시도 -> InvalidCompletion 거부
    let dup_res = state.finish_run(active_id, Ok(make_test_report(false, vec![])));
    assert_eq!(dup_res, Err(GuiStateError::InvalidCompletion));
    assert_eq!(state.phase(), RunPhase::Finished);

    // 5. 새 실행 시작 시 직전 결과 초기화 및 이전 ID 완료 거부 검증
    let snap2 = state.begin_run().expect("새 실행");
    assert_eq!(
        state.last_result(),
        None,
        "새 실행 시작 시 직전 결과 초기화"
    );
    let stale_res2 = state.finish_run(active_id, Ok(make_test_report(false, vec![])));
    assert_eq!(stale_res2, Err(GuiStateError::InvalidCompletion));
    assert_eq!(state.active_run_id(), Some(snap2.run_id()));
}

#[test]
fn test_report_and_error_preservation() {
    let mut state = GuiState::new();
    state.replace_targets("127.0.0.1:80").expect("대상 설정");

    let snapshot = state.begin_run().expect("실행 시작");

    // CRLF, 한글, 중복 메시지를 포함한 보고서
    let complex_errors = vec![
        "원격 호스트에서 응답이 없습니다.\r\n다시 시도하세요.".to_string(),
        "한글 오류 메시지 테스트".to_string(),
        "한글 오류 메시지 테스트".to_string(), // 중복 메시지
    ];
    let complex_report = make_test_report(true, complex_errors.clone());

    state
        .finish_run(snapshot.run_id(), Ok(complex_report.clone()))
        .expect("완료 보고서 보관");

    let saved = state.last_result().unwrap().as_ref().unwrap();
    assert_eq!(saved, &complex_report);
    assert_eq!(saved.errors, complex_errors);

    // Err(Vec<String>) 전달 시 보존 검증
    let snap2 = state.begin_run().expect("두 번째 실행");
    let string_errors = vec![
        "치명적 로컬 소켓 오류\r\n코드: 10054".to_string(),
        "중복 항목".to_string(),
        "중복 항목".to_string(),
    ];
    state
        .finish_run(snap2.run_id(), Err(string_errors.clone()))
        .expect("오류 보관");

    let saved_err = state.last_result().unwrap().as_ref().unwrap_err();
    assert_eq!(saved_err, &string_errors);
}

#[test]
fn test_error_display_coverage() {
    let errors = [
        (
            GuiStateError::Busy,
            "진단이 진행 중이거나 취소 처리 중입니다.",
        ),
        (
            GuiStateError::NoFeatures,
            "진단 기능이 하나도 선택되지 않았습니다.",
        ),
        (
            GuiStateError::InvalidIndex,
            "대상 인덱스가 범위를 벗어났습니다.",
        ),
        (
            GuiStateError::IdExhausted,
            "실행 식별자 카운터가 최댓값에 도달했습니다.",
        ),
        (
            GuiStateError::InvalidCompletion,
            "활성 실행 식별자와 일치하지 않거나 이미 완료된 실행입니다.",
        ),
    ];

    for (err, expected_msg) in errors {
        assert_eq!(format!("{err}"), expected_msg);
        assert!((&err as &dyn std::error::Error).source().is_none());
    }

    let input_err = GuiStateError::InvalidInput(vec![
        InputError {
            line: 1,
            message: "첫 번째 오류".to_string(),
        },
        InputError {
            line: 2,
            message: "두 번째 오류".to_string(),
        },
    ]);
    let input_str = format!("{input_err}");
    assert!(input_str.contains("[행 1] 첫 번째 오류"));
    assert!(input_str.contains("[행 2] 두 번째 오류"));
}

#[test]
fn test_run_id_and_snapshot_accessors() {
    let id = RunId(42);
    assert_eq!(id.as_u64(), 42);
    assert_eq!(format!("{id}"), "42");
    assert_eq!(id, RunId(42));
    assert!(id < RunId(43));

    let snap = RunSnapshot {
        run_id: id,
        request: QuickRunRequest {
            session_id: "gui-run-42".to_string(),
            timestamp_iso8601: None,
            source_host: None,
            targets: vec![],
            options: QuickOptions::default(),
            max_result_bytes: DEFAULT_MAX_RESULT_BYTES,
        },
        plan: QuickPlan {
            targets: vec![],
            tcp_timeout_ms: DEFAULT_TCP_TIMEOUT_MS,
            icmp_timeout_ms: None,
            concurrency: DEFAULT_CONCURRENCY,
            limitations: vec![],
        },
    };

    assert_eq!(snap.run_id(), id);
    assert_eq!(snap.request().session_id, "gui-run-42");
    assert_eq!(snap.plan().tcp_timeout_ms, DEFAULT_TCP_TIMEOUT_MS);
}

// 아래 보강은 부모가 독립 QA 지적을 실제 Core 계약과 대조해 추가했다.
// 합성 보고서는 상태모델의 보존 입력이며 실제 측정/패킷/서비스 상태의 증거가 아니다.
fn parent_rich_report(cancelled: bool, limited: bool) -> QuickRunReport {
    let mut report = make_test_report(
        cancelled,
        vec!["원문\r\n한글".into(), "중복".into(), "중복".into()],
    );
    report.limit_reached = limited;
    report.omitted_results = if limited { 7 } else { 0 };
    report.invocations = ProbeCounts {
        tcp_connect: 2,
        icmp_ping: 3,
        local_network: 4,
        dns_lookup: 5,
        icmp_traceroute: 6,
    };
    report.max_active_targets = 4;
    report.targets_started = 3;
    report.targets_completed = 2;
    report.results[0].details = serde_json::json!({
        "outcome": "CONNECTED",
        "limitations": ["원문\r\n한글", "중복", "중복"],
        "raw_measurement": {
            "target": "127.0.0.1:080",
            "local_address": "127.0.0.1:49152",
            "error_message": null,
            "nested": {"strings": ["한글", "\r\n", "한글"], "zero": 0}
        }
    });
    let mut refused = report.results[0].clone();
    refused.status = QuickStatus::FAIL;
    refused.os_error_code = Some(10061);
    refused.elapsed_ms = Some(0);
    refused.details = serde_json::json!({
        "outcome": "REFUSED", "raw_measurement": {
            "os_error_code": 10061, "error_message": "거부\r\n원문", "local_address": null
        }
    });
    let mut unknown = report.results[0].clone();
    unknown.feature = QuickFeature::IcmpTraceroute;
    unknown.status = QuickStatus::UNKNOWN;
    unknown.evidence_level = EvidenceLevel::UNKNOWN;
    unknown.elapsed_ms = None;
    unknown.details = serde_json::json!({
        "outcome": "UNAVAILABLE", "raw_measurement": {"hops": [], "limitations": ["미확인", "미확인"]}
    });
    report.results.extend([refused, unknown]);
    report.serialized_result_bytes = report
        .results
        .iter()
        .map(|row| serde_json::to_vec(row).unwrap().len())
        .sum();
    report
}

#[test]
fn parent_leading_zero_port_keeps_core_policy_and_raw() {
    for input in ["127.0.0.1:080", "[::1]:00080", "EXAMPLE.COM:00080"] {
        let core_targets = parse_target_list(input).unwrap();
        let mut state = GuiState::new();
        state.replace_targets(input).unwrap();
        assert_eq!(state.targets(), core_targets);
        assert_eq!(state.targets()[0].port, 80);
        assert_eq!(state.targets()[0].raw_input, input);
        let before_append = state.clone();
        state.append_targets(input).unwrap();
        assert_eq!(
            state, before_append,
            "동일 원문 중복은 새 대상을 만들지 않는다"
        );
        let expected = build_quick_plan(state.targets(), state.options()).unwrap();
        let snapshot = state.begin_run().unwrap();
        assert_eq!(snapshot.request().targets, core_targets);
        assert_eq!(snapshot.plan(), &expected);
    }
}

#[test]
fn parent_append_combined_limit_dedup_and_mixed_failure_are_atomic() {
    let initial_text = (1..MAX_TARGETS)
        .map(|port| format!("Example.COM:{port}"))
        .collect::<Vec<_>>()
        .join("\n");
    let mut initial = GuiState::new();
    initial.replace_targets(&initial_text).unwrap();
    assert_eq!(initial.targets().len(), MAX_TARGETS - 1);
    let extra = format!("example.com:{MAX_TARGETS}\nEXAMPLE.COM:1\nExample.COM:{MAX_TARGETS}");
    let mut combined = initial.clone();
    combined.append_targets(&extra).unwrap();
    assert_eq!(combined.targets().len(), MAX_TARGETS);
    assert_eq!(combined.targets()[0].raw_input, "Example.COM:1");
    assert_eq!(
        combined.targets(),
        parse_target_list(&format!("{initial_text}\n{extra}")).unwrap()
    );
    let before = combined.clone();
    assert!(matches!(
        combined.append_targets(&format!("example.com:{}", MAX_TARGETS + 1)),
        Err(GuiStateError::InvalidInput(_))
    ));
    assert_eq!(combined, before);
    let before = initial.clone();
    assert!(matches!(
        initial.append_targets(&format!("example.com:{MAX_TARGETS}\nbad-line")),
        Err(GuiStateError::InvalidInput(_))
    ));
    assert_eq!(initial, before, "앞의 유효 행까지 부분 추가하면 안 된다");
    for whitespace in ["", "\n \t\n"] {
        let before = combined.clone();
        combined.append_targets(whitespace).unwrap();
        assert_eq!(combined, before);
    }
}

#[test]
fn parent_failed_start_preserves_completed_result_and_consumes_no_id() {
    let mut completed = GuiState::new();
    completed.replace_targets("127.0.0.1:80").unwrap();
    let first = completed.begin_run().unwrap();
    completed
        .finish_run(first.run_id(), Ok(parent_rich_report(true, true)))
        .unwrap();
    let invalid_options = [
        QuickOptions {
            selected_features: vec![],
            ..QuickOptions::default()
        },
        QuickOptions {
            selected_features: vec![QuickFeature::TcpConnect, QuickFeature::TcpConnect],
            ..QuickOptions::default()
        },
        QuickOptions {
            tcp_timeout_ms: 0,
            ..QuickOptions::default()
        },
        QuickOptions {
            tcp_timeout_ms: 60001,
            ..QuickOptions::default()
        },
        QuickOptions {
            concurrency: 0,
            ..QuickOptions::default()
        },
        QuickOptions {
            concurrency: 5,
            ..QuickOptions::default()
        },
    ];
    for options in invalid_options {
        let mut state = completed.clone();
        state.set_options(options).unwrap();
        let before = state.clone();
        assert!(state.begin_run().is_err());
        assert_eq!(
            state, before,
            "오류 뒤 이전 report와 ID를 포함한 전체 상태 보존"
        );
        state.set_options(QuickOptions::default()).unwrap();
        let next = state.begin_run().unwrap();
        assert_eq!(next.run_id().as_u64(), first.run_id().as_u64() + 1);
    }
    let mut empty = completed.clone();
    empty.remove_target(0).unwrap();
    let before = empty.clone();
    assert!(matches!(
        empty.begin_run(),
        Err(GuiStateError::InvalidInput(_))
    ));
    assert_eq!(empty, before);
    empty.replace_targets("127.0.0.1:80").unwrap();
    assert_eq!(empty.begin_run().unwrap().run_id().as_u64(), 2);

    let mut exhausted = completed;
    exhausted.next_run_counter = u64::MAX;
    let before = exhausted.clone();
    assert_eq!(exhausted.begin_run(), Err(GuiStateError::IdExhausted));
    assert_eq!(exhausted, before);
}

#[test]
fn parent_busy_and_stale_completion_preserve_entire_state() {
    for cancelling in [false, true] {
        let mut state = GuiState::new();
        state.replace_targets("Example.COM:080\n[::1]:443").unwrap();
        let snapshot = state.begin_run().unwrap();
        if cancelling {
            assert_eq!(state.request_cancel(), Some(snapshot.run_id()));
        }
        let before = state.clone();
        assert_eq!(
            state.replace_targets("127.0.0.1:1"),
            Err(GuiStateError::Busy)
        );
        assert_eq!(state, before);
        assert_eq!(
            state.append_targets("127.0.0.1:2"),
            Err(GuiStateError::Busy)
        );
        assert_eq!(state, before);
        assert_eq!(state.remove_target(usize::MAX), Err(GuiStateError::Busy));
        assert_eq!(state, before);
        assert_eq!(
            state.set_options(QuickOptions {
                selected_features: vec![],
                ..QuickOptions::default()
            }),
            Err(GuiStateError::Busy)
        );
        assert_eq!(state, before);
        assert_eq!(state.begin_run(), Err(GuiStateError::Busy));
        assert_eq!(state, before);
        assert_eq!(
            state.finish_run(
                RunId(snapshot.run_id().as_u64() + 1),
                Err(vec!["stale".into()])
            ),
            Err(GuiStateError::InvalidCompletion)
        );
        assert_eq!(state, before);
        if cancelling {
            assert_eq!(state.request_cancel(), None);
            assert_eq!(state, before);
        }
        state
            .finish_run(snapshot.run_id(), Ok(parent_rich_report(false, true)))
            .unwrap();
        let finished = state.clone();
        assert_eq!(
            state.finish_run(snapshot.run_id(), Err(vec!["duplicate".into()])),
            Err(GuiStateError::InvalidCompletion)
        );
        assert_eq!(state, finished);
        assert_eq!(state.request_cancel(), None);
        assert_eq!(state, finished);
        let second = state.begin_run().unwrap();
        assert_eq!(state.last_result(), None);
        let running = state.clone();
        assert_eq!(
            state.finish_run(snapshot.run_id(), Ok(parent_rich_report(false, false))),
            Err(GuiStateError::InvalidCompletion)
        );
        assert_eq!(state, running);
        assert_eq!(state.active_run_id(), Some(second.run_id()));
    }
}

#[test]
fn parent_nested_snapshot_clones_cannot_change_active_request_or_plan() {
    let mut state = GuiState::new();
    state.replace_targets("Example.COM:080\n[::1]:443").unwrap();
    let snapshot = state.begin_run().unwrap();
    let before = state.clone();
    let mut external = snapshot.clone();
    external.request.session_id.clear();
    external.request.targets[0].host = "changed.invalid".into();
    external.request.targets[0].raw_input.clear();
    external.request.options.selected_features.clear();
    external.request.options.tcp_timeout_ms = 0;
    external.request.max_result_bytes = 0;
    external.plan.targets[0].target.port = 1;
    external.plan.targets[0].features.clear();
    external.plan.targets[0].requires_resolution = false;
    external.plan.limitations.push("외부 변경".into());
    external.plan.concurrency = 0;
    assert_ne!(external, snapshot);
    assert_eq!(state, before);
    assert_eq!(state.active_snapshot(), Some(&snapshot));
}

#[test]
fn parent_all_completion_variants_keep_whole_result_without_reclassification() {
    for cancel_requested in [false, true] {
        for cancelled_report in [false, true] {
            for limited in [false, true] {
                let mut state = GuiState::new();
                state.replace_targets("127.0.0.1:80").unwrap();
                let snapshot = state.begin_run().unwrap();
                if cancel_requested {
                    state.request_cancel();
                }
                let supplied = Ok(parent_rich_report(cancelled_report, limited));
                state
                    .finish_run(snapshot.run_id(), supplied.clone())
                    .unwrap();
                assert_eq!(state.last_result(), Some(&supplied));
                assert_eq!(state.phase(), RunPhase::Finished);
                assert_eq!(state.active_snapshot(), None);
            }
        }
        let mut state = GuiState::new();
        state.replace_targets("127.0.0.1:80").unwrap();
        let snapshot = state.begin_run().unwrap();
        if cancel_requested {
            state.request_cancel();
        }
        let supplied = Err(vec!["오류\r\n한글".into(), "중복".into(), "중복".into()]);
        state
            .finish_run(snapshot.run_id(), supplied.clone())
            .unwrap();
        assert_eq!(state.last_result(), Some(&supplied));
    }
}

#[test]
fn parent_valid_timeout_and_concurrency_boundaries_keep_core_plan() {
    for timeout in [1, DEFAULT_TCP_TIMEOUT_MS, 60000] {
        for concurrency in 1..=network_core::targets::MAX_CONCURRENCY {
            let mut state = GuiState::new();
            state
                .replace_targets("127.0.0.1:80\nexample.com:443")
                .unwrap();
            state
                .set_options(QuickOptions {
                    tcp_timeout_ms: timeout,
                    concurrency,
                    selected_features: vec![QuickFeature::TcpConnect],
                })
                .unwrap();
            let expected = build_quick_plan(state.targets(), state.options()).unwrap();
            let snapshot = state.begin_run().unwrap();
            assert_eq!(snapshot.plan(), &expected);
            assert_eq!(snapshot.request().options, *state.options());
            assert_eq!(
                snapshot.request().max_result_bytes,
                DEFAULT_MAX_RESULT_BYTES
            );
        }
    }
}
