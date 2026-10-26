//! GuiPresenter 순수 단위 테스트.
//!
//! 네트워크, Win32 API, I/O, 스레드, 파일 접근 일체 배제.

use super::*;
use crate::gui_state::RunPhase;
use network_core::quick::QuickFeature;
use network_core::targets::{MAX_INPUT_BYTES, QuickTarget};

#[test]
fn test_decode_utf16_valid_and_boundaries() {
    // 1. 정상 UTF-16 변환
    let text = "127.0.0.1:80\r\nexample.com:443";
    let utf16: Vec<u16> = text.encode_utf16().collect();
    let decoded = decode_utf16_input(&utf16, false, 1000, 1000).expect("정상 디코드 성공");
    assert_eq!(decoded, text);

    // 앞뒤 공백이나 개행이 트림되거나 변조되지 않음 검증
    let with_spaces = "  test:80  ";
    let spaces_utf16: Vec<u16> = with_spaces.encode_utf16().collect();
    let decoded_spaces =
        decode_utf16_input(&spaces_utf16, false, 100, 100).expect("공백 보존 디코드");
    assert_eq!(decoded_spaces, with_spaces);

    // 2. 대리 코드(surrogate) 오류 거부
    let unpaired_surrogate = vec![0xD800, 0x0061];
    let err = decode_utf16_input(&unpaired_surrogate, false, 100, 100)
        .expect_err("unpaired surrogate 거부");
    assert_eq!(err, DecodeError::InvalidSurrogate);

    // 3. 중간 NUL 문자 거부
    let embedded_nul = vec![0x0061, 0x0000, 0x0062];
    let err_nul = decode_utf16_input(&embedded_nul, false, 100, 100).expect_err("중간 NUL 거부");
    assert_eq!(err_nul, DecodeError::EmbeddedNul);

    // 4. max_utf16 길이 초과 거부
    let raw = vec![0x0061; 10];
    let err_len = decode_utf16_input(&raw, false, 5, 100).expect_err("max_utf16 초과 거부");
    assert_eq!(err_len, DecodeError::Utf16TooLong { len: 10, max: 5 });

    // 5. max_utf8 바이트 초과 거부 (한글 '가'는 3바이트)
    let hangul: Vec<u16> = "가나다".encode_utf16().collect(); // 9 UTF-8 바이트
    let err_bytes = decode_utf16_input(&hangul, false, 100, 6).expect_err("max_utf8 초과 거부");
    assert!(matches!(err_bytes, DecodeError::Utf8TooLong { .. }));

    // 6. truncated_flag == true 거부
    let err_trunc =
        decode_utf16_input(&utf16, true, 1000, 1000).expect_err("잘림 플래그 감지 거부");
    assert_eq!(err_trunc, DecodeError::TruncatedInput);
}

#[test]
fn test_parse_ascii_numbers() {
    // 1. 정상 ASCII 숫자
    assert_eq!(parse_ascii_u64("3000"), Ok(3000));
    assert_eq!(parse_ascii_u64("1"), Ok(1));
    assert_eq!(parse_ascii_usize("4"), Ok(4));
    assert_eq!(parse_ascii_usize("1"), Ok(1));

    // 2. 빈 문자열 거부
    assert!(parse_ascii_u64("").is_err());
    assert!(parse_ascii_usize("").is_err());

    // 3. 부호 포함 거부
    assert!(parse_ascii_u64("+3000").is_err());
    assert!(parse_ascii_u64("-3000").is_err());
    assert!(parse_ascii_usize("+4").is_err());

    // 4. 소수점 거부
    assert!(parse_ascii_u64("3000.5").is_err());

    // 5. 공백 포함 거부
    assert!(parse_ascii_u64(" 3000 ").is_err());
    assert!(parse_ascii_usize(" 4").is_err());

    // 6. 비ASCII 숫자 거부 (전각 숫자 등)
    assert!(parse_ascii_u64("３０００").is_err());

    // 7. 정수 오버플로 거부
    assert!(parse_ascii_u64("999999999999999999999999999999999999999999").is_err());
}

#[test]
fn test_presenter_targets_crud() {
    let mut presenter = GuiPresenter::new();

    // 초기 상태 검증
    assert_eq!(presenter.state().targets().len(), 0);
    assert_eq!(presenter.selected_index(), None);
    assert_eq!(presenter.plan_preview(), None);
    assert!(!presenter.is_plan_stale());

    // 1. append_targets
    presenter
        .append_targets("127.0.0.1:80\nexample.com:443")
        .expect("추가 성공");
    assert_eq!(presenter.state().targets().len(), 2);
    assert_eq!(presenter.selected_index(), None);
    assert_eq!(presenter.state().targets()[0].raw_input, "127.0.0.1:80");
    assert_eq!(presenter.state().targets()[1].raw_input, "example.com:443");

    // 2. set_selected_index
    presenter
        .set_selected_index(Some(1))
        .expect("인덱스 1 선택");
    assert_eq!(presenter.selected_index(), Some(1));

    // 범위 밖 인덱스 선택 시 에러 및 기존 선택 보존
    let err = presenter
        .set_selected_index(Some(5))
        .expect_err("범위 밖 선택 실패");
    assert_eq!(err, PresenterError::InvalidIndex);
    assert_eq!(presenter.selected_index(), Some(1));

    // 3. remove_selected
    presenter.remove_selected().expect("인덱스 1 삭제");
    assert_eq!(presenter.state().targets().len(), 1);
    assert_eq!(presenter.state().targets()[0].raw_input, "127.0.0.1:80");
    assert_eq!(presenter.selected_index(), None);

    // 선택 없는 상태에서 삭제 시도 -> NoSelection
    let err_nosel = presenter
        .remove_selected()
        .expect_err("선택 없음 삭제 실패");
    assert_eq!(err_nosel, PresenterError::NoSelection);
    assert_eq!(presenter.state().targets().len(), 1);

    // 4. replace_targets
    presenter
        .replace_targets("[::1]:8080")
        .expect("전체 교체 성공");
    assert_eq!(presenter.state().targets().len(), 1);
    assert_eq!(presenter.state().targets()[0].raw_input, "[::1]:8080");
    assert_eq!(presenter.selected_index(), None);
}

#[test]
fn test_target_limits_100_and_101() {
    let mut presenter = GuiPresenter::new();

    // 100개 대상 생성
    let mut lines = String::new();
    for i in 1..=100 {
        lines.push_str(&format!("10.0.0.{}:80\n", i));
    }
    presenter.replace_targets(&lines).expect("100개 등록 성공");
    assert_eq!(presenter.state().targets().len(), 100);

    // 101번째 추가 시도 -> 거부 및 상태 불변
    let err = presenter
        .append_targets("10.0.0.101:80")
        .expect_err("101번째 추가 거부");
    assert!(matches!(err, PresenterError::StateError(_)));
    assert_eq!(
        presenter.state().targets().len(),
        100,
        "실패 시 기존 100개 상태 보존"
    );
}

#[test]
fn test_target_limits_max_input_bytes_and_overflow() {
    let mut presenter = GuiPresenter::new();

    // 1. MAX_INPUT_BYTES (32768) 초과 입력 거부
    let mut huge = String::with_capacity(MAX_INPUT_BYTES + 100);
    while huge.len() < MAX_INPUT_BYTES + 1 {
        huge.push_str("127.0.0.1:80\n");
    }
    let err = presenter
        .replace_targets(&huge)
        .expect_err("바이트 상한 초과 거부");
    assert!(matches!(err, PresenterError::StateError(_)));
    assert_eq!(presenter.state().targets().len(), 0);
}

#[test]
fn test_dedup_and_invalid_inputs() {
    let mut presenter = GuiPresenter::new();

    // 1. 중복 대상 입력 시도 (동일 host:port)
    presenter
        .replace_targets("example.com:80\nEXAMPLE.COM:80")
        .expect("중복 정규화 성공");
    assert_eq!(
        presenter.state().targets().len(),
        1,
        "대소문자 동일 도메인은 1개로 중복 제거됨"
    );

    // 2. GUI 목록은 Core의 080 허용 정책을 그대로 소비한다. CLI worker 정책과 다르다.
    presenter.append_targets("127.0.0.1:080").unwrap();
    assert_eq!(presenter.state().targets()[1].port, 80);
    assert_eq!(presenter.state().targets()[1].raw_input, "127.0.0.1:080");
    presenter.append_targets("127.0.0.1:80").unwrap();
    assert_eq!(presenter.state().targets().len(), 2);
    assert_eq!(presenter.state().targets()[1].raw_input, "127.0.0.1:080");

    // 3. 잘못된 호스트 (URI 스킴) 거부 및 상태 보존
    let err_scheme = presenter
        .append_targets("http://example.com:80")
        .expect_err("URI 스킴 거부");
    assert!(matches!(err_scheme, PresenterError::StateError(_)));
    assert_eq!(presenter.state().targets().len(), 2);
}

#[test]
fn test_options_validation_and_atomicity() {
    let mut presenter = GuiPresenter::new();
    presenter
        .replace_targets("127.0.0.1:80")
        .expect("대상 1개 등록");

    // 1. 기능이 하나도 선택되지 않은 경우 거부 및 상태 불변
    presenter.update_draft_options("3000", "4", Vec::new());
    let err_nofeat = presenter
        .confirm_plan()
        .expect_err("기능 미선택 confirm 거부");
    assert_eq!(err_nofeat, PresenterError::NoFeatures);
    assert_eq!(presenter.plan_preview(), None);
    assert_eq!(
        presenter.state().options().selected_features.len(),
        2,
        "모델 옵션은 기본값 2개로 유지"
    );

    // 2. 정상 옵션 확인 -> 성공 및 preview 생성
    presenter.update_draft_options(
        "5000",
        "2",
        vec![QuickFeature::TcpConnect, QuickFeature::IcmpPing],
    );
    presenter.confirm_plan().expect("정상 옵션 계획 수립 성공");
    assert!(presenter.plan_preview().is_some());
    assert_eq!(presenter.state().options().tcp_timeout_ms, 5000);
    assert_eq!(presenter.state().options().concurrency, 2);
    assert!(!presenter.is_plan_stale());

    // 3. 범위 밖 타임아웃 (0ms) -> 거부 및 기존 모델 불변
    presenter.update_draft_options(
        "0",
        "2",
        vec![QuickFeature::TcpConnect, QuickFeature::IcmpPing],
    );
    let err_zero = presenter.confirm_plan().expect_err("0ms 타임아웃 거부");
    assert!(matches!(err_zero, PresenterError::StateError(_)));
    assert_eq!(
        presenter.state().options().tcp_timeout_ms,
        5000,
        "기존 옵션 5000ms 유지"
    );
    assert_eq!(presenter.draft_timeout_ms(), "0", "draft 문자열은 보존됨");

    // 4. 범위 밖 타임아웃 (60001ms) -> 거부 및 기존 모델 불변
    presenter.update_draft_options(
        "60001",
        "2",
        vec![QuickFeature::TcpConnect, QuickFeature::IcmpPing],
    );
    let err_high = presenter.confirm_plan().expect_err("60001ms 타임아웃 거부");
    assert!(matches!(err_high, PresenterError::StateError(_)));
    assert_eq!(
        presenter.state().options().tcp_timeout_ms,
        5000,
        "기존 옵션 5000ms 유지"
    );

    // 5. 범위 밖 동시성 (0 및 5) -> 거부 및 기존 모델 불변
    presenter.update_draft_options(
        "3000",
        "0",
        vec![QuickFeature::TcpConnect, QuickFeature::IcmpPing],
    );
    assert!(presenter.confirm_plan().is_err());
    assert_eq!(presenter.state().options().concurrency, 2);

    presenter.update_draft_options(
        "3000",
        "5",
        vec![QuickFeature::TcpConnect, QuickFeature::IcmpPing],
    );
    assert!(presenter.confirm_plan().is_err());
    assert_eq!(presenter.state().options().concurrency, 2);

    // 6. 수치 overflow 문자열 -> NumberParseError 및 기존 모델 불변
    presenter.update_draft_options(
        "999999999999999999999999999999",
        "4",
        vec![QuickFeature::TcpConnect],
    );
    let err_overflow = presenter.confirm_plan().expect_err("수치 오버플로 거부");
    assert!(matches!(err_overflow, PresenterError::NumberParseError(_)));
    assert_eq!(presenter.state().options().tcp_timeout_ms, 5000);
}

#[test]
fn test_plan_preview_invariants_and_stale_transitions() {
    let mut presenter = GuiPresenter::new();
    presenter
        .replace_targets("127.0.0.1:80\n[::1]:443")
        .expect("대상 등록");

    // 계획 확인 전 상태
    assert_eq!(presenter.state().phase(), RunPhase::Ready);
    assert_eq!(presenter.state().active_run_id(), None);
    assert_eq!(presenter.state().last_result(), None);

    // 계획 확인 실행
    presenter.confirm_plan().expect("계획 확인");

    // 계약 불변식 검증: begin_run/finish_run을 호출하지 않아야 함
    assert_eq!(
        presenter.state().phase(),
        RunPhase::Ready,
        "계획 확인은 phase를 변경하지 않음"
    );
    assert_eq!(
        presenter.state().active_run_id(),
        None,
        "계획 확인은 활성 run_id를 생성하지 않음"
    );
    assert_eq!(
        presenter.state().last_result(),
        None,
        "계획 확인은 last_result를 건드리지 않음"
    );
    assert!(!presenter.is_plan_stale(), "방금 확인된 계획은 최신 상태");

    // 1. 대상 추가 시 stale 전환 검증
    presenter.append_targets("10.0.0.1:80").expect("추가");
    assert!(
        presenter.is_plan_stale(),
        "대상 추가 후 계획은 stale 상태여야 함"
    );

    // 다시 계획 확인
    presenter.confirm_plan().expect("계획 재확인");
    assert!(!presenter.is_plan_stale());

    // 2. 대상 교체 시 stale 전환 검증
    presenter.replace_targets("192.168.1.1:80").expect("교체");
    assert!(
        presenter.is_plan_stale(),
        "대상 교체 후 계획은 stale 상태여야 함"
    );

    presenter.confirm_plan().expect("계획 재확인");
    assert!(!presenter.is_plan_stale());

    // 3. 대상 삭제 시 stale 전환 검증
    presenter.set_selected_index(Some(0)).expect("선택");
    presenter.remove_selected().expect("삭제");
    assert!(
        presenter.is_plan_stale(),
        "대상 삭제 후 계획은 stale 상태여야 함"
    );

    // 4. 옵션 draft 변경 시 stale 전환 검증
    presenter
        .replace_targets("127.0.0.1:80")
        .expect("대상 재등록");
    presenter.confirm_plan().expect("계획 재확인");
    assert!(!presenter.is_plan_stale());

    presenter.update_draft_options(
        "2000",
        "1",
        vec![QuickFeature::TcpConnect, QuickFeature::IcmpPing],
    );
    assert!(
        presenter.is_plan_stale(),
        "옵션 draft 변경 후 계획은 stale 상태여야 함"
    );
}

#[test]
fn test_renderer_truncation_boundary_65536() {
    let mut presenter = GuiPresenter::new();

    // 1. 미수립 상태 렌더링
    let empty_render = presenter.render_plan_preview();
    assert!(empty_render.contains("모드: 입력·계획 확인 전용"));
    assert!(empty_render.contains("수립된 계획이 없습니다"));

    // 2. 정상 계획 렌더링
    presenter
        .replace_targets("example.com:80\n127.0.0.1:443")
        .expect("대상 등록");
    presenter.confirm_plan().expect("계획 확인");
    let normal_render = presenter.render_plan_preview();
    assert!(normal_render.contains("【Network Quick Check 진단 계획 확인】"));
    assert!(normal_render.contains("정규화 호스트: example.com, 포트: 80"));
    assert!(normal_render.contains("사전 DNS 주소 해석 필요: 예"));
    assert!(normal_render.contains("정규화 호스트: 127.0.0.1, 포트: 443"));
    assert!(normal_render.contains("사전 DNS 주소 해석 필요: 아니오"));
    assert!(normal_render.len() <= MAX_RENDER_BYTES);

    // 3. 65,536바이트 경계 절단 검증용 대규모 합성 계획
    let mut huge_targets = Vec::new();
    for i in 0..1000 {
        huge_targets.push(network_core::targets::PlannedTarget {
            target: QuickTarget {
                host: format!("host-{}.long-domain-name-for-testing-boundary.local", i),
                port: 8080,
                raw_input: format!(
                    "host-{}.long-domain-name-for-testing-boundary.local:8080",
                    i
                ),
            },
            features: vec![
                QuickFeature::TcpConnect,
                QuickFeature::IcmpPing,
                QuickFeature::IcmpTraceroute,
                QuickFeature::DnsLookup,
                QuickFeature::LocalNetwork,
            ],
            requires_resolution: true,
        });
    }

    let synthetic_plan = QuickPlan {
        targets: huge_targets,
        tcp_timeout_ms: 3000,
        icmp_timeout_ms: Some(2000),
        concurrency: 4,
        limitations: vec!["긴 제한사항 안내 메시지입니다. ".repeat(100)],
    };

    presenter.plan_preview = Some(synthetic_plan);
    let rendered_huge = presenter.render_plan_preview();

    // 상한 65,536바이트 준수 검증
    assert!(
        rendered_huge.len() <= MAX_RENDER_BYTES,
        "렌더링 바이트 수({})가 최대 상한({}) 이하이어야 합니다.",
        rendered_huge.len(),
        MAX_RENDER_BYTES
    );
    // 생략 고지 포함 검증
    assert!(
        rendered_huge.contains(TRUNCATION_NOTICE),
        "상한 초과 시 생략 고지가 포함되어야 합니다."
    );
    // 유효한 UTF-8 문자 경계 검증
    assert!(
        std::str::from_utf8(rendered_huge.as_bytes()).is_ok(),
        "렌더링 결과는 항상 유효한 UTF-8 문자열이어야 합니다."
    );
}

#[test]
fn test_render_error() {
    let mut presenter = GuiPresenter::new();

    // 오류 없는 상태
    assert_eq!(presenter.render_error(), "");

    // 오류 설정 상태
    presenter.set_error(Some("테스트 오류 메시지입니다.".to_string()));
    let rendered = presenter.render_error();
    assert!(rendered.contains("【오류 안내】"));
    assert!(rendered.contains("테스트 오류 메시지입니다."));
}

// 부모 보강: 모델/선택/preview/stale 전체를 비교하되 오류 표시 문자열은 실패를 알리므로 제외한다.
fn assert_protected_equal(actual: &GuiPresenter, before: &GuiPresenter) {
    assert_eq!(actual.state, before.state);
    assert_eq!(actual.selected_index, before.selected_index);
    assert_eq!(actual.plan_preview, before.plan_preview);
    assert_eq!(actual.is_plan_stale, before.is_plan_stale);
    assert_eq!(actual.draft_timeout_ms, before.draft_timeout_ms);
    assert_eq!(actual.draft_concurrency, before.draft_concurrency);
    assert_eq!(actual.draft_features, before.draft_features);
}
fn bytes_fixture(n: usize) -> String {
    let seed = "127.0.0.2:80";
    assert!(n >= seed.len());
    let value = seed.to_owned() + &"\n".repeat(n - seed.len());
    assert_eq!(value.len(), n);
    value
}
#[test]
fn parent_exact_core_policy_and_full_plans() {
    let input = "EXAMPLE.com:080\r\nexample.COM:80\r\n[::1]:443\r\n127.0.0.1:80";
    let mut p = GuiPresenter::new();
    p.replace_targets(input).unwrap();
    assert_eq!(
        p.state().targets(),
        network_core::targets::parse_target_list(input).unwrap()
    );
    assert_eq!(p.state().targets()[0].raw_input, "EXAMPLE.com:080");
    for timeout in [1, 3000, 60000] {
        for concurrency in 1..=4 {
            let features = vec![
                QuickFeature::TcpConnect,
                QuickFeature::IcmpPing,
                QuickFeature::IcmpTraceroute,
                QuickFeature::DnsLookup,
                QuickFeature::LocalNetwork,
            ];
            p.update_draft_options(
                &timeout.to_string(),
                &concurrency.to_string(),
                features.clone(),
            );
            p.confirm_plan().unwrap();
            assert_eq!(
                p.plan_preview(),
                Some(&build_quick_plan(p.state().targets(), p.state().options()).unwrap())
            );
            assert_eq!(p.draft_concurrency(), concurrency.to_string());
            assert_eq!(p.draft_features(), features);
            let state = p.state.clone();
            p.confirm_plan().unwrap();
            assert_eq!(p.state, state);
        }
    }
}
#[test]
fn parent_failed_edits_preserve_finished_state_and_selection() {
    let mut p = GuiPresenter::new();
    p.replace_targets("127.0.0.1:80\n[::1]:80").unwrap();
    p.confirm_plan().unwrap();
    let snapshot = p.state.begin_run().unwrap();
    p.state
        .finish_run(snapshot.run_id(), Err(vec!["원문\r\n완료 오류".to_owned()]))
        .unwrap();
    p.set_selected_index(Some(1)).unwrap();
    for text in [
        "::1:80",
        "127.0.0.1:0",
        "127.0.0.1:65536",
        "127.0.0.2:80\nhttp://bad:80",
    ] {
        let before = p.clone();
        assert!(p.append_targets(text).is_err());
        assert_protected_equal(&p, &before);
        assert!(p.replace_targets(text).is_err());
        assert_protected_equal(&p, &before);
    }
    let before = p.clone();
    assert!(p.set_selected_index(Some(99)).is_err());
    assert_protected_equal(&p, &before);
    // 미리보기 반복은 이전 완료 결과와 다음 성공 실행 ID까지 보존한다.
    let mut expected = p.state.clone();
    let next = expected.begin_run().unwrap().run_id();
    p.confirm_plan().unwrap();
    p.confirm_plan().unwrap();
    assert_eq!(p.state.last_result(), before.state.last_result());
    assert_eq!(p.state.begin_run().unwrap().run_id(), next);
    let busy = p.clone();
    assert!(p.append_targets("127.0.0.2:80").is_err());
    assert_protected_equal(&p, &busy);
    assert!(p.confirm_plan().is_err());
    assert_protected_equal(&p, &busy);
}
#[test]
fn parent_exact_bytes_and_combined_append_boundaries() {
    let mut initial = GuiPresenter::new();
    initial.replace_targets("127.0.0.1:80").unwrap();
    initial.confirm_plan().unwrap();
    initial.set_selected_index(Some(0)).unwrap();
    for n in [MAX_INPUT_BYTES, MAX_INPUT_BYTES + 1] {
        let text = bytes_fixture(n);
        let mut p = initial.clone();
        let result = p.replace_targets(&text);
        if n == MAX_INPUT_BYTES {
            result.unwrap();
        } else {
            assert!(result.is_err());
            assert_protected_equal(&p, &initial);
        }
    }
    let used = initial.state().targets()[0].raw_input.len() + 1;
    for n in [MAX_INPUT_BYTES, MAX_INPUT_BYTES + 1] {
        let text = bytes_fixture(n - used);
        assert_eq!(used + text.len(), n);
        let mut p = initial.clone();
        let result = p.append_targets(&text);
        if n == MAX_INPUT_BYTES {
            result.unwrap();
        } else {
            assert!(result.is_err());
            assert_protected_equal(&p, &initial);
        }
    }
    let text = (1..=100)
        .map(|i| format!("10.0.0.{i}:80"))
        .collect::<Vec<_>>()
        .join("\n");
    let mut p = GuiPresenter::new();
    p.replace_targets(&text).unwrap();
    p.confirm_plan().unwrap();
    p.set_selected_index(Some(99)).unwrap();
    let before = p.clone();
    assert!(p.append_targets("10.0.0.101:80").is_err());
    assert_protected_equal(&p, &before);
    p.append_targets("10.0.0.1:080").unwrap();
    assert_eq!(p.state().targets().len(), 100);
    assert_eq!(p.selected_index(), None);
}
#[test]
fn parent_option_utf16_and_exact_decode_boundaries() {
    let mut p = GuiPresenter::new();
    p.replace_targets("127.0.0.1:80").unwrap();
    p.confirm_plan().unwrap();
    let raw = |s: &str| s.encode_utf16().collect::<Vec<_>>();
    for (a, b) in [
        (vec![0xd800], raw("4")),
        (raw("3000"), vec![0]),
        (vec![49; 33], raw("4")),
    ] {
        let before = p.clone();
        assert!(
            p.update_draft_utf16(&a, &b, vec![QuickFeature::TcpConnect])
                .is_err()
        );
        assert_eq!(p, before);
    }
    for n in [MAX_INPUT_BYTES, MAX_INPUT_BYTES + 1] {
        let source = vec![65u16; n];
        let r = decode_utf16_input(&source, false, MAX_INPUT_BYTES + 1, MAX_INPUT_BYTES);
        assert_eq!(r.is_ok(), n == MAX_INPUT_BYTES);
    }
    let text = "가".repeat(MAX_INPUT_BYTES / 3);
    let source = raw(&text);
    assert_eq!(
        decode_utf16_input(&source, false, MAX_INPUT_BYTES, MAX_INPUT_BYTES).unwrap(),
        text
    );
    assert!(
        decode_utf16_input(
            &raw(&(text + "가")),
            false,
            MAX_INPUT_BYTES,
            MAX_INPUT_BYTES
        )
        .is_err()
    );
}
#[test]
fn parent_many_core_errors_are_bounded_while_formatting() {
    let mut p = GuiPresenter::new();
    p.replace_targets("127.0.0.1:80").unwrap();
    p.confirm_plan().unwrap();
    let before = p.clone();
    let text = ":\n".repeat(MAX_INPUT_BYTES / 2);
    assert_eq!(text.len(), MAX_INPUT_BYTES);
    assert!(p.replace_targets(&text).is_err());
    assert_protected_equal(&p, &before);
    let stored = p.last_error().unwrap();
    assert!(stored.len() <= MAX_RENDER_BYTES);
    assert!(stored.contains(TRUNCATION_NOTICE));
    assert!(p.render_error().len() <= MAX_RENDER_BYTES);
    struct Repeated<'a>(&'a std::cell::Cell<usize>);
    impl std::fmt::Display for Repeated<'_> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            for _ in 0..100000 {
                self.0.set(self.0.get() + 1);
                f.write_str("다중바이트 오류를 계속 쓰는 시험입니다. ")?;
            }
            Ok(())
        }
    }
    let count = std::cell::Cell::new(0);
    p.record_error(&Repeated(&count));
    assert!(count.get() < 2000);
    assert!(p.last_error().unwrap().contains(TRUNCATION_NOTICE));
    assert!(p.last_error().unwrap().len() <= MAX_RENDER_BYTES);
}
#[test]
fn parent_invalid_options_preserve_entire_protected_snapshot() {
    let mut p = GuiPresenter::new();
    p.replace_targets("127.0.0.1:80").unwrap();
    p.confirm_plan().unwrap();
    p.set_selected_index(Some(0)).unwrap();
    for (time, concurrent, features) in [
        ("0", "1", vec![QuickFeature::TcpConnect]),
        ("60001", "1", vec![QuickFeature::TcpConnect]),
        ("3000", "5", vec![QuickFeature::TcpConnect]),
        ("3000", "4", vec![]),
        ("+1", "1", vec![QuickFeature::TcpConnect]),
    ] {
        p.update_draft_options(time, concurrent, features);
        let before = p.clone();
        assert!(p.confirm_plan().is_err());
        assert_protected_equal(&p, &before);
    }
}
