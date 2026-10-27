//! Network Quick Check(Part B) 순수 진단 결과 뷰 및 필터링 모듈.
//!
//! 본 모듈은 코어 진단 실행 보고서(`QuickRunReport`)에 대한 순수 참조 기반 뷰(`ResultView`)와
//! 필터링(`ResultFilter`, `select_rows`), 그리고 표시 헬퍼 함수들을 제공합니다.
//!
//! ## 핵심 설계 및 불변식
//! - **완전한 순수성(Purity)**: I/O, Win32, 파일 쓰기, 클립보드, 시계, 환경변수, 스레드, 비동기 런타임 배제.
//! - **단일 진실 공급원 준수**: 코어의 `QuickResult` 및 `QuickRunReport`를 빌린 참조(`&`)로만 다루며,
//!   DTO 복제, 상태 머신 추가, 임의의 재판정이나 집계를 수행하지 않습니다.
//! - **필터와 코어 통계의 엄격한 분리**: UI 필터로 제외된 행 수(`filtered_out_count`)와
//!   코어 진단 실행기가 메모리 한도 초과 등으로 누락한 결과 수(`omitted_results`)를 절대 합치지 않습니다.
//! - **원문 보존 및 위장 금지**: SYN 패킷 미관측, 타임아웃, 무응답 홉에 대해 차단 지점이나 패킷 관찰을
//!   발명하지 않으며, 미확인/실패 상태(`UNKNOWN`, `FAIL`, `SKIPPED`)를 임의로 정규화하거나 PASS로 위장하지 않습니다.
//! - **독립된 근거 수준 및 상태**: `status`와 `evidence_level`은 독립적으로 취급되며,
//!   `details`의 `outcome`이나 `limitations`는 존재하는 값만 읽고 누락/비객체 시 임의 추론을 하지 않습니다.

use network_core::quick::{EvidenceLevel, QuickFeature, QuickResult, QuickStatus};
use network_core::runner::QuickRunReport;

/// 진단 결과 필터 조건.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResultFilter {
    /// 상태 일치 필터 (None이면 모든 상태 허용).
    pub status: Option<QuickStatus>,
    /// 기능 일치 필터 (None이면 모든 기능 허용).
    pub feature: Option<QuickFeature>,
    /// 근거 수준 일치 필터 (None이면 모든 근거 수준 허용).
    pub evidence_level: Option<EvidenceLevel>,
    /// 대상 검색 질의 문자열 (빈 문자열이면 전체 허용, 대소문자 구분 리터럴 부분 검색).
    pub target_query: String,
}

impl ResultFilter {
    /// 지정된 결과 행이 현재 필터 조건을 만족하는지 검사합니다.
    ///
    /// ## 규칙
    /// - `status`, `feature`, `evidence_level` 조건은 `Some`인 경우 정확 일치해야 합니다.
    /// - `target_query`가 비어있지 않은 경우:
    ///   - `target_host`
    ///   - `resolved_ip` (존재하는 경우)
    ///   - `target_port`의 10진수 문자열
    ///     위 3개 대상 중 하나라도 검색어 문자열을 대소문자 구분 리터럴로 포함하고 있으면 통과합니다.
    /// - 모든 조건은 논리적 AND로 결합됩니다.
    /// - DNS 해석, 문자열 트림, 정규화, 주소 문법 재검증은 일체 수행하지 않습니다.
    pub fn matches(&self, result: &QuickResult) -> bool {
        if self.status.is_some_and(|status| result.status != status)
            || self
                .feature
                .is_some_and(|feature| result.feature != feature)
            || self
                .evidence_level
                .is_some_and(|evidence| result.evidence_level != evidence)
        {
            return false;
        }
        if !self.target_query.is_empty() {
            let port_str = result.target_port.to_string();
            let matches_host = result.target_host.contains(&self.target_query);
            let matches_resolved = result
                .resolved_ip
                .as_ref()
                .is_some_and(|ip| ip.contains(&self.target_query));
            let matches_port = port_str.contains(&self.target_query);

            if !matches_host && !matches_resolved && !matches_port {
                return false;
            }
        }
        true
    }
}

/// 원본 보고서에서 필터 조건에 부합하는 결과 행들을 선택합니다.
///
/// 원본 보고서 내의 인덱스, 순서, 중복을 변경 없이 그대로 보존합니다.
pub fn select_rows<'a>(
    report: &'a QuickRunReport,
    filter: &ResultFilter,
) -> Vec<(usize, &'a QuickResult)> {
    report
        .results
        .iter()
        .enumerate()
        .filter(|(_, res)| filter.matches(res))
        .collect()
}

/// 진단 결과 뷰 (빌린 참조 모델).
///
/// 진단 미실행(`NotRun`), 실행 오류(`RunErrors`), 정상 보고서(`Report`)를 엄격히 구분합니다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResultView<'a> {
    /// 진단이 아직 실행되지 않은 상태.
    NotRun,
    /// 진단 실행 중 발생한 치명적 오류 목록.
    RunErrors(&'a [String]),
    /// 정상 수신된 진단 보고서 뷰.
    Report {
        /// 원본 진단 실행 보고서에 대한 불변 참조.
        report: &'a QuickRunReport,
        /// 필터를 통과한 선택 행 목록 (원본 인덱스 및 결과 참조 쌍).
        selected_rows: Vec<(usize, &'a QuickResult)>,
        /// 원본 보고서에 보관된 전체 결과 행 수.
        retained_count: usize,
        /// 현재 필터에 의해 표시에서 제외된 행 수 (`retained_count - selected_rows.len()`).
        filtered_out_count: usize,
    },
}

impl<'a> ResultView<'a> {
    /// 원본 보고서가 있는 경우 이를 참조합니다.
    pub fn report(&self) -> Option<&'a QuickRunReport> {
        match self {
            Self::Report { report, .. } => Some(*report),
            _ => None,
        }
    }

    /// 현재 뷰에서 선택된 결과 행 슬라이스를 반환합니다.
    pub fn selected_rows(&self) -> &[(usize, &'a QuickResult)] {
        match self {
            Self::Report { selected_rows, .. } => selected_rows.as_slice(),
            _ => &[],
        }
    }
}

/// 주어진 진단 실행 결과 소스와 필터 조건으로부터 참조 기반 `ResultView`를 구축합니다.
///
/// ## 구분 원칙
/// - `source == None`: `ResultView::NotRun`
/// - `source == Some(Err(errors))`: `ResultView::RunErrors(errors.as_slice())`
/// - `source == Some(Ok(report))`: `ResultView::Report`
///   - 빈 보고서, 필터 일치 0행, 정상 일치 행을 모두 정밀하게 표현합니다.
///   - `report.cancelled`, `limit_reached`, `omitted_results`, `errors`, `invocations`,
///     `serialized_result_bytes` 등의 원본 필드는 필터와 무관하게 원본 그대로 접근 가능합니다.
///   - `filtered_out_count`는 UI 필터에 의해 숨겨진 행 수이며 코어의 `omitted_results`와 절대 합치지 않습니다.
pub fn build_result_view<'a>(
    source: Option<&'a Result<QuickRunReport, Vec<String>>>,
    filter: &ResultFilter,
) -> ResultView<'a> {
    match source {
        None => ResultView::NotRun,
        Some(Err(errors)) => ResultView::RunErrors(errors.as_slice()),
        Some(Ok(report)) => {
            let selected_rows = select_rows(report, filter);
            let retained_count = report.results.len();
            let filtered_out_count = retained_count.saturating_sub(selected_rows.len());
            ResultView::Report {
                report,
                selected_rows,
                retained_count,
                filtered_out_count,
            }
        }
    }
}

/// 진단 결과 상태의 한글 라벨을 반환합니다.
pub const fn status_label_ko(status: QuickStatus) -> &'static str {
    match status {
        QuickStatus::PASS => "성공",
        QuickStatus::FAIL => "실패",
        QuickStatus::WARN => "경고",
        QuickStatus::SKIPPED => "미실행",
        QuickStatus::UNKNOWN => "확인불가",
    }
}

/// 진단 결과 상태의 코드와 한글 라벨을 결합한 표시 문자열을 반환합니다.
pub const fn status_display(status: QuickStatus) -> &'static str {
    match status {
        QuickStatus::PASS => "PASS (성공)",
        QuickStatus::FAIL => "FAIL (실패)",
        QuickStatus::WARN => "WARN (경고)",
        QuickStatus::SKIPPED => "SKIPPED (미실행)",
        QuickStatus::UNKNOWN => "UNKNOWN (확인불가)",
    }
}

/// 진단 근거 수준의 한글 라벨을 반환합니다.
pub const fn evidence_label_ko(evidence: EvidenceLevel) -> &'static str {
    match evidence {
        EvidenceLevel::OBSERVED => "관측",
        EvidenceLevel::INFERRED => "추론",
        EvidenceLevel::UNKNOWN => "미확인",
    }
}

/// 진단 근거 수준의 코드와 한글 라벨을 결합한 표시 문자열을 반환합니다.
pub const fn evidence_display(evidence: EvidenceLevel) -> &'static str {
    match evidence {
        EvidenceLevel::OBSERVED => "OBSERVED (관측)",
        EvidenceLevel::INFERRED => "INFERRED (추론)",
        EvidenceLevel::UNKNOWN => "UNKNOWN (미확인)",
    }
}

/// 진단 기능의 한글 표시 이름을 반환합니다.
pub const fn feature_display_ko(feature: QuickFeature) -> &'static str {
    match feature {
        QuickFeature::TcpConnect => "TCP 연결",
        QuickFeature::IcmpPing => "ICMP Ping",
        QuickFeature::IcmpTraceroute => "ICMP Traceroute",
        QuickFeature::DnsLookup => "DNS 조회",
        QuickFeature::LocalNetwork => "로컬 네트워크",
    }
}

/// 진단 결과의 details 객체에서 outcome 문자열을 안전하게 추출합니다.
///
/// details가 객체이고 outcome이 문자열인 경우에만 `Some(&str)`을 반환하며,
/// 비객체이거나 누락 또는 타입이 다른 경우 어떠한 추론이나 기본값도 발명하지 않고 `None`을 반환합니다.
pub fn extract_outcome(result: &QuickResult) -> Option<&str> {
    result
        .details
        .as_object()
        .and_then(|obj| obj.get("outcome"))
        .and_then(|val| val.as_str())
}

/// 진단 결과의 details 객체에서 limitations 문자열 슬라이스 목록을 안전하게 추출합니다.
///
/// limitations가 배열인 경우 문자열 요소만 수집하여 반환하며 비객체 또는 누락 시 빈 벡터를 반환합니다.
pub fn extract_limitations(result: &QuickResult) -> Vec<&str> {
    let Some(obj) = result.details.as_object() else {
        return Vec::new();
    };
    let Some(lim_val) = obj.get("limitations") else {
        return Vec::new();
    };
    let Some(arr) = lim_val.as_array() else {
        return Vec::new();
    };
    arr.iter().filter_map(|v| v.as_str()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use network_core::quick::{QUICK_PRODUCT_NAME, QUICK_SCHEMA_VERSION};
    use network_core::runner::ProbeCounts;

    /// 테스트용 합성 QuickResult를 생성하는 헬퍼 함수.
    fn make_test_result(
        host: &str,
        resolved_ip: Option<&str>,
        port: u16,
        feature: QuickFeature,
        status: QuickStatus,
        evidence: EvidenceLevel,
    ) -> QuickResult {
        QuickResult {
            schema_version: QUICK_SCHEMA_VERSION.to_string(),
            product: QUICK_PRODUCT_NAME.to_string(),
            session_id: "test-session".to_string(),
            timestamp_iso8601: Some("2026-10-26T12:00:00Z".to_string()),
            source_host: Some("client.local".to_string()),
            target_host: host.to_string(),
            resolved_ip: resolved_ip.map(|s| s.to_string()),
            target_port: port,
            feature,
            status,
            elapsed_ms: Some(15),
            os_error_code: None,
            details: serde_json::json!({
                "outcome": "CONNECTED",
                "limitations": ["테스트 제약사항"],
                "raw_measurement": {}
            }),
            evidence_level: evidence,
        }
    }

    /// 테스트용 합성 QuickRunReport를 생성하는 헬퍼 함수.
    fn make_test_report(results: Vec<QuickResult>) -> QuickRunReport {
        QuickRunReport {
            results,
            cancelled: false,
            limit_reached: false,
            omitted_results: 5,
            errors: vec!["오류 메시지".to_string()],
            invocations: ProbeCounts {
                tcp_connect: 1,
                icmp_ping: 1,
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
    fn test_all_75_status_evidence_feature_combinations() {
        // QuickStatus(5) * EvidenceLevel(3) * QuickFeature(5) = 75가지 조합
        let all_statuses = [
            QuickStatus::PASS,
            QuickStatus::FAIL,
            QuickStatus::WARN,
            QuickStatus::SKIPPED,
            QuickStatus::UNKNOWN,
        ];
        let all_evidences = [
            EvidenceLevel::OBSERVED,
            EvidenceLevel::INFERRED,
            EvidenceLevel::UNKNOWN,
        ];
        let all_features = [
            QuickFeature::TcpConnect,
            QuickFeature::IcmpPing,
            QuickFeature::IcmpTraceroute,
            QuickFeature::DnsLookup,
            QuickFeature::LocalNetwork,
        ];

        let mut all_results = Vec::new();
        for &status in &all_statuses {
            for &evidence in &all_evidences {
                for &feature in &all_features {
                    all_results.push(make_test_result(
                        "example.com",
                        Some("93.184.216.34"),
                        80,
                        feature,
                        status,
                        evidence,
                    ));
                }
            }
        }
        assert_eq!(all_results.len(), 75);

        let report = make_test_report(all_results);

        // 1. 기본 필터(빈 필터)는 75개 모두 선택해야 함
        let default_filter = ResultFilter::default();
        let selected_all = select_rows(&report, &default_filter);
        assert_eq!(selected_all.len(), 75);

        // 2. 각 75개 조합을 정확히 1개씩 단독 필터링하여 일치 확인
        for &status in &all_statuses {
            for &evidence in &all_evidences {
                for &feature in &all_features {
                    let filter = ResultFilter {
                        status: Some(status),
                        feature: Some(feature),
                        evidence_level: Some(evidence),
                        target_query: String::new(),
                    };
                    let selected = select_rows(&report, &filter);
                    assert_eq!(
                        selected.len(),
                        1,
                        "조합 {:?}/{:?}/{:?}은 정확히 1개만 매칭되어야 합니다.",
                        status,
                        feature,
                        evidence
                    );
                    assert_eq!(selected[0].1.status, status);
                    assert_eq!(selected[0].1.feature, feature);
                    assert_eq!(selected[0].1.evidence_level, evidence);
                }
            }
        }

        // 3. 상태 단독 필터: 각 상태별 정확히 15개(3*5) 매칭 확인
        for &status in &all_statuses {
            let filter = ResultFilter {
                status: Some(status),
                ..Default::default()
            };
            let selected = select_rows(&report, &filter);
            assert_eq!(selected.len(), 15);
        }

        // 4. 근거 단독 필터: 각 근거별 정확히 25개(5*5) 매칭 확인
        for &evidence in &all_evidences {
            let filter = ResultFilter {
                evidence_level: Some(evidence),
                ..Default::default()
            };
            let selected = select_rows(&report, &filter);
            assert_eq!(selected.len(), 25);
        }

        // 5. 기능 단독 필터: 각 기능별 정확히 15개(5*3) 매칭 확인
        for &feature in &all_features {
            let filter = ResultFilter {
                feature: Some(feature),
                ..Default::default()
            };
            let selected = select_rows(&report, &filter);
            assert_eq!(selected.len(), 15);
        }
    }

    #[test]
    fn test_target_query_filtering_rules() {
        let results = vec![
            make_test_result(
                "example.com",
                Some("93.184.216.34"),
                80,
                QuickFeature::TcpConnect,
                QuickStatus::PASS,
                EvidenceLevel::OBSERVED,
            ),
            make_test_result(
                "EXAMPLE.ORG",
                Some("93.184.216.35"),
                8080,
                QuickFeature::TcpConnect,
                QuickStatus::FAIL,
                EvidenceLevel::OBSERVED,
            ),
            make_test_result(
                "test.local",
                Some("2001:db8::1"),
                443,
                QuickFeature::TcpConnect,
                QuickStatus::PASS,
                EvidenceLevel::OBSERVED,
            ),
            make_test_result(
                "no-ip.domain",
                None,
                53,
                QuickFeature::DnsLookup,
                QuickStatus::UNKNOWN,
                EvidenceLevel::UNKNOWN,
            ),
        ];
        let report = make_test_report(results);

        // 1. 대소문자 구분 literal 검색
        let filter_lower = ResultFilter {
            target_query: "example".to_string(),
            ..Default::default()
        };
        let sel_lower = select_rows(&report, &filter_lower);
        assert_eq!(sel_lower.len(), 1);
        assert_eq!(sel_lower[0].1.target_host, "example.com");

        let filter_upper = ResultFilter {
            target_query: "EXAMPLE".to_string(),
            ..Default::default()
        };
        let sel_upper = select_rows(&report, &filter_upper);
        assert_eq!(sel_upper.len(), 1);
        assert_eq!(sel_upper[0].1.target_host, "EXAMPLE.ORG");

        // 2. 포트 10진 문자열 검색
        let filter_port = ResultFilter {
            target_query: "80".to_string(),
            ..Default::default()
        };
        // 80과 8080 둘 다 "80"을 부분 문자열로 포함
        let sel_port = select_rows(&report, &filter_port);
        assert_eq!(sel_port.len(), 2);
        assert_eq!(sel_port[0].1.target_port, 80);
        assert_eq!(sel_port[1].1.target_port, 8080);

        // 3. IPv6 주소 부분 검색
        let filter_ipv6 = ResultFilter {
            target_query: "db8::".to_string(),
            ..Default::default()
        };
        let sel_ipv6 = select_rows(&report, &filter_ipv6);
        assert_eq!(sel_ipv6.len(), 1);
        assert_eq!(sel_ipv6[0].1.target_host, "test.local");

        // 4. resolved_ip가 None인 대상에서 IP 검색 시 미매칭 확인
        let filter_ip_none = ResultFilter {
            target_query: "127.0.0.1".to_string(),
            ..Default::default()
        };
        let sel_ip_none = select_rows(&report, &filter_ip_none);
        assert!(sel_ip_none.is_empty());

        // 5. 복합 필터 AND 조건 (feature + status + query)
        let filter_complex = ResultFilter {
            status: Some(QuickStatus::PASS),
            feature: Some(QuickFeature::TcpConnect),
            evidence_level: Some(EvidenceLevel::OBSERVED),
            target_query: "example".to_string(),
        };
        let sel_complex = select_rows(&report, &filter_complex);
        assert_eq!(sel_complex.len(), 1);
        assert_eq!(sel_complex[0].1.target_host, "example.com");

        // 복합 필터에서 하나라도 불일치 시 제외 확인
        let filter_mismatch = ResultFilter {
            status: Some(QuickStatus::FAIL),
            target_query: "example.com".to_string(),
            ..Default::default()
        };
        assert!(select_rows(&report, &filter_mismatch).is_empty());
    }

    #[test]
    fn test_select_rows_preserves_order_and_duplicates() {
        // 동일한 호스트와 포트를 가진 중복 결과 행들
        let results = vec![
            make_test_result(
                "dup.com",
                Some("1.1.1.1"),
                80,
                QuickFeature::TcpConnect,
                QuickStatus::PASS,
                EvidenceLevel::OBSERVED,
            ),
            make_test_result(
                "other.com",
                Some("2.2.2.2"),
                80,
                QuickFeature::TcpConnect,
                QuickStatus::FAIL,
                EvidenceLevel::OBSERVED,
            ),
            make_test_result(
                "dup.com",
                Some("1.1.1.1"),
                80,
                QuickFeature::TcpConnect,
                QuickStatus::PASS,
                EvidenceLevel::OBSERVED,
            ),
        ];
        let report = make_test_report(results);

        let filter = ResultFilter {
            target_query: "dup.com".to_string(),
            ..Default::default()
        };
        let selected = select_rows(&report, &filter);

        // 원본 인덱스 0과 2가 순서대로 보존되어야 함
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].0, 0);
        assert_eq!(selected[0].1.target_host, "dup.com");
        assert_eq!(selected[1].0, 2);
        assert_eq!(selected[1].1.target_host, "dup.com");
    }

    #[test]
    fn test_build_result_view_variants_and_separation() {
        let filter = ResultFilter {
            status: Some(QuickStatus::PASS),
            ..Default::default()
        };

        // 1. None 소스 -> NotRun
        let view_none = build_result_view(None, &filter);
        assert_eq!(view_none, ResultView::NotRun);
        assert!(view_none.report().is_none());
        assert!(view_none.selected_rows().is_empty());

        // 2. Err 소스 -> RunErrors
        let errors = vec!["진단 중단 오류".to_string()];
        let err_source = Err(errors.clone());
        let view_err = build_result_view(Some(&err_source), &filter);
        match view_err {
            ResultView::RunErrors(err_slice) => {
                assert_eq!(err_slice, &["진단 중단 오류"]);
            }
            _ => panic!("RunErrors 뷰가 생성되어야 합니다."),
        }

        // 3. Ok 빈 보고서 -> Report { retained: 0, filtered_out: 0 }
        let empty_report = make_test_report(Vec::new());
        let ok_empty = Ok(empty_report);
        let view_empty = build_result_view(Some(&ok_empty), &filter);
        match view_empty {
            ResultView::Report {
                report: _,
                selected_rows,
                retained_count,
                filtered_out_count,
            } => {
                assert!(selected_rows.is_empty());
                assert_eq!(retained_count, 0);
                assert_eq!(filtered_out_count, 0);
            }
            _ => panic!("Report 뷰가 생성되어야 합니다."),
        }

        // 4. Ok 정상 보고서 (일부 필터 제외 발생)
        let results = vec![
            make_test_result(
                "h1",
                None,
                80,
                QuickFeature::TcpConnect,
                QuickStatus::PASS,
                EvidenceLevel::OBSERVED,
            ),
            make_test_result(
                "h2",
                None,
                80,
                QuickFeature::TcpConnect,
                QuickStatus::FAIL,
                EvidenceLevel::OBSERVED,
            ),
            make_test_result(
                "h3",
                None,
                80,
                QuickFeature::TcpConnect,
                QuickStatus::WARN,
                EvidenceLevel::OBSERVED,
            ),
        ];
        let mut report = make_test_report(results);
        report.omitted_results = 99; // 코어 메모리 초과 누락 건수

        let ok_report = Ok(report);
        let view_report = build_result_view(Some(&ok_report), &filter);

        match view_report {
            ResultView::Report {
                report: ref_report,
                selected_rows,
                retained_count,
                filtered_out_count,
            } => {
                // PASS인 h1 1건만 선택
                assert_eq!(selected_rows.len(), 1);
                assert_eq!(selected_rows[0].0, 0);
                assert_eq!(selected_rows[0].1.target_host, "h1");

                // 보관 건수는 3, 필터 제외는 2
                assert_eq!(retained_count, 3);
                assert_eq!(filtered_out_count, 2);

                // 코어 omitted_results(99)와 UI filtered_out_count(2)가 엄격히 분리되어 보존됨
                assert_eq!(ref_report.omitted_results, 99);
                assert_ne!(filtered_out_count, ref_report.omitted_results);
            }
            _ => panic!("Report 뷰가 생성되어야 합니다."),
        }
    }

    #[test]
    fn test_display_helpers_and_details_extraction() {
        // 상태 표시 검증
        assert_eq!(status_label_ko(QuickStatus::PASS), "성공");
        assert_eq!(status_label_ko(QuickStatus::FAIL), "실패");
        assert_eq!(status_label_ko(QuickStatus::WARN), "경고");
        assert_eq!(status_label_ko(QuickStatus::SKIPPED), "미실행");
        assert_eq!(status_label_ko(QuickStatus::UNKNOWN), "확인불가");

        assert_eq!(status_display(QuickStatus::PASS), "PASS (성공)");
        assert_eq!(status_display(QuickStatus::FAIL), "FAIL (실패)");
        assert_eq!(status_display(QuickStatus::WARN), "WARN (경고)");
        assert_eq!(status_display(QuickStatus::SKIPPED), "SKIPPED (미실행)");
        assert_eq!(status_display(QuickStatus::UNKNOWN), "UNKNOWN (확인불가)");

        // 근거 표시 검증
        assert_eq!(evidence_label_ko(EvidenceLevel::OBSERVED), "관측");
        assert_eq!(evidence_label_ko(EvidenceLevel::INFERRED), "추론");
        assert_eq!(evidence_label_ko(EvidenceLevel::UNKNOWN), "미확인");

        assert_eq!(evidence_display(EvidenceLevel::OBSERVED), "OBSERVED (관측)");
        assert_eq!(evidence_display(EvidenceLevel::INFERRED), "INFERRED (추론)");
        assert_eq!(evidence_display(EvidenceLevel::UNKNOWN), "UNKNOWN (미확인)");

        // 기능 표시 검증
        assert_eq!(feature_display_ko(QuickFeature::TcpConnect), "TCP 연결");
        assert_eq!(feature_display_ko(QuickFeature::IcmpPing), "ICMP Ping");
        assert_eq!(
            feature_display_ko(QuickFeature::IcmpTraceroute),
            "ICMP Traceroute"
        );
        assert_eq!(feature_display_ko(QuickFeature::DnsLookup), "DNS 조회");
        assert_eq!(
            feature_display_ko(QuickFeature::LocalNetwork),
            "로컬 네트워크"
        );

        // details 추출 검증 (정상 값)
        let mut res = make_test_result(
            "h",
            None,
            80,
            QuickFeature::TcpConnect,
            QuickStatus::PASS,
            EvidenceLevel::OBSERVED,
        );
        assert_eq!(extract_outcome(&res), Some("CONNECTED"));
        assert_eq!(extract_limitations(&res), vec!["테스트 제약사항"]);

        // details가 비객체인 경우 -> 추론 없이 None 반환
        res.details = serde_json::Value::String("비정상 문자열".to_string());
        assert_eq!(extract_outcome(&res), None);
        assert!(extract_limitations(&res).is_empty());

        // outcome이 문자열이 아닌 경우 -> 추론 없이 None 반환
        res.details = serde_json::json!({
            "outcome": 12345,
            "limitations": "배열이 아님"
        });
        assert_eq!(extract_outcome(&res), None);
        assert!(extract_limitations(&res).is_empty());

        // limitations 배열 내에 비문자열이 섞인 경우 문자열만 필터링
        res.details = serde_json::json!({
            "outcome": "OK",
            "limitations": ["유효 제약", 999, true, "또 다른 제약"]
        });
        assert_eq!(extract_outcome(&res), Some("OK"));
        assert_eq!(extract_limitations(&res), vec!["유효 제약", "또 다른 제약"]);
    }
}
