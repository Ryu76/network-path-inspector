//! Network Path Inspector(Part A) 및 Network Quick Check(Part B)의
//! 실제 소유 루프백 TCP 대조 및 계약 동등성 검증 시험.
//!
//! ## 원칙 및 설계
//! - 본 시험은 소유 루프백(`127.0.0.1` / `::1`) 대상에 대해 양 제품의 실제 진단 엔트리포인트
//!   (`npi_probes::engine::run_profile`, `network_core::runner::run_quick`)를 순차 실행하여
//!   OS 네이티브 TCP 연결(`NativeProbeBackend` 및 `connect_once`)의 실제 결과와 계약 일치성을 대조합니다.
//! - 실제 네트워크 소켓을 생성하는 4개 테스트(`native_ipv4_connected`, `native_ipv4_refused`,
//!   `native_ipv6_connected`, `native_ipv6_refused`)는 모두 `#[ignore = "소유 루프백 실제 시험: 부모 명시 실행"]`으로
//!   격리되어 기본 시험 실행 시 어떤 네트워크 소켓이나 런타임도 기동하지 않습니다.
//! - 순수 단위 테스트(`wrapper_guards_reject_invalid_inputs_before_native_delegation`) 1개를 통해
//!   소켓이나 비동기 런타임 없이 `std::task::Waker::noop()`을 이용하여 시험용 wrapper가 잘못된 대상 및 컨텍스트 입력을
//!   `NativeProbeBackend` 위임 전에 즉각 거부함을 검증합니다.
//! - 픽스처는 RAII 소켓을 두 제품 실행까지 유지해 close-to-connect 공백을 없앱니다.
//!   bound/nonlisten의 독점 예약이나 모든 경쟁 조건 제거를 보장하지 않습니다.
//!   성공 연결은 서버 쓰기 없이 실제 EOF까지 읽어 수신 애플리케이션 바이트 0을 관찰합니다.
//! - 1000ms 임시 입력에서는 거부 응답 전에 TIMED_OUT이 관찰됐습니다. 해당 실패 증거는 보존하며,
//!   이 최종 비교에는 제품의 변경 없는 기본 입력 3000ms를 두 제품 모두에 적용합니다.
//!   이는 DROP 성능 목표의 완화나 TIMED_OUT을 REFUSED로 보정하는 처리가 아닙니다.
//! - 본 시험은 단일 호스트 루프백 관측일 뿐이며, 실 망 패킷 캡처/DROP/ICMP 차단/성능 인증으로 승격하지 않습니다.

#[cfg(windows)]
mod windows_native_equivalence {
    use std::io;
    use std::net::{IpAddr, SocketAddr};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use network_core::TcpMeasurement;
    use network_core::quick::{
        EvidenceLevel, QUICK_PRODUCT_NAME, QUICK_SCHEMA_VERSION, QuickContext, QuickFeature,
        QuickResult, QuickStatus, tcp_to_quick_result,
    };
    use network_core::runner::{
        DEFAULT_MAX_RESULT_BYTES, DnsProbeFuture, NativeProbeBackend, ProbeFuture,
        QuickProbeBackend, QuickRunReport, QuickRunRequest, run_quick,
    };
    use network_core::targets::{DEFAULT_TCP_TIMEOUT_MS, QuickOptions, QuickTarget};
    use network_core::traceroute::TraceOptions;
    use npi_core::FeatureResult;
    use npi_probes::engine::{MEASUREMENT_FORMAT_G2A, run_profile};
    use tokio::net::{TcpListener, TcpSocket, TcpStream};

    /// 시험 전용 QuickProbeBackend 래퍼.
    ///
    /// - `tcp` 호출 시 사전에 지정된 소유 픽스처 대상(target SocketAddr, ctx.target_host,
    ///   ctx.target_port, ctx.session_id, timeout)과 정확히 일치하는지 먼저 검사합니다.
    /// - 일치하지 않으면 `NativeProbeBackend` 위임 없이 즉시 `Err`를 반환합니다.
    /// - 일치하는 경우에만 실제 `NativeProbeBackend::tcp`에 정확히 1회 위임합니다.
    /// - 위임 반환값은 일체 수정하거나 재작성하지 않고 그대로 반환하되, 반환 직전
    ///   JSON 직렬화 바이트를 메모리에 보관하여 최종 보고서 행과의 무손실 일치를 검증합니다.
    /// - `icmp`, `host`, `resolve`, `trace` 등 비인가 메서드 호출 시 별도 카운터를 증가시키고
    ///   즉시 `Err`를 반환하며 네이티브 위임을 수행하지 않습니다.
    struct GuardedNativeQuickBackend {
        expected_target: SocketAddr,
        expected_session_id: String,
        expected_timeout: Duration,
        tcp_calls: AtomicUsize,
        native_delegations: AtomicUsize,
        icmp_calls: AtomicUsize,
        host_calls: AtomicUsize,
        resolve_calls: AtomicUsize,
        trace_calls: AtomicUsize,
        captured_result_bytes: Mutex<Option<Vec<u8>>>,
        inner: NativeProbeBackend,
    }

    impl GuardedNativeQuickBackend {
        fn new(
            expected_target: SocketAddr,
            expected_session_id: String,
            expected_timeout: Duration,
        ) -> Self {
            Self {
                expected_target,
                expected_session_id,
                expected_timeout,
                tcp_calls: AtomicUsize::new(0),
                native_delegations: AtomicUsize::new(0),
                icmp_calls: AtomicUsize::new(0),
                host_calls: AtomicUsize::new(0),
                resolve_calls: AtomicUsize::new(0),
                trace_calls: AtomicUsize::new(0),
                captured_result_bytes: Mutex::new(None),
                inner: NativeProbeBackend,
            }
        }

        fn captured_bytes(&self) -> Option<Vec<u8>> {
            self.captured_result_bytes.lock().unwrap().clone()
        }

        fn tcp_calls(&self) -> usize {
            self.tcp_calls.load(Ordering::SeqCst)
        }

        fn native_delegations(&self) -> usize {
            self.native_delegations.load(Ordering::SeqCst)
        }

        fn other_calls(&self) -> (usize, usize, usize, usize) {
            (
                self.icmp_calls.load(Ordering::SeqCst),
                self.host_calls.load(Ordering::SeqCst),
                self.resolve_calls.load(Ordering::SeqCst),
                self.trace_calls.load(Ordering::SeqCst),
            )
        }
    }

    impl QuickProbeBackend for GuardedNativeQuickBackend {
        fn tcp<'a>(
            &'a self,
            ctx: QuickContext,
            target: SocketAddr,
            timeout: Duration,
            cancel: Arc<AtomicBool>,
        ) -> ProbeFuture<'a> {
            self.tcp_calls.fetch_add(1, Ordering::SeqCst);

            let mut guard_errors = Vec::new();
            if target != self.expected_target {
                guard_errors.push(format!(
                    "대상 SocketAddr 불일치: 기대 '{:?}', 실제 '{:?}'",
                    self.expected_target, target
                ));
            }
            if ctx.target_host != self.expected_target.ip().to_string() {
                guard_errors.push(format!(
                    "ctx.target_host 불일치: 기대 '{}', 실제 '{}'",
                    self.expected_target.ip(),
                    ctx.target_host
                ));
            }
            if ctx.target_port != self.expected_target.port() {
                guard_errors.push(format!(
                    "ctx.target_port 불일치: 기대 {}, 실제 {}",
                    self.expected_target.port(),
                    ctx.target_port
                ));
            }
            if ctx.session_id != self.expected_session_id {
                guard_errors.push(format!(
                    "ctx.session_id 불일치: 기대 '{}', 실제 '{}'",
                    self.expected_session_id, ctx.session_id
                ));
            }
            if timeout != self.expected_timeout {
                guard_errors.push(format!(
                    "timeout 불일치: 기대 {:?}, 실제 {:?}",
                    self.expected_timeout, timeout
                ));
            }

            if !guard_errors.is_empty() {
                return Box::pin(async move { Err(guard_errors) });
            }

            self.native_delegations.fetch_add(1, Ordering::SeqCst);

            Box::pin(async move {
                let res = self.inner.tcp(ctx, target, timeout, cancel).await;
                if let Ok(ref quick_result) = res {
                    let bytes = serde_json::to_vec(quick_result)
                        .expect("실제 native 결과의 반환 직전 직렬화 실패");
                    let mut lock = self.captured_result_bytes.lock().unwrap();
                    *lock = Some(bytes);
                }
                res
            })
        }

        fn icmp<'a>(
            &'a self,
            _ctx: QuickContext,
            _target: IpAddr,
            _timeout: Duration,
            _cancel: Arc<AtomicBool>,
        ) -> ProbeFuture<'a> {
            self.icmp_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                Err(vec![
                    "시험 wrapper 정책 위반: ICMP 프로브 호출 비인가".to_string(),
                ])
            })
        }

        fn host<'a>(
            &'a self,
            _ctx: QuickContext,
            _target: IpAddr,
            _cancel: Arc<AtomicBool>,
        ) -> ProbeFuture<'a> {
            self.host_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                Err(vec![
                    "시험 wrapper 정책 위반: Host 스냅샷 호출 비인가".to_string(),
                ])
            })
        }

        fn resolve<'a>(
            &'a self,
            _ctx: QuickContext,
            _timeout: Duration,
            _cancel: Arc<AtomicBool>,
        ) -> DnsProbeFuture<'a> {
            self.resolve_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                Err(vec![
                    "시험 wrapper 정책 위반: DNS 해석 호출 비인가".to_string(),
                ])
            })
        }

        fn trace<'a>(
            &'a self,
            _ctx: QuickContext,
            _target: IpAddr,
            _options: TraceOptions,
            _cancel: Arc<AtomicBool>,
        ) -> ProbeFuture<'a> {
            self.trace_calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                Err(vec![
                    "시험 wrapper 정책 위반: ICMP Traceroute 호출 비인가".to_string(),
                ])
            })
        }
    }

    /// Inspector 실행 프로필 생성 도우미 (인수 3개 <= 7).
    fn build_inspector_profile(ip_str: &str, port: u16, timeout_ms: u64) -> serde_json::Value {
        serde_json::json!({
            "schema_version": "1.1",
            "profile_id": "tcp-native-equiv-inspector",
            "label": "TCP 네이티브 대조 시험",
            "mode": "standalone",
            "selected_features": ["tcp_connect"],
            "capture_approved": false,
            "target": {
                "host": ip_str,
                "port": port,
                "protocol": "TCP"
            },
            "limits": {
                "tcp_timeout_ms": timeout_ms,
                "max_hops": 30,
                "retries": 0,
                "max_concurrent_tcp": 1,
                "capture_duration_secs": 30,
                "capture_max_bytes": 52428800,
                "log_retention_days": 30,
                "ui_updates_per_second": 4
            }
        })
    }

    /// Quick 진단 실행 요청 DTO 생성 도우미 (인수 4개 <= 7).
    fn build_quick_request(
        session_id: &str,
        ip_str: &str,
        port: u16,
        timeout_ms: u64,
    ) -> QuickRunRequest {
        QuickRunRequest {
            session_id: session_id.to_string(),
            timestamp_iso8601: None,
            source_host: None,
            targets: vec![QuickTarget {
                host: ip_str.to_string(),
                port,
                raw_input: format!("{ip_str}:{port}"),
            }],
            options: QuickOptions {
                tcp_timeout_ms: timeout_ms,
                concurrency: 1,
                selected_features: vec![QuickFeature::TcpConnect],
            },
            max_result_bytes: DEFAULT_MAX_RESULT_BYTES,
        }
    }

    /// `tokio::io::AsyncReadExt` 의존성 없이 `TcpStream.readable()` 및 `try_read`로
    /// 클라이언트 EOF를 비동기 폴링 대기하는 서버 수신 도우미 (인수 2개 <= 7).
    async fn wait_for_stream_eof(
        stream: &mut TcpStream,
        timeout: Duration,
    ) -> Result<usize, String> {
        tokio::time::timeout(timeout, async {
            let mut buf = [0u8; 64];
            let mut total_bytes = 0usize;
            loop {
                stream
                    .readable()
                    .await
                    .map_err(|e| format!("stream.readable 대기 실패: {e}"))?;
                match stream.try_read(&mut buf) {
                    Ok(0) => {
                        return Ok(total_bytes);
                    }
                    Ok(n) => {
                        total_bytes += n;
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(e) => return Err(format!("stream.try_read 실패: {e}")),
                }
            }
        })
        .await
        .map_err(|_| "서버 EOF 관찰 타임아웃 경과".to_string())?
    }

    /// 필수 nullable 키는 누락과 명시적 null을 구별한다. Value의 [] 인덱싱으로 대체하지 않는다.
    fn assert_explicit_nulls(value: &serde_json::Value, keys: &[&str]) {
        for key in keys {
            assert_eq!(
                value.get(*key),
                Some(&serde_json::Value::Null),
                "필수 null 키: {key}"
            );
        }
    }

    /// 실제 원시값의 소유 목적지와 전체 JSON/오류 메시지를 독립 기대값으로 검증한다.
    fn assert_native_raw(
        raw: &TcpMeasurement,
        raw_json: &serde_json::Value,
        ctx: &QuickContext,
        expected_outcome: &str,
        expected_code: Option<i32>,
    ) {
        let ip: IpAddr = ctx
            .target_host
            .parse()
            .expect("시험 대상은 정확한 IP 리터럴");
        assert_eq!(raw.target, SocketAddr::new(ip, ctx.target_port).to_string());
        assert_eq!(raw.outcome, expected_outcome);
        assert_eq!(raw.error_code, expected_code);
        assert_eq!(raw.application_bytes_sent, 0);
        assert_eq!(&serde_json::to_value(raw).unwrap(), raw_json);
        match expected_outcome {
            "CONNECTED" => {
                assert_eq!(raw.error_message, None);
                assert!(raw.local_address.is_some());
                assert_explicit_nulls(raw_json, &["error_code", "error_message"]);
            }
            "REFUSED" => {
                assert!(
                    raw.error_message
                        .as_deref()
                        .is_some_and(|message| !message.is_empty())
                );
                assert_eq!(raw.local_address, None);
                assert_explicit_nulls(raw_json, &["local_address"]);
            }
            _ => panic!("지원하지 않는 시험 outcome: {expected_outcome}"),
        }
    }

    /// native와 같은 실측값 replay를 각각 자기 원문에 대조하며 두 측정 시점끼리는 비교하지 않는다.
    fn assert_quick_projection(
        row: &QuickResult,
        raw: &TcpMeasurement,
        raw_json: &serde_json::Value,
        ctx: &QuickContext,
        expected_outcome: &str,
        expected_code: Option<i32>,
    ) {
        assert_native_raw(raw, raw_json, ctx, expected_outcome, expected_code);
        let status = match expected_outcome {
            "CONNECTED" => QuickStatus::PASS,
            "REFUSED" => QuickStatus::FAIL,
            _ => panic!("지원하지 않는 시험 outcome: {expected_outcome}"),
        };
        assert_eq!(row.schema_version, QUICK_SCHEMA_VERSION);
        assert_eq!(row.product, QUICK_PRODUCT_NAME);
        assert_eq!(row.status, status);
        assert_eq!(row.evidence_level, EvidenceLevel::OBSERVED);
        assert_eq!(row.feature, QuickFeature::TcpConnect);
        assert_eq!(row.session_id, ctx.session_id);
        assert_eq!(row.timestamp_iso8601, ctx.timestamp_iso8601);
        assert_eq!(row.source_host, ctx.source_host);
        assert_eq!(row.target_host, ctx.target_host);
        assert_eq!(row.target_port, ctx.target_port);
        assert_eq!(row.resolved_ip.as_deref(), Some(ctx.target_host.as_str()));
        assert_eq!(row.os_error_code, expected_code);
        assert_eq!(row.elapsed_ms, Some(raw.elapsed_ms));
        assert_eq!(row.details.as_object().expect("details 객체").len(), 3);
        assert_eq!(
            row.details.get("outcome"),
            Some(&serde_json::json!(raw.outcome))
        );
        assert_eq!(
            row.details.get("limitations"),
            Some(&serde_json::json!(raw.limitations))
        );
        assert_eq!(row.details.get("raw_measurement"), Some(raw_json));
        let row_json = serde_json::to_value(row).unwrap();
        assert_explicit_nulls(&row_json, &["timestamp_iso8601", "source_host"]);
        if expected_code.is_none() {
            assert_explicit_nulls(&row_json, &["os_error_code"]);
        }
    }

    /// Inspector 실제 실행 결과와 원시값 replay 검증. 인수 5개이며 측정값은 조립하지 않는다.
    fn verify_inspector_output(
        envelope_val: &serde_json::Value,
        expected_outcome: &str,
        expected_code: Option<i32>,
        quick_ctx: &QuickContext,
        profile: &serde_json::Value,
    ) -> TcpMeasurement {
        let envelope_before = serde_json::to_vec(envelope_val).unwrap();
        assert_eq!(envelope_val.get("target"), profile.get("target"));
        assert_eq!(envelope_val["measurement_format"], MEASUREMENT_FORMAT_G2A);
        assert_eq!(envelope_val["profile_id"], "tcp-native-equiv-inspector");

        assert_eq!(
            envelope_val["collector_counts"]["tcp_connect"], 1,
            "Inspector tcp_connect 수집기 카운트는 정확히 1이어야 합니다"
        );
        assert_eq!(
            envelope_val["collector_counts"]["host_network_snapshot"], 0,
            "Inspector host_network_snapshot 수집기 카운트는 정확히 0이어야 합니다"
        );
        assert_eq!(
            envelope_val["collector_counts"]["icmp_ping"], 0,
            "Inspector icmp_ping 수집기 카운트는 정확히 0이어야 합니다"
        );

        let meas_obj = envelope_val["measurements"]
            .as_object()
            .expect("measurements는 객체여야 합니다");
        assert_eq!(
            meas_obj.len(),
            1,
            "measurements 객체에는 tcp_connect 키 하나만 있어야 합니다"
        );
        assert!(
            meas_obj.contains_key("tcp_connect"),
            "measurements 객체에 'tcp_connect' 키가 있어야 합니다"
        );

        let raw_val = meas_obj.get("tcp_connect").unwrap();
        let raw: TcpMeasurement = serde_json::from_value(raw_val.clone())
            .expect("measurements.tcp_connect는 유효한 TcpMeasurement여야 합니다");
        let raw_json_before = serde_json::to_vec(raw_val).unwrap();
        let raw_typed_before = serde_json::to_vec(&raw).unwrap();
        assert_native_raw(&raw, raw_val, quick_ctx, expected_outcome, expected_code);

        // JSON 객체 키 순서는 값의 일부가 아니다. 필드·배열·null 전체는 그대로 대조한다.
        assert_eq!(
            &serde_json::to_value(&raw).expect("raw 재직렬화"),
            raw_val,
            "raw_measurement serde roundtrip JSON 값이 완전 일치해야 합니다"
        );

        assert_eq!(raw.outcome, expected_outcome);
        assert_eq!(raw.error_code, expected_code);
        assert_eq!(raw.application_bytes_sent, 0);

        let rows = envelope_val["feature_results"]
            .as_array()
            .expect("feature_results는 배열이어야 합니다");
        assert_eq!(
            rows.len(),
            23,
            "Inspector feature_results는 23개 행이어야 합니다"
        );

        let mut tcp_row_opt = None;
        for row_val in rows {
            let fid = row_val["feature_id"]
                .as_str()
                .expect("feature_id는 문자열이어야 합니다");
            if fid == "tcp_connect" {
                tcp_row_opt = Some(row_val);
            } else {
                assert_explicit_nulls(
                    row_val,
                    &[
                        "classification",
                        "duration_ms",
                        "error_code",
                        "started_at_utc",
                        "ended_at_utc",
                    ],
                );
                assert_eq!(
                    row_val["status"], "SKIPPED_BY_USER",
                    "미선택 기능 행('{fid}')의 status는 SKIPPED_BY_USER여야 합니다"
                );
                assert!(
                    row_val["classification"].is_null(),
                    "SKIPPED_BY_USER 행의 classification은 null이어야 합니다"
                );
                assert!(
                    row_val["duration_ms"].is_null(),
                    "SKIPPED_BY_USER 행의 duration_ms는 null이어야 합니다"
                );
                assert!(
                    row_val["error_code"].is_null(),
                    "SKIPPED_BY_USER 행의 error_code는 null이어야 합니다"
                );
                assert_eq!(
                    row_val["evidence_ids"],
                    serde_json::json!([]),
                    "SKIPPED_BY_USER 행의 evidence_ids는 빈 배열이어야 합니다"
                );
            }
        }

        let tcp_row_val = tcp_row_opt.expect("feature_results에 tcp_connect 행이 존재해야 합니다");
        assert_explicit_nulls(tcp_row_val, &["started_at_utc", "ended_at_utc"]);
        if expected_code.is_none() {
            assert_explicit_nulls(tcp_row_val, &["error_code"]);
        }
        let tcp_row: FeatureResult =
            serde_json::from_value(tcp_row_val.clone()).expect("tcp_connect 행 역직렬화 실패");

        assert_eq!(tcp_row.feature_id, "tcp_connect");
        assert_eq!(tcp_row.group_id, "G-NET");
        assert_eq!(
            tcp_row.duration_ms,
            Some(raw.elapsed_ms),
            "Inspector 행 duration_ms는 raw.elapsed_ms와 일치해야 합니다"
        );
        assert_eq!(
            tcp_row.error_code,
            raw.error_code.map(i64::from),
            "Inspector 행 error_code는 raw.error_code와 일치해야 합니다"
        );
        assert!(
            tcp_row.evidence_ids.is_empty(),
            "메모리 단일 측정 결과의 evidence_ids는 빈 배열이어야 합니다"
        );
        assert_eq!(
            tcp_row.started_at_utc, None,
            "가짜 실측 UTC를 만들지 않으므로 started_at_utc는 None이어야 합니다"
        );
        assert_eq!(
            tcp_row.ended_at_utc, None,
            "가짜 실측 UTC를 만들지 않으므로 ended_at_utc는 None이어야 합니다"
        );
        assert!(
            tcp_row.limitations.starts_with(&raw.limitations),
            "Inspector 행 limitations는 raw.limitations로 시작해야 합니다"
        );
        if let Some(ref msg) = raw.error_message {
            assert!(
                tcp_row
                    .limitations
                    .contains(&format!("OS 소켓 오류 메시지: {msg}")),
                "Inspector 행 limitations에 OS 소켓 오류 메시지가 포함되어야 합니다"
            );
        }
        assert!(
            !tcp_row.next_checks.is_empty(),
            "Inspector 행 next_checks는 비어있지 않아야 합니다"
        );

        let (exp_status, exp_classification) = match expected_outcome {
            "CONNECTED" => ("PASS", "OBSERVED"),
            "REFUSED" => ("FAIL", "OBSERVED"),
            _ => panic!("지원하지 않는 시험 outcome: {expected_outcome}"),
        };
        assert_eq!(tcp_row.status, exp_status);
        assert_eq!(tcp_row.classification.as_deref(), Some(exp_classification));

        let replay_quick = tcp_to_quick_result(quick_ctx, &raw)
            .expect("동일 raw에 대한 tcp_to_quick_result 호출 성공");
        assert_eq!(
            replay_quick.elapsed_ms,
            Some(raw.elapsed_ms),
            "replay 결과 elapsed_ms 무손실 일치"
        );
        assert_eq!(
            replay_quick.os_error_code, raw.error_code,
            "replay 결과 os_error_code 무손실 일치"
        );
        assert_eq!(
            replay_quick.details["outcome"],
            serde_json::json!(raw.outcome)
        );
        assert_eq!(&replay_quick.details["raw_measurement"], raw_val);
        assert_quick_projection(
            &replay_quick,
            &raw,
            raw_val,
            quick_ctx,
            expected_outcome,
            expected_code,
        );
        // 각 표현의 자기 전후 bytes만 비교한다. struct와 Value의 서로 다른 키 순서는 비교하지 않는다.
        assert_eq!(serde_json::to_vec(&raw).unwrap(), raw_typed_before);
        assert_eq!(serde_json::to_vec(raw_val).unwrap(), raw_json_before);
        assert_eq!(serde_json::to_vec(envelope_val).unwrap(), envelope_before);

        raw
    }

    /// Quick 실제 실행 결과 보고서 및 자기 raw 독립 검증 (인수 5개 <= 7).
    fn verify_quick_report(
        report: &QuickRunReport,
        wrapper: &GuardedNativeQuickBackend,
        expected_outcome: &str,
        expected_code: Option<i32>,
        expected_ctx: &QuickContext,
    ) -> TcpMeasurement {
        let report_before = serde_json::to_vec(report).unwrap();
        assert_eq!(
            report.results.len(),
            1,
            "Quick 보고서 results는 정확히 1행이어야 합니다"
        );
        assert!(!report.cancelled, "cancelled는 false여야 합니다");
        assert!(!report.limit_reached, "limit_reached는 false여야 합니다");
        assert_eq!(
            report.omitted_results, 0,
            "omitted_results는 0이어야 합니다"
        );
        assert!(
            report.errors.is_empty(),
            "errors는 비어있어야 합니다: {:?}",
            report.errors
        );
        assert_eq!(report.targets_started, 1);
        assert_eq!(report.targets_completed, 1);

        assert_eq!(
            report.invocations.tcp_connect, 1,
            "Quick invocations tcp_connect는 정확히 1이어야 합니다"
        );
        assert_eq!(report.invocations.icmp_ping, 0);
        assert_eq!(report.invocations.local_network, 0);
        assert_eq!(report.invocations.dns_lookup, 0);
        assert_eq!(report.invocations.icmp_traceroute, 0);

        assert_eq!(wrapper.tcp_calls(), 1);
        assert_eq!(wrapper.native_delegations(), 1);
        assert_eq!(wrapper.other_calls(), (0, 0, 0, 0));

        let result_row = &report.results[0];
        let row_bytes = serde_json::to_vec(result_row).expect("QuickResult 직렬화");
        assert_eq!(
            report.serialized_result_bytes,
            row_bytes.len(),
            "serialized_result_bytes는 결과 행의 직렬화 바이트 크기와 일치해야 합니다"
        );

        let captured = wrapper
            .captured_bytes()
            .expect("wrapper에 반환 직전 바이트가 보관되어 있어야 합니다");
        assert_eq!(
            captured, row_bytes,
            "wrapper에서 반환 직전 캡처한 바이트가 최종 Quick 보고서 행과 정확히 일치해야 합니다"
        );

        assert_eq!(result_row.schema_version, QUICK_SCHEMA_VERSION);
        assert_eq!(result_row.product, QUICK_PRODUCT_NAME);
        assert_eq!(result_row.session_id, expected_ctx.session_id);
        assert_eq!(result_row.timestamp_iso8601, None);
        assert_eq!(result_row.feature, QuickFeature::TcpConnect);

        let (exp_status, exp_evidence) = match expected_outcome {
            "CONNECTED" => (QuickStatus::PASS, EvidenceLevel::OBSERVED),
            "REFUSED" => (QuickStatus::FAIL, EvidenceLevel::OBSERVED),
            _ => panic!("지원하지 않는 outcome: {expected_outcome}"),
        };
        assert_eq!(result_row.status, exp_status);
        assert_eq!(result_row.evidence_level, exp_evidence);
        assert_eq!(result_row.os_error_code, expected_code);

        let raw_val = &result_row.details["raw_measurement"];
        let quick_raw: TcpMeasurement = serde_json::from_value(raw_val.clone())
            .expect("Quick details.raw_measurement 역직렬화 실패");

        assert_eq!(quick_raw.outcome, expected_outcome);
        assert_eq!(quick_raw.error_code, expected_code);
        assert_eq!(quick_raw.application_bytes_sent, 0);
        assert_eq!(result_row.elapsed_ms, Some(quick_raw.elapsed_ms));

        assert_quick_projection(
            result_row,
            &quick_raw,
            raw_val,
            expected_ctx,
            expected_outcome,
            expected_code,
        );
        assert_eq!(serde_json::to_vec(report).unwrap(), report_before);
        quick_raw
    }

    /// 1. IPv4 실제 소유 루프백 연결 대조 시험 (`127.0.0.1`).
    #[tokio::test]
    #[ignore = "소유 루프백 실제 시험: 부모 명시 실행"]
    async fn native_ipv4_connected() {
        let ip_str = "127.0.0.1";
        let ip: IpAddr = ip_str.parse().unwrap();

        let listener = TcpListener::bind(SocketAddr::new(ip, 0))
            .await
            .expect("IPv4 소유 루프백 listener bind 실패");
        let port = listener.local_addr().expect("local_addr 실패").port();
        assert_ne!(port, 0, "OS 할당 포트는 0이 아니어야 합니다");

        let target_sock = SocketAddr::new(ip, port);
        // 제품의 기존 3000ms 기본 입력을 그대로 사용한다. 판정·성능 기준 변경이 아니다.
        let timeout_ms = DEFAULT_TCP_TIMEOUT_MS;

        let inspector_profile = build_inspector_profile(ip_str, port, timeout_ms);
        let inspector_cancelled = Arc::new(AtomicBool::new(false));

        let quick_session_id = "native-ipv4-connected-session".to_string();
        let quick_request = build_quick_request(&quick_session_id, ip_str, port, timeout_ms);
        let quick_cancel = Arc::new(AtomicBool::new(false));

        let wrapper = Arc::new(GuardedNativeQuickBackend::new(
            target_sock,
            quick_session_id.clone(),
            Duration::from_millis(timeout_ms),
        ));

        let quick_ctx = QuickContext {
            session_id: quick_session_id.clone(),
            timestamp_iso8601: None,
            source_host: None,
            target_host: ip_str.to_string(),
            target_port: port,
        };

        // Stage 1: Inspector 실행 및 서버 accept/EOF 관찰
        let server_stage1 = async {
            let (mut stream, peer_addr) =
                tokio::time::timeout(Duration::from_secs(3), listener.accept())
                    .await
                    .expect("Inspector accept 타임아웃 경과")
                    .expect("Inspector accept 실패");
            let bytes_read = wait_for_stream_eof(&mut stream, Duration::from_secs(3))
                .await
                .expect("Inspector stream EOF 대기 실패");
            (peer_addr, bytes_read)
        };
        let inspector_stage = async {
            run_profile(&inspector_profile, inspector_cancelled)
                .await
                .expect("Inspector run_profile 실행 실패")
        };

        let ((peer1, bytes1), inspector_envelope) =
            tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(server_stage1, inspector_stage)
            })
            .await
            .expect("전체 Inspector 스테이지 시간 초과");

        assert_eq!(
            bytes1, 0,
            "서버는 클라이언트로부터 애플리케이션 바이트 0을 관찰해야 합니다"
        );
        let inspector_raw = verify_inspector_output(
            &inspector_envelope,
            "CONNECTED",
            None,
            &quick_ctx,
            &inspector_profile,
        );
        assert_eq!(
            inspector_raw.local_address,
            Some(peer1.to_string()),
            "Inspector raw local_address는 서버가 관찰한 accept peer_addr와 정확히 일치해야 합니다"
        );

        // Stage 2: Quick 실행 및 서버 accept/EOF 관찰
        let server_stage2 = async {
            let (mut stream, peer_addr) =
                tokio::time::timeout(Duration::from_secs(3), listener.accept())
                    .await
                    .expect("Quick accept 타임아웃 경과")
                    .expect("Quick accept 실패");
            let bytes_read = wait_for_stream_eof(&mut stream, Duration::from_secs(3))
                .await
                .expect("Quick stream EOF 대기 실패");
            (peer_addr, bytes_read)
        };
        let quick_stage = async {
            run_quick(&quick_request, wrapper.clone(), quick_cancel)
                .await
                .expect("Quick run_quick 실행 실패")
        };

        let ((peer2, bytes2), quick_report) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(server_stage2, quick_stage)
        })
        .await
        .expect("전체 Quick 스테이지 시간 초과");

        assert_eq!(
            bytes2, 0,
            "서버는 클라이언트로부터 애플리케이션 바이트 0을 관찰해야 합니다"
        );
        let quick_raw = verify_quick_report(&quick_report, &wrapper, "CONNECTED", None, &quick_ctx);
        assert_eq!(
            quick_raw.local_address,
            Some(peer2.to_string()),
            "Quick raw local_address는 서버가 관찰한 accept peer_addr와 정확히 일치해야 합니다"
        );

        assert_eq!(inspector_raw.outcome, "CONNECTED");
        assert_eq!(quick_raw.outcome, "CONNECTED");
        drop(listener);
    }

    /// 2. IPv4 실제 소유 루프백 거부 대조 시험 (`127.0.0.1` bound/nonlisten).
    #[tokio::test]
    #[ignore = "소유 루프백 실제 시험: 부모 명시 실행"]
    async fn native_ipv4_refused() {
        let ip_str = "127.0.0.1";
        let ip: IpAddr = ip_str.parse().unwrap();

        let socket = TcpSocket::new_v4().expect("IPv4 TcpSocket 생성 실패");
        socket
            .bind(SocketAddr::new(ip, 0))
            .expect("IPv4 소켓 bind 실패");
        let port = socket.local_addr().expect("local_addr 실패").port();
        assert_ne!(port, 0, "OS 할당 포트는 0이 아니어야 합니다");

        let target_sock = SocketAddr::new(ip, port);
        // 제품의 기존 3000ms 기본 입력을 그대로 사용한다. 판정·성능 기준 변경이 아니다.
        let timeout_ms = DEFAULT_TCP_TIMEOUT_MS;

        let inspector_profile = build_inspector_profile(ip_str, port, timeout_ms);
        let inspector_cancelled = Arc::new(AtomicBool::new(false));

        let quick_session_id = "native-ipv4-refused-session".to_string();
        let quick_request = build_quick_request(&quick_session_id, ip_str, port, timeout_ms);
        let quick_cancel = Arc::new(AtomicBool::new(false));

        let wrapper = Arc::new(GuardedNativeQuickBackend::new(
            target_sock,
            quick_session_id.clone(),
            Duration::from_millis(timeout_ms),
        ));

        let quick_ctx = QuickContext {
            session_id: quick_session_id.clone(),
            timestamp_iso8601: None,
            source_host: None,
            target_host: ip_str.to_string(),
            target_port: port,
        };

        // Stage 1: Inspector 순차 실행
        let inspector_envelope = tokio::time::timeout(
            Duration::from_secs(5),
            run_profile(&inspector_profile, inspector_cancelled),
        )
        .await
        .expect("Inspector 실행 시간 초과")
        .expect("Inspector run_profile 실행 실패");

        let inspector_raw = verify_inspector_output(
            &inspector_envelope,
            "REFUSED",
            Some(10061),
            &quick_ctx,
            &inspector_profile,
        );
        assert_eq!(inspector_raw.local_address, None);
        assert_eq!(inspector_raw.application_bytes_sent, 0);

        // Stage 2: Quick 순차 실행 (socket 소유 유지 상태에서 실행)
        let quick_report = tokio::time::timeout(
            Duration::from_secs(5),
            run_quick(&quick_request, wrapper.clone(), quick_cancel),
        )
        .await
        .expect("Quick 실행 시간 초과")
        .expect("Quick run_quick 실행 실패");

        let quick_raw =
            verify_quick_report(&quick_report, &wrapper, "REFUSED", Some(10061), &quick_ctx);
        assert_eq!(quick_raw.local_address, None);
        assert_eq!(quick_raw.application_bytes_sent, 0);

        assert_eq!(inspector_raw.outcome, "REFUSED");
        assert_eq!(quick_raw.outcome, "REFUSED");
        assert_eq!(inspector_raw.error_code, Some(10061));
        assert_eq!(quick_raw.error_code, Some(10061));

        drop(socket);
    }

    /// 3. IPv6 실제 소유 루프백 연결 대조 시험 (`::1`).
    #[tokio::test]
    #[ignore = "소유 루프백 실제 시험: 부모 명시 실행"]
    async fn native_ipv6_connected() {
        let ip_str = "::1";
        let ip: IpAddr = ip_str.parse().unwrap();

        let listener = TcpListener::bind(SocketAddr::new(ip, 0))
            .await
            .expect("IPv6 소유 루프백 listener bind 실패");
        let port = listener.local_addr().expect("local_addr 실패").port();
        assert_ne!(port, 0, "OS 할당 포트는 0이 아니어야 합니다");

        let target_sock = SocketAddr::new(ip, port);
        // 제품의 기존 3000ms 기본 입력을 그대로 사용한다. 판정·성능 기준 변경이 아니다.
        let timeout_ms = DEFAULT_TCP_TIMEOUT_MS;

        let inspector_profile = build_inspector_profile(ip_str, port, timeout_ms);
        let inspector_cancelled = Arc::new(AtomicBool::new(false));

        let quick_session_id = "native-ipv6-connected-session".to_string();
        let quick_request = build_quick_request(&quick_session_id, ip_str, port, timeout_ms);
        let quick_cancel = Arc::new(AtomicBool::new(false));

        let wrapper = Arc::new(GuardedNativeQuickBackend::new(
            target_sock,
            quick_session_id.clone(),
            Duration::from_millis(timeout_ms),
        ));

        let quick_ctx = QuickContext {
            session_id: quick_session_id.clone(),
            timestamp_iso8601: None,
            source_host: None,
            target_host: ip_str.to_string(),
            target_port: port,
        };

        // Stage 1: Inspector 실행 및 서버 accept/EOF 관찰
        let server_stage1 = async {
            let (mut stream, peer_addr) =
                tokio::time::timeout(Duration::from_secs(3), listener.accept())
                    .await
                    .expect("Inspector accept 타임아웃 경과")
                    .expect("Inspector accept 실패");
            let bytes_read = wait_for_stream_eof(&mut stream, Duration::from_secs(3))
                .await
                .expect("Inspector stream EOF 대기 실패");
            (peer_addr, bytes_read)
        };
        let inspector_stage = async {
            run_profile(&inspector_profile, inspector_cancelled)
                .await
                .expect("Inspector run_profile 실행 실패")
        };

        let ((peer1, bytes1), inspector_envelope) =
            tokio::time::timeout(Duration::from_secs(5), async {
                tokio::join!(server_stage1, inspector_stage)
            })
            .await
            .expect("전체 Inspector 스테이지 시간 초과");

        assert_eq!(
            bytes1, 0,
            "서버는 클라이언트로부터 애플리케이션 바이트 0을 관찰해야 합니다"
        );
        let inspector_raw = verify_inspector_output(
            &inspector_envelope,
            "CONNECTED",
            None,
            &quick_ctx,
            &inspector_profile,
        );
        assert_eq!(
            inspector_raw.local_address,
            Some(peer1.to_string()),
            "Inspector raw local_address는 서버가 관찰한 accept peer_addr와 정확히 일치해야 합니다"
        );

        // Stage 2: Quick 실행 및 서버 accept/EOF 관찰
        let server_stage2 = async {
            let (mut stream, peer_addr) =
                tokio::time::timeout(Duration::from_secs(3), listener.accept())
                    .await
                    .expect("Quick accept 타임아웃 경과")
                    .expect("Quick accept 실패");
            let bytes_read = wait_for_stream_eof(&mut stream, Duration::from_secs(3))
                .await
                .expect("Quick stream EOF 대기 실패");
            (peer_addr, bytes_read)
        };
        let quick_stage = async {
            run_quick(&quick_request, wrapper.clone(), quick_cancel)
                .await
                .expect("Quick run_quick 실행 실패")
        };

        let ((peer2, bytes2), quick_report) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(server_stage2, quick_stage)
        })
        .await
        .expect("전체 Quick 스테이지 시간 초과");

        assert_eq!(
            bytes2, 0,
            "서버는 클라이언트로부터 애플리케이션 바이트 0을 관찰해야 합니다"
        );
        let quick_raw = verify_quick_report(&quick_report, &wrapper, "CONNECTED", None, &quick_ctx);
        assert_eq!(
            quick_raw.local_address,
            Some(peer2.to_string()),
            "Quick raw local_address는 서버가 관찰한 accept peer_addr와 정확히 일치해야 합니다"
        );

        assert_eq!(inspector_raw.outcome, "CONNECTED");
        assert_eq!(quick_raw.outcome, "CONNECTED");
        drop(listener);
    }

    /// 4. IPv6 실제 소유 루프백 거부 대조 시험 (`::1` bound/nonlisten).
    #[tokio::test]
    #[ignore = "소유 루프백 실제 시험: 부모 명시 실행"]
    async fn native_ipv6_refused() {
        let ip_str = "::1";
        let ip: IpAddr = ip_str.parse().unwrap();

        let socket = TcpSocket::new_v6().expect("IPv6 TcpSocket 생성 실패");
        socket
            .bind(SocketAddr::new(ip, 0))
            .expect("IPv6 소켓 bind 실패");
        let port = socket.local_addr().expect("local_addr 실패").port();
        assert_ne!(port, 0, "OS 할당 포트는 0이 아니어야 합니다");

        let target_sock = SocketAddr::new(ip, port);
        // 제품의 기존 3000ms 기본 입력을 그대로 사용한다. 판정·성능 기준 변경이 아니다.
        let timeout_ms = DEFAULT_TCP_TIMEOUT_MS;

        let inspector_profile = build_inspector_profile(ip_str, port, timeout_ms);
        let inspector_cancelled = Arc::new(AtomicBool::new(false));

        let quick_session_id = "native-ipv6-refused-session".to_string();
        let quick_request = build_quick_request(&quick_session_id, ip_str, port, timeout_ms);
        let quick_cancel = Arc::new(AtomicBool::new(false));

        let wrapper = Arc::new(GuardedNativeQuickBackend::new(
            target_sock,
            quick_session_id.clone(),
            Duration::from_millis(timeout_ms),
        ));

        let quick_ctx = QuickContext {
            session_id: quick_session_id.clone(),
            timestamp_iso8601: None,
            source_host: None,
            target_host: ip_str.to_string(),
            target_port: port,
        };

        // Stage 1: Inspector 순차 실행
        let inspector_envelope = tokio::time::timeout(
            Duration::from_secs(5),
            run_profile(&inspector_profile, inspector_cancelled),
        )
        .await
        .expect("Inspector 실행 시간 초과")
        .expect("Inspector run_profile 실행 실패");

        let inspector_raw = verify_inspector_output(
            &inspector_envelope,
            "REFUSED",
            Some(10061),
            &quick_ctx,
            &inspector_profile,
        );
        assert_eq!(inspector_raw.local_address, None);
        assert_eq!(inspector_raw.application_bytes_sent, 0);

        // Stage 2: Quick 순차 실행 (socket 소유 유지 상태에서 실행)
        let quick_report = tokio::time::timeout(
            Duration::from_secs(5),
            run_quick(&quick_request, wrapper.clone(), quick_cancel),
        )
        .await
        .expect("Quick 실행 시간 초과")
        .expect("Quick run_quick 실행 실패");

        let quick_raw =
            verify_quick_report(&quick_report, &wrapper, "REFUSED", Some(10061), &quick_ctx);
        assert_eq!(quick_raw.local_address, None);
        assert_eq!(quick_raw.application_bytes_sent, 0);

        assert_eq!(inspector_raw.outcome, "REFUSED");
        assert_eq!(quick_raw.outcome, "REFUSED");
        assert_eq!(inspector_raw.error_code, Some(10061));
        assert_eq!(quick_raw.error_code, Some(10061));

        drop(socket);
    }

    /// 5. 순수 단위 시험: 부정 입력에 대해 Native 위임 전에 즉각 거부함을 확인 (runtime/socket 0).
    #[test]
    fn wrapper_guards_reject_invalid_inputs_before_native_delegation() {
        let synthetic_target: SocketAddr = "127.0.0.1:49999".parse().unwrap();
        let session_id = "test-guard-session".to_string();
        let timeout = Duration::from_millis(1000);

        let wrapper = GuardedNativeQuickBackend::new(synthetic_target, session_id.clone(), timeout);

        let noop_waker = std::task::Waker::noop();
        let mut cx = std::task::Context::from_waker(noop_waker);
        let cancel = Arc::new(AtomicBool::new(false));

        // 1) 대상 IP 불일치
        {
            let wrong_target: SocketAddr = "127.0.0.2:49999".parse().unwrap();
            let ctx = QuickContext {
                session_id: session_id.clone(),
                timestamp_iso8601: None,
                source_host: None,
                target_host: "127.0.0.1".to_string(),
                target_port: 49999,
            };
            let mut fut = wrapper.tcp(ctx, wrong_target, timeout, cancel.clone());
            match Pin::new(&mut fut).poll(&mut cx) {
                std::task::Poll::Ready(Err(errs)) => {
                    assert!(errs.iter().any(|e| e.contains("SocketAddr 불일치")));
                }
                other => panic!("잘못된 IP에 대해 즉시 Err가 반환되어야 합니다: {:?}", other),
            }
        }

        // 2) 대상 포트 불일치
        {
            let wrong_target: SocketAddr = "127.0.0.1:50000".parse().unwrap();
            let ctx = QuickContext {
                session_id: session_id.clone(),
                timestamp_iso8601: None,
                source_host: None,
                target_host: "127.0.0.1".to_string(),
                target_port: 49999,
            };
            let mut fut = wrapper.tcp(ctx, wrong_target, timeout, cancel.clone());
            match Pin::new(&mut fut).poll(&mut cx) {
                std::task::Poll::Ready(Err(errs)) => {
                    assert!(errs.iter().any(|e| e.contains("SocketAddr 불일치")));
                }
                other => panic!(
                    "잘못된 포트에 대해 즉시 Err가 반환되어야 합니다: {:?}",
                    other
                ),
            }
        }

        // 3) ctx.target_host 불일치
        {
            let ctx = QuickContext {
                session_id: session_id.clone(),
                timestamp_iso8601: None,
                source_host: None,
                target_host: "127.0.0.3".to_string(),
                target_port: 49999,
            };
            let mut fut = wrapper.tcp(ctx, synthetic_target, timeout, cancel.clone());
            match Pin::new(&mut fut).poll(&mut cx) {
                std::task::Poll::Ready(Err(errs)) => {
                    assert!(errs.iter().any(|e| e.contains("ctx.target_host 불일치")));
                }
                other => panic!(
                    "잘못된 ctx.target_host에 대해 즉시 Err가 반환되어야 합니다: {:?}",
                    other
                ),
            }
        }

        // 4) ctx.target_port 불일치
        {
            let ctx = QuickContext {
                session_id: session_id.clone(),
                timestamp_iso8601: None,
                source_host: None,
                target_host: "127.0.0.1".to_string(),
                target_port: 48888,
            };
            let mut fut = wrapper.tcp(ctx, synthetic_target, timeout, cancel.clone());
            match Pin::new(&mut fut).poll(&mut cx) {
                std::task::Poll::Ready(Err(errs)) => {
                    assert!(errs.iter().any(|e| e.contains("ctx.target_port 불일치")));
                }
                other => panic!(
                    "잘못된 ctx.target_port에 대해 즉시 Err가 반환되어야 합니다: {:?}",
                    other
                ),
            }
        }

        // 5) timeout 불일치
        {
            let wrong_timeout = Duration::from_millis(2000);
            let ctx = QuickContext {
                session_id: session_id.clone(),
                timestamp_iso8601: None,
                source_host: None,
                target_host: "127.0.0.1".to_string(),
                target_port: 49999,
            };
            let mut fut = wrapper.tcp(ctx, synthetic_target, wrong_timeout, cancel.clone());
            match Pin::new(&mut fut).poll(&mut cx) {
                std::task::Poll::Ready(Err(errs)) => {
                    assert!(errs.iter().any(|e| e.contains("timeout 불일치")));
                }
                other => panic!(
                    "잘못된 timeout에 대해 즉시 Err가 반환되어야 합니다: {:?}",
                    other
                ),
            }
        }

        // 6) session_id 불일치
        {
            let ctx = QuickContext {
                session_id: "wrong-session".to_string(),
                timestamp_iso8601: None,
                source_host: None,
                target_host: "127.0.0.1".to_string(),
                target_port: 49999,
            };
            let mut fut = wrapper.tcp(ctx, synthetic_target, timeout, cancel.clone());
            match Pin::new(&mut fut).poll(&mut cx) {
                std::task::Poll::Ready(Err(errs)) => {
                    assert!(errs.iter().any(|e| e.contains("ctx.session_id 불일치")));
                }
                other => panic!(
                    "잘못된 session_id에 대해 즉시 Err가 반환되어야 합니다: {:?}",
                    other
                ),
            }
        }

        // Native 위임 카운터가 반드시 정확히 0이어야 함
        assert_eq!(
            wrapper.native_delegations(),
            0,
            "부정 입력 가드에 걸려 NativeProbeBackend 위임 카운터는 정확히 0이어야 합니다"
        );
        assert_eq!(wrapper.tcp_calls(), 6);
        assert_eq!(wrapper.other_calls(), (0, 0, 0, 0));
    }
}
