//! Network Quick Check(Part B) 순수 Rust 비동기 진단 실행기 모듈.
//!
//! ## 설계 및 안전 원칙
//! - **실제 측정 엔진 재사용**: 본 모듈은 TCP/ICMP/호스트 스냅샷 등 네트워크 측정 로직을
//!   직접 구현하거나 복제하지 않으며, 검증된 `NativeProbeBackend`를 통해 기존 `network_core`의
//!   `connect_once`, `ping_once`, `collect_host_snapshot` 및 어댑터를 재사용합니다.
//! - **비파괴·읽기 전용**: 시스템 정책, 방화벽, 레지스트리, 라우팅 테이블 변경을 절대 수행하지 않습니다.
//! - **측정 사실·추론·미확인의 엄격한 분리**: 패킷 캡처(PCAP) 근거 없는 SYN/RST 관찰 주장이나
//!   응답 없는 HOP을 차단 장비로 단정하지 않으며, 미확인 nullable 필드는 명시적 `None`(`null`)으로 유지합니다.
//! - **결과 위장 금지**: `CANCELLED`, `UNAVAILABLE`, `LOCAL_ERROR` 등 실패/미지원 상태를
//!   `PASS`나 `SKIPPED`로 위장하지 않으며 원본 오류 분류를 정확히 보존합니다.
//! - **메모리 예산 엄격 준수**: 보관 결과의 JSON 직렬화 바이트(`serialized_result_bytes`)를
//!   기준으로 예산을 관리하며, 예산 초과 시 즉각 추가 저장을 중단하고 명시적인 한도 도달(`limit_reached = true`)과
//!   누락 건수(`omitted_results`)를 집계합니다.
//!
//! ## 알려진 한계 및 취소 계약
//! - **도메인 주소 해석 미지원**: 이번 마일스톤(QG2)에서는 도메인 주소 해석(DNS Resolver)이
//!   구현되어 있지 않으므로, 주소 해석이 필요한 대상은 모든 프로브 시작 전에 명확한 `Err`로 실행을 차단합니다.
//! - **ICMP 동기 호출 한계**: Windows IP Helper ICMP API(`ping_once`)는 블로킹 시스템 호출이므로,
//!   `tokio::task::spawn_blocking`을 통해 비동기 런타임 차단을 방지하되 호출 중인 작업은 OS 타임아웃(최대 2000ms)
//!   경과 후 취소가 감지됩니다 (즉각적인 하드 킬을 보장하지 않습니다).
//! - **백엔드 취소 계약**: 사용자 정의 `QuickProbeBackend` 구현체가 취소 원자 플래그를 무시하는 경우,
//!   비동기 실행기는 퓨처를 안전하게 중단(drop)하거나 drain하지만 임의의 OS 스레드를 강제 종료할 수 없습니다.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::measurements::{host_to_quick_result, icmp_to_quick_result};
use crate::quick::{
    EvidenceLevel, QUICK_PRODUCT_NAME, QUICK_SCHEMA_VERSION, QuickContext, QuickFeature,
    QuickResult, QuickStatus, tcp_to_quick_result, validate_quick_result,
    validate_rfc3339_timestamp,
};
use crate::targets::{QuickOptions, QuickPlan, QuickTarget, build_quick_plan};

/// 최소 허용 결과 직렬화 바이트 한도 (4KB = 4,096 바이트).
pub const MIN_RESULT_BYTES: usize = 4096;

/// 기본 최대 결과 직렬화 바이트 한도 (16MB = 16,777,216 바이트).
pub const DEFAULT_MAX_RESULT_BYTES: usize = 16777216;

/// 최대 허용 결과 직렬화 바이트 한도 (16MB = 16,777,216 바이트).
pub const MAX_RESULT_BYTES: usize = 16777216;

/// 단일 진단 세션에서 허용되는 최대 검사 대상 수 (100개).
pub const MAX_TARGETS: usize = 100;

/// 최대 허용 동시 검사 대상 작업 수 (4).
pub const MAX_CONCURRENT_TARGETS: usize = 4;

/// 단일 진단 세션에서 생성 가능한 최대 결과 행 수 (100 대상 * 5 기능 = 500개).
pub const MAX_ROWS: usize = 500;

/// Network Quick Check 진단 실행 요청 DTO.
// 요청은 내부 Rust 타입이며 아직 JSON wire DTO 계약이 아니다.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuickRunRequest {
    /// 고유 세션 식별자 (비어있을 수 없음).
    pub session_id: String,
    /// ISO8601 (RFC3339) 형식의 요청 생성 일시.
    pub timestamp_iso8601: Option<String>,
    /// 진단을 요청한 출발지 호스트명 또는 IP.
    pub source_host: Option<String>,
    /// 검사 대상 목록 (최대 100개).
    pub targets: Vec<QuickTarget>,
    /// 진단 옵션 (타임아웃, 동시성, 선택된 기능).
    pub options: QuickOptions,
    /// 직렬화된 진단 결과의 최대 보관 바이트 한도 (4096..=16777216).
    pub max_result_bytes: usize,
}

/// 프로브 기능별 실제 백엔드 호출 횟수 집계 DTO.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ProbeCounts {
    /// 실제 TCP 연결 시도 호출 횟수.
    pub tcp_connect: usize,
    /// 실제 ICMP Ping 시도 호출 횟수.
    pub icmp_ping: usize,
    /// 실제 로컬 호스트 네트워크 스냅샷 수집 호출 횟수.
    pub local_network: usize,
    /// 실제 DNS 질의 시도 호출 횟수 (현재 slice 미지원: 항상 0).
    pub dns_lookup: usize,
    /// 실제 ICMP Traceroute 시도 호출 횟수 (현재 slice 미지원: 항상 0).
    pub icmp_traceroute: usize,
}

/// Network Quick Check 진단 실행 최종 보고서 DTO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuickRunReport {
    /// 보관된 진단 결과 목록 (입력 대상 순서 및 기능 순서로 안정 정렬됨).
    pub results: Vec<QuickResult>,
    /// 사용자 요청 또는 한도 초과/오류로 인한 취소 여부.
    pub cancelled: bool,
    /// 결과 바이트 한도에 도달하여 추가 결과 저장을 중단했는지 여부.
    pub limit_reached: bool,
    /// 바이트 한도 초과 또는 중도 취소로 인해 누락된 결과 수.
    pub omitted_results: usize,
    /// 실행 중 발생한 오류 및 경고 메시지 목록.
    pub errors: Vec<String>,
    /// 프로브 기능별 실제 백엔드 호출 횟수.
    pub invocations: ProbeCounts,
    /// 동시 실행 중 실제 관찰된 최대 활성 대상 수.
    pub max_active_targets: usize,
    /// 실제 진단 작업이 시작된 대상 수.
    pub targets_started: usize,
    /// 실제 진단 작업이 완료된 대상 수.
    pub targets_completed: usize,
    /// 보관된 진단 결과들의 실제 JSON 직렬화 바이트 합계 (max_result_bytes 이하).
    pub serialized_result_bytes: usize,
}

/// 프로브 비동기 실행 반환 퓨처 타입.
pub type ProbeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<QuickResult, Vec<String>>> + Send + 'a>>;

/// Network Quick Check 프로브 백엔드 추상화 트레이트.
pub trait QuickProbeBackend: Send + Sync {
    /// 단일 대상에 대해 비동기 TCP 연결 프로브를 수행합니다.
    fn tcp<'a>(
        &'a self,
        ctx: QuickContext,
        target: SocketAddr,
        timeout: Duration,
        cancel: Arc<AtomicBool>,
    ) -> ProbeFuture<'a>;

    /// 단일 대상에 대해 동기 ICMP Ping 프로브를 수행합니다.
    fn icmp<'a>(
        &'a self,
        ctx: QuickContext,
        target: IpAddr,
        timeout: Duration,
        cancel: Arc<AtomicBool>,
    ) -> ProbeFuture<'a>;

    /// 로컬 호스트 네트워크 정보 스냅샷 수집 프로브를 수행합니다.
    fn host<'a>(
        &'a self,
        ctx: QuickContext,
        target: IpAddr,
        cancel: Arc<AtomicBool>,
    ) -> ProbeFuture<'a>;
}

/// 실제 OS 네이티브 네트워킹 API를 호출하는 기본 프로브 백엔드 구현체.
#[derive(Debug, Clone, Copy, Default)]
pub struct NativeProbeBackend;

impl QuickProbeBackend for NativeProbeBackend {
    fn tcp<'a>(
        &'a self,
        ctx: QuickContext,
        target: SocketAddr,
        timeout: Duration,
        cancel: Arc<AtomicBool>,
    ) -> ProbeFuture<'a> {
        Box::pin(async move {
            let measurement = crate::tcp::connect_once(target, timeout, cancel).await;
            tcp_to_quick_result(&ctx, &measurement)
        })
    }

    fn icmp<'a>(
        &'a self,
        ctx: QuickContext,
        target: IpAddr,
        timeout: Duration,
        cancel: Arc<AtomicBool>,
    ) -> ProbeFuture<'a> {
        Box::pin(async move {
            let measurement = tokio::task::spawn_blocking(move || {
                crate::icmp::ping_once(target, timeout, cancel)
            })
            .await
            .map_err(|join_err| {
                vec![format!(
                    "ICMP Ping 동기 작업 spawn_blocking 실패 (JoinError): {join_err}"
                )]
            })?;

            icmp_to_quick_result(&ctx, &measurement)
        })
    }

    fn host<'a>(
        &'a self,
        ctx: QuickContext,
        target: IpAddr,
        cancel: Arc<AtomicBool>,
    ) -> ProbeFuture<'a> {
        Box::pin(async move {
            if cancel.load(Ordering::SeqCst) {
                return Err(vec![
                    "호스트 스냅샷 수집 시작 전 취소 플래그가 감지되었습니다.".to_string(),
                ]);
            }

            let started = Instant::now();
            let snapshot =
                tokio::task::spawn_blocking(move || crate::host::collect_host_snapshot(target))
                    .await
                    .map_err(|join_err| {
                        vec![format!(
                            "호스트 스냅샷 동기 수집 spawn_blocking 실패 (JoinError): {join_err}"
                        )]
                    })?;

            let elapsed_ms = Some(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX));
            host_to_quick_result(&ctx, &snapshot, elapsed_ms)
        })
    }
}

/// 내부 원자적 백엔드 호출 카운터.
#[derive(Debug, Default)]
struct SharedInvocationCounters {
    tcp_connect: AtomicUsize,
    icmp_ping: AtomicUsize,
    local_network: AtomicUsize,
    dns_lookup: AtomicUsize,
    icmp_traceroute: AtomicUsize,
}

/// 단일 대상 프로브 실행에 필요한 공통 컨텍스트 및 백엔드 의존성.
struct SingleTargetExecutionContext {
    backend: Arc<dyn QuickProbeBackend>,
    cancel: Arc<AtomicBool>,
    session_id: String,
    timestamp_iso8601: Option<String>,
    source_host: Option<String>,
    tcp_timeout_ms: u64,
    icmp_timeout_ms: Option<u64>,
    counters: Arc<SharedInvocationCounters>,
}

/// 단일 대상 작업 실행 결과.
struct SingleTargetOutput {
    target_idx: usize,
    results: Vec<(usize, QuickResult)>,
    errors: Vec<String>,
}

/// 요청의 기본 메타데이터 및 바이트 예산을 철저히 검증합니다.
fn pre_validate_request(request: &QuickRunRequest) -> Result<QuickPlan, Vec<String>> {
    let mut errors = Vec::new();

    if !(MIN_RESULT_BYTES..=MAX_RESULT_BYTES).contains(&request.max_result_bytes) {
        errors.push(format!(
            "max_result_bytes({})는 {MIN_RESULT_BYTES}..={MAX_RESULT_BYTES} 바이트 범위여야 합니다.",
            request.max_result_bytes
        ));
    }

    if request.session_id.trim().is_empty() {
        errors.push("session_id는 비어있을 수 없습니다.".to_string());
    }

    if let Some(ref ts) = request.timestamp_iso8601 {
        if ts.trim().is_empty() {
            errors.push("timestamp_iso8601는 비어있을 수 없습니다.".to_string());
        } else if let Err(e) = validate_rfc3339_timestamp(ts) {
            errors.push(format!("timestamp_iso8601 형식 오류: {e}"));
        }
    }

    if let Some(ref sh) = request.source_host
        && sh.trim().is_empty()
    {
        errors.push("source_host는 비어있을 수 없습니다.".to_string());
    }

    if request.targets.len() > MAX_TARGETS {
        errors.push(format!(
            "대상 목록 크기({})가 최대 허용치({MAX_TARGETS})를 초과했습니다.",
            request.targets.len()
        ));
    }

    let plan = match build_quick_plan(&request.targets, &request.options) {
        Ok(p) => p,
        Err(input_errors) => {
            for err in input_errors {
                errors.push(err.message);
            }
            return Err(errors);
        }
    };

    // 도메인 주소 해석 요구 검증: 이번 slice에서 DNS resolver 미구현이므로
    // 선행 주소 해석이 필요한 대상(TCP/Ping/Traceroute/LocalNetwork 선택)이 있으면 전면 차단
    for planned in &plan.targets {
        if planned.requires_resolution {
            errors.push(format!(
                "도메인 대상 '{}'은 이번 버전에서 지원하지 않습니다 (DNS 리졸버 미구현으로 선행 주소 해석 불가, IP 주소를 직접 지정해야 합니다).",
                planned.target.host
            ));
        }
    }

    if errors.is_empty() {
        Ok(plan)
    } else {
        Err(errors)
    }
}

/// 오류 또는 무결성 검증 실패 시 UNKNOWN/UNKNOWN LOCAL_ERROR 결과를 생성합니다.
fn make_local_error_result(
    ctx: &QuickContext,
    feature: QuickFeature,
    expected_ip: Option<IpAddr>,
    err_msg: String,
) -> QuickResult {
    let resolved_ip = expected_ip.map(|ip| ip.to_string());
    let details = serde_json::json!({
        "outcome": "LOCAL_ERROR",
        "limitations": [err_msg],
        "raw_measurement": {}
    });

    QuickResult {
        schema_version: QUICK_SCHEMA_VERSION.to_string(),
        product: QUICK_PRODUCT_NAME.to_string(),
        session_id: ctx.session_id.clone(),
        timestamp_iso8601: ctx.timestamp_iso8601.clone(),
        source_host: ctx.source_host.clone(),
        target_host: ctx.target_host.clone(),
        resolved_ip,
        target_port: ctx.target_port,
        feature,
        status: QuickStatus::UNKNOWN,
        elapsed_ms: None,
        os_error_code: None,
        details,
        evidence_level: EvidenceLevel::UNKNOWN,
    }
}

/// 백엔드가 반환한 결과의 컨텍스트 메타데이터 및 IP 교차 오염 여부를 철저히 검증합니다.
fn verify_backend_result(
    ctx: &QuickContext,
    expected_feature: QuickFeature,
    expected_ip: Option<IpAddr>,
    backend_res: Result<QuickResult, Vec<String>>,
    errors: &mut Vec<String>,
) -> QuickResult {
    match backend_res {
        Ok(res) => {
            let mut mismatches = Vec::new();

            if res.session_id != ctx.session_id {
                mismatches.push(format!(
                    "session_id 불일치 (기대: '{}', 실제: '{}')",
                    ctx.session_id, res.session_id
                ));
            }
            if res.target_host != ctx.target_host {
                mismatches.push(format!(
                    "target_host 불일치 (기대: '{}', 실제: '{}')",
                    ctx.target_host, res.target_host
                ));
            }
            if res.target_port != ctx.target_port {
                mismatches.push(format!(
                    "target_port 불일치 (기대: {}, 실제: {})",
                    ctx.target_port, res.target_port
                ));
            }
            if res.feature != expected_feature {
                mismatches.push(format!(
                    "feature 불일치 (기대: {:?}, 실제: {:?})",
                    expected_feature, res.feature
                ));
            }
            if res.timestamp_iso8601 != ctx.timestamp_iso8601 {
                mismatches.push(format!(
                    "timestamp_iso8601 불일치 (기대: {:?}, 실제: {:?})",
                    ctx.timestamp_iso8601, res.timestamp_iso8601
                ));
            }
            if res.source_host != ctx.source_host {
                mismatches.push(format!(
                    "source_host 불일치 (기대: {:?}, 실제: {:?})",
                    ctx.source_host, res.source_host
                ));
            }

            // resolved_ip 교차 오염 검증: target IP가 있는 경우 수치 비교
            if let Some(ref res_ip_str) = res.resolved_ip
                && let Some(exp_ip) = expected_ip
            {
                match res_ip_str.trim().parse::<IpAddr>() {
                    Ok(parsed_ip) => {
                        if parsed_ip != exp_ip {
                            mismatches.push(format!(
                                "resolved_ip 교차 오염 감지 (기대: '{exp_ip}', 실제: '{parsed_ip}')"
                            ));
                        }
                    }
                    Err(_) => {
                        mismatches.push(format!("유효하지 않은 resolved_ip 형식: '{res_ip_str}'"));
                    }
                }
            }

            if let Err(val_errs) = validate_quick_result(&res) {
                mismatches.extend(val_errs);
            }

            if mismatches.is_empty() {
                res
            } else {
                let err_text = format!("백엔드 결과 무결성 위반: {}", mismatches.join("; "));
                errors.push(err_text.clone());
                make_local_error_result(ctx, expected_feature, expected_ip, err_text)
            }
        }
        Err(err_list) => {
            let err_text = format!("백엔드 프로브 실행 오류: {}", err_list.join("; "));
            errors.push(err_text.clone());
            make_local_error_result(ctx, expected_feature, expected_ip, err_text)
        }
    }
}

/// 사전 취소 상태에서 전체 계획에 대한 CANCELLED 결과들을 안전하게 생성합니다.
fn build_pre_cancelled_report(
    request: &QuickRunRequest,
    plan: &QuickPlan,
) -> Result<QuickRunReport, Vec<String>> {
    let mut results = Vec::new();
    let mut serialized_bytes = 0;
    let mut limit_reached = false;
    let mut errors = Vec::new();

    let total_expected = plan.targets.len() * request.options.selected_features.len();

    for planned in &plan.targets {
        for feature in &request.options.selected_features {
            let resolved_ip = planned
                .target
                .host
                .trim()
                .parse::<IpAddr>()
                .ok()
                .map(|ip| ip.to_string());

            let details = serde_json::json!({
                "outcome": "CANCELLED",
                "limitations": [
                    "진단 실행 시작 전 사용자 취소 플래그가 감지되어 프로브를 호출하지 않았습니다."
                ],
                "raw_measurement": {}
            });

            let item = QuickResult {
                schema_version: QUICK_SCHEMA_VERSION.to_string(),
                product: QUICK_PRODUCT_NAME.to_string(),
                session_id: request.session_id.clone(),
                timestamp_iso8601: request.timestamp_iso8601.clone(),
                source_host: request.source_host.clone(),
                target_host: planned.target.host.clone(),
                resolved_ip,
                target_port: planned.target.port,
                feature: *feature,
                status: QuickStatus::UNKNOWN,
                elapsed_ms: None,
                os_error_code: None,
                details,
                evidence_level: EvidenceLevel::UNKNOWN,
            };

            if let Err(e) = validate_quick_result(&item) {
                errors.extend(e);
            }

            let item_bytes = serde_json::to_vec(&item).map(|v| v.len()).unwrap_or(0);
            if serialized_bytes + item_bytes > request.max_result_bytes {
                limit_reached = true;
                errors.push(format!(
                    "최대 결과 직렬화 한도({} 바이트)에 도달하여 추가 결과 저장을 중단했습니다.",
                    request.max_result_bytes
                ));
                break;
            }

            serialized_bytes += item_bytes;
            results.push(item);
        }

        if limit_reached {
            break;
        }
    }

    let omitted_results = total_expected.saturating_sub(results.len());

    Ok(QuickRunReport {
        results,
        cancelled: true,
        limit_reached,
        omitted_results,
        errors,
        invocations: ProbeCounts::default(),
        max_active_targets: 0,
        targets_started: 0,
        targets_completed: 0,
        serialized_result_bytes: serialized_bytes,
    })
}

/// 단일 검사 대상에 대해 선택된 진단 기능들을 순차적으로 실행합니다.
async fn run_single_target(
    target_idx: usize,
    planned_target: crate::targets::PlannedTarget,
    exec_ctx: Arc<SingleTargetExecutionContext>,
) -> SingleTargetOutput {
    let mut results = Vec::new();
    let mut errors = Vec::new();

    let parsed_ip = planned_target.target.host.trim().parse::<IpAddr>().ok();

    for (feature_idx, feature) in planned_target.features.iter().enumerate() {
        // 각 기능 실행 전 취소 여부 확인: 중도 취소 시 미시작 기능은 실행하지 않음
        if exec_ctx.cancel.load(Ordering::SeqCst) {
            break;
        }

        let ctx = QuickContext {
            session_id: exec_ctx.session_id.clone(),
            timestamp_iso8601: exec_ctx.timestamp_iso8601.clone(),
            source_host: exec_ctx.source_host.clone(),
            target_host: planned_target.target.host.clone(),
            target_port: planned_target.target.port,
        };

        match feature {
            QuickFeature::TcpConnect => {
                let Some(ip) = parsed_ip else {
                    let err_msg = format!(
                        "TCP 연결 프로브를 위한 유효한 대상 IP 주소가 없습니다: '{}'",
                        planned_target.target.host
                    );
                    errors.push(err_msg.clone());
                    let res =
                        make_local_error_result(&ctx, QuickFeature::TcpConnect, None, err_msg);
                    results.push((feature_idx, res));
                    continue;
                };

                let socket_addr = SocketAddr::new(ip, planned_target.target.port);
                let timeout = Duration::from_millis(exec_ctx.tcp_timeout_ms);

                // 백엔드 메소드를 실제 호출하는 순간에만 카운터 증가
                exec_ctx.counters.tcp_connect.fetch_add(1, Ordering::SeqCst);

                let backend_future = exec_ctx.backend.tcp(
                    ctx.clone(),
                    socket_addr,
                    timeout,
                    Arc::clone(&exec_ctx.cancel),
                );
                let backend_res = backend_future.await;

                let verified = verify_backend_result(
                    &ctx,
                    QuickFeature::TcpConnect,
                    Some(ip),
                    backend_res,
                    &mut errors,
                );
                results.push((feature_idx, verified));
            }

            QuickFeature::IcmpPing => {
                let Some(ip) = parsed_ip else {
                    let err_msg = format!(
                        "ICMP Ping 프로브를 위한 유효한 대상 IP 주소가 없습니다: '{}'",
                        planned_target.target.host
                    );
                    errors.push(err_msg.clone());
                    let res = make_local_error_result(&ctx, QuickFeature::IcmpPing, None, err_msg);
                    results.push((feature_idx, res));
                    continue;
                };

                let timeout_ms = exec_ctx.icmp_timeout_ms.unwrap_or_else(|| {
                    std::cmp::min(exec_ctx.tcp_timeout_ms, crate::targets::MAX_ICMP_TIMEOUT_MS)
                });
                let timeout = Duration::from_millis(timeout_ms);

                exec_ctx.counters.icmp_ping.fetch_add(1, Ordering::SeqCst);

                let backend_future =
                    exec_ctx
                        .backend
                        .icmp(ctx.clone(), ip, timeout, Arc::clone(&exec_ctx.cancel));
                let backend_res = backend_future.await;

                let verified = verify_backend_result(
                    &ctx,
                    QuickFeature::IcmpPing,
                    Some(ip),
                    backend_res,
                    &mut errors,
                );
                results.push((feature_idx, verified));
            }

            QuickFeature::LocalNetwork => {
                let Some(ip) = parsed_ip else {
                    let err_msg = format!(
                        "로컬 네트워크 스냅샷 수집을 위한 유효한 대상 IP 주소가 없습니다: '{}'",
                        planned_target.target.host
                    );
                    errors.push(err_msg.clone());
                    let res =
                        make_local_error_result(&ctx, QuickFeature::LocalNetwork, None, err_msg);
                    results.push((feature_idx, res));
                    continue;
                };

                exec_ctx
                    .counters
                    .local_network
                    .fetch_add(1, Ordering::SeqCst);

                let backend_future =
                    exec_ctx
                        .backend
                        .host(ctx.clone(), ip, Arc::clone(&exec_ctx.cancel));
                let backend_res = backend_future.await;

                let verified = verify_backend_result(
                    &ctx,
                    QuickFeature::LocalNetwork,
                    Some(ip),
                    backend_res,
                    &mut errors,
                );
                results.push((feature_idx, verified));
            }

            QuickFeature::DnsLookup | QuickFeature::IcmpTraceroute => {
                // 이번 slice에서는 DNS/Trace 프로브가 미구현이므로 백엔드 호출 0회, 명시적 UNAVAILABLE 행 생성
                let feature_name = feature.as_str();
                let details = serde_json::json!({
                    "outcome": "UNAVAILABLE",
                    "limitations": [
                        format!("'{feature_name}' 프로브는 이번 마일스톤(QG2)에서 지원되지 않으며 백엔드 호출 없이 UNAVAILABLE로 처리되었습니다.")
                    ],
                    "raw_measurement": {}
                });

                let unavailable_res = QuickResult {
                    schema_version: QUICK_SCHEMA_VERSION.to_string(),
                    product: QUICK_PRODUCT_NAME.to_string(),
                    session_id: ctx.session_id.clone(),
                    timestamp_iso8601: ctx.timestamp_iso8601.clone(),
                    source_host: ctx.source_host.clone(),
                    target_host: ctx.target_host.clone(),
                    resolved_ip: parsed_ip.map(|ip| ip.to_string()),
                    target_port: ctx.target_port,
                    feature: *feature,
                    status: QuickStatus::UNKNOWN,
                    elapsed_ms: None,
                    os_error_code: None,
                    details,
                    evidence_level: EvidenceLevel::UNKNOWN,
                };

                if let Err(e) = validate_quick_result(&unavailable_res) {
                    errors.extend(e);
                }
                results.push((feature_idx, unavailable_res));
            }
        }
    }

    SingleTargetOutput {
        target_idx,
        results,
        errors,
    }
}

/// Network Quick Check 진단을 실행합니다.
///
/// - 사전 검증을 통해 유효하지 않은 대상/옵션 및 도메인 대상을 사전에 차단합니다.
/// - 동시 대상 작업 수는 `request.options.concurrency` (최대 4) 이하로 엄격히 제한됩니다.
/// - `JoinSet`을 이용하여 최대 `concurrency`개만 동시 실행하며, 100개 작업을 미리 생성하지 않습니다.
/// - 중도 취소 또는 메모리 예산 초과 시 미시작 작업은 실행하지 않고 실행 중인 태스크를 정상 drain합니다.
/// - 최종 보고서의 `results`는 원래 입력 대상 순서와 기능 순서로 안정 정렬됩니다.
pub async fn run_quick(
    request: &QuickRunRequest,
    backend: Arc<dyn QuickProbeBackend>,
    cancel: Arc<AtomicBool>,
) -> Result<QuickRunReport, Vec<String>> {
    let plan = pre_validate_request(request)?;

    let total_expected_rows = plan.targets.len() * request.options.selected_features.len();

    // 선택된 기능이 전혀 없는 경우: 백엔드 호출 없이 즉시 빈 보고서 반환
    if request.options.selected_features.is_empty() {
        return Ok(QuickRunReport {
            results: Vec::new(),
            cancelled: cancel.load(Ordering::SeqCst),
            limit_reached: false,
            omitted_results: 0,
            errors: Vec::new(),
            invocations: ProbeCounts::default(),
            max_active_targets: 0,
            targets_started: 0,
            targets_completed: 0,
            serialized_result_bytes: 0,
        });
    }

    // 사전 취소 상태인 경우: 백엔드 호출 0회로 사전 취소 보고서 반환
    if cancel.load(Ordering::SeqCst) {
        return build_pre_cancelled_report(request, &plan);
    }

    let concurrency_cap = std::cmp::min(plan.concurrency, MAX_CONCURRENT_TARGETS);
    let concurrency = std::cmp::max(1, concurrency_cap);

    let active_targets = Arc::new(AtomicUsize::new(0));
    let max_active_observed = Arc::new(AtomicUsize::new(0));
    let targets_started = Arc::new(AtomicUsize::new(0));
    let targets_completed = Arc::new(AtomicUsize::new(0));
    let invocation_counters = Arc::new(SharedInvocationCounters::default());

    let exec_ctx = Arc::new(SingleTargetExecutionContext {
        backend: Arc::clone(&backend),
        cancel: Arc::clone(&cancel),
        session_id: request.session_id.clone(),
        timestamp_iso8601: request.timestamp_iso8601.clone(),
        source_host: request.source_host.clone(),
        tcp_timeout_ms: plan.tcp_timeout_ms,
        icmp_timeout_ms: plan.icmp_timeout_ms,
        counters: Arc::clone(&invocation_counters),
    });

    let mut global_errors = Vec::new();
    let mut task_outputs = Vec::new();

    let mut join_set = tokio::task::JoinSet::new();
    let mut target_iter = plan.targets.iter().cloned().enumerate();

    let mut current_approx_bytes = 0usize;
    let mut early_limit_stop = false;

    loop {
        let is_cancelled = cancel.load(Ordering::SeqCst);

        // 취소되지 않았고 한도 초과 플래그가 없는 경우 concurrency 한도까지 spawn
        while !is_cancelled && !early_limit_stop && join_set.len() < concurrency {
            if let Some((target_idx, planned_target)) = target_iter.next() {
                targets_started.fetch_add(1, Ordering::SeqCst);

                let active_counter = Arc::clone(&active_targets);
                let max_active = Arc::clone(&max_active_observed);
                let completed_counter = Arc::clone(&targets_completed);
                let exec_ctx_clone = Arc::clone(&exec_ctx);

                join_set.spawn(async move {
                    let cur = active_counter.fetch_add(1, Ordering::SeqCst) + 1;
                    max_active.fetch_max(cur, Ordering::SeqCst);

                    let output =
                        run_single_target(target_idx, planned_target, exec_ctx_clone).await;

                    active_counter.fetch_sub(1, Ordering::SeqCst);
                    completed_counter.fetch_add(1, Ordering::SeqCst);
                    output
                });
            } else {
                break;
            }
        }

        if join_set.is_empty() {
            break;
        }

        if let Some(join_res) = join_set.join_next().await {
            match join_res {
                Ok(target_output) => {
                    for (_, res) in &target_output.results {
                        if let Ok(v) = serde_json::to_vec(res) {
                            current_approx_bytes += v.len();
                        }
                    }

                    task_outputs.push(target_output);

                    // 바이트 예산 초과 시 즉각 추가 작업 차단 및 drain 유도
                    if current_approx_bytes > request.max_result_bytes && !early_limit_stop {
                        early_limit_stop = true;
                        cancel.store(true, Ordering::SeqCst);
                        global_errors.push(format!(
                            "결과 직렬화 바이트가 한도({} 바이트)에 도달하여 후속 작업 실행을 중단합니다.",
                            request.max_result_bytes
                        ));
                    }
                }
                Err(join_err) => {
                    cancel.store(true, Ordering::SeqCst);
                    global_errors.push(format!(
                        "스케줄러 비동기 작업 비정상 종료 (JoinError): {join_err}"
                    ));
                }
            }
        }
    }

    // 1. 모든 작업 결과 수집 및 에러 통합
    let mut all_results = Vec::new();
    for output in task_outputs {
        global_errors.extend(output.errors);
        for (f_idx, res) in output.results {
            all_results.push((output.target_idx, f_idx, res));
        }
    }

    // 2. 원래 입력 대상 순서 및 기능 순서로 안정 정렬
    all_results.sort_by_key(|(t_idx, f_idx, _)| (*t_idx, *f_idx));

    // 3. 바이트 한도 내에서 최종 결과 보관
    let mut kept_results = Vec::new();
    let mut serialized_result_bytes = 0;
    let mut limit_reached = false;

    for (_, _, res) in all_results {
        let res_bytes = match serde_json::to_vec(&res) {
            Ok(v) => v.len(),
            Err(e) => {
                global_errors.push(format!("결과 JSON 직렬화 실패: {e}"));
                continue;
            }
        };

        if serialized_result_bytes + res_bytes > request.max_result_bytes {
            limit_reached = true;
            break;
        }

        serialized_result_bytes += res_bytes;
        kept_results.push(res);
    }

    if limit_reached && !global_errors.iter().any(|e| e.contains("최대 결과 직렬화")) {
        global_errors.push(format!(
            "최대 결과 직렬화 한도({} 바이트)를 초과하여 추가 결과 저장을 중단했습니다.",
            request.max_result_bytes
        ));
    }

    let omitted_results = total_expected_rows.saturating_sub(kept_results.len());
    let cancelled = cancel.load(Ordering::SeqCst);

    let invocations = ProbeCounts {
        tcp_connect: invocation_counters.tcp_connect.load(Ordering::SeqCst),
        icmp_ping: invocation_counters.icmp_ping.load(Ordering::SeqCst),
        local_network: invocation_counters.local_network.load(Ordering::SeqCst),
        dns_lookup: invocation_counters.dns_lookup.load(Ordering::SeqCst),
        icmp_traceroute: invocation_counters.icmp_traceroute.load(Ordering::SeqCst),
    };

    Ok(QuickRunReport {
        results: kept_results,
        cancelled,
        limit_reached,
        omitted_results,
        errors: global_errors,
        invocations,
        max_active_targets: max_active_observed.load(Ordering::SeqCst),
        targets_started: targets_started.load(Ordering::SeqCst),
        targets_completed: targets_completed.load(Ordering::SeqCst),
        serialized_result_bytes,
    })
}
