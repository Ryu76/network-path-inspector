//! Network Quick Check(Part B) 순수 Rust 비동기 진단 실행기 모듈.
//!
//! ## 설계 및 안전 원칙
//! - **실제 측정 엔진 재사용**: 본 모듈은 TCP/ICMP/호스트 스냅샷/DNS 해석 등 네트워크 측정 로직을
//!   직접 구현하거나 복제하지 않으며, 검증된 `QuickProbeBackend`를 통해 기존 `network_core`의
//!   `connect_once`, `ping_once`, `collect_host_snapshot` 및 `dns_engine::resolve_isolated`와 어댑터를 재사용합니다.
//! - **비파괴·읽기 전용**: 시스템 정책, 방화벽, 레지스트리, 라우팅 테이블 변경을 절대 수행하지 않습니다.
//! - **측정 사실·추론·미확인의 엄격한 분리**: 패킷 캡처(PCAP) 근거 없는 SYN/RST 관찰 주장이나
//!   응답 없는 HOP을 차단 장비로 단정하지 않으며, 미확인 nullable 필드는 명시적 `None`(`null`)으로 유지합니다.
//! - **결과 위장 금지**: `CANCELLED`, `UNAVAILABLE`, `LOCAL_ERROR` 등 실패/미지원 상태를
//!   `PASS`나 `SKIPPED`로 위장하지 않으며 원본 오류 분류를 정확히 보존합니다.
//! - **메모리 예산 엄격 준수**: 보관 결과의 JSON 직렬화 바이트(`serialized_result_bytes`)를
//!   기준으로 예산을 관리하며, 예산 초과 시 즉각 추가 저장을 중단하고 명시적인 한도 도달(`limit_reached = true`)과
//!   누락 건수(`omitted_results`)를 집계합니다.
//! - **DNS 주소 선택 및 단일 진실 공급원 준수**: OS 해석기가 반환한 첫 번째 SocketAddr만 후보로 사용하며,
//!   임의 재정렬, trim, 형태 수리, 다음 IP 자동 대체 연결(fallback)을 일체 수행하지 않습니다.
//!   첫 번째 후보 주소가 미지정, 멀티캐스트, 브로드캐스트, 링크로컬 등 안전하지 않은 주소인 경우
//!   연결을 즉각 차단하고 후속 프로브를 실행하지 않습니다.
//!
//! ## 알려진 한계 및 취소 계약
//! - **ICMP Traceroute 지원 및 기본 구현 계약**: Part B Network Quick Check의 선택 ICMP Traceroute 프로브를
//!   연결합니다. 트레이트 기본 구현은 실제 I/O 없이 UNKNOWN/UNKNOWN UNAVAILABLE (사전 취소 시 CANCELLED) 결과를 반환하며,
//!   `NativeProbeBackend`는 `System32\tracert.exe` 기반 `trace_once`를 `spawn_blocking`으로 안전하게 호출합니다.
//! - **ICMP 동기 호출 한계**: Windows IP Helper ICMP API(`ping_once`)는 블로킹 시스템 호출이므로,
//!   `tokio::task::spawn_blocking`을 통해 비동기 런타임 차단을 방지하되 호출 중인 작업은 OS 타임아웃(최대 2000ms)
//!   경과 후 취소가 감지됩니다 (즉각적인 하드 킬을 보장하지 않습니다).
//! - **백엔드 취소 계약**: 사용자 정의 `QuickProbeBackend` 구현체가 취소 원자 플래그를 무시하는 경우,
//!   비동기 실행기는 퓨처를 안전하게 중단(drop)하거나 drain하지만 임의의 OS 스레드를 강제 종료할 수 없습니다.

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::dns::dns_to_quick_result;
use crate::dns_engine::DnsMeasurement;
use crate::measurements::{host_to_quick_result, icmp_to_quick_result};
use crate::quick::{
    EvidenceLevel, QUICK_PRODUCT_NAME, QUICK_SCHEMA_VERSION, QuickContext, QuickFeature,
    QuickResult, QuickStatus, tcp_to_quick_result, validate_quick_result,
    validate_rfc3339_timestamp,
};
use crate::targets::{QuickOptions, QuickPlan, QuickTarget, build_quick_plan, parse_target_pair};
use crate::traceroute::{TraceMeasurement, TraceOptions, trace_to_quick_result};

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
    /// 실제 DNS 리졸버 백엔드 resolve 호출 횟수 (네트워크 질의 수가 아님).
    pub dns_lookup: usize,
    /// 실제 ICMP Traceroute 백엔드 trace 호출 횟수 (OS 프로세스/패킷 수가 아님).
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

/// 프로브 비동기 DNS 해석 반환 퓨처 타입.
pub type DnsProbeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<DnsMeasurement, Vec<String>>> + Send + 'a>>;

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

    /// 단일 도메인 또는 IP 대상에 대해 DNS 해석을 수행합니다.
    ///
    /// 기본 구현은 미구성 오류(`Err`)를 반환하여 기존 구현체와의 하위 호환성을 유지합니다.
    fn resolve<'a>(
        &'a self,
        ctx: QuickContext,
        timeout: Duration,
        cancel: Arc<AtomicBool>,
    ) -> DnsProbeFuture<'a> {
        let _ = (ctx, timeout, cancel);
        Box::pin(async move {
            Err(vec![
                "기본 프로브 백엔드에 DNS 해석기(resolve)가 구현되지 않았습니다.".to_string(),
            ])
        })
    }

    /// 단일 대상 IP에 대해 비동기 ICMP Traceroute 프로브를 수행합니다.
    ///
    /// 기본 구현은 실제 I/O 없이 UNKNOWN/UNKNOWN UNAVAILABLE (이미 취소된 경우 CANCELLED) 결과를 반환하여
    /// 기존 구현체와의 하위 호환성을 유지합니다.
    fn trace<'a>(
        &'a self,
        ctx: QuickContext,
        target: IpAddr,
        options: TraceOptions,
        cancel: Arc<AtomicBool>,
    ) -> ProbeFuture<'a> {
        let _ = (options, target);
        Box::pin(async move {
            let is_cancelled = cancel.load(Ordering::SeqCst);
            let outcome = if is_cancelled {
                "CANCELLED"
            } else {
                "UNAVAILABLE"
            };
            let limitation = if is_cancelled {
                "진단 시작 전 취소 요청이 감지되어 Traceroute 프로브를 실행하지 않았습니다.".to_string()
            } else {
                "기본 프로브 백엔드에 ICMP Traceroute(trace)가 구현되지 않았습니다.".to_string()
            };
            let details = serde_json::json!({
                "outcome": outcome,
                "limitations": [limitation],
                "raw_measurement": {}
            });
            let result = QuickResult {
                schema_version: QUICK_SCHEMA_VERSION.to_string(),
                product: QUICK_PRODUCT_NAME.to_string(),
                session_id: ctx.session_id,
                timestamp_iso8601: ctx.timestamp_iso8601,
                source_host: ctx.source_host,
                target_host: ctx.target_host,
                resolved_ip: None,
                target_port: ctx.target_port,
                feature: QuickFeature::IcmpTraceroute,
                status: QuickStatus::UNKNOWN,
                elapsed_ms: None,
                os_error_code: None,
                details,
                evidence_level: EvidenceLevel::UNKNOWN,
            };
            Ok(result)
        })
    }
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

    fn trace<'a>(
        &'a self,
        ctx: QuickContext,
        target: IpAddr,
        options: TraceOptions,
        cancel: Arc<AtomicBool>,
    ) -> ProbeFuture<'a> {
        Box::pin(async move {
            let measurement = tokio::task::spawn_blocking(move || {
                crate::traceroute::trace_once(target, &options, cancel)
            })
            .await
            .map_err(|join_err| {
                vec![format!(
                    "ICMP Traceroute 동기 작업 spawn_blocking 실패 (JoinError): {join_err}"
                )]
            })?;

            trace_to_quick_result(&ctx, &measurement)
        })
    }
}

/// 실제 OS 네이티브 네트워킹 API 및 격리된 DNS helper 프로세스를 호출하는 프로브 백엔드 구현체.
#[derive(Debug, Clone)]
pub struct NativeDnsProbeBackend {
    pub helper_executable: PathBuf,
    inner: NativeProbeBackend,
}

impl NativeDnsProbeBackend {
    /// 명시적 helper 실행파일 경로로 새 백엔드를 생성합니다.
    pub fn new(helper_executable: PathBuf) -> Self {
        Self {
            helper_executable,
            inner: NativeProbeBackend,
        }
    }
}

impl QuickProbeBackend for NativeDnsProbeBackend {
    fn tcp<'a>(
        &'a self,
        ctx: QuickContext,
        target: SocketAddr,
        timeout: Duration,
        cancel: Arc<AtomicBool>,
    ) -> ProbeFuture<'a> {
        self.inner.tcp(ctx, target, timeout, cancel)
    }

    fn icmp<'a>(
        &'a self,
        ctx: QuickContext,
        target: IpAddr,
        timeout: Duration,
        cancel: Arc<AtomicBool>,
    ) -> ProbeFuture<'a> {
        self.inner.icmp(ctx, target, timeout, cancel)
    }

    fn host<'a>(
        &'a self,
        ctx: QuickContext,
        target: IpAddr,
        cancel: Arc<AtomicBool>,
    ) -> ProbeFuture<'a> {
        self.inner.host(ctx, target, cancel)
    }

    fn resolve<'a>(
        &'a self,
        ctx: QuickContext,
        timeout: Duration,
        cancel: Arc<AtomicBool>,
    ) -> DnsProbeFuture<'a> {
        let helper = self.helper_executable.clone();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let measurement = crate::dns_engine::resolve_isolated(
                    &helper,
                    &ctx.target_host,
                    ctx.target_port,
                    timeout,
                    cancel,
                );
                Ok(measurement)
            })
            .await
            .map_err(|join_err| {
                vec![format!(
                    "DNS 해석 동기 작업 spawn_blocking 실패 (JoinError): {join_err}"
                )]
            })?
        })
    }

    fn trace<'a>(
        &'a self,
        ctx: QuickContext,
        target: IpAddr,
        options: TraceOptions,
        cancel: Arc<AtomicBool>,
    ) -> ProbeFuture<'a> {
        self.inner.trace(ctx, target, options, cancel)
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

/// 해석된 IP 주소가 진단 대상으로서 안전한지 검증합니다.
///
/// 기존 `targets`의 `parse_target_pair`를 재사용하여 미지정/멀티캐스트/브로드캐스트를 검증하고,
/// 추가로 링크로컬 주소(169.254.0.0/16, fe80::/10)를 엄격히 차단합니다.
fn is_safe_resolved_ip(ip: IpAddr, port: u16) -> bool {
    let ip_str = ip.to_string();
    let port_str = port.to_string();
    if parse_target_pair(&ip_str, &port_str).is_err() {
        return false;
    }

    match ip {
        IpAddr::V4(v4) => {
            if v4.is_link_local() {
                return false;
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_unicast_link_local() {
                return false;
            }
        }
    }

    true
}

/// 검증 완료된 필수 DNS 해석 원문 DTO 전체를 JSON 문자열 형태로 limitations에 첨부합니다.
///
/// details 3개 필드(outcome, limitations, raw_measurement) 계약을 유지하면서
/// 완전한 JSON 문자열로 limitations 배열에 보존합니다.
fn append_dns_raw_limitation(result: &mut QuickResult, dns_m: &DnsMeasurement) {
    if let Ok(json_str) = serde_json::to_string(dns_m)
        && let Some(details_obj) = result.details.as_object_mut()
        && let Some(limitations_val) = details_obj.get_mut("limitations")
        && let Some(limitations) = limitations_val.as_array_mut()
    {
        let raw_dto_msg =
            serde_json::Value::String(format!("필수 DNS 해석 원문(JSON): {json_str}"));
        if !limitations.contains(&raw_dto_msg) {
            limitations.push(raw_dto_msg);
        }
    }
}

/// 도메인 대상의 프로브 결과에 DNS 필수 해석 원문 정보 및 첫 후보 선택 정책 한계를 추가합니다.
///
/// 기존 `details.raw_measurement`를 일체 덮어쓰지 않고 `limitations` 배열에만 고유하게 추가합니다.
fn append_domain_resolution_limitations(
    result: &mut QuickResult,
    dns_m: &DnsMeasurement,
    selected_ip: IpAddr,
) {
    if let Some(details_obj) = result.details.as_object_mut()
        && let Some(limitations_val) = details_obj.get_mut("limitations")
        && let Some(limitations) = limitations_val.as_array_mut()
    {
        let policy_msg = serde_json::Value::String(format!(
            "도메인 주소 해석 결과 중 OS가 반환한 첫 번째 주소('{selected_ip}')만 후보로 사용하였으며, 다른 주소로의 자동 대체 연결은 시도하지 않음"
        ));
        if !limitations.contains(&policy_msg) {
            limitations.push(policy_msg);
        }
        let raw_addresses_msg = serde_json::Value::String(format!(
            "해석된 전체 주소 목록(총 {}개): [{}]",
            dns_m.addresses.len(),
            dns_m.addresses.join(", ")
        ));
        if !limitations.contains(&raw_addresses_msg) {
            limitations.push(raw_addresses_msg);
        }
    }
    append_dns_raw_limitation(result, dns_m);
}

/// 선행 DNS 해석 실패 또는 미지원 기능에 대한 UNAVAILABLE 결과를 생성합니다.
fn make_unavailable_result(
    ctx: &QuickContext,
    feature: QuickFeature,
    reason: String,
) -> QuickResult {
    let details = serde_json::json!({
        "outcome": "UNAVAILABLE",
        "limitations": [reason],
        "raw_measurement": {}
    });

    QuickResult {
        schema_version: QUICK_SCHEMA_VERSION.to_string(),
        product: QUICK_PRODUCT_NAME.to_string(),
        session_id: ctx.session_id.clone(),
        timestamp_iso8601: ctx.timestamp_iso8601.clone(),
        source_host: ctx.source_host.clone(),
        target_host: ctx.target_host.clone(),
        resolved_ip: None,
        target_port: ctx.target_port,
        feature,
        status: QuickStatus::UNKNOWN,
        elapsed_ms: None,
        os_error_code: None,
        details,
        evidence_level: EvidenceLevel::UNKNOWN,
    }
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

/// Traceroute 백엔드 결과의 메타데이터, DTO 무결성 및 모순 여부를 엄격히 검증합니다.
///
/// ## 검증 규칙
/// 1. generic 메타데이터(session_id, host, port, timestamp, source) 및 DTO 스키마 유효성을 검증합니다.
/// 2. details.raw_measurement가 빈 객체({})인 미측정 default 결과는 outcome이 UNAVAILABLE 또는 CANCELLED이고,
///    status/evidence가 UNKNOWN이며, elapsed_ms/os_error_code/resolved_ip가 null인 경우에만 허용합니다.
/// 3. 실측 row인 경우 top resolved_ip가 Some(expected_ip)여야 하며 null 실측 IP를 엄격히 거부합니다.
/// 4. raw_measurement를 TraceMeasurement로 역직렬화한 후 다시 직렬화하는 roundtrip 일치를 확인합니다.
/// 5. raw_measurement.target IP를 파싱하여 기대 대상 IP(expected_ip)와 정확히 일치하는지 확인합니다.
/// 6. `trace_to_quick_result`를 호출하여 canonical outcome/status/evidence/elapsed/os_error_code/raw의 일치를 검증합니다.
/// 7. 검증 실패 시 위조/불량 응답을 수리하지 않고 고정 LOCAL_ERROR 경로로 거부하며 민감 원문을 반사하지 않습니다.
fn verify_trace_backend_result(
    ctx: &QuickContext,
    expected_ip: Option<IpAddr>,
    backend_res: Result<QuickResult, Vec<String>>,
    errors: &mut Vec<String>,
) -> QuickResult {
    match backend_res {
        Ok(res) => {
            let mut mismatches = Vec::new();

            // 1. 공통 generic 메타데이터 검증
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
            if res.feature != QuickFeature::IcmpTraceroute {
                mismatches.push(format!(
                    "feature 불일치 (기대: {:?}, 실제: {:?})",
                    QuickFeature::IcmpTraceroute,
                    res.feature
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

            if let Err(val_errs) = validate_quick_result(&res) {
                mismatches.extend(val_errs);
            }

            // 2. details 구조 및 raw_measurement 무결성 검증
            let details_obj = match res.details.as_object() {
                Some(obj) => obj,
                None => {
                    mismatches.push("details가 JSON 객체 형식이 아닙니다.".to_string());
                    let err_text = format!(
                        "Traceroute 백엔드 결과 무결성 위반: {}",
                        mismatches.join("; ")
                    );
                    errors.push(err_text.clone());
                    return make_local_error_result(
                        ctx,
                        QuickFeature::IcmpTraceroute,
                        expected_ip,
                        err_text,
                    );
                }
            };

            let outcome_str = details_obj
                .get("outcome")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let raw_val = match details_obj.get("raw_measurement") {
                Some(v) => v,
                None => {
                    mismatches.push("details에 raw_measurement 키가 누락되었습니다.".to_string());
                    let err_text = format!(
                        "Traceroute 백엔드 결과 무결성 위반: {}",
                        mismatches.join("; ")
                    );
                    errors.push(err_text.clone());
                    return make_local_error_result(
                        ctx,
                        QuickFeature::IcmpTraceroute,
                        expected_ip,
                        err_text,
                    );
                }
            };

            let is_empty_raw = raw_val.as_object().map_or(false, |m| m.is_empty());

            if is_empty_raw {
                // default 미측정 상태: UNAVAILABLE 또는 CANCELLED만 빈 raw_measurement를 허용
                if outcome_str != "UNAVAILABLE" && outcome_str != "CANCELLED" {
                    mismatches.push(format!(
                        "빈 raw_measurement 상태에서는 outcome이 UNAVAILABLE 또는 CANCELLED여야 합니다 (실제: '{outcome_str}')."
                    ));
                }
                if res.status != QuickStatus::UNKNOWN {
                    mismatches.push(format!(
                        "미측정 기본 결과의 status는 UNKNOWN이어야 합니다 (실제: {:?}).",
                        res.status
                    ));
                }
                if res.evidence_level != EvidenceLevel::UNKNOWN {
                    mismatches.push(format!(
                        "미측정 기본 결과의 evidence_level은 UNKNOWN이어야 합니다 (실제: {:?}).",
                        res.evidence_level
                    ));
                }
                if res.elapsed_ms.is_some() {
                    mismatches.push(
                        "미측정 기본 결과의 elapsed_ms는 null이어야 합니다.".to_string(),
                    );
                }
                if res.os_error_code.is_some() {
                    mismatches.push(
                        "미측정 기본 결과의 os_error_code는 null이어야 합니다.".to_string(),
                    );
                }
                if res.resolved_ip.is_some() {
                    mismatches.push(
                        "미측정 기본 결과의 resolved_ip는 null이어야 합니다.".to_string(),
                    );
                }
            } else {
                // 실측 row 검증
                let Some(exp_ip) = expected_ip else {
                    mismatches.push(
                        "실측 Traceroute 결과이나 기대 대상 IP(expected_ip)가 없습니다."
                            .to_string(),
                    );
                    let err_text = format!(
                        "Traceroute 백엔드 결과 무결성 위반: {}",
                        mismatches.join("; ")
                    );
                    errors.push(err_text.clone());
                    return make_local_error_result(
                        ctx,
                        QuickFeature::IcmpTraceroute,
                        expected_ip,
                        err_text,
                    );
                };

                let expected_ip_str = exp_ip.to_string();
                match &res.resolved_ip {
                    Some(top_ip) => {
                        if top_ip != &expected_ip_str {
                            mismatches.push(format!(
                                "top resolved_ip 불일치 (기대: '{expected_ip_str}', 실제: '{top_ip}')"
                            ));
                        }
                    }
                    None => {
                        mismatches.push(
                            "실측 Traceroute 결과의 top resolved_ip가 null일 수 없습니다."
                                .to_string(),
                        );
                    }
                }

                // TraceMeasurement 구조 역직렬화 및 직렬화 roundtrip 검증
                match serde_json::from_value::<TraceMeasurement>(raw_val.clone()) {
                    Ok(measurement) => {
                        match serde_json::to_value(&measurement) {
                            Ok(roundtrip_val) => {
                                if &roundtrip_val != raw_val {
                                    mismatches.push(
                                        "raw_measurement 직렬화 roundtrip 불일치".to_string(),
                                    );
                                }
                            }
                            Err(e) => {
                                mismatches.push(format!("TraceMeasurement 재직렬화 실패: {e}"));
                            }
                        }

                        // 무보정 target IP 파싱 및 expectedIP 일치 확인
                        match measurement.target.parse::<IpAddr>() {
                            Ok(parsed_target_ip) => {
                                if parsed_target_ip != exp_ip {
                                    mismatches.push(format!(
                                        "raw_measurement.target IP({parsed_target_ip})가 기대 대상 IP({exp_ip})와 불일치합니다."
                                    ));
                                }
                            }
                            Err(_) => {
                                mismatches.push(
                                    "raw_measurement.target이 유효한 IpAddr 형식이 아닙니다."
                                        .to_string(),
                                );
                            }
                        }

                        // trace_to_quick_result로 기존 성공 게이트 재사용 및 canonical 비교 검증
                        match trace_to_quick_result(ctx, &measurement) {
                            Ok(canonical) => {
                                if res.status != canonical.status {
                                    mismatches.push(format!(
                                        "status 불일치 (기대: {:?}, 실제: {:?})",
                                        canonical.status, res.status
                                    ));
                                }
                                if res.evidence_level != canonical.evidence_level {
                                    mismatches.push(format!(
                                        "evidence_level 불일치 (기대: {:?}, 실제: {:?})",
                                        canonical.evidence_level, res.evidence_level
                                    ));
                                }
                                if res.elapsed_ms != canonical.elapsed_ms {
                                    mismatches.push(format!(
                                        "elapsed_ms 불일치 (기대: {:?}, 실제: {:?})",
                                        canonical.elapsed_ms, res.elapsed_ms
                                    ));
                                }
                                if res.os_error_code != canonical.os_error_code {
                                    mismatches.push(format!(
                                        "os_error_code 불일치 (기대: {:?}, 실제: {:?})",
                                        canonical.os_error_code, res.os_error_code
                                    ));
                                }
                                if res.resolved_ip != canonical.resolved_ip {
                                    mismatches.push(format!(
                                        "resolved_ip 불일치 (기대: {:?}, 실제: {:?})",
                                        canonical.resolved_ip, res.resolved_ip
                                    ));
                                }
                                let can_outcome = canonical
                                    .details
                                    .get("outcome")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("");
                                if outcome_str != can_outcome {
                                    mismatches.push(format!(
                                        "details.outcome 불일치 (기대: '{can_outcome}', 실제: '{outcome_str}')"
                                    ));
                                }
                                let can_raw = canonical.details.get("raw_measurement");
                                if Some(raw_val) != can_raw {
                                    mismatches.push("details.raw_measurement 불일치".to_string());
                                }
                            }
                            Err(adapter_errs) => {
                                mismatches.push(format!(
                                    "trace_to_quick_result 어댑터 검증 실패: {}",
                                    adapter_errs.join("; ")
                                ));
                            }
                        }
                    }
                    Err(_) => {
                        mismatches.push(
                            "raw_measurement를 TraceMeasurement 구조로 역직렬화할 수 없습니다."
                                .to_string(),
                        );
                    }
                }
            }

            if mismatches.is_empty() {
                res
            } else {
                let err_text = format!(
                    "Traceroute 백엔드 결과 무결성 위반: {}",
                    mismatches.join("; ")
                );
                errors.push(err_text.clone());
                make_local_error_result(
                    ctx,
                    QuickFeature::IcmpTraceroute,
                    expected_ip,
                    err_text,
                )
            }
        }
        Err(err_list) => {
            let err_text = format!("백엔드 Traceroute 프로브 실행 오류: {}", err_list.join("; "));
            errors.push(err_text.clone());
            make_local_error_result(
                ctx,
                QuickFeature::IcmpTraceroute,
                expected_ip,
                err_text,
            )
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
    let is_ip = parsed_ip.is_some();

    let has_dns_feature = planned_target.features.contains(&QuickFeature::DnsLookup);
    let needs_resolution = planned_target.requires_resolution;

    let should_resolve = if is_ip {
        has_dns_feature
    } else {
        needs_resolution || has_dns_feature
    };

    let dns_ctx = QuickContext {
        session_id: exec_ctx.session_id.clone(),
        timestamp_iso8601: exec_ctx.timestamp_iso8601.clone(),
        source_host: exec_ctx.source_host.clone(),
        target_host: planned_target.target.host.clone(),
        target_port: planned_target.target.port,
    };

    let mut dns_measurement: Option<DnsMeasurement> = None;
    let mut dns_quick_result: Option<Result<QuickResult, Vec<String>>> = None;
    let mut selected_ip: Option<IpAddr> = parsed_ip;
    let mut dns_failed = false;
    let mut dns_failure_reason: Option<String> = None;

    // 선행 DNS 해석이 필요한 경우 대상당 정확히 1회만 호출
    if should_resolve {
        if exec_ctx.cancel.load(Ordering::SeqCst) {
            dns_failed = true;
            dns_failure_reason = Some("DNS 해석 시작 전 취소 플래그가 감지되었습니다.".to_string());
        } else {
            exec_ctx.counters.dns_lookup.fetch_add(1, Ordering::SeqCst);
            let timeout = Duration::from_millis(exec_ctx.tcp_timeout_ms);
            let dns_future =
                exec_ctx
                    .backend
                    .resolve(dns_ctx.clone(), timeout, Arc::clone(&exec_ctx.cancel));
            let res = dns_future.await;

            match res {
                Ok(measurement) => {
                    let q_res = dns_to_quick_result(&dns_ctx, &measurement);
                    match q_res {
                        Ok(verified_q_res) => {
                            if measurement.outcome == crate::dns_engine::OUTCOME_RESOLVED {
                                if let Some(first_addr_str) = measurement.addresses.first() {
                                    if let Ok(first_sock) = first_addr_str.parse::<SocketAddr>() {
                                        let ip = first_sock.ip();
                                        if is_safe_resolved_ip(ip, planned_target.target.port) {
                                            if !is_ip {
                                                selected_ip = Some(ip);
                                            }
                                        } else {
                                            dns_failed = true;
                                            dns_failure_reason = Some(format!(
                                                "해석된 첫 번째 주소('{ip}')가 안전하지 않은 주소(미지정/멀티캐스트/브로드캐스트/링크로컬)로 거부되었습니다."
                                            ));
                                        }
                                    } else {
                                        dns_failed = true;
                                        dns_failure_reason = Some(format!(
                                            "해석된 주소('{first_addr_str}')가 정규 SocketAddr 표기가 아닙니다."
                                        ));
                                    }
                                } else {
                                    dns_failed = true;
                                    dns_failure_reason = Some(
                                        "RESOLVED 상태이나 반환된 주소 목록이 비어 있습니다."
                                            .to_string(),
                                    );
                                }
                            } else {
                                dns_failed = true;
                                dns_failure_reason = Some(format!(
                                    "DNS 해석 결과가 성공(RESOLVED)이 아닙니다 (결과 상태: '{}').",
                                    measurement.outcome
                                ));
                            }
                            dns_quick_result = Some(Ok(verified_q_res));
                            // 유효성 검증(dns_to_quick_result)을 통과한 valid한 DTO만 보존 (불량 원문 반사 방지)
                            dns_measurement = Some(measurement);
                        }
                        Err(val_errs) => {
                            let msg = format!("DNS 결과 유효성 검증 실패: {}", val_errs.join("; "));
                            errors.push(msg.clone());
                            dns_failed = true;
                            dns_failure_reason = Some(msg);
                            dns_quick_result = Some(Err(val_errs));
                        }
                    }
                }
                Err(backend_errs) => {
                    let msg = format!("DNS 백엔드 호출 실패: {}", backend_errs.join("; "));
                    errors.push(msg.clone());
                    dns_failed = true;
                    dns_failure_reason = Some(msg);
                    dns_quick_result = Some(Err(backend_errs));
                }
            }
        }
    }

    // 도메인 대상인 경우 DNS 해석 실패 시 연결 승격 금지
    if !is_ip && dns_failed {
        selected_ip = None;
    }

    // 선택된 기능들을 순서대로 처리
    for (feature_idx, feature) in planned_target.features.iter().enumerate() {
        let ctx = QuickContext {
            session_id: exec_ctx.session_id.clone(),
            timestamp_iso8601: exec_ctx.timestamp_iso8601.clone(),
            source_host: exec_ctx.source_host.clone(),
            target_host: planned_target.target.host.clone(),
            target_port: planned_target.target.port,
        };

        match feature {
            QuickFeature::DnsLookup => {
                if let Some(dns_res) = &dns_quick_result {
                    match dns_res {
                        Ok(q_res) => {
                            results.push((feature_idx, q_res.clone()));
                        }
                        Err(errs) => {
                            let err_msg = format!("DNS 해석 실패: {}", errs.join("; "));
                            let local_err = make_local_error_result(
                                &ctx,
                                QuickFeature::DnsLookup,
                                None,
                                err_msg,
                            );
                            results.push((feature_idx, local_err));
                        }
                    }
                } else if exec_ctx.cancel.load(Ordering::SeqCst) {
                    let cancel_res = make_local_error_result(
                        &ctx,
                        QuickFeature::DnsLookup,
                        None,
                        "진단 실행 취소로 인해 DNS 조회가 실행되지 않았습니다.".to_string(),
                    );
                    results.push((feature_idx, cancel_res));
                } else {
                    let unavail_res = make_unavailable_result(
                        &ctx,
                        QuickFeature::DnsLookup,
                        "DNS 조회가 실행되지 않았습니다.".to_string(),
                    );
                    results.push((feature_idx, unavail_res));
                }
            }

            QuickFeature::TcpConnect => {
                // 선행 DNS 해석 완료 직후 취소 시 해당 의존 기능만 건너뛰고 완료된 DNS 결과는 보존
                if exec_ctx.cancel.load(Ordering::SeqCst) {
                    continue;
                }

                let Some(ip) = selected_ip else {
                    let reason = dns_failure_reason.clone().unwrap_or_else(|| {
                        format!(
                            "TCP 연결 프로브를 위한 유효한 대상 IP 주소가 없습니다: '{}'",
                            planned_target.target.host
                        )
                    });
                    let mut res = make_unavailable_result(&ctx, QuickFeature::TcpConnect, reason);
                    if !is_ip && let Some(ref dns_m) = dns_measurement {
                        append_dns_raw_limitation(&mut res, dns_m);
                    }
                    results.push((feature_idx, res));
                    continue;
                };

                let socket_addr = SocketAddr::new(ip, planned_target.target.port);
                let timeout = Duration::from_millis(exec_ctx.tcp_timeout_ms);

                exec_ctx.counters.tcp_connect.fetch_add(1, Ordering::SeqCst);

                let backend_future = exec_ctx.backend.tcp(
                    ctx.clone(),
                    socket_addr,
                    timeout,
                    Arc::clone(&exec_ctx.cancel),
                );
                let backend_res = backend_future.await;

                let mut verified = verify_backend_result(
                    &ctx,
                    QuickFeature::TcpConnect,
                    Some(ip),
                    backend_res,
                    &mut errors,
                );

                if !is_ip && let Some(ref dns_m) = dns_measurement {
                    append_domain_resolution_limitations(&mut verified, dns_m, ip);
                }

                results.push((feature_idx, verified));
            }

            QuickFeature::IcmpPing => {
                // 선행 DNS 해석 완료 직후 취소 시 해당 의존 기능만 건너뛰고 완료된 DNS 결과는 보존
                if exec_ctx.cancel.load(Ordering::SeqCst) {
                    continue;
                }

                let Some(ip) = selected_ip else {
                    let reason = dns_failure_reason.clone().unwrap_or_else(|| {
                        format!(
                            "ICMP Ping 프로브를 위한 유효한 대상 IP 주소가 없습니다: '{}'",
                            planned_target.target.host
                        )
                    });
                    let mut res = make_unavailable_result(&ctx, QuickFeature::IcmpPing, reason);
                    if !is_ip && let Some(ref dns_m) = dns_measurement {
                        append_dns_raw_limitation(&mut res, dns_m);
                    }
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

                let mut verified = verify_backend_result(
                    &ctx,
                    QuickFeature::IcmpPing,
                    Some(ip),
                    backend_res,
                    &mut errors,
                );

                if !is_ip && let Some(ref dns_m) = dns_measurement {
                    append_domain_resolution_limitations(&mut verified, dns_m, ip);
                }

                results.push((feature_idx, verified));
            }

            QuickFeature::LocalNetwork => {
                // 선행 DNS 해석 완료 직후 취소 시 해당 의존 기능만 건너뛰고 완료된 DNS 결과는 보존
                if exec_ctx.cancel.load(Ordering::SeqCst) {
                    continue;
                }

                let Some(ip) = selected_ip else {
                    let reason = dns_failure_reason.clone().unwrap_or_else(|| {
                        format!(
                            "로컬 네트워크 스냅샷 수집을 위한 유효한 대상 IP 주소가 없습니다: '{}'",
                            planned_target.target.host
                        )
                    });
                    let mut res = make_unavailable_result(&ctx, QuickFeature::LocalNetwork, reason);
                    if !is_ip && let Some(ref dns_m) = dns_measurement {
                        append_dns_raw_limitation(&mut res, dns_m);
                    }
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

                let mut verified = verify_backend_result(
                    &ctx,
                    QuickFeature::LocalNetwork,
                    Some(ip),
                    backend_res,
                    &mut errors,
                );

                if !is_ip && let Some(ref dns_m) = dns_measurement {
                    append_domain_resolution_limitations(&mut verified, dns_m, ip);
                }

                results.push((feature_idx, verified));
            }

            QuickFeature::IcmpTraceroute => {
                // 선행 DNS 해석 완료 직후 취소 시 해당 의존 기능만 건너뛰고 완료된 DNS 결과는 보존
                if exec_ctx.cancel.load(Ordering::SeqCst) {
                    continue;
                }

                let Some(ip) = selected_ip else {
                    let reason = dns_failure_reason.clone().unwrap_or_else(|| {
                        format!(
                            "ICMP Traceroute 프로브를 위한 유효한 대상 IP 주소가 없습니다: '{}'",
                            planned_target.target.host
                        )
                    });
                    let mut res =
                        make_unavailable_result(&ctx, QuickFeature::IcmpTraceroute, reason);
                    if !is_ip && let Some(ref dns_m) = dns_measurement {
                        append_dns_raw_limitation(&mut res, dns_m);
                    }
                    results.push((feature_idx, res));
                    continue;
                };

                let trace_options = TraceOptions::default();

                exec_ctx
                    .counters
                    .icmp_traceroute
                    .fetch_add(1, Ordering::SeqCst);

                let backend_future = exec_ctx.backend.trace(
                    ctx.clone(),
                    ip,
                    trace_options,
                    Arc::clone(&exec_ctx.cancel),
                );
                let backend_res = backend_future.await;

                let mut verified = verify_trace_backend_result(
                    &ctx,
                    Some(ip),
                    backend_res,
                    &mut errors,
                );

                if !is_ip && let Some(ref dns_m) = dns_measurement {
                    append_domain_resolution_limitations(&mut verified, dns_m, ip);
                }

                results.push((feature_idx, verified));
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
/// - 사전 검증을 통해 유효하지 않은 대상/옵션 입력을 사전에 차단합니다.
/// - 도메인 및 IP 대상 모두 단일 대상 안에서 필요한 사전 DNS 해석을 처리합니다.
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
