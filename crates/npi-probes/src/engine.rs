//! G2-A 단일 대상 프로브 및 호스트 스냅샷 실행 엔진.
//!
//! - 입력 프로필을 `npi_core::validate_profile`로 먼저 검증한다.
//! - G2-A 정책에 따라 리터럴 IPv4/IPv6 루프백(`127.0.0.1`, `::1` 등) 단일 대상만 허용하며,
//!   도메인 이름(`DNS_ERROR`/`UNAVAILABLE`), 비루프백 주소, 포트 0, 재시도(`retries > 0`) 요청은
//!   어떠한 수집기나 소켓도 호출하기 전에 즉시 거부한다.
//! - 선택된 기능 중 `tcp_connect`, `icmp_ping`, `nic_inventory`, `route_table` 4개만 순차 실행한다.
//! - `nic_inventory` 또는 `route_table`이 선택된 경우 호스트 스냅샷은 실행당 정확히 1회만 수집하여 공유한다.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use npi_core::{
    FeatureResult, Profile, Target, canonical_registry, plan_features, validate_profile,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    host::{HostSnapshot, collect_host_snapshot},
    icmp::{IcmpMeasurement, ping_once},
    tcp::{TcpMeasurement, connect_once},
};

/// G2-A 중간 측정 엔벨로프 포맷 버전 문자열.
pub const MEASUREMENT_FORMAT_G2A: &str = "npi-g2-a-1";

/// G2-A 단계에서 실제 측정을 지원하는 기능 ID 목록.
pub const SUPPORTED_G2A_FEATURES: [&str; 4] =
    ["tcp_connect", "icmp_ping", "nic_inventory", "route_table"];

/// G2-A ICMP 동기 호출의 계약상 최대 타임아웃 상한(밀리초).
const MAX_ICMP_TIMEOUT_MS: u64 = 2_000;

/// 엔진 실행 중 실제 호출된 수집기 및 프로브 횟수 DTO.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectorCounts {
    pub host_network_snapshot: u64,
    pub tcp_connect: u64,
    pub icmp_ping: u64,
}

/// G2-A 단일 대상 측정 결과 엔벨로프 DTO.
/// 정규 G1 `Session` 1.1 스키마를 변형하지 않고 G2-A 중간 측정 결과를 전달한다.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EngineEnvelope {
    pub measurement_format: String,
    pub profile_id: String,
    pub target: Target,
    pub feature_results: Vec<FeatureResult>,
    pub measurements: BTreeMap<String, Value>,
    pub collector_counts: CollectorCounts,
    pub limitations: Vec<String>,
}

/// 프로필을 검증하고 G2-A 루프백 단일 대상 측정을 순차적으로 실행한다.
pub async fn run_profile(
    profile: &serde_json::Value,
    cancelled: Arc<AtomicBool>,
) -> Result<serde_json::Value, Vec<String>> {
    validate_profile(profile)?;

    let parsed_profile: Profile = serde_json::from_value(profile.clone())
        .map_err(|err| vec![format!("프로필 역직렬화 실패: {err}")])?;

    if parsed_profile.target.port == 0 {
        return Err(vec![
            "target.port는 0일 수 없습니다 (LOCAL_ERROR)".to_string(),
        ]);
    }

    let target_ip: IpAddr = match parsed_profile.target.host.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => {
            return Err(vec![format!(
                "G2-A 단계는 리터럴 IPv4/IPv6 주소만 지원하며 백그라운드 도메인 해석을 수행하지 않습니다 (DNS_ERROR / UNAVAILABLE): {}",
                parsed_profile.target.host
            )]);
        }
    };

    if target_ip.is_unspecified() || target_ip.is_multicast() || !target_ip.is_loopback() {
        return Err(vec![format!(
            "G2-A 개발자 CLI 루프백 전용 정책 위반: 비루프백 또는 허용되지 않는 대상 주소({})는 실행할 수 없습니다 (loopback only)",
            parsed_profile.target.host
        )]);
    }

    if parsed_profile.limits.retries > 0 {
        return Err(vec![format!(
            "G2-A 단계는 재시도(limits.retries={})를 지원하지 않으며 retries=0만 허용합니다",
            parsed_profile.limits.retries
        )]);
    }

    let registry = canonical_registry();
    let capabilities = BTreeSet::new();
    let plan = plan_features(profile, &registry, &capabilities)?;

    let execution_order: Vec<String> = plan
        .get("execution_order")
        .cloned()
        .ok_or_else(|| vec!["실행 계획에 execution_order 필드가 없습니다".to_string()])
        .and_then(|v| {
            serde_json::from_value(v)
                .map_err(|err| vec![format!("execution_order 역직렬화 실패: {err}")])
        })?;

    let mut feature_results: Vec<FeatureResult> = plan
        .get("feature_results")
        .cloned()
        .ok_or_else(|| vec!["실행 계획에 feature_results 필드가 없습니다".to_string()])
        .and_then(|v| {
            serde_json::from_value(v)
                .map_err(|err| vec![format!("feature_results 역직렬화 실패: {err}")])
        })?;

    let selected_set: BTreeSet<&str> = parsed_profile
        .selected_features
        .iter()
        .map(String::as_str)
        .collect();

    // 선택되었으나 G2-A에서 구현되지 않은 기능은 모두 UNAVAILABLE(UNKNOWN)로 고정한다.
    for row in &mut feature_results {
        let fid = row.feature_id.as_str();
        if !selected_set.contains(fid) {
            continue;
        }
        if !SUPPORTED_G2A_FEATURES.contains(&fid) {
            row.status = "UNAVAILABLE".to_string();
            row.classification = Some("UNKNOWN".to_string());
            row.evidence_ids.clear();
            row.started_at_utc = None;
            row.ended_at_utc = None;
            row.duration_ms = None;
            row.error_code = None;
            row.limitations.retain(|msg| {
                !msg.contains("not executed") && !msg.contains("아직 실행되지 않았습니다")
            });
            row.limitations.push(format!(
                "'{}' 기능은 G2-A 단일 대상 기초 측정 단계에서 아직 구현되지 않았습니다 (UNAVAILABLE in G2-A)",
                row.feature_id
            ));
            row.next_checks = vec![
                "G2-A 지원 기능(tcp_connect, icmp_ping, nic_inventory, route_table)을 선택하거나 후속 단계 구현을 확인하세요"
                    .to_string(),
            ];
        }
    }

    let executable_order: Vec<String> = execution_order
        .into_iter()
        .filter(|fid| SUPPORTED_G2A_FEATURES.contains(&fid.as_str()))
        .collect();

    let mut collector_counts = CollectorCounts {
        host_network_snapshot: 0,
        tcp_connect: 0,
        icmp_ping: 0,
    };
    let mut measurements: BTreeMap<String, Value> = BTreeMap::new();
    let mut cached_snapshot: Option<(HostSnapshot, u64)> = None;
    let mut run_cancelled = cancelled.load(Ordering::SeqCst);
    let mut icmp_timeout_bounded_note: Option<String> = None;

    for fid in &executable_order {
        if run_cancelled || cancelled.load(Ordering::SeqCst) {
            run_cancelled = true;
            if let Some(row) = find_feature_row_mut(&mut feature_results, fid) {
                mark_feature_cancelled_before_call(row);
            }
            continue;
        }

        match fid.as_str() {
            "nic_inventory" | "route_table" => {
                let (snapshot, elapsed_ms) = match &cached_snapshot {
                    Some(pair) => pair,
                    None => {
                        let start = Instant::now();
                        let snap = collect_host_snapshot(target_ip);
                        let elapsed = start.elapsed().as_millis() as u64;
                        collector_counts.host_network_snapshot += 1;
                        cached_snapshot.insert((snap, elapsed))
                    }
                };

                let snap_val = serde_json::to_value(snapshot)
                    .map_err(|err| vec![format!("호스트 스냅샷 직렬화 실패: {err}")])?;
                measurements.insert(fid.clone(), snap_val);

                if let Some(row) = find_feature_row_mut(&mut feature_results, fid) {
                    apply_host_snapshot_result(row, fid, snapshot, *elapsed_ms);
                }

                // 동기 호스트 스냅샷 수집이 완료된 후 취소 신호가 감지된 경우,
                // 이미 완료된 관찰 데이터는 CANCELLED로 덮어쓰지 않고 보존하며 이후 미호출 수집기만 취소 처리한다.
                if cancelled.load(Ordering::SeqCst) {
                    run_cancelled = true;
                }
            }
            "tcp_connect" => {
                // 제품 TCP 연결 타임아웃은 프로필의 limits.tcp_timeout_ms를 변경 없이 그대로 사용한다.
                let target_sock = SocketAddr::new(target_ip, parsed_profile.target.port);
                let timeout = Duration::from_millis(parsed_profile.limits.tcp_timeout_ms);
                let tcp_meas = connect_once(target_sock, timeout, Arc::clone(&cancelled)).await;
                collector_counts.tcp_connect += 1;

                if tcp_meas.outcome == "CANCELLED" || cancelled.load(Ordering::SeqCst) {
                    run_cancelled = true;
                }

                let meas_val = serde_json::to_value(&tcp_meas)
                    .map_err(|err| vec![format!("TCP 측정 결과 직렬화 실패: {err}")])?;
                measurements.insert("tcp_connect".to_string(), meas_val);

                if let Some(row) = find_feature_row_mut(&mut feature_results, "tcp_connect") {
                    apply_tcp_result(row, &tcp_meas);
                }
            }
            "icmp_ping" => {
                let requested_ms = parsed_profile.limits.tcp_timeout_ms;
                let (timeout, timeout_note) = resolve_icmp_timeout(requested_ms);
                icmp_timeout_bounded_note = Some(timeout_note);

                let icmp_meas = ping_once(target_ip, timeout, Arc::clone(&cancelled));
                collector_counts.icmp_ping += 1;

                if icmp_meas.outcome == "CANCELLED" || cancelled.load(Ordering::SeqCst) {
                    run_cancelled = true;
                }

                let meas_val = serde_json::to_value(&icmp_meas)
                    .map_err(|err| vec![format!("ICMP 측정 결과 직렬화 실패: {err}")])?;
                measurements.insert("icmp_ping".to_string(), meas_val);

                if let Some(row) = find_feature_row_mut(&mut feature_results, "icmp_ping") {
                    apply_icmp_result(row, &icmp_meas, icmp_timeout_bounded_note.as_deref());
                }
            }
            _ => {}
        }
    }

    let mut limitations = vec![
        "본 출력은 G2-A 단일 대상 중간 측정 엔벨로프(npi-g2-a-1)이며 정규 Session 1.1 문서나 최종 보고서가 아닙니다"
            .to_string(),
        "실제 UTC 시각 및 Session 1.1 통합은 후속 단계 대상이므로 started_at_utc와 ended_at_utc는 null로 유지하고 Instant 기반 경과 시간만 기록합니다"
            .to_string(),
        "원시 측정 DTO는 메모리 내 measurements 객체로만 반환되며 영구 증거 파일로 아카이브되지 않았으므로 evidence_ids는 빈 배열([])로 유지합니다"
            .to_string(),
        "G2-A 개발자 CLI 정책에 따라 리터럴 IPv4/IPv6 루프백(127.0.0.1, ::1) 단일 대상만 허용하며 패킷 캡처·경로 추적·백그라운드 DNS 조회·PDF 생성·반복 모니터는 수행하지 않습니다"
            .to_string(),
    ];

    if collector_counts.host_network_snapshot > 0 {
        limitations.push(
            "호스트 네트워크 스냅샷(GetAdaptersAddresses/GetIpForwardTable2/GetBestRoute2)은 동기 네이티브 호출이므로 실행 시간이 소요될 수 있으며, OS 라우팅 선택 결과는 원격 구간 연결성 증거가 아닙니다"
                .to_string(),
        );
    }

    if let Some(note) = icmp_timeout_bounded_note {
        limitations.push(note);
    }

    let envelope = EngineEnvelope {
        measurement_format: MEASUREMENT_FORMAT_G2A.to_string(),
        profile_id: parsed_profile.profile_id,
        target: parsed_profile.target,
        feature_results,
        measurements,
        collector_counts,
        limitations,
    };

    serde_json::to_value(envelope).map_err(|err| vec![format!("결과 엔벨로프 직렬화 실패: {err}")])
}

/// 프로필의 `limits.tcp_timeout_ms`는 변경하지 않고,
/// G2-A ICMP 동기 프로브 호출용 타임아웃(`clamp(1, 2000)`)과 실제 선택된 타임아웃 한계 설명을 반환한다.
fn resolve_icmp_timeout(tcp_timeout_ms: u64) -> (Duration, String) {
    let bounded_ms = tcp_timeout_ms.clamp(1, MAX_ICMP_TIMEOUT_MS);
    let note = if tcp_timeout_ms > MAX_ICMP_TIMEOUT_MS {
        format!(
            "프로필 limits.tcp_timeout_ms({tcp_timeout_ms}ms)가 G2-A ICMP 동기 대기 상한({MAX_ICMP_TIMEOUT_MS}ms)을 초과하여 icmp_ping 호출 타임아웃을 {bounded_ms}ms(clamp 1..={MAX_ICMP_TIMEOUT_MS}ms)로 제한했습니다 (제품 TCP 타임아웃 {tcp_timeout_ms}ms는 변경하지 않음)"
        )
    } else {
        format!(
            "G2-A icmp_ping 호출 타임아웃은 프로필 limits.tcp_timeout_ms({tcp_timeout_ms}ms)에 clamp(1, {MAX_ICMP_TIMEOUT_MS})를 적용한 실제 선택값 {bounded_ms}ms를 사용했습니다 (제품 TCP 타임아웃 {tcp_timeout_ms}ms는 변경하지 않음)"
        )
    };
    (Duration::from_millis(bounded_ms), note)
}

fn find_feature_row_mut<'a>(
    rows: &'a mut [FeatureResult],
    feature_id: &str,
) -> Option<&'a mut FeatureResult> {
    rows.iter_mut().find(|r| r.feature_id == feature_id)
}

fn mark_feature_cancelled_before_call(row: &mut FeatureResult) {
    row.status = "CANCELLED".to_string();
    row.classification = Some("UNKNOWN".to_string());
    row.evidence_ids.clear();
    row.started_at_utc = None;
    row.ended_at_utc = None;
    row.duration_ms = None;
    row.error_code = None;
    row.limitations = vec![
        "실행 전 취소 신호가 확인되어 프로브/수집기를 호출하지 않았으며 가짜 측정 시간이나 증거를 생성하지 않았습니다 (cancelled)"
            .to_string(),
    ];
    row.next_checks = vec!["취소 사유를 확인한 뒤 필요 시 측정을 다시 실행하세요".to_string()];
}

fn is_snapshot_non_windows_unavailable(snapshot: &HostSnapshot) -> bool {
    let all_null = snapshot.adapters.is_null()
        && snapshot.routes.is_null()
        && snapshot.selected_route.is_null();
    if cfg!(not(windows)) && all_null {
        return true;
    }
    let mentions_unavail = snapshot
        .limitations
        .iter()
        .chain(snapshot.errors.iter())
        .any(|s| {
            let upper = s.to_ascii_uppercase();
            upper.contains("UNAVAILABLE")
                || s.contains("비 Windows")
                || upper.contains("NON-WINDOWS")
        });
    all_null && mentions_unavail
}

fn is_nonempty_object_array(val: &Value) -> bool {
    val.as_array().is_some_and(|arr| {
        !arr.is_empty()
            && arr
                .iter()
                .all(|item| item.as_object().is_some_and(|obj| !obj.is_empty()))
    })
}

fn has_valid_host_component(feature_id: &str, snapshot: &HostSnapshot) -> bool {
    match feature_id {
        "nic_inventory" => is_nonempty_object_array(&snapshot.adapters),
        "route_table" => {
            let routes_present = is_nonempty_object_array(&snapshot.routes);
            let selected_route_present = snapshot
                .selected_route
                .as_object()
                .is_some_and(|obj| !obj.is_empty());
            routes_present && selected_route_present
        }
        _ => false,
    }
}

fn apply_host_snapshot_result(
    row: &mut FeatureResult,
    feature_id: &str,
    snapshot: &HostSnapshot,
    elapsed_ms: u64,
) {
    row.evidence_ids.clear();
    row.started_at_utc = None;
    row.ended_at_utc = None;
    row.duration_ms = Some(elapsed_ms);
    row.error_code = None;

    let mut lims = snapshot.limitations.clone();
    for err in &snapshot.errors {
        push_unique(&mut lims, format!("호스트 스냅샷 오류: {err}"));
    }
    push_unique(
        &mut lims,
        "호스트 네이티브 동기 API 호출은 블로킹 실행 시간이 소요될 수 있습니다".to_string(),
    );
    push_unique(
        &mut lims,
        "OS 어댑터/라우팅 테이블 및 경로 선택 결과는 로컬 설정 관찰값이며 원격 연결성 증거가 아닙니다"
            .to_string(),
    );
    push_unique(
        &mut lims,
        "원시 측정값이 영구 아카이브 파일로 저장되지 않았으므로 evidence_ids는 빈 배열([])입니다"
            .to_string(),
    );

    if is_snapshot_non_windows_unavailable(snapshot) {
        row.status = "UNAVAILABLE".to_string();
        row.classification = Some("UNKNOWN".to_string());
        row.limitations = lims;
        row.next_checks = vec![
            "Windows 호스트 환경에서 실행하여 네이티브 어댑터/라우트 정보를 수집하세요".to_string(),
        ];
        return;
    }

    let component_present = has_valid_host_component(feature_id, snapshot);

    if !component_present {
        push_unique(
            &mut lims,
            format!(
                "'{feature_id}' 필수 구성요소 데이터가 누락되었거나 유효하지 않아 ERROR(UNKNOWN)로 기록했습니다"
            ),
        );
        row.status = "ERROR".to_string();
        row.classification = Some("UNKNOWN".to_string());
        row.limitations = lims;
        row.next_checks = vec![
            "호스트 네트워크 API 오류 메시지를 확인하고 인터페이스 및 라우팅 상태를 점검하세요"
                .to_string(),
        ];
    } else if !snapshot.errors.is_empty() {
        push_unique(
            &mut lims,
            format!(
                "'{feature_id}' 구성요소 데이터는 관찰되었으나 호스트 스냅샷 수집 오류가 함께 발생하여 부분 수집을 은폐하지 않고 WARN(OBSERVED)으로 기록했습니다"
            ),
        );
        row.status = "WARN".to_string();
        row.classification = Some("OBSERVED".to_string());
        row.limitations = lims;
        row.next_checks = vec![
            "관찰된 로컬 어댑터/라우트 데이터와 함께 호스트 스냅샷 오류 원인을 점검하세요"
                .to_string(),
        ];
    } else {
        row.status = "PASS".to_string();
        row.classification = Some("OBSERVED".to_string());
        row.limitations = lims;
        row.next_checks = vec![
            "수집된 로컬 어댑터 및 OS 라우트 선택 결과를 확인하고 실제 프로브(tcp_connect, icmp_ping) 결과와 함께 비교하세요"
                .to_string(),
        ];
    }
}

pub fn apply_tcp_result(row: &mut FeatureResult, meas: &TcpMeasurement) {
    row.evidence_ids.clear();
    row.started_at_utc = None;
    row.ended_at_utc = None;
    row.duration_ms = Some(meas.elapsed_ms);
    row.error_code = meas.error_code.map(i64::from);

    let mut lims = meas.limitations.clone();
    if let Some(ref msg) = meas.error_message {
        push_unique(&mut lims, format!("OS 소켓 오류 메시지: {msg}"));
    }
    push_unique(
        &mut lims,
        "소켓 연결 결과는 OS API 수준의 관찰값이며 패킷 캡처 없이는 SYN 또는 RST 패킷 실제 관찰이나 차단 장비를 단정할 수 없습니다"
            .to_string(),
    );
    push_unique(
        &mut lims,
        "원시 측정값이 영구 아카이브 파일로 저장되지 않았으므로 evidence_ids는 빈 배열([])입니다"
            .to_string(),
    );
    row.limitations = lims;

    match meas.outcome.as_str() {
        "CONNECTED" => {
            row.status = "PASS".to_string();
            row.classification = Some("OBSERVED".to_string());
            row.next_checks = vec![
                "TCP 3-way 핸드셰이크 연결이 확인되었습니다 (애플리케이션 바이트 미전송)"
                    .to_string(),
            ];
        }
        "REFUSED" | "RESET" | "TIMED_OUT" | "UNREACHABLE" => {
            row.status = "FAIL".to_string();
            row.classification = Some("OBSERVED".to_string());
            row.next_checks = vec![
                "대상 포트 리스닝 상태 및 경로/방화벽 정책을 점검하되 패킷 캡처 없이 차단 원인을 단정하지 마세요"
                    .to_string(),
            ];
        }
        "CANCELLED" => {
            row.status = "CANCELLED".to_string();
            row.classification = Some("UNKNOWN".to_string());
            row.next_checks = vec!["취소 요청에 의해 TCP 연결 시도가 중단되었습니다".to_string()];
        }
        _ => {
            row.status = "ERROR".to_string();
            row.classification = if meas.error_code.is_some() {
                Some("OBSERVED".to_string())
            } else {
                Some("UNKNOWN".to_string())
            };
            row.next_checks = vec![
                "대상 주소/포트 범위 및 로컬 소켓 설정 오류(LOCAL_ERROR)를 확인하세요".to_string(),
            ];
        }
    }
}

fn apply_icmp_result(row: &mut FeatureResult, meas: &IcmpMeasurement, timeout_note: Option<&str>) {
    row.evidence_ids.clear();
    row.started_at_utc = None;
    row.ended_at_utc = None;
    row.duration_ms = Some(meas.elapsed_ms);
    row.error_code = meas
        .error_code
        .or_else(|| meas.ip_status.filter(|&status| status != 0))
        .map(i64::from);

    let mut lims = meas.limitations.clone();
    if let Some(note) = timeout_note {
        push_unique(&mut lims, note.to_string());
    }
    push_unique(
        &mut lims,
        "ICMP 에코 무응답이나 타임아웃은 TCP 서비스 실패 또는 차단 장비 확정을 뜻하지 않으며 패킷 캡처 증거가 아닙니다"
            .to_string(),
    );
    push_unique(
        &mut lims,
        "원시 측정값이 영구 아카이브 파일로 저장되지 않았으므로 evidence_ids는 빈 배열([])입니다"
            .to_string(),
    );
    row.limitations = lims;

    match meas.outcome.as_str() {
        "REPLY" => {
            row.status = "PASS".to_string();
            row.classification = Some("OBSERVED".to_string());
            row.next_checks = vec![
                "ICMP 에코 응답이 관찰되었습니다 (TCP 포트 연결성과는 별개입니다)".to_string(),
            ];
        }
        "TIMEOUT" | "TIMED_OUT" | "UNREACHABLE" => {
            row.status = "WARN".to_string();
            row.classification = Some("OBSERVED".to_string());
            row.next_checks = vec![
                "ICMP 응답 지연/미수신이 관찰되었으나 ICMP 정책 제한일 수 있으므로 tcp_connect 결과와 함께 확인하세요"
                    .to_string(),
            ];
        }
        "CANCELLED" => {
            row.status = "CANCELLED".to_string();
            row.classification = Some("UNKNOWN".to_string());
            row.next_checks = vec!["취소 요청에 의해 ICMP 측정이 중단되었습니다".to_string()];
        }
        "UNAVAILABLE" => {
            row.status = "UNAVAILABLE".to_string();
            row.classification = Some("UNKNOWN".to_string());
            row.next_checks = vec!["Windows IcmpSendEcho2 지원 환경인지 확인하세요".to_string()];
        }
        _ => {
            row.status = "ERROR".to_string();
            row.classification = if meas.error_code.is_some() || meas.ip_status.is_some() {
                Some("OBSERVED".to_string())
            } else {
                Some("UNKNOWN".to_string())
            };
            row.next_checks =
                vec!["ICMP 호출 오류 코드 및 입력 제한 조건을 확인하세요".to_string()];
        }
    }
}

fn push_unique(list: &mut Vec<String>, item: String) {
    if !list.iter().any(|existing| existing == &item) {
        list.push(item);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// 테스트 전용(`TEST-ONLY`) 계획 단계 초기 `FeatureResult` 행 생성 헬퍼.
    /// 실제 수집기나 소켓을 전혀 호출하지 않는다.
    fn test_only_planned_feature_row(feature_id: &str, group_id: &str) -> FeatureResult {
        FeatureResult {
            feature_id: feature_id.to_string(),
            group_id: group_id.to_string(),
            status: "WARN".to_string(),
            classification: Some("UNKNOWN".to_string()),
            evidence_ids: vec!["stale-evidence-must-be-cleared".to_string()],
            started_at_utc: Some("2026-01-01T00:00:00Z".to_string()),
            ended_at_utc: Some("2026-01-01T00:00:01Z".to_string()),
            duration_ms: None,
            error_code: Some(999),
            limitations: vec![
                "G1 실행 계획 단계이며 아직 실행되지 않았습니다 (not executed)".to_string(),
            ],
            next_checks: Vec::new(),
        }
    }

    /// 테스트 전용(`TEST-ONLY`) 완전 수집 합성 `HostSnapshot` 픽스처.
    /// 실제 호스트 인터페이스나 OS 라우팅 테이블이 아니다.
    fn test_only_fabricated_full_snapshot_fixture() -> HostSnapshot {
        HostSnapshot {
            adapters: json!([
                {
                    "interface_index": 1,
                    "name": "test-only-loopback-adapter-fixture",
                    "operational_status": "Up",
                    "ip_addresses": ["127.0.0.1/8"]
                }
            ]),
            routes: json!([
                {
                    "destination_prefix": "127.0.0.0/8",
                    "next_hop": "0.0.0.0",
                    "interface_index": 1,
                    "metric": 256
                }
            ]),
            selected_route: json!({
                "interface_index": 1,
                "source_ip": "127.0.0.1",
                "next_hop": "0.0.0.0",
                "note": "TEST-ONLY OS route selection fixture"
            }),
            errors: Vec::new(),
            limitations: vec!["[TEST-ONLY] 합성 호스트 스냅샷 픽스처 한계 설명".to_string()],
        }
    }

    #[test]
    fn host_snapshot_full_fixture_marks_pass_and_observed_without_fake_evidence() {
        let snapshot = test_only_fabricated_full_snapshot_fixture();

        let mut nic_row = test_only_planned_feature_row("nic_inventory", "G-NET");
        apply_host_snapshot_result(&mut nic_row, "nic_inventory", &snapshot, 7);

        assert_eq!(nic_row.status, "PASS");
        assert_eq!(nic_row.classification.as_deref(), Some("OBSERVED"));
        assert_eq!(nic_row.duration_ms, Some(7));
        assert!(nic_row.started_at_utc.is_none());
        assert!(nic_row.ended_at_utc.is_none());
        assert!(nic_row.evidence_ids.is_empty());
        assert!(nic_row.error_code.is_none());
        assert!(
            nic_row
                .limitations
                .iter()
                .any(|m| m.contains("[TEST-ONLY] 합성 호스트 스냅샷 픽스처 한계 설명"))
        );

        let mut route_row = test_only_planned_feature_row("route_table", "G-NET");
        apply_host_snapshot_result(&mut route_row, "route_table", &snapshot, 7);

        assert_eq!(route_row.status, "PASS");
        assert_eq!(route_row.classification.as_deref(), Some("OBSERVED"));
        assert_eq!(route_row.duration_ms, Some(7));
        assert!(route_row.started_at_utc.is_none());
        assert!(route_row.ended_at_utc.is_none());
        assert!(route_row.evidence_ids.is_empty());
        assert!(route_row.error_code.is_none());
    }

    #[test]
    fn host_snapshot_partial_fixture_with_errors_marks_warn_and_observed() {
        // 구성요소 데이터가 실제로 존재하더라도 snapshot.errors가 비어 있지 않으면
        // 부분 수집을 PASS로 은폐하지 않고 WARN + OBSERVED로 기록해야 한다.
        let mut partial_snapshot = test_only_fabricated_full_snapshot_fixture();
        partial_snapshot.errors =
            vec!["[TEST-ONLY] 일부 보조 테이블 수집 중 Win32 오류 발생".to_string()];

        let mut nic_row = test_only_planned_feature_row("nic_inventory", "G-NET");
        apply_host_snapshot_result(&mut nic_row, "nic_inventory", &partial_snapshot, 11);

        assert_eq!(nic_row.status, "WARN");
        assert_eq!(nic_row.classification.as_deref(), Some("OBSERVED"));
        assert_eq!(nic_row.duration_ms, Some(11));
        assert!(nic_row.started_at_utc.is_none());
        assert!(nic_row.ended_at_utc.is_none());
        assert!(nic_row.evidence_ids.is_empty());
        assert!(
            nic_row
                .limitations
                .iter()
                .any(|m| m.contains("[TEST-ONLY] 일부 보조 테이블 수집 중 Win32 오류 발생"))
        );
        assert!(
            nic_row
                .limitations
                .iter()
                .any(|m| m.contains("[TEST-ONLY] 합성 호스트 스냅샷 픽스처 한계 설명"))
        );

        let mut route_row = test_only_planned_feature_row("route_table", "G-NET");
        apply_host_snapshot_result(&mut route_row, "route_table", &partial_snapshot, 11);

        assert_eq!(route_row.status, "WARN");
        assert_eq!(route_row.classification.as_deref(), Some("OBSERVED"));
        assert_eq!(route_row.duration_ms, Some(11));
        assert!(route_row.started_at_utc.is_none());
        assert!(route_row.ended_at_utc.is_none());
        assert!(route_row.evidence_ids.is_empty());
        assert!(
            route_row
                .limitations
                .iter()
                .any(|m| m.contains("[TEST-ONLY] 일부 보조 테이블 수집 중 Win32 오류 발생"))
        );

        // 어댑터는 정상 수집되었으나 라우트 수집이 실패한 혼합 스냅샷 픽스처 검증:
        // nic_inventory는 WARN + OBSERVED, route_table은 ERROR + UNKNOWN이어야 한다.
        let mut adapters_only_partial = test_only_fabricated_full_snapshot_fixture();
        adapters_only_partial.routes = json!([]);
        adapters_only_partial.selected_route = Value::Null;
        adapters_only_partial.errors =
            vec!["[TEST-ONLY] GetIpForwardTable2 / GetBestRoute2 호출 실패".to_string()];

        let mut nic_mixed = test_only_planned_feature_row("nic_inventory", "G-NET");
        apply_host_snapshot_result(&mut nic_mixed, "nic_inventory", &adapters_only_partial, 15);
        assert_eq!(nic_mixed.status, "WARN");
        assert_eq!(nic_mixed.classification.as_deref(), Some("OBSERVED"));

        let mut route_mixed = test_only_planned_feature_row("route_table", "G-NET");
        apply_host_snapshot_result(&mut route_mixed, "route_table", &adapters_only_partial, 15);
        assert_eq!(route_mixed.status, "ERROR");
        assert_eq!(route_mixed.classification.as_deref(), Some("UNKNOWN"));
    }

    #[test]
    fn host_snapshot_failed_or_missing_component_fixture_marks_error_and_unknown() {
        // 1. 구성요소가 null이고 오류가 기록된 실패 픽스처
        let failed_snapshot = HostSnapshot {
            adapters: Value::Null,
            routes: Value::Null,
            selected_route: Value::Null,
            errors: vec!["[TEST-ONLY] 네이티브 호스트 API 호출 실패 (win32=5)".to_string()],
            limitations: vec!["[TEST-ONLY] 실패 픽스처 한계".to_string()],
        };

        let mut nic_row = test_only_planned_feature_row("nic_inventory", "G-NET");
        apply_host_snapshot_result(&mut nic_row, "nic_inventory", &failed_snapshot, 4);
        assert_eq!(nic_row.status, "ERROR");
        assert_eq!(nic_row.classification.as_deref(), Some("UNKNOWN"));
        assert_eq!(nic_row.duration_ms, Some(4));
        assert!(nic_row.started_at_utc.is_none());
        assert!(nic_row.ended_at_utc.is_none());
        assert!(nic_row.evidence_ids.is_empty());
        assert!(
            nic_row
                .limitations
                .iter()
                .any(|m| m.contains("[TEST-ONLY] 네이티브 호스트 API 호출 실패 (win32=5)"))
        );

        let mut route_row = test_only_planned_feature_row("route_table", "G-NET");
        apply_host_snapshot_result(&mut route_row, "route_table", &failed_snapshot, 4);
        assert_eq!(route_row.status, "ERROR");
        assert_eq!(route_row.classification.as_deref(), Some("UNKNOWN"));
        assert!(route_row.started_at_utc.is_none());
        assert!(route_row.ended_at_utc.is_none());
        assert!(route_row.evidence_ids.is_empty());

        // 2. snapshot.errors가 비어 있더라도 배열이 비어 있거나([]) selected_route가 누락된 경우
        // 절대 PASS로 위장하지 않고 ERROR + UNKNOWN을 반환해야 한다.
        let empty_component_snapshot = HostSnapshot {
            adapters: json!([]),
            routes: json!([]),
            selected_route: json!({}),
            errors: Vec::new(),
            limitations: Vec::new(),
        };

        let mut empty_nic_row = test_only_planned_feature_row("nic_inventory", "G-NET");
        apply_host_snapshot_result(
            &mut empty_nic_row,
            "nic_inventory",
            &empty_component_snapshot,
            2,
        );
        assert_eq!(empty_nic_row.status, "ERROR");
        assert_eq!(empty_nic_row.classification.as_deref(), Some("UNKNOWN"));

        let mut empty_route_row = test_only_planned_feature_row("route_table", "G-NET");
        apply_host_snapshot_result(
            &mut empty_route_row,
            "route_table",
            &empty_component_snapshot,
            2,
        );
        assert_eq!(empty_route_row.status, "ERROR");
        assert_eq!(empty_route_row.classification.as_deref(), Some("UNKNOWN"));
    }

    #[test]
    fn host_snapshot_non_windows_unavailable_fixture_marks_unavailable() {
        let non_win_snapshot = HostSnapshot {
            adapters: Value::Null,
            routes: Value::Null,
            selected_route: Value::Null,
            errors: Vec::new(),
            limitations: vec![
                "[TEST-ONLY] 비 Windows 환경에서는 호스트 스냅샷 수집이 지원되지 않습니다 (UNAVAILABLE)"
                    .to_string(),
            ],
        };

        let mut nic_row = test_only_planned_feature_row("nic_inventory", "G-NET");
        apply_host_snapshot_result(&mut nic_row, "nic_inventory", &non_win_snapshot, 0);
        assert_eq!(nic_row.status, "UNAVAILABLE");
        assert_eq!(nic_row.classification.as_deref(), Some("UNKNOWN"));
        assert!(nic_row.started_at_utc.is_none());
        assert!(nic_row.ended_at_utc.is_none());
        assert!(nic_row.evidence_ids.is_empty());

        let mut route_row = test_only_planned_feature_row("route_table", "G-NET");
        apply_host_snapshot_result(&mut route_row, "route_table", &non_win_snapshot, 0);
        assert_eq!(route_row.status, "UNAVAILABLE");
        assert_eq!(route_row.classification.as_deref(), Some("UNKNOWN"));
    }

    #[test]
    fn icmp_timeout_clamping_exposes_chosen_timeout_and_preserves_tcp_setting() {
        let (clamped_dur, clamped_note) = resolve_icmp_timeout(5_000);
        assert_eq!(clamped_dur, Duration::from_millis(2_000));
        assert!(clamped_note.contains("5000ms"));
        assert!(clamped_note.contains("2000ms"));
        assert!(clamped_note.contains("TCP 타임아웃 5000ms는 변경하지 않음"));

        let (within_dur, within_note) = resolve_icmp_timeout(1_200);
        assert_eq!(within_dur, Duration::from_millis(1_200));
        assert!(within_note.contains("1200ms"));
        assert!(within_note.contains("clamp(1, 2000)"));

        let fake_icmp = IcmpMeasurement {
            target: "127.0.0.1".to_string(),
            outcome: "REPLY".to_string(),
            elapsed_ms: 3,
            ip_status: Some(0),
            error_code: None,
            rtt_ms: Some(1),
            ttl: Some(128),
            limitations: vec!["[TEST-ONLY] ICMP 단위 시험 픽스처".to_string()],
        };
        let mut icmp_row = test_only_planned_feature_row("icmp_ping", "G-NET");
        apply_icmp_result(&mut icmp_row, &fake_icmp, Some(&clamped_note));
        assert_eq!(icmp_row.status, "PASS");
        assert_eq!(icmp_row.classification.as_deref(), Some("OBSERVED"));
        assert!(icmp_row.limitations.iter().any(|m| m.contains("2000ms")));
    }

    #[test]
    fn cancellation_after_completed_snapshot_preserves_observed_and_cancels_later_features() {
        let snapshot = test_only_fabricated_full_snapshot_fixture();
        let mut completed_nic_row = test_only_planned_feature_row("nic_inventory", "G-NET");
        apply_host_snapshot_result(&mut completed_nic_row, "nic_inventory", &snapshot, 9);

        let mut later_tcp_row = test_only_planned_feature_row("tcp_connect", "G-NET");
        mark_feature_cancelled_before_call(&mut later_tcp_row);

        assert_eq!(completed_nic_row.status, "PASS");
        assert_eq!(
            completed_nic_row.classification.as_deref(),
            Some("OBSERVED")
        );
        assert_eq!(completed_nic_row.duration_ms, Some(9));

        assert_eq!(later_tcp_row.status, "CANCELLED");
        assert_eq!(later_tcp_row.classification.as_deref(), Some("UNKNOWN"));
        assert!(later_tcp_row.duration_ms.is_none());
        assert!(later_tcp_row.started_at_utc.is_none());
        assert!(later_tcp_row.ended_at_utc.is_none());
        assert!(later_tcp_row.evidence_ids.is_empty());
    }
}
