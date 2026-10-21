//! # network-core
//!
//! Network Path Inspector(Part A)와 Network Quick Check(Part B) 제품군을 위한 공통 네트워킹 진단 facade 라이브러리.
//!
//! ## 설계 및 안전 원칙
//! - **단일 진실 공급원(Single Source of Truth)**: 기존 `npi-core` 및 `npi-probes`의
//!   핵심 측정 엔진(TCP 연결, 오류 분류, ICMP Ping, 호스트 스냅샷)을 재사용(re-export)하여
//!   두 제품 간 단일 구현을 유지합니다.
//! - **측정 사실·추론·확인 불가의 엄격한 분리**: 패킷 캡처 근거 없는 SYN/RST 관찰 주장이나
//!   응답 없는 HOP을 차단 장비로 단정하는 행위를 엄격히 금지합니다.
//! - **비파괴 운영**: 시스템 정책, 방화벽 규칙, 레지스트리, 라우팅 테이블 변경을 수행하지 않는 읽기·측정 전용입니다.
//!
//! ## 제품 경계 및 QG2 이후 구현 예정 범위
//! - 본 라이브러리는 무설치 단일 EXE인 Network Quick Check(Part B)와
//!   정밀 진단 도구인 Network Path Inspector(Part A)의 공통 기반을 제공합니다.
//! - Quick Check에는 브라우저 엔진(WebView), Npcap, Agent 세션, PDF 렌더러, SQLite 의존성을 일체 포함하지 않습니다.
//! - QG1 단계에서는 공통 facade 및 Quick Check DTO/어댑터를 확립하며,
//!   ICMP Traceroute 상세 프로브, 독립 DNS 진단 프로브, 로컬 네트워크 UI/엔진 바인딩 및 네이티브 Windows GUI 통합은
//!   QG2 이후 마일스톤(QG2~QG7)에서 단계별로 추가 구현됩니다.

pub mod host;
pub mod icmp;
pub mod quick;
pub mod tcp;

pub use host::{
    AdapterEntry, HostSnapshot, PrefixEntry, RouteEntry, SelectedRouteEntry, UnicastAddressEntry,
    collect_host_snapshot,
};
pub use icmp::{IcmpMeasurement, ping_once};
pub use quick::{
    validate_quick_result, validate_rfc3339_timestamp, EVIDENCE_VALUES, EVIDENCE_VALUES_COUNT,
    EvidenceLevel, FEATURE_VALUES, FEATURE_VALUES_COUNT, QUICK_PRODUCT_NAME, QUICK_SCHEMA_VERSION,
    QuickContext, QuickFeature, QuickResult, QuickStatus, STATUS_VALUES, STATUS_VALUES_COUNT,
    tcp_to_quick_result,
};
pub use tcp::{TcpMeasurement, TcpOutcome, classify_tcp_error, connect_once};
