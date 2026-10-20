use serde::{Deserialize, Serialize};

/// 실행 모드 열거형 (`standalone` | `paired_offline`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExecutionMode {
    #[serde(rename = "standalone")]
    Standalone,
    #[serde(rename = "paired_offline")]
    PairedOffline,
}

impl ExecutionMode {
    /// 계약에 정의된 실행 모드 문자열을 반환한다.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Standalone => "standalone",
            Self::PairedOffline => "paired_offline",
        }
    }

    /// 문자열로부터 실행 모드를 파싱한다.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "standalone" => Some(Self::Standalone),
            "paired_offline" => Some(Self::PairedOffline),
            _ => None,
        }
    }
}

/// 기능 그룹 ID 열거형 (`G-NET`, `G-PATH`, `G-PKT`, `G-PAIR`, `G-OPS`, `G-EVID`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GroupId {
    #[serde(rename = "G-NET")]
    GNet,
    #[serde(rename = "G-PATH")]
    GPath,
    #[serde(rename = "G-PKT")]
    GPkt,
    #[serde(rename = "G-PAIR")]
    GPair,
    #[serde(rename = "G-OPS")]
    GOps,
    #[serde(rename = "G-EVID")]
    GEvid,
}

impl GroupId {
    /// 계약에 정의된 그룹 ID 문자열을 반환한다.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::GNet => "G-NET",
            Self::GPath => "G-PATH",
            Self::GPkt => "G-PKT",
            Self::GPair => "G-PAIR",
            Self::GOps => "G-OPS",
            Self::GEvid => "G-EVID",
        }
    }

    /// 문자열로부터 그룹 ID를 파싱한다.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "G-NET" => Some(Self::GNet),
            "G-PATH" => Some(Self::GPath),
            "G-PKT" => Some(Self::GPkt),
            "G-PAIR" => Some(Self::GPair),
            "G-OPS" => Some(Self::GOps),
            "G-EVID" => Some(Self::GEvid),
            _ => None,
        }
    }
}

/// 기능 실행 비용 등급 열거형 (`LOW` | `MEDIUM` | `HIGH`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CostClass {
    Low,
    Medium,
    High,
}

impl CostClass {
    /// 계약에 정의된 비용 등급 문자열을 반환한다.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
        }
    }

    /// 문자열로부터 비용 등급을 파싱한다.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "LOW" => Some(Self::Low),
            "MEDIUM" => Some(Self::Medium),
            "HIGH" => Some(Self::High),
            _ => None,
        }
    }
}

/// 기능 권한 수준 열거형 (`USER` | `CONDITIONAL`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PermissionLevel {
    User,
    Conditional,
}

impl PermissionLevel {
    /// 계약에 정의된 권한 수준 문자열을 반환한다.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::User => "USER",
            Self::Conditional => "CONDITIONAL",
        }
    }

    /// 문자열로부터 권한 수준을 파싱한다.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "USER" => Some(Self::User),
            "CONDITIONAL" => Some(Self::Conditional),
            _ => None,
        }
    }
}

/// 진단 대상 호스트 및 TCP 포트 정의 DTO.
/// 모든 필드는 필수이며 알 수 없는 필드는 거부한다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub protocol: String,
}

/// 실행 제한 및 자원 상한 설정 DTO.
/// 모든 필드는 필수이며 누락 시 가짜 기본값을 주입하지 않는다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub tcp_timeout_ms: u64,
    pub max_hops: u64,
    pub retries: u64,
    pub max_concurrent_tcp: u64,
    pub capture_duration_secs: u64,
    pub capture_max_bytes: u64,
    pub log_retention_days: u64,
    pub ui_updates_per_second: u64,
}

/// 진단 실행 프로필 DTO.
/// `capture_approved`를 포함한 모든 필드가 명시적으로 존재해야 하며,
/// 검증 과정에서 암묵적으로 캡처 동의를 부여하지 않는다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub schema_version: String,
    pub profile_id: String,
    pub label: String,
    pub mode: String,
    pub selected_features: Vec<String>,
    pub capture_approved: bool,
    pub target: Target,
    pub limits: Limits,
}

/// 기능 레지스트리 항목 정의 DTO.
/// 계약에 정의된 10개 필드가 모두 존재해야 하며 알 수 없는 필드를 거부한다.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeatureDefinition {
    pub feature_id: String,
    pub group_id: String,
    pub label: String,
    pub description: String,
    pub default_selected: bool,
    pub requirements: Vec<String>,
    pub dependencies: Vec<String>,
    pub cost_class: String,
    pub permission_level: String,
    pub supported_modes: Vec<String>,
}
