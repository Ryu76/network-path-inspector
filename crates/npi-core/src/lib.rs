pub mod models;
pub mod session;
pub mod validation;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub use models::{
    CostClass, ExecutionMode, FeatureDefinition, GroupId, Limits, PermissionLevel, Profile, Target,
};
pub use session::{
    Evidence, FeatureResult, Finding, ResourceMetrics, Session, convert_legacy_session,
    validate_session,
};
pub use validation::{validate_profile, validate_registry};

const G1_CONTRACT_JSON: &str = include_str!("../../../contracts/g1-interface-contract.json");

/// TCP 연결 시도 결과 분류 열거형.
/// 주의: 소켓 수준의 `Refused`(Winsock 10061)는 OS 소켓 오류 관찰 결과일 뿐이며,
/// 패킷 캡처 근거 없이 실제 네트워크 상에서 SYN/RST 패킷이 관찰되었다고 단정하지 않는다.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TcpOutcome {
    Connected,
    Refused,
    TimedOut,
    Unreachable,
    LocalError,
    DnsError,
    Cancelled,
}

impl TcpOutcome {
    /// 계약에 정의된 대문자 스네이크 케이스 문자열을 반환한다.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Connected => "CONNECTED",
            Self::Refused => "REFUSED",
            Self::TimedOut => "TIMED_OUT",
            Self::Unreachable => "UNREACHABLE",
            Self::LocalError => "LOCAL_ERROR",
            Self::DnsError => "DNS_ERROR",
            Self::Cancelled => "CANCELLED",
        }
    }
}

/// Winsock/OS 오류 코드 및 취소·시간초과 플래그를 계약된 TCP 결과 문자열로 분류한다.
/// OS 오류 코드 10061(`REFUSED`)은 소켓 API 수준의 거부 응답이며 패킷 캡처로 관찰된 RST를 의미하지 않는다.
/// 오류 코드가 없거나(`None`), `0`이거나, 알 수 없는 코드인 경우 절대 성공(`CONNECTED`)으로 분류하지 않는다.
pub fn classify_tcp_error(code: Option<i32>, timed_out: bool, cancelled: bool) -> String {
    let outcome = if cancelled {
        TcpOutcome::Cancelled
    } else if timed_out {
        TcpOutcome::TimedOut
    } else {
        match code {
            Some(10061) => TcpOutcome::Refused,
            Some(10060) => TcpOutcome::TimedOut,
            Some(10051 | 10065) => TcpOutcome::Unreachable,
            Some(10050 | 10013 | 10054) => TcpOutcome::LocalError,
            Some(11001 | 11004) => TcpOutcome::DnsError,
            Some(0) | None | Some(_) => TcpOutcome::LocalError,
        }
    };
    outcome.as_str().to_string()
}

/// 내장된 G1 인터페이스 계약에서 정규 기능 레지스트리(`features` 배열)를 파싱해 반환한다.
pub fn canonical_registry() -> Value {
    let contract: Value = serde_json::from_str(G1_CONTRACT_JSON)
        .expect("내장된 g1-interface-contract.json은 항상 유효한 JSON이어야 합니다");
    contract
        .get("features")
        .expect("내장된 g1-interface-contract.json에는 features 필드가 존재해야 합니다")
        .clone()
}
