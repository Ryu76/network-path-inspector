//! TCP 연결 측정 및 오류 분류 facade 모듈.
//!
//! 이 모듈은 하위 구현을 복제하거나 수정하지 않고 `npi_core`와 `npi_probes`의
//! 검증된 단일 구현을 re-export하여 Network Path Inspector와 Network Quick Check 두 제품의
//! 단일 진실 공급원(Single Source of Truth)을 유지합니다.

pub use npi_core::{TcpOutcome, classify_tcp_error};
pub use npi_probes::tcp::{TcpMeasurement, connect_once};
