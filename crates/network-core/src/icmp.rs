//! ICMP Echo(Ping) 측정 facade 모듈.
//!
//! 이 모듈은 `npi_probes`의 Windows IP Helper 기반 ICMP Echo 측정 구현을 re-export합니다.
//! - OS API 수준의 측정 관찰 결과이며 패킷 캡처(PCAP) 근거가 아닙니다.
//! - ICMP 무응답이나 도달 불가는 TCP 연결 실패 또는 중간 차단 장비 존재를 단정하지 않습니다.

pub use npi_probes::icmp::{IcmpMeasurement, ping_once};
