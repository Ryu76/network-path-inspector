//! 로컬 호스트 네트워크 정보 수집 facade 모듈.
//!
//! 이 모듈은 `npi_probes`의 Windows 네이티브 읽기 전용 호스트 네트워크 스냅샷 수집기를 re-export합니다.
//! - 외부 명령어(`ipconfig`, `route` 등)나 서브프로세스를 실행하지 않습니다.
//! - 패킷 송수신, 소켓 연결, OS 네트워크 정책 변경을 수행하지 않는 순수 읽기 전용 수집기입니다.

pub use npi_probes::host::{
    AdapterEntry, HostSnapshot, PrefixEntry, RouteEntry, SelectedRouteEntry, UnicastAddressEntry,
    collect_host_snapshot,
};
