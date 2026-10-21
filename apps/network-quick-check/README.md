# Network Quick Check (`apps/network-quick-check`)

## 1. 개요
Network Quick Check는 별도의 설치 과정 없이 Windows 단일 실행 파일(EXE)을 복사하여 즉시 IP:Port 통신 상태를 진단할 수 있도록 기획된 경량 네트워크 진단 도구입니다.

- **현재 단계**: QG0 (설계 제안 및 계획 단계이며, 실행 파일 및 GUI 코드는 아직 0단계임).
- **공통 기반**: `crates/network-core` facade를 통해 기존 `npi-core` 및 `npi-probes` 구현을 재사용(기존 Inspector는 그대로 보존).
- **의존성 배제**: WebView, Npcap, Agent, PDF, SQLite 라이브러리를 일체 포함하지 않음.

## 2. 설계 및 계약 문서 (상대 링크)
- [아키텍처 사양서](../../docs/quick-check/architecture.md)
- [위협 분석 및 보안 원칙](../../docs/quick-check/threat-model.md)
- [품질 게이트 계획](../../docs/quick-check/gates.md)
- [요구사항 추적성 매트릭스](../../docs/quick-check/requirement-traceability.md)
- [설계 결정 기록 (ADR)](../../docs/quick-check/decisions.md)
- [인터페이스 계약](../../contracts/quick-check-interface-v0.1.json)
- [Network Path Inspector Harness PRD v1.2](../../docs/requirements/Network_Path_Inspector_Harness_PRD_v1.2.md)

## 3. 작업자 주의사항
- 본 디렉터리의 실제 구현 코드 및 테스트 실행은 부모 작업자/별도 worker의 검증 계획에 따라 순차 진행됩니다.
- 단독 진단은 서버 수신 여부를 알 수 없으므로 연결 실패를 방화벽 차단으로 단정하지 않습니다.
- 운영 환경 무변경 원칙을 준수하며 시스템 정책/방화벽/라우팅 변경을 일체 수행하지 않습니다.
