# Network Quick Check 아키텍처 사양서 (QG0)

## 1. 개요 및 워크스페이스 구조
- **제품 목적**: PC 1대에서 설치 없이 즉시 실행 가능한 네이티브 Win32 GUI 단일 EXE 통신 진단 도구 제안.
- **워크스페이스 공존**: 기존 `Inspector`를 보존하면서 동일 워크스페이스 내 `apps/network-quick-check`를 별도 개발.
- **코어 재사용**: `crates/network-core` facade를 통해 기존 `npi-core` 및 `npi-probes` 구현을 재사용하며, 코드 복제나 광역 rename, 기존 앱 facade 전환 완료 주장을 금지.
- **금지 의존성**: WebView, Npcap, Agent, PDF, SQLite는 Quick Check 빌드에 일체 포함하지 않음.
- **데이터 계약 및 PRD**: [quick-check-interface-v0.1.json](../../contracts/quick-check-interface-v0.1.json) 및 [PRD v1.2](../requirements/Network_Path_Inspector_Harness_PRD_v1.2.md) 준수.

## 2. 스레드 모델 및 비동기 처리
- **UI 반응성**: UI 스레드 네트워크 I/O 0건 원칙 준수. 워커 스레드와 이벤트 큐를 통해 통신.
- **취소 및 타임아웃 한계**: 소켓 취소 10ms 폴링 목표는 hard 보장이 아니며, ICMP 동기 API 호출 시 최대 2초 블로킹 가능. 취소 정리 3초는 Inspector 제안 예산의 재사용이며 Quick 실측 보장값이 아님.
- **부하 제어**: 최대 100건 대상 큐잉, 기본/최대 동시성 4, TCP 타임아웃 기본 3000ms. 선택하지 않은 상세 기능은 0회 실행.

## 3. 주소 해석 및 DNS 관측 원칙
- **해석 분리**: 도메인 접속을 위한 필수 OS 주소 해석(OS resolver)과 별도 상세 DNS 검사를 엄격히 분리.
- **관측 한계**: OS resolver는 hosts 파일 및 캐시를 참조하므로 실제 DNS 서버/RR/TTL 관찰 결과가 아님. 다수의 OS 주소 반환을 DNS 레코드 수집으로 단정 금지.
- **다중 IP 처리**: 단일 IP 가정을 배제하고 선택된 실제 접속 IP와 해석 주소 목록 전체를 구분 기록. DNS 모듈은 현재 root 미연결 상태이며 생산용 미완료.

## 4. 결과 내구성 및 원자적 파일 쓰기
- **원자적 저장 계획**: 단순 rename만으로는 전원 차단 시 파일 무결성을 보장하지 못하므로, 동일 볼륨 임시파일 기록 -> flush/sync -> 원자적 교체 정책과 검증 시험 계획 수립.
- **자동화 금지**: 자동 업로드 및 백그라운드 자동 저장 기능 없음.
