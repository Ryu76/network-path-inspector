# Network Quick Check 요구사항 추적성 매트릭스 (QG0)

## 1. 개요 및 상태 기준
- 본 문서는 PRD v1.2 Part B에 정의된 Network Quick Check의 13개 P0 필수 요구사항에 대한 추적성 및 품질 게이트 연계를 정의함.
- **현재 구현 상태(2026-10-26)**: 공유 Core와 프로브 실행기, 동일 EXE DNS worker, 개발용 단일 TCP CLI가 root에 제한 수용되었고, 순수 GUI 입력·실행 상태모델도 추가 수용되었다. Win32 화면·GUI/runner 연결·전체 QG2/QG3·배포는 미완료다. 최신 근거는 `../../artifacts/qg3a-gui-state-acceptance.json` 및 `../../artifacts/quick-check-progress.json`이다.
- **아래 표의 시점**: QG0 설계 당시의 원본 계획·차단 조건을 보존한 표다. 표의 초기 상태를 현재 구현률로 집계하지 않는다. 현재 게이트 판정은 `gates.md` 후속 수용 기록을 따른다. 지원 목표의 Server 2012 이후 확대는 `development-authorization-2026-10-26.md`, 미검증 호환성 경계는 `windows-compatibility-review-2026-10-26.md`를 따른다.
- **상태 기준**:
  - `not-started`: 구현 및 검증 미착수 상태.
  - `partial`: 기존 crate(`npi-core`/`npi-probes`)에 원시 구현이 존재하거나 별도 worktree에서 구현·검증 중이나, network-core facade 미연동 또는 root 미통합·미수용 상태.
  - `blocked`: 선행 검증 환경(클린 VM/PE, 실제 2VLAN/DROP/ICMP 차단망 등) 미확보 또는 선행 UI 미구현으로 인해 시험 진행이 차단된 상태.

## 2. P0 요구사항 추적표 (정확 13건)

| 요구사항 ID | 요구사항 내용 | 담당 게이트 | 핵심 수용 기준 (계획) | 기대 결과 (계획) | 검증 증거 (계획) | 환경 미확보 시 (Blocked 조건) | 현재 상태 | 비고 및 한계 |
|---|---|---|---|---|---|---|---|---|
| **Q-P0-01** | 무설치 단일 EXE | **QG6** | 클린 Windows 10/11/Server x64 VM에서 추가 런타임/설치/관리자 권한 없이 단일 EXE 실행 및 기본 검사 동작, PE 바이너리 import/manifest 별도 검사 | 설치 관리자/의존성 패키지/서비스 등록 없이 독립 실행 및 UI 표출 | 클린 VM 실행 로그, 모듈 의존성 검사 결과, SHA-256 체크섬 | 클린 Windows VM/PE 테스트 환경 미확보 시 `blocked` | `blocked` | CRT static(`crt-static`) 링크 검토 단계이며 실제 무설치 성공 미확정 |
| **Q-P0-02** | 입력 및 유효성 검사 | **QG3** | IPv4, IPv6, 도메인, 포트(1~65535), 타임아웃(ms) 입력 유효성 검증 및 오류 사용자 피드백 | 유효 입력 정상 수용, 유효하지 않은 입력(범위 밖 포트, 특수문자, 포맷 오류) 시 사전 차단 및 경고 표시 | 경계값/오류값 입력 테스트 로그, UI 경고 메시지 캡처 | Win32 GUI 입력 폼 미구현 상태이므로 `blocked` | `not-started` | Win32 컨트롤 및 입력 유효성 검사 로직 미작성 |
| **Q-P0-03** | TCP Connect | **QG2** | CONNECTED(PASS/OBSERVED), REFUSED/RESET/TIMED_OUT/UNREACHABLE(FAIL/OBSERVED), LOCAL_ERROR(UNKNOWN/OBSERVED) 분류 및 OS 오류코드 보존 | TCP 핸드셰이크 결과에 따라 계약 스키마에 정의된 상태 및 증거 수준으로 정확히 매핑, 원시 소켓 오류코드 유지 | 정상/거부/DROP 테스트 결과 JSON, 소켓 오류 로그 | 실제 거부/DROP 네트워크 테스트베드 미확보 시 `blocked` (루프백 대체 금지) | `partial` | npi-probes에 원시 구현 존재하나 network-core facade 미연결 (별도 worktree 구현·검증 중, root 미통합) |
| **Q-P0-04** | Ping | **QG2** | ICMP Echo 왕복 시간 및 패킷 손실률 측정, ICMP 차단 시 TCP 결과와 분리 표시 | Ping 응답 지연(ms) 표시, ICMP 필터링 환경에서도 TCP 성공 여부 독립 판정 유지 | ICMP 차단/허용 테스트베드 측정 로그 | 실제 ICMP 차단 테스트베드 미확보 시 `blocked` (루프백 대체 금지) | `partial` | npi-probes에 ICMP 구현 존재하나 GUI 미연동 (별도 worktree 구현·검증 중) |
| **Q-P0-05** | 경로 추적 | **QG2** | Windows 기본 API/명령 기반 ICMP Traceroute 실행, 비응답 HOP '미확인(UNKNOWN)' 처리, 특정 장비 차단 단정 금지 | 각 HOP별 IP 및 지연시간 표시, 비응답 HOP에 대해 차단 단정 없이 UNKNOWN 처리, 명령 채택 시 숨김창/타임아웃/자식종료 처리 | HOP별 출력 덤프, 자식 프로세스 수명주기 로그 | 다중 홉 테스트 경로 미확보 시 `blocked` | `not-started` | 프로젝트 Traceroute 구현 없음. QG2 프로브 단계에서 Windows API/명령 활용 검증 예정 |
| **Q-P0-06** | DNS 조회 | **QG2** | 도메인 접속을 위한 필수 OS 주소 해석과 상세 DNS 검사 분리, 다중 IP 목록 및 실제 선택 접속 IP 보존 | 도메인 입력 시 전체 해석 IP 목록과 실제 접속 IP 구분 기록, IP 직접 입력 시 불필요한 DNS 0회 실행 | 해석 IP 배열 및 선택 접속 IP 로깅 파일 | 격리 DNS 테스트베드 미확보 시 `blocked` | `partial` | DNS 모듈 root 미연결, OS resolver 캐시/hosts 참조 한계 명시 필요 |
| **Q-P0-07** | 로컬 네트워크 정보 | **QG2** | 활성 NIC, 할당 IP, 게이트웨이, DNS, 목적지 경로 정보 수집, 비선택 시 수집 배제 | 활성 어댑터 정보 정상 표시, 조회 실패 시 제한사항 명시 | 수집된 로컬 네트워크 구성 덤프 JSON | 다중 NIC/특수 어댑터 테스트 환경 미확보 시 `blocked` | `partial` | npi-probes 어댑터 조회 존재하나 facade 미연결 |
| **Q-P0-08** | 다중 대상 | **QG3**<br>(QG4 연계) | IP:Port 여러 건 붙여넣기/추가/삭제/중복 제거, 최대 100건 대상 큐잉, 대상별 개별 결과 보존 및 오염 방지 | 클립보드 다중 행 붙여넣기 및 중복 제거 정상 작동, 각 대상(IP:Port:세션)별 독립된 결과 매핑 및 격리 유지 | 100건 대상 입력/붙여넣기 테스트 로그, 중복 제거 전후 목록, 대상별 결과 격리 매핑 로그 | Win32 GUI 다중 대상 관리 컨트롤 미구현 상태이므로 `blocked` | `not-started` | 100건 상한은 설계 제안치(Proposal)이며 한도 도달 시 명시 상태 기록 및 silent drop 금지 |
| **Q-P0-09** | 기능 선택 | **QG3** | 체크박스를 통한 기능 선택(TCP, Ping, Trace, DNS, 로컬 정보), 기본값 TCP+Ping 적용, 비선택 기능 0회 실행 | 체크 해제된 기능의 코드 및 네트워크 I/O 0회 호출 검증 | 기능 디스패처 호출 로그 카운트 (비선택 = 0) | 기능 디스패처 및 GUI 체크박스 미구현 상태이므로 `blocked` | `not-started` | 선택형 실행 디스패처 미구현 |
| **Q-P0-10** | 결과 필터 | **QG5**<br>(QG3 연계) | 전체/성공(PASS)/실패(FAIL)/경고(WARN) 상태 필터, 기능별(TCP, Ping 등) 필터, 대상별(IP, 도메인, 포트 검색) 필터 지원 | 필터 조건 변경 시 화면에 일치하는 결과만 즉시 필터링 표출 | 필터 상태별 노출 데이터 검증 테스트 로그 | 결과 메모리 모델 및 UI 뷰포트 미구현 상태이므로 `blocked` | `not-started` | 결과 메모리 모델 및 UI 필터 미구현 |
| **Q-P0-11** | 결과 공유 | **QG5** | 결과 클립보드 복사, TXT/CSV 저장, UTF-8 인코딩, 메타데이터(설정·대상·출발지/목적지·시각/시간대·프로그램 버전) 정확성, CSV 수식 주입 방어(`=`, `+`, `-`, `@`), 원자적 파일 쓰기, 공유 전 개인정보 안내 | 내보낸 파일의 필수 필드 누락 없음, Excel 수식 실행 차단 이스케이프 확인, 임시파일 쓰기 후 교체로 파일 손상 방지, PII 안내 표시 | 내보낸 CSV/TXT 샘플 파일, 수식 인젝션 무력화 검증 로그, 임시파일 원자적 교체 로그 | 파일 저장/복사 핸들러 미작성 상태이므로 `blocked` | `not-started` | 원자적 파일 쓰기 및 이스케이프 로직 미구현 |
| **Q-P0-12** | 취소/타임아웃 | **QG4** | 사용자 중지 시 취소 토큰 즉시 전파, 소켓 및 자식 프로세스 정리, UI 스레드 응답 유지, 부분 결과 '중단됨(UNKNOWN)' 보존 | 취소 후 잔여 소켓/프로세스 0건, UI 프리징 없음, 취소된 작업의 부분 결과 손실 없음 | 취소 이벤트 시 핸들 모니터링 로그, 부분 결과 스키마 덤프 | 취소 토큰 디스패처 미구현 상태이므로 `blocked` | `not-started` | ICMP 동기 2초 블로킹 한계 및 엄격 취소시간 미보장 유지 |
| **Q-P0-13** | 안전한 기본값 | **QG4** | 포트 스캔/대역 탐색 배제, 사용자 명시 대상만 검사, 동시성 상한 4 준수, 기본 TCP 타임아웃 3000ms | 동시 활성 프로브 수 4 이하 상시 유지, 미인가 IP/포트 접근 0건 | 동시성 세마포어 모니터링 로그, 패킷 대상 감사 로그 | 동시성 제어 큐 미구현 상태이므로 `blocked` | `not-started` | 동시성 세마포어 및 안전 제한 미구현 |

## 3. 품질 게이트 연계 요약
- **QG0 (설계/범위 확정)**: 무설치·무관리자 기본 경로 검증 계획 승인 포함 (현재 제안 단계).
- **QG1 (코어 facade 추출)**: `network-core` facade 분리 및 계약 스키마 검증 (현재 별도 worktree 구현·검증 중, root 미통합·미수용).
- **QG2 (프로브 검증)**: Q-P0-03 (TCP), Q-P0-04 (Ping), Q-P0-05 (Traceroute), Q-P0-06 (DNS), Q-P0-07 (로컬 정보).
- **QG3 (GUI 연동)**: Q-P0-02 (입력 검증), Q-P0-08 (다중 대상 관리), Q-P0-09 (기능 선택).
- **QG4 (동시성/자원 한계)**: Q-P0-12 (취소/수명주기), Q-P0-13 (안전 기본값), 대상 격리 및 메모리 상한(제안치).
- **QG5 (내보내기 무결성)**: Q-P0-10 (결과 필터), Q-P0-11 (복사/TXT/CSV 저장 및 보안).
- **QG6 (단일 EXE 배포)**: Q-P0-01 (클린 VM 무설치 실행).
- **QG7 (성능 실측/통합 회귀)**: PRD 20.1 지표 실측 보고서(미실측 목표치) 및 Inspector/Quick 동일 조건 TCP 분류 동등성/양방향 회귀.

## 4. 관련 기준 문서
- 인터페이스 계약: [quick-check-interface-v0.1.json](../../contracts/quick-check-interface-v0.1.json)
- 품질 게이트 계획: [gates.md](gates.md)
- 아키텍처 사양서: [architecture.md](architecture.md)
- 설계 결정 기록: [decisions.md](decisions.md)
- 위협 분석: [threat-model.md](threat-model.md)
- 상위 요구사항: [Network Path Inspector Harness PRD v1.2](../requirements/Network_Path_Inspector_Harness_PRD_v1.2.md)
