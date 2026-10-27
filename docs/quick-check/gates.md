# Network Quick Check — 하네스 품질 게이트 정의서 (QG0~QG7)

- 문서 버전: 0.1.0 (QG0 초안)
- 작성일: 2026-10-21
- 상태: QG0 설계 단계 (게이트 기준 및 검증 계획 수립)
- 관련 PRD: [Network_Path_Inspector_Harness_PRD_v1.2.md](file:///E:/harnes/network-path-inspector/docs/requirements/Network_Path_Inspector_Harness_PRD_v1.2.md) Part B Section 22
- 계약 파일: [.harness/references/qg1-contract.json](file:///E:/harnes/network-path-inspector/.harness/references/qg1-contract.json)

---

## 1. 개요 및 게이트 운영 원칙

Network Quick Check는 각 단계별 엄격한 품질 게이트(Quality Gate)를 통과해야만 다음 구현 단계로 진입할 수 있습니다.

### 1.1 게이트 거버넌스 4대 원칙
1. **증거 기반 통과 (Evidence-Driven Pass)**: 실제 실행 로그와 테스트 산출물 증거가 확보되지 않은 항목은 절대 통과 처리하지 않습니다.
2. **미검증 및 환경 제약 보존 (Preserve Blocked State)**: 깨끗한 VM, 실제 패킷 DROP 환경, ICMP 차단 방화벽, 서로 다른 2개 VLAN 등 필수 물리 환경이 갖춰지지 않은 경우 임의로 OS 정책을 변경하여 테스트를 통과시키지 않고 `blocked` 상태로 정직하게 기록합니다.
3. **기존 Inspector 무파괴 원칙 (Zero Regression)**: 새 크레이트나 기능을 구현할 때 기존 `npi-core` 및 `npi-probes`의 테스트와 기능을 100% 보존하며, 회귀 발생 시 즉각 중단합니다.
4. **계획과 실행의 엄격한 분리**: 본 문서에 기재된 명령은 "향후 검증 실행 계획(Planned Verification Commands)"이며, QG0 시점에서 실제로 실행되었거나 성공했다고 주장하지 않습니다.

---

## 2. 세부 품질 게이트 정의 (QG0 ~ QG7)

### QG0: 제품 범위 확정, Windows 지원 매트릭스 및 위협/권한 분석

- **목적 및 범위**: 무설치 네이티브 Quick Check의 기능 범위(Q-P0-01~13), 위협 모델, 권한 모델(`asInvoker`), Windows 지원 매트릭스 확정 및 QG0/QG1 설계서 작성.
- **수용 기준 (Acceptance Criteria)**:
  - PRD v1.2 원문 요구사항과 1:1 매핑되는 13개 P0 요구사항 추적 매트릭스 작성 완료.
  - STRIDE 위협 모델 및 권한/무설치 원칙 문서화 완료.
  - 초기 x64 타깃 및 개발시험 Win10 19045 한정, Win10/11/Server 2016+ 수용 후보 판정 명시.
  - 기존 Inspector 소스 및 DTO 바이트 무변경 유지.
- **미검증 항목 (Unverified Items)**:
  - 실제 실행 바이너리 및 GUI 부재로 인한 런타임 동작 미검증.
  - Windows 매트릭스(11, Server 2016+) 및 깨끗한 VM에서의 실제 실행 미검증 (계획 단계).
- **의존성 (Dependencies)**:
  - PRD v1.2 원문, `.harness/references/qg1-contract.json`.
- **대상/변경 파일**:
  - `docs/quick-check/architecture.md`
  - `docs/quick-check/threat-model.md`
  - `docs/quick-check/gates.md`
  - `docs/quick-check/requirement-traceability.md`
  - `docs/quick-check/decisions.md`
  - `apps/network-quick-check/README.md`
- **실행 계획 명령 (Planned Commands)**:
  ```powershell
  # QG0 산출물 파일 무결성 및 인코딩 검사 계획
  Get-ChildItem -Path docs/quick-check -Filter *.md | ForEach-Object { Get-Content $_.FullName -Raw }
  ```
- **원본 증거 원칙**: 설계 문서 내 모든 링크, 제약사항, 계약 JSON의 해시 및 필드가 원본과 일치해야 함.

---

### QG1: 공통 Facade 정의, 인터페이스 계약 및 기존 기능 회귀 검증

- **목적 및 범위**: `crates/network-core` facade 라이브러리 정의, `qg1-contract.json` 준수 DTO 및 매핑 구현, 기존 `npi-core`/`npi-probes` 회귀 검증.
- **수용 기준 (Acceptance Criteria)**:
  - `qg1-contract.json`에 정의된 14개 정규 필드, 5개 null 허용 필드, 5개 상태, 3개 증거 수준 타입 구현.
  - `TcpOutcome` -> Quick Check 계약 매핑 구현 (`LOCAL_ERROR` -> `UNKNOWN/OBSERVED`, `CANCELLED` -> `UNKNOWN/UNKNOWN`).
  - 기존 `npi-core` 및 `npi-probes`의 전체 단위/통합 테스트 100% 통과 (기존 테스트 삭제/수정 금지).
  - Quick Check 코드에서 Webview/Npcap/Agent/PDF/SQLite 의존성 0건 확인.
- **미검증 항목 (Unverified Items)**:
  - 실제 네트워크 소켓 및 GUI 런타임 통합 동작.
- **의존성 (Dependencies)**:
  - QG0 승인, 부모 에이전트의 `crates/network-core` 코드 구현.
- **대상/변경 파일**:
  - `Cargo.toml` (워크스페이스 멤버 추가 계획)
  - `crates/network-core/Cargo.toml` [예정/Planned]
  - `crates/network-core/src/**` [예정/Planned]
- **실행 계획 명령 (Planned Commands)**:
  ```powershell
  # QG1 검증 실행 계획 (부모 에이전트가 실행 예정)
  cargo check --workspace
  cargo test -p npi-core
  cargo test -p npi-probes
  cargo test -p network-core
  ```
- **원본 증거 원칙**: 기존 단위 테스트 실행 로그 및 `network-core`의 DTO 직렬화/역직렬화 테스트 통과 로그.

---

### QG2: 프로브 계층 통합 (TCP, Ping, DNS, 라우팅, Traceroute)

- **목적 및 범위**: 단일 대상에 대한 비동기 TCP 연결, ICMP Ping, 시스템 DNS 리졸버, 호스트 정보 수집, Traceroute 기본 프로브 구현 및 오류 분류 검증.
- **수용 기준 (Acceptance Criteria)**:
  - 정상 연결(`CONNECTED` -> PASS), 포트 거부(`REFUSED` -> FAIL), 타임아웃(`TIMED_OUT` -> FAIL), 도달 불가(`UNREACHABLE` -> FAIL) 분류 검증.
  - Ping 응답 시간 수집 및 ICMP 실패와 TCP 실패의 명확한 분리.
  - 대상이 도메인일 때의 필수 IP 해석과 상세 `dns_lookup` 기능의 분리 검증 (기능별 미선택 시 DNS 질의 0회).
  - Traceroute 무응답 홉을 차단 장비로 단정하지 않고 `UNKNOWN` 처리.
- **미검증 항목 (Unverified Items)**:
  - 실제 원격 방화벽 DROP 및 패킷 필터링 환경 (실험실 환경 부재 시 `blocked`).
- **의존성 (Dependencies)**:
  - QG1 통과.
- **대상/변경 파일**:
  - `crates/network-core/src/probes/**` [예정/Planned]
- **실행 계획 명령 (Planned Commands)**:
  ```powershell
  # QG2 루프백 및 모의 소켓 검증 계획
  cargo test -p network-core --test probe_tests
  ```
- **원본 증거 원칙**: 모의 소켓/네트워크 응답별 `status`, `evidence_level`, `details` 매핑 결과 로그.

---

### QG3: 단일 화면 GUI, 다중 대상 입력 및 기능 선택 UX

- **목적 및 범위**: `apps/network-quick-check` 네이티브 Win32 GUI 구현, 다중 대상(최대 100건) 입력/붙여넣기, 기능별 체크박스, UI 비차단 구조 검증.
- **수용 기준 (Acceptance Criteria)**:
  - Win32 API 직접 기반 GUI 창 생성 및 컨트롤 배치.
  - 최대 100건 대상 입력 및 중복 제거 동작.
  - 기능 체크박스 선택에 따라 미선택 기능의 프로브 호출 0회 검증.
  - 진단 진행 중 UI 메인 스레드 응답성 유지 (네트워크 I/O 0건, 윈도우 이동/크기 조절 정상).
- **미검증 항목 (Unverified Items)**:
  - 고부하(100개 동시 대상) 환경에서의 UI 렌더링 프레임 드롭 실측치.
- **의존성 (Dependencies)**:
  - QG2 통과.
- **대상/변경 파일**:
  - `apps/network-quick-check/Cargo.toml` [예정/Planned]
  - `apps/network-quick-check/src/**` [예정/Planned]
- **실행 계획 명령 (Planned Commands)**:
  ```powershell
  # QG3 GUI 크레이트 빌드 및 비차단 검증 계획
  cargo check -p network-quick-check
  cargo test -p network-quick-check
  ```
- **원본 증거 원칙**: GUI 메시지 펌프 분리 및 MPSC 이벤트 채널 갱신 검증 코드 및 로그.

---

### QG4: 취소, 동시성 제한 및 자원 회수 검증

- **목적 및 범위**: 중지(취소) 버튼 클릭 시의 즉각적인 진단 중단, 동시성 제한(기본 4, 하드캡 4), 메모리 및 소켓 핸들 누수 방지 검증.
- **수용 기준 (Acceptance Criteria)**:
  - 취소 요청 시 비동기 TCP 즉각 중단 및 잔여 프로브 취소(`CANCELLED` -> `UNKNOWN/UNKNOWN`).
  - 동시 실행 태스크가 최대 4개를 초과하지 않음(세마포어 제어 검증).
  - 취소 후 잔류 소켓 및 자식 프로세스 핸들 0개 확인.
  - 동기 ICMP 프로브의 경우 최대 2,000ms 블로킹 한계 내에서 안전하게 종료됨을 확인.
- **미검증 항목 (Unverified Items)**:
  - 장시간(24시간) 지속 실행 시의 미세 메모리 누수.
- **의존성 (Dependencies)**:
  - QG3 통과.
- **대상/변경 파일**:
  - `apps/network-quick-check/src/worker/**` [예정/Planned]
- **실행 계획 명령 (Planned Commands)**:
  ```powershell
  # QG4 취소 및 동시성 제어 테스트 계획
  cargo test -p network-quick-check --test concurrency_tests
  ```
- **원본 증거 원칙**: 작업 취소 시의 타임스탬프 차이(종료 지연 시간) 및 세마포어 최대 획득 수 기록.

---

### QG5: 결과 복사, TXT/CSV 저장, 필터링 및 보안 검증

- **목적 및 범위**: 결과 필터링(전체/성공/실패/경고), 텍스트 클립보드 복사, TXT 및 CSV 파일 저장, CSV Injection 방어 및 개인정보 경고 검증.
- **수용 기준 (Acceptance Criteria)**:
  - UTF-8 인코딩 및 줄바꿈 일관성 확인.
  - CSV 내보내기 시 `=`, `+`, `-`, `@` 문자로 시작하는 필드에 단일 따옴표(`'`) 이스케이프 적용 확인.
  - 파일 저장 시 원자적 교체(`ReplaceFile`/`rename`) 동작 확인.
  - 클립보드 복사 및 저장 전 사내망/개인정보 노출 주의 안내 다이얼로그 노출 확인.
- **미검증 항목 (Unverified Items)**:
  - 마스킹 위치 결정 정책의 P1 사용자 피드백.
- **의존성 (Dependencies)**:
  - QG4 통과.
- **대상/변경 파일**:
  - `apps/network-quick-check/src/export/**` [예정/Planned]
- **실행 계획 명령 (Planned Commands)**:
  ```powershell
  # QG5 내보내기 및 CSV 인젝션 방어 테스트 계획
  cargo test -p network-quick-check --test export_security_tests
  ```
- **원본 증거 원칙**: 내보낸 CSV/TXT 샘플 파일 및 인젝션 이스케이프 단위 테스트 결과.

---

### QG6: Release 단일 EXE 빌드 및 무설치 VM 환경 수용 검증

- **목적 및 범위**: 최적화 Release 빌드 생성, PE 의존성 감사, 사전 요구사항(런타임)이 없는 깨끗한 Windows VM에서의 무설치 실행 검증.
- **수용 기준 (Acceptance Criteria)**:
  - Release 빌드 결과물 단일 파일 `NetworkQuickCheck.exe` 생성.
  - 바이너리 크기 설계 목표(10MB 이하) 측정 및 기록.
  - PE Import 테이블에 금지된 외부 DLL(Webview2, Npcap, C-Runtime 배포 DLL 등) 부재 확인.
  - 깨끗한 Windows 10/11/Server 2016+ VM에 복사하여 별도 설치 절차나 UAC 프롬프트 없이 즉시 구동 확인.
- **미검증 항목 (Unverified Items)**:
  - ARM64 윈도우 환경 (지원 보류).
  - 사내 EDR/AppLocker에 의한 차단 환경 (조직 정책에 따름).
- **의존성 (Dependencies)**:
  - QG5 통과.
- **대상/변경 파일**:
  - `Cargo.toml` (릴리즈 프로파일 설정)
  - `apps/network-quick-check/build.rs` [예정/Planned]
- **실행 계획 명령 (Planned Commands)**:
  ```powershell
  # QG6 릴리즈 빌드 및 PE Import 감사 계획
  cargo build --release -p network-quick-check
  dumpbin /dependents target/release/NetworkQuickCheck.exe
  ```
- **원본 증거 원칙**: PE 의존성 목록(`dumpbin` 덤프) 및 VM 실행 스크린샷/로그.

---

### QG7: 성능 예산 측정, 안정성 및 양방향 최종 회귀 검증

- **목적 및 범위**: 유휴/동작 메모리 및 CPU 측정, 기존 Network Path Inspector 및 Quick Check 양쪽의 전체 회귀 검증 완료.
- **수용 기준 (Acceptance Criteria)**:
  - 유휴 메모리(목표 30MB 이하), 유휴 CPU(목표 1% 이하) 실측 및 기록.
  - Inspector 및 Quick Check 전체 테스트 스위트 100% 통과.
  - 성능 목표 미달 시 임의로 기준치를 상향하지 않고 원인과 병목을 투명하게 기록.
- **미검증 항목 (Unverified Items)**:
  - 2개 서로 다른 실제 VLAN 간 방화벽 통과 실측 (실험실 환경 필요).
- **의존성 (Dependencies)**:
  - QG6 통과.
- **대상/변경 파일**:
  - 전체 워크스페이스
- **실행 계획 명령 (Planned Commands)**:
  ```powershell
  # QG7 전체 회귀 검증 실행 계획
  cargo test --workspace --all-targets
  ```
- **원본 증거 원칙**: 최종 통합 테스트 실행 보고서 및 성능 측정 로그.
