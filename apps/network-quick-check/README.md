# Network Quick Check (무설치 경량 네트워크 통신 진단 도구)

- 제품명: Network Quick Check (Part B)
- 현재 버전: 0.1.0 (QG0 설계 단계)
- 관련 PRD: [Network_Path_Inspector_Harness_PRD_v1.2.md](file:///E:/harnes/network-path-inspector/docs/requirements/Network_Path_Inspector_Harness_PRD_v1.2.md) Part B
- 아키텍처 문서: [architecture.md](../../docs/quick-check/architecture.md)
- 품질 게이트: [gates.md](../../docs/quick-check/gates.md)
- 요구사항 추적: [requirement-traceability.md](../../docs/quick-check/requirement-traceability.md)
- 설계 결정 기록: [decisions.md](../../docs/quick-check/decisions.md)
- 위협 모델: [threat-model.md](../../docs/quick-check/threat-model.md)

---

## 1. 제품 개요

Network Quick Check는 별도의 설치 절차(인스톨러, 서비스 등록, 관리자 권한)나 외부 런타임(WebView2, Npcap, C++ 재배포 패키지) 없이, **단일 실행 파일(`NetworkQuickCheck.exe`)을 PC에 복사하여 즉시 실행할 수 있는 경량 네이티브 Windows GUI 진단 도구**입니다.

서로 다른 사설망이나 VLAN 환경에서 목적지 IP/도메인 및 TCP 포트로의 통신 가능 여부를 빠르게 검증하고, 측정된 관찰 사실을 TXT 또는 CSV 파일로 안전하게 공유할 수 있습니다.

> [!IMPORTANT]
> **현재 구현 상태 고지**: 본 문서는 **QG0 하네스 품질 게이트 설계 산출물**입니다. 현재 시점에서는 소스 코드 구현 및 실행 파일 빌드가 진행되지 않은 "설계 단계"이며, 실제 바이너리 및 GUI 구현은 후속 게이트(QG1~QG3)에서 순차적으로 진행될 예정입니다.

---

## 2. 핵심 원칙 및 특징

1. **무설치 네이티브 단일 바이너리**:
   - 인스톨러, 드라이버, 레지스트리 등록 없이 단일 EXE 파일로 동작합니다.
   - MSVC CRT 정적 링크(`/MT`) 검토를 통해 C++ 재배포 패키지 부재 환경을 지원합니다.
2. **최소 권한 및 비파괴성 (asInvoker)**:
   - 일반 사용자 권한으로 실행되며 UAC 승격을 요구하지 않습니다.
   - OS 방화벽, 라우팅 테이블, 시스템 레지스트리, 네트워크 인터페이스 설정을 절대 변경하지 않습니다.
3. **무거운 외부 의존성 배제**:
   - WebView2 / Tauri / 브라우저 엔진 배제 (Win32 네이티브 API 직접 사용 우선).
   - Npcap / WinPcap 패킷 캡처 드라이버 배제.
   - SQLite 등 임베디드 데이터베이스 엔진 배제.
   - PDF 생성 렌더러 배제 (TXT/CSV 내보내기만 제공).
4. **엄격한 사실과 추론의 분리**:
   - 단독 진단 특성상 대상 서버에서의 수신 여부나 물리적 SYN/RST 패킷 관찰을 단정하지 않습니다.
   - 연결 실패를 방화벽 차단으로 단정하지 않고 OS 소켓 API 수준의 오류 코드를 있는 그대로 기록합니다.
5. **안전한 기본값 및 스캔 오용 방지**:
   - 최대 대상 수 100건 상한 (`max_targets: 100`).
   - 동시 검사 수 기본 4, 상한 4 (`concurrency cap 4`).
   - 서브넷(CIDR) 대역 스캔 및 포트 범위 스캔 기능 0건 (원천 배제).

---

## 3. 화면 구성 및 사용자 흐름 (설계안)

```text
┌ Network Quick Check ──────────────────────────────────────────────────┐
│ 대상: [192.168.10.100] 포트: [1526] [대상 추가] [여러 건 붙여넣기] │
│ 기능: [✓]TCP [✓]Ping [ ]Traceroute [ ]DNS [ ]로컬 네트워크       │
│ 타임아웃 [3000ms]  동시 검사 [4]  [시작] [중지]                 │
├───────────────────────────────────────────────────────────────────────┤
│ 필터: [전체 ▼] [기능 ▼] [대상 검색...]                             │
│ 192.168.10.100:1526 | TCP | FAIL | TIMEOUT | 3001ms             │
│ 192.168.10.100      | Ping| PASS | 2ms                           │
├───────────────────────────────────────────────────────────────────────┤
│ [결과 복사] [TXT 저장] [CSV 저장] [상세 보기]                     │
└───────────────────────────────────────────────────────────────────────┘
```

1. 사용자가 단일 `NetworkQuickCheck.exe`를 실행합니다.
2. 목적지 IP 또는 도메인과 포트를 입력하거나, 클립보드에서 여러 행을 붙여넣습니다 (최대 100건).
3. 검사할 기능을 선택합니다 (기본값: TCP Connect + Ping 선택, Traceroute 해제).
4. **시작** 버튼을 누르면 UI 멈춤 없이 실시간으로 진단 결과가 표시되며, 필요 시 언제든 **중지**할 수 있습니다.
5. 완료된 결과를 상태별로 필터링하고 클립보드로 복사하거나 TXT/CSV 파일로 저장합니다.

---

## 4. 빌드 및 개발 환경 안내 (향후 계획)

> [!NOTE]
> 아래 빌드 명령은 향후 QG1 이후 구현이 진행되었을 때 사용될 계획 명령입니다.

### 4.1 요구사항
- Rust 1.98 이상 (2024 Edition)
- 타깃 툴체인: `x86_64-pc-windows-msvc` (Visual Studio 2022 C++ 빌드 도구)

### 4.2 빌드 계획 명령
```powershell
# 개발용 빌드 검사
cargo check -p network-quick-check

# Release 단일 바이너리 빌드
cargo build --release -p network-quick-check

# 산출물 위치
# target/release/NetworkQuickCheck.exe
```

---

## 5. 보안 및 데이터 보호 정책

1. **자동 저장 및 원격 전송 금지**: 진단 결과는 메모리에만 임시 유지되며, 사용자의 명시적인 저장 명령 없이 파일로 저장되거나 원격 서버로 전송되지 않습니다.
2. **원자적 파일 저장 (Atomic Write)**: 파일 저장 시 임시 파일을 거쳐 교체하므로 저장 도중 전원 차단이나 충돌이 발생해도 파일이 손상되지 않습니다.
3. **CSV 수식 주입(Formula Injection) 방어**: 엑셀 등에서 수식으로 해석될 수 있는 문자(`=`, `+`, `-`, `@` 등)로 시작하는 셀 데이터는 선행 단일 따옴표(`'`)로 강제 이스케이프 처리됩니다.
4. **사내망 정보 보호 안내**: 결과 내보내기 시 내부망 IP 대역 및 호스트명이 포함되어 있음을 사용자에게 사전 안내합니다.
