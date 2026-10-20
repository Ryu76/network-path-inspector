# ADR-0001: G0 안전 개발 범위, x64 타깃, OS 지원 검증 경계 및 미서명 개발 빌드 정책

- 상태: Accepted (G0 Baseline / 배포 선행 조건 분리)
- 작성일: 2026-10-20
- 관련 요구사항: PRD 6.1, 10.2 (G0, G7, G8), 16.1, 16.5

## 1. 배경 및 문제 (Context)
- `PRD.md` 6.1절은 "Windows 10/11 및 Windows Server 2016 이상(지원 버전은 실제 테스트로 확정)"을 기술 기준안으로 제시하고, 16절(구현 전 결정 필요 사항)에서 1) 지원 Windows Server 최소 버전과 x64 전용 여부, 5) 코드 서명 및 사내 배포 방식을 확정하도록 요구한다.
- 현재 하네스 개발 환경에서 확인된 부모 호스트 OS는 **Windows 10 Pro (Build 19045, x64)** 단일 호스트뿐이며, Windows 11이나 Windows Server 2016/2019/2022 실험실 호스트 및 조직 코드 서명 인증서(Authenticode/EV)는 아직 제공·검증되지 않았다.
- AI 작업자가 실측하지 않은 OS 호환성을 "지원 완료"로 가정하거나, 서명 인증서 없이 배포 완료(G8)를 주장하는 것은 PRD 10.1절 및 10.5절 규칙에 위배된다.

## 2. 출처 사실 (Source Facts)
1. Tauri 공식 전제조건 문서(`https://tauri.app/start/prerequisites/`, 로컬 사본 `.harness/references/tauri-prerequisites.txt`)에 따르면:
   - Windows용 Tauri 개발에는 Microsoft C++ Build Tools 및 Microsoft Edge WebView2가 필요하며, Rust 기본 툴체인으로 `stable-msvc`(`x86_64-pc-windows-msvc` 등)를 사용한다.
   - WebView2는 Windows 10 버전 1803 이상에 기본 설치되어 있다.
   - MSI 설치 프로그램 빌드 시 Windows 선택적 기능인 `VBSCRIPT`(`light.exe` 실행 의존성)가 필요하며 이는 향후 Windows 버전에서 비활성화될 수 있다.
2. Windows ICMP API 공식 문서(`https://learn.microsoft.com/en-us/windows/win32/api/icmpapi/nf-icmpapi-icmpsendecho2`, 로컬 사본 `.harness/references/icmp-api.txt`)에 따르면 `IcmpSendEcho2`는 `Iphlpapi.dll`을 통해 클라이언트/서버 Windows에서 기본 제공된다.

## 3. 결정 (Decision)
요구사항을 축소하거나 약화시키지 않으면서 **G0 로컬 개발 수용 기준**과 **운영 배포 준비 선행 조건**을 다음과 같이 엄격히 분리한다.

1. **초기 타깃 아키텍처**: `x86_64-pc-windows-msvc` (**x64 전용**)로 확정한다(32비트 `i686` 및 `aarch64`는 초기 범위에서 제외).
2. **OS 검증 경계**:
   - 현재 검증된(Verified) 개발/테스트 호스트 OS는 **Windows 10 Pro (Build 19045) x64** 부모 호스트로 한정한다.
   - **Windows 11** 및 **Windows Server 2016 이상**은 목표 지원 대상(Target Support Matrix)으로 유지하되, 해당 OS에서의 실제 테스트(WebView2 런타임 존재 여부, Headless Agent 실행, 방화벽/네트워크 API 동작, MSI/EXE 설치 검증)가 완료되기 전까지는 문서나 UI에서 "인증/검증 완료(Certified/Verified)"로 주장하지 않고 `unverified` / `blocked` 상태로 기록한다.
3. **빌드 및 코드 서명 정책**:
   - G0~G7 로컬 개발 및 검증 단계에서는 **서명되지 않은 로컬 개발 빌드(Unsigned Local Dev Build)** 만 생성·사용한다.
   - 코드 서명 인증서 발급, 바이너리/설치본 서명, SmartScreen/사내 배포 정책 통과는 G8 게이트의 필수 선행 조건(Deferred Deployment Prerequisite)으로 분리하여 관리한다.

## 4. 결과 및 영향 (Consequences)
- G1~G6 개발 및 단위/통합 시험은 현재 Windows 10 Pro 19045 (x64) 호스트에서 안전하게 진행할 수 있다.
- `docs/gate-checklist.md`에서 G7(두 VLAN 및 타깃 OS 실측)과 G8(서명·배포·설치 검증)은 실제 환경 및 인증서 확보 전까지 `blocked` 상태를 유지하며 허위 통과 처리가 방지된다.
