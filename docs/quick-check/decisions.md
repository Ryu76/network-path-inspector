# Network Quick Check 설계 결정 기록 (QG0)

> [!NOTE]
> 본 문서에 기록된 모든 설계 결정(ADR)은 **제안 및 부모 검토 대기** 상태이며, 별도 사용자 승인 완료나 실행 통과 상태가 아님.

## ADR-Q01: GUI 기술 스택 제안
- **상태**: 제안 (부모 검토 대기)
- **결정 제안**: Windows 네이티브 Win32 GUI (windows-sys 또는 windows crate 기반) 직접 활용.
- **배경 및 대안**: 외부 웹뷰 및 무거운 C++ 런타임 배제를 목표로 함. Slint, Iced 등의 대안은 웹뷰/C++ 필수라고 단정하지 않으며, 단일 실행 파일 종속성 최소화 관점에서 **이번 범위 미선정**으로 분류함.

## ADR-Q02: 런타임 링크 및 무설치 배포 제안
- **상태**: 제안 (부모 검토 대기)
- **결정 제안**: MSVC 정적 CRT(`crt-static`) 링크 검토.
- **한계 및 주의사항**: 정적 CRT는 검토 설정일 뿐 현재 무설치 성공을 증명하지 않음. Windows 핵심 OS DLL(kernel32 등) 의존성은 남으므로, QG6 클린 VM/PE 검증을 필수 통과 조건으로 둠.

## ADR-Q03: 데이터 스키마 및 상태 매핑 제안
- **상태**: 제안 (부모 검토 대기)
- **결정 제안**: 기존 Inspector `Session 1.1`과 분리된 Quick Check 전용 `schema_version: "1.0"`, `product: "network-quick-check"` 적용.
- **매핑 규칙**: [quick-check-interface-v0.1.json](../../contracts/quick-check-interface-v0.1.json) 준수.
  - `CANCELLED` -> `status: UNKNOWN`, `evidence: UNKNOWN`
  - `LOCAL_ERROR` -> `status: UNKNOWN`, `evidence: OBSERVED` (원시 OS 오류코드 보존)

## ADR-Q04: 실행 한계값 및 기본 프리셋 제안
- **상태**: 제안 (부모 검토 대기)
- **결정 제안**: 대상 최대 100건(큐잉), 동시성 4(상한 4 고정), TCP 타임아웃 3000ms.
- **기본 선택**: TCP Connect + Ping만 활성화. Traceroute, DNS, 로컬 네트워크 정보는 기본 해제(선택하지 않은 기능은 0회 실행).
- **상위 요구사항**: [PRD v1.2](../requirements/Network_Path_Inspector_Harness_PRD_v1.2.md)의 부하 보호 원칙 반영.
