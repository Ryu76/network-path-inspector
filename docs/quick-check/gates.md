# Network Quick Check 품질 게이트 계획 (QG0)

## 1. 지원 OS 후보 매트릭스 및 제약
- **후보 대상**: Windows 10/11 x64 및 Windows Server 2016+ x64 (후보 범위이며 QG6 실제 OS 검증 전 미확정).
- **개발 시험 환경**: 현재 개발 시험은 Windows 10 (Build 19045) x64 단일 환경에서만 수행. ARM64는 현재 범위에서 보류.
- **CRT 링크 한계**: CRT static 링크(`crt-static`)는 배포 검토 설정일 뿐 현재 무설치 성공을 의미하지 않으며 OS 필수 DLL은 여전히 동적 연결됨.

## 2. 게이트별 수용 기준 및 검증 계획 (전 단계 미검증 계획 상태)
| Gate | 검증 목표 | 수용 기준 (계획) | 현재 상태 |
|---|---|---|---|
| **QG0** | 설계 및 범위 확정 | 후보 OS 합의, 위협 모델, 계약 상대경로 정합성 검토 | **제안 단계** (부모 검토 대기) |
| **QG1** | 코어 facade 추출 | `network-core` facade 분리 및 계약 스키마 검증, 기존 Inspector 회귀 | 미검증 계획 (코드 미작성) |
| **QG2** | 프로브 검증 | 정상/거부/DROP/DNS 실패/ICMP 차단 단위 검증 (루프백으로 DROP/차단 대체 불가) | 미검증 계획 (공유 변경 회귀 필수) |
| **QG3** | Win32 GUI 연동 | UI 비차단(I/O 0), 비선택 기능 0회 실행 검증 | 미검증 계획 (GUI 미구현) |
| **QG4** | 동시성 및 취소 | 4 동시성 준수, 취소 시 소켓 정리 및 큐 회수 검증 | 미검증 계획 |
| **QG5** | 내보내기 무결성 | UTF-8 인코딩, CSV 수식 주입 방어, 원자적 쓰기 검증 | 미검증 계획 |
| **QG6** | 단일 EXE 무설치 | 깨끗한 Windows VM/PE에서 추가 런타임/설치 없이 실행 검증 | 미검증 계획 (실제 OS 인증 필요) |
| **QG7** | 통합 회귀 | Inspector와 Quick Check 양방향 회귀 검증 (Quick 통과를 Inspector 완료로 치환 금지) | 미검증 계획 |

## 3. 검증 원칙 및 회귀 통제
- **대체 금지**: 로컬 127.0.0.1 루프백 시험 결과로 실제 DROP, ICMP 차단, 2VLAN 환경의 미검증(blocked) 항목을 통과 처리하지 않음.
- **공유 회귀**: Inspector G2 미완료가 Quick QG2 진행을 막지는 않으나, 공통 코어 수정 시 Inspector 회귀 시험이 필수적임.
- **참조 문서**: [인터페이스 계약](../../contracts/quick-check-interface-v0.1.json) 및 [PRD v1.2](../requirements/Network_Path_Inspector_Harness_PRD_v1.2.md).
