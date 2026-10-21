# Network Quick Check 요구사항 추적성 매트릭스 (QG0)

## 1. P0 요구사항 추적표 (정확 13건)
- **상태 기준**: `not-started`(미착수), `partial`(기존 crate에 원시 구현 존재하나 Quick 미연동), `blocked`(선행 검증 환경 또는 타깃 검증 미실행).
- Quick Check 실행 파일 및 GUI 코드는 현재 0단계이며, 동작 중인 상태로 단정하지 않음.

| 요구사항 ID | 요구사항 내용 | 핵심 수용 기준 (계획) | 현재 상태 | 비고 및 한계 |
|---|---|---|---|---|
| **Q-P0-01** | 무설치 단일 EXE | 클린 Windows 환경에서 설치 없이 실행 | `blocked` | QG6 클린 VM 검증 미실행, CRT static 검토 단계 |
| **Q-P0-02** | 입력 및 유효성 검사 | IP/도메인, 포트(1~65535), 타임아웃 검증 | `not-started` | GUI 입력 컨트롤 및 검증 로직 미작성 |
| **Q-P0-03** | TCP Connect | 성공/거부/시간초과/오류 분류, 소켓 오류코드 보존 | `partial` | npi-probes 원시 프로브 존재하나 facade 미연결 |
| **Q-P0-04** | Ping | ICMP 응답시간/손실 표시, TCP 실패와 분리 | `partial` | npi-probes에 ICMP 구현 존재, GUI 미연동 |
| **Q-P0-05** | 경로 추적 | ICMP Traceroute, 미응답 HOP '미확인' 처리 | `not-started` | 프로젝트 Traceroute 구현 없음. Windows API/기본 명령 활용 및 검증은 QG2 예정 |
| **Q-P0-06** | DNS 조회 | 필수 도메인 해석과 DNS 검사 분리, IP 목록 기록 | `partial` | DNS 모듈 root 미연결, OS 해석 한계 명시 필요 |
| **Q-P0-07** | 로컬 네트워크 정보 | 로컬 NIC/IP/게이트웨이/경로 정보 수집 | `partial` | npi-probes 어댑터 조회 존재, 비선택 시 수집 배제 |
| **Q-P0-08** | 다중 대상 | 최대 100건 대상 추가/삭제, 개별 결과 보존 | `not-started` | 대상 관리 큐 및 실행 스케줄러 미구현 |
| **Q-P0-09** | 기능 선택 | 기본 TCP+Ping, 미선택 기능 0회 실행 보장 | `not-started` | 선택형 실행 디스패처 미구현 |
| **Q-P0-10** | 결과 필터 | 전체/성공/실패/기능별/대상별 결과 필터링 | `not-started` | 결과 메모리 모델 및 UI 필터 미구현 |
| **Q-P0-11** | 결과 공유 | TXT/CSV 저장, UTF-8, CSV 수식 주입 방어 | `not-started` | 원자적 파일 쓰기 및 이스케이프 로직 미구현 |
| **Q-P0-12** | 취소/타임아웃 | 작업 중단 지원, 소켓 정리, UI 응답 유지 | `not-started` | 취소 토큰 전달 및 큐 정리 미구현 |
| **Q-P0-13** | 안전한 기본값 | 포트 스캔/대역 탐색 배제, 동시성 4 제한 | `not-started` | 동시성 세마포어 및 안전 제한 미구현 |

## 2. 관련 기준 문서
- 계약 정의: [quick-check-interface-v0.1.json](../../contracts/quick-check-interface-v0.1.json)
- 상위 요구사항: [Network Path Inspector Harness PRD v1.2](../requirements/Network_Path_Inspector_Harness_PRD_v1.2.md)
