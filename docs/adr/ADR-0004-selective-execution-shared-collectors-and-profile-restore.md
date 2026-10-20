# ADR-0004: 미선택 진단 기능 프로브 0회 보장, 내부 선행 수집기 1회 공유 및 고비용 프로파일 복원 재확인

- 상태: Accepted
- 작성일: 2026-10-20
- 관련 요구사항: PRD 13.1, 14.2, 14.3, 15 (G1, G2, G3, G4); `contracts/g1-interface-contract.json` (`safety_rules`)

## 1. 배경 및 문제 (Context)
1. **미선택 진단 기능 비실행 vs 선행 공통 수집 공유의 경계**:
   - `PRD.md` 14.3절은 "선택 기능을 DAG로 정렬해 필요한 선행 수집만 실행한다. 공통 NIC/라우트 조회는 세션당 1회 수집 후 공유"라고 기술하는 동시에, 14.2절과 15절(G2, G3, G4)은 "선택 기능만 실행", "비활성 기능 프로브 0회", "비선택 시 캡처 시작 0회", "선택하지 않은 기능은 `SKIPPED_BY_USER`"를 요구한다.
   - 만약 사용자가 `nic_inventory`나 `route_table`을 체크 해제했는데 내부 선행 수집기가 동작할 경우, 이를 어떻게 처리해야 "비선택 프로브 0회" 및 "`SKIPPED_BY_USER` 표시" 규칙과 충돌하지 않는지 명확한 아키텍처 규칙이 필요하다.
2. **프로파일 복원 시 고위험·고비용 기능 자동 활성화 위험**:
   - `PRD.md` 14.2절은 "선택 상태를 프로파일로 저장/불러오기/복제할 수 있으며 최근 사용값은 복원하되 위험·고부하 기능은 자동 활성화하지 않는다"고 규정한다. 어떤 기능이 위험·고부하 기능인지 계약 필드 기준으로 명확히 정의해야 한다.

## 2. 결정 (Decision)
`contracts/g1-interface-contract.json`의 `safety_rules`에 맞추어 다음 규칙을 확정한다:

1. **미선택 진단 프로브 절대 비실행 (Zero Probe for Deselected Features)**:
   - 사용자가 선택하지 않은(`selected_features`에 없는) 모든 진단 프로브(`tcp_connect`, `icmp_ping`, `dns_lookup`, `icmp_traceroute`, `tcp_traceroute`, `packet_capture`, `listening_check`, `firewall_log`, `tcp_monitor` 등)는 **단 1회도 네트워크 패킷 송신이나 외부 프로브를 실행하지 않는다**.
   - 선택되지 않은 기능의 `FeatureResult.status`는 반드시 `SKIPPED_BY_USER`로 기록하며, `PASS`나 `FAIL`로 위장하지 않는다.
2. **내부 선행 수집기(Internal Shared Collector)의 엄격한 경계**:
   - 선택된 기능을 수행하기 위해 출발지 인터페이스나 라우팅 경로 같은 로컬 읽기 전용 컨텍스트가 내부적으로 필요한 경우, 엔진은 해당 로컬 스냅샷 수집기를 **세션당 최대 1회 내부적으로 공유**할 수 있다.
   - 단, 사용자가 `nic_inventory` 또는 `route_table` 기능을 선택 해제했다면 해당 기능의 `FeatureResult` 상태는 여전히 `SKIPPED_BY_USER`로 유지해야 하며, 내부 선행 수집은 오직 읽기 전용 로컬 조회에만 허용된다.
   - **의존성이나 프리셋 선택이 패킷 캡처 동의(`capture_approved`)나 고위험 외부 프로브 실행을 자동으로 활성화해서는 절대 안 된다**(`dependencies must not auto-consent capture`). 예를 들어 `syn_rst_analysis`나 `packet_compare`만 선택하고 `packet_capture`를 선택/동의하지 않았다면, 캡처를 자동 시작하지 않고 `packet_evidence` 요구사항 미충족으로 인해 `UNAVAILABLE`로 처리한다.
3. **프로파일 불러오기/복원 시 안전 초기화 규칙 (Profile Restore Safety)**:
   - 프리셋 선택(`precise-default` 포함)이나 저장된 `Profile` 복원 시 **`capture_approved`는 항상 `false`로 강제 초기화(strip)** 한다.
   - 프로파일 복원 시 `cost_class: "HIGH"`(`tcp_traceroute`, `packet_capture`) 또는 위험/조건부 권한(`permission_level: "CONDITIONAL"` 및 캡처 의존 기능) 항목은 자동 실행 상태로 복원하지 않고 선택 목록에서 제거하거나 사용자가 실행 전 명시적으로 재확인(reconfirm)할 때까지 비활성 상태로 둔다.

## 3. 결과 및 영향 (Consequences)
- G2/G3/G4 게이트의 "비선택 프로브 0회", "비선택 캡처 시작 0회", "공통 수집 중복 없음" 요구사항을 동시에 만족한다.
- 과거에 정밀 캡처 프로파일을 사용했더라도 앱 재시작이나 프로파일 불러오기 시 무단 캡처·고부하 프로브가 실행되는 사고를 원천 방지한다.
