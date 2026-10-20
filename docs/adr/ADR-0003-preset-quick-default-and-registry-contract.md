# ADR-0003: 빠른 진단(`quick-default`) 프리셋 5개 기능 정규화 및 6그룹/23기능 고정 계약

- 상태: Accepted
- 작성일: 2026-10-20
- 관련 요구사항: PRD 14.1, 14.2, 14.4, 15 (G1); `contracts/g1-interface-contract.json`

## 1. 배경 및 문제 (Context)
`PRD.md` 원문에는 빠른 진단(`quick-default`) 기본 선택 기능 집합에 대해 두 곳의 서술 차이가 존재한다:
1. **PRD 14.1절(기능 그룹 정의 표)**: 각 그룹의 '기본 선택' 열을 합산하면 다음과 같이 **5개 기능**이다.
   - `G-NET`: TCP Connect (`tcp_connect`), ICMP Ping (`icmp_ping`)
   - `G-PATH`: NIC/게이트웨이 (`nic_inventory`), 라우팅 테이블 (`route_table`)
   - `G-EVID`: 결과 JSON (`result_json`)
   - (14.5절 화면 레이아웃 예시 하단에도 `[선택 5개]`로 표기됨)
2. **PRD 14.4절(데이터 모델 추가 JSON 예시)**: `profile_id: "quick-default"` 예시의 `selected_features` 배열에는 `["tcp_connect", "icmp_ping", "nic_inventory", "route_table"]`로 **4개 기능**만 적혀 있고 `result_json`이 생략되어 있다.

이 모호성을 해결하지 않으면 워크트리 간(코어, UI, 테스트) 기본 프리셋 기대값이 불일치하게 된다.

## 2. 결정 (Decision)
1. **`quick-default` 프리셋의 정규(Canonical) 정의를 5개 기능으로 확정한다**:
   - `contracts/g1-interface-contract.json`의 `presets["quick-default"]` 정의에 따라 정규 목록은 다음 **5개 기능 ID**로 고정한다:
     1. `tcp_connect` (`G-NET`, `default_selected: true`)
     2. `icmp_ping` (`G-NET`, `default_selected: true`)
     3. `nic_inventory` (`G-PATH`, `default_selected: true`)
     4. `route_table` (`G-PATH`, `default_selected: true`)
     5. `result_json` (`G-EVID`, `default_selected: true`)
   - PRD 14.4절의 4개 항목 JSON 스니펫은 지면상 축약된 예시로 해석하며, 실제 스키마 및 프리셋 검증에서는 계약 파일의 5개 목록을 단일 진실 공급원(Single Source of Truth)으로 사용한다.
2. **6개 그룹 및 23개 기능 ID 고정**:
   - 그룹 ID(6개): `G-NET`, `G-PATH`, `G-PKT`, `G-PAIR`, `G-OPS`, `G-EVID`.
   - 기능 ID(23개):
     - `G-NET` (3): `tcp_connect`, `icmp_ping`, `dns_lookup`
     - `G-PATH` (4): `icmp_traceroute`, `tcp_traceroute`, `route_table`, `nic_inventory`
     - `G-PKT` (4): `packet_capture`, `syn_rst_analysis`, `firewall_log`, `listening_check`
     - `G-PAIR` (4): `agent_session`, `import_bundle`, `packet_compare`, `clock_skew`
     - `G-OPS` (3): `tcp_monitor`, `config_change`, `history_query`
     - `G-EVID` (5): `result_json`, `pdf_report`, `pcap_export`, `hash_verify`, `policy_check`
   - 기타 표준 프리셋도 `contracts/g1-interface-contract.json`의 정의(`path-default` 7개, `precise-default` 11개, `paired-default` 5개)를 그대로 따른다.

## 3. 결과 및 영향 (Consequences — 설계 목표 및 수용 검증 계획)
- PRD 원문을 수정하지 않고도 14.1절 표, 14.5절 UI 레이아웃(`[선택 5개]`), 그리고 `contracts/g1-interface-contract.json`을 일관된 단일 계약 기준으로 정렬한다.
- 현재 시점에는 컴파일된 코어/런타임이 없으며 G1이 아직 통과되지 않았으므로, 코어·UI·테스트 통합 시 동일한 23개 기능 ID와 4개 프리셋 정의를 G1 수용 검증 기준으로 사용할 예정이다.
