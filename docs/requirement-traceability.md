> **G0 설계 시점 문서**: 아래 표의 상태는 최초 설계 당시 기록이다. 현재 로컬 수용 판정은 G0 개발 범위/G1 오프라인 기반 통과이며, 최신 실제 수치·소스·미완료 범위는 `PROGRESS.md` 및 `artifacts/g1-gate-report.json`을 기준으로 한다. 전체 P0·실제 통신·설치·운영 완료를 의미하지 않는다.

# Network Path Inspector (NPI) 요구사항 추적 매트릭스 (Requirement Traceability Matrix)

- 문서 버전: 1.1.0-g0
- 기준 PRD: `PRD.md` (버전 1.1.0, SHA-256: `faffff45de66126dad6a0a81045dd22b536e9739e78947b426bd42d4a0ef7aa1`)
- 기준 인터페이스 계약: `contracts/g1-interface-contract.json` (`contract_version: "g1-1.1.0"`, `schema_version: "1.1"`)
- 고정 상태값(`status`) 규칙: 모든 행은 오직 `not-started`, `partial`, `implemented`, `blocked` 중 하나의 값만 가진다. 현재 NPI 코어는 비어 있으며 G1도 통과되지 않았으므로 어떠한 항목도 `implemented`로 표기하지 않는다. 다른 격리된 워크트리(worktree)의 코드는 부모 워크스페이스의 통합 컴파일·테스트 검증 전까지 구현 증거로 인정하지 않으며, 게이트 통과 상태 변경은 부모가 결정한다.

---

## 1. 필수 기능 요구사항 추적표 (P0-01 ~ P0-13)

`PRD.md` 2.1절의 필수 요구사항 `P0-01`부터 `P0-13`까지의 정확한 ID별 아키텍처 모듈, 계약 기능 ID, 검증 게이트 및 현재 상태를 추적한다.

| 요구사항 ID | 요구사항 명칭 | PRD 수용 기준 요약 | 매핑 그룹 및 기능 ID (`g1-interface-contract.json`) | 아키텍처 모듈 및 설계 문서 (ADR) | 검증 게이트 | 부모 검증 방법 (Test Policy) | status |
|---|---|---|---|---|---|---|---|
| **P0-01** | 단독 진단 | 한 PC에서 목적지 IPv4/IPv6·도메인, TCP 포트(1~65535), 타임아웃 입력 후 단독 모드(`standalone`) 검사 가능; CIDR/URI/자격증명 입력 거부 | `G-NET` (`tcp_connect`, `icmp_ping`, `dns_lookup`), `G-PATH` (`nic_inventory`, `route_table`), `G-EVID` (`result_json`) / 프리셋 `quick-default` | `ui`, `diagnostic-orchestrator`, `security-policy` ([architecture.md](./architecture.md), [ADR-0003](./adr/ADR-0003-preset-quick-default-and-registry-contract.md)) | G1, G2 | `Target` 입력 검증 단위 테스트 및 `127.0.0.1`/`::1` 단일 대상 단독 진단 통합 테스트 | `not-started` |
| **P0-02** | TCP Connect | 연결 성공(`CONNECTED`)/거부(`REFUSED`)/시간초과(`TIMED_OUT`)/도달 불가(`UNREACHABLE`)/로컬 오류(`LOCAL_ERROR`)/DNS 오류(`DNS_ERROR`)/취소(`CANCELLED`) 분류; Winsock 소켓 오류코드(`10061`, `10060` 등) 기록 | `G-NET` / `tcp_connect` (`SOCKET`, `DNS` 증거) | `tcp-probe`, `evidence-normalizer` ([architecture.md](./architecture.md) 4.1절) | G1, G2 | Winsock 오류 코드 매핑 단위 테스트, 로컬 루프백 리스닝/미리스닝/타임아웃 통합 테스트 | `not-started` |
| **P0-03** | ICMP Ping | 응답 시간(RTT), 손실률 측정, ICMP 비응답(차단)과 TCP 연결 실패/성공을 명확히 구별 | `G-NET` / `icmp_ping` (`ICMP` 증거) | `icmp-probe` (`Iphlpapi.dll` `IcmpSendEcho2` / `Icmp6SendEcho2`, [architecture.md](./architecture.md) 3.3절) | G1, G2 | ICMP 응답/비응답 및 TCP 성공/실패 조합에 대한 단위·특성화(Characterization) 테스트 | `not-started` |
| **P0-04** | 경로 추적 | ICMP 경로 추적 + 가능 시 TCP TTL 프로브; 각 HOP의 응답/비응답과 프로브 방법 명시; TCP 백엔드 미충족 시 무언 ICMP 대체 금지 | `G-PATH` / `icmp_traceroute`, `tcp_traceroute` (`requirements: ["validated_tcp_ttl_backend"]`) | `route-trace` ([ADR-0005](./adr/ADR-0005-tcp-traceroute-capability-and-no-silent-icmp-fallback.md)) | G1, G3, G3-v1.1 | TTL 정규화 단위 테스트, `validated_tcp_ttl_backend` 미충족 시 `UNAVAILABLE` 반환 및 무언 폴백 금지 검증 | `not-started` |
| **P0-05** | 네트워크 상태 | 로컬 IP, NIC 목록, 게이트웨이, DNS, 라우팅 테이블, 선택된 출발지 인터페이스 읽기 전용 수집 | `G-PATH` / `nic_inventory`, `route_table` (`HOST_SNAPSHOT` 증거) | `host-inventory` ([architecture.md](./architecture.md) 3.3절, [ADR-0004](./adr/ADR-0004-selective-execution-shared-collectors-and-profile-restore.md)) | G1, G2, G2-v1.1 | Windows `route print` / NIC 정보 대조 특성화 테스트 및 세션당 1회 내부 수집 공유 검증 | `not-started` |
| **P0-06** | 로컬 리스닝 확인 | 서버 설치/실행 시 대상 포트 `LISTENING` 여부, 바인딩 주소, 프로세스 ID(PID) 확인 | `G-PKT` / `listening_check` (`HOST_SNAPSHOT` 증거) | `host-inventory` ([architecture.md](./architecture.md) 3.3절) | G1, G2, G5 | 로컬 임시 리스너 바인딩 유무에 따른 `listening_check` 결과 및 `netstat` 대조 테스트 | `not-started` |
| **P0-07** | 선택적 패킷 캡처 | 외부 기설치 Npcap 및 캡처 권한(`capture_privilege`)·사용자 동의(`capture_consent`) 확인, 대상 IP/포트 BPF 필터링, PCAPNG/PCAP 스트리밍 저장(최대 50 MiB/30초), 미설치/실패 시 `UNAVAILABLE` 및 명확한 안내 | `G-PKT` / `packet_capture`, `syn_rst_analysis` (`PACKET`, `CAPTURE_METADATA` 증거) | `packet-capture` ([ADR-0002](./adr/ADR-0002-npcap-optional-adapter-and-licensing.md), [ADR-0004](./adr/ADR-0004-selective-execution-shared-collectors-and-profile-restore.md)) | G0, G4, G4-v1.1 | 비선택 시 캡처 시작 0회, 미설치/권한 부족 시 `UNAVAILABLE` 및 기본 진단 유지 검증 (내부 사용/번들 전 조직 차원의 Npcap 적용 라이선스 검토는 별도 블로커) | `blocked` |
| **P0-08** | 양방향 진단 | 클라이언트·서버 양측 동일 `session_id`를 사용하여 캡처/진단 결과(`host_role: client|server`)를 시간·5-tuple·NAT 가능성에 따라 상호 비교 | `G-PAIR` / `agent_session`, `packet_compare`, `clock_skew` | `correlation-engine`, `evidence-normalizer` ([architecture.md](./architecture.md) 3.2절, [ADR-0006](./adr/ADR-0006-privacy-masking-offline-pairing-and-evidence-provenance.md)) | G1, G5, G5-v1.1 | 클라이언트/서버 합성 픽스처 쌍을 이용한 SYN/SYN-ACK/RST 매칭, NAT 5-tuple 불일치, 시계 오차(`null` 포함) 단위 테스트 | `not-started` |
| **P0-09** | 오프라인 병합 | 실시간 직접 통신이나 인바운드 포트 개방 없이 서버/클라이언트 결과 ZIP 파일을 가져와(`paired_offline`) 안전하게 병합 분석 | `G-PAIR` / `import_bundle` (`IMPORT` 증거) | `storage`, `correlation-engine`, `security-policy` ([threat-model.md](./threat-model.md) 3.1절, [ADR-0006](./adr/ADR-0006-privacy-masking-offline-pairing-and-evidence-provenance.md)) | G1, G5, G5-v1.1 | 정상 ZIP 병합 골든마스터 테스트 및 악성 ZIP(Zip Slip, Symlink, Zip Bomb, 중복 엔트리, 해시 불일치, 외부 리소스 열기 금지) 부정 테스트 | `not-started` |
| **P0-10** | 보고서 | PDF(`report.pdf`) + 기계 판독 JSON(`session.json`, `measurements.jsonl`, `system_snapshot.json`, `limitations.json`) + 원본 로그/캡처 + `SHA256SUMS.txt`를 ZIP으로 출력 | `G-EVID` / `result_json`, `pdf_report`, `pcap_export`, `hash_verify` | `report-builder`, `storage` ([architecture.md](./architecture.md) 3.4절, [ADR-0006](./adr/ADR-0006-privacy-masking-offline-pairing-and-evidence-provenance.md)) | G1, G6, G6-v1.1 | ZIP 산출물 구조 검증, `SHA256SUMS.txt` 재계산 일치, 캡처 미실행 시 가짜 PCAP 미생성, 기본 마스킹 ON 및 반출 경고 테스트 | `not-started` |
| **P0-11** | 근거 수준 | 모든 판정에 `OBSERVED` / `INFERRED` / `UNKNOWN` 표시; `OBSERVED`는 실재하는 `evidence_ids[]` 필수; '마지막 응답 HOP = 차단 장비' 또는 캡처 없는 'SYN/RST 패킷 관찰' 단정 금지 | 공통 `Finding` 및 `FeatureResult` 스키마 (`classifications`, `confidence`, `evidence_ids`) | `SharedCore` 판정 분류기 ([architecture.md](./architecture.md) 4절, [threat-model.md](./threat-model.md) 3.2절) | G1, G2, G3, G4, G5, G6 | 부정 테스트(Negative Tests): 캡처 없이 `SYN`/`RST` 관찰 판정 거부, 미응답 HOP 차단 단정 거부, 미존재 `evidence_id` 참조 거부, `synthetic: true` 실측 위장 거부 | `not-started` |
| **P0-12** | 방화벽 정책 검증 | 출발지·목적지·포트·프로토콜·업체 허용 통보 메모(`POLICY_MEMO`)와 실제 측정 결과를 나란히 비교하고 방화벽 세션/Drop 로그 확인 요청 문구 포함 | `G-EVID` / `policy_check` (`POLICY_MEMO` 증거) | `report-builder`, `correlation-engine` ([architecture.md](./architecture.md), PRD UC-03) | G1, G6 | 업체 허용 메모 입력 시 '업체 통보: 허용 / 측정: TCP 실패' 사실 기록 및 차단 장비 미확정(`UNKNOWN`/`INFERRED`) 유지 검증 | `not-started` |
| **P0-13** | 비파괴 운영 | Oracle DB 인증/SQL 수행 불필요(TCP 핸드셰이크만으로 검사); OS 방화벽/라우트/레지스트리/인증서/서비스 무변경; 대역 스캔 금지 | 전체 기능 (`safety_rules`, `Target` 단일 호스트:포트 제약) | `security-policy`, `SharedCore` 검증기 ([architecture.md](./architecture.md) 1.1절, [threat-model.md](./threat-model.md) 3.3절) | G0 ~ G8 전체 | URI/자격증명/CIDR 입력 거부 테스트, 실행 전후 OS 설정 무변경 검증, 코드 내 DB 드라이버/SQL/권한 상승 호출 부재 정적 검증 (현재 G0 설계 규칙만 정의됨, 코어 비어 있음·G1 미통과) | `partial` |

---

## 2. 사용 시나리오 추적표 (UC-01 ~ UC-03)

`PRD.md` 3절의 핵심 사용 시나리오 `UC-01` ~ `UC-03`에 대한 실행 흐름 및 게이트 추적표이다.

| 시나리오 ID | 시나리오 명칭 | 시나리오 실행 흐름 및 제약 사항 | 관련 P0 요구사항 | 기본 프리셋 및 핵심 기능 ID | 정확성 및 안전 검증 포인트 | 검증 게이트 | status |
|---|---|---|---|---|---|---|---|
| **UC-01** | 이용자 PC 단독 진단 | 1. 단일 대상 IP/도메인 및 TCP 포트 입력 (`standalone` 모드)<br>2. 로컬 NIC/라우트/DNS -> TCP 연결 -> ICMP/TCP 경로 추적 -> 선택적 캡처 실행<br>3. 실패 유형과 마지막 응답 HOP 표시(미응답 구간은 확인 불가 `UNKNOWN` 표시)<br>4. 증거 ZIP 및 PDF 생성 | P0-01, P0-02, P0-03, P0-04, P0-05, P0-07, P0-10, P0-11, P0-13 | `quick-default`, `path-default`, `precise-default` (`tcp_connect`, `icmp_ping`, `nic_inventory`, `route_table`, `icmp_traceroute`, `tcp_traceroute`, `packet_capture`, `result_json`, `pdf_report`) | - 미선택 기능 `SKIPPED_BY_USER` 및 프로브 0회<br>- 캡처 미실행 시 소켓 오류코드만 `OBSERVED` 기록<br>- 마지막 응답 HOP을 차단 장비로 단정 금지<br>- 실제 네트워크 시험은 부모의 `127.0.0.1`/`::1` 루프백으로 제한(예시 `192.168.*` 실제 접속 금지) | G1, G2, G3, G4, G6 | `not-started` |
| **UC-02** | 서버+이용자 PC 양방향 진단 | 1. 양쪽에서 동일 `session_id` 설정<br>2. 동일 시간대 선택적 캡처 및 서버 `listening_check` / `firewall_log` 수집<br>3. 클라이언트 TCP 연결 시도 및 양측 이벤트/패킷 저장<br>4. 오프라인 ZIP(`paired_offline`) 가져오기(`import_bundle`) 및 병합<br>5. SYN 송신·서버 수신·SYN-ACK·클라이언트 수신 비교 | P0-06, P0-07, P0-08, P0-09, P0-10, P0-11, P0-13 | `paired-default` (`agent_session`, `import_bundle`, `packet_compare`, `clock_skew`, `result_json`) + `listening_check`, `firewall_log`, `packet_capture` | - 서버 `SYN` 미관찰 시 서버 미도착으로 단정하지 않고 NIC/필터/드롭/비대칭 경로 가능성 명시<br>- 양측 시계 오차(`clock_offset_ms`, `clock_uncertainty_ms`) 미측정 시 `null` 유지<br>- ZIP 가져오기 시 7중 보안 검증 및 외부 리소스 열기 금지 | G1, G4, G5, G6 | `not-started` |
| **UC-03** | 업체 정책 허용 주장 검증 | 1. 정책 요청 번호, 업체 회신 시간, 출발지/목적지 IP, 프로토콜/포트, 허용 통보 메모 입력<br>2. 실제 진단 측정 결과와 업체 통보 내용 대조<br>3. '업체 통보: 허용 / 측정: TCP 실패'를 사실로 기록하고 차단 장비는 미확정(`UNKNOWN`)으로 표시<br>4. 방화벽 세션/정책 매칭/Drop 로그 확인 요청 문구 포함 보고서 생성 | P0-01, P0-02, P0-10, P0-11, P0-12, P0-13 | `policy_check`, `result_json`, `pdf_report`, `hash_verify` | - 방화벽 로그/장비 캡처 증거 없이 특정 방화벽을 차단 원인으로 자동 단정하는 문구 생성 금지<br>- 기본 마스킹 ON 및 반출 전 노출 경고 표시 | G1, G2, G6 | `not-started` |

---

## 3. 계약 고정 6개 그룹 및 23개 기능 전수 추적표 (`contracts/g1-interface-contract.json`)

`contracts/g1-interface-contract.json`에 정의된 6개 그룹 및 23개 기능 ID의 속성, 소속 프리셋, 요구사항 및 현재 구현 상태를 전수 추적한다.

| 순번 | 그룹 ID | 기능 ID (`feature_id`) | 한글 라벨 (`label`) | 기본 선택 (`default_selected`) | 소속 기본 프리셋 | 선행 요구사항 (`requirements[]`) | 비용 등급 (`cost_class`) | 권한 수준 (`permission_level`) | 관련 PRD 요구사항 | 검증 게이트 | status |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `G-NET` | `tcp_connect` | TCP 연결 | `true` | `quick`, `path`, `precise` | `[]` | `LOW` | `USER` | P0-01, P0-02, P0-13 | G1, G2 | `not-started` |
| 2 | `G-NET` | `icmp_ping` | ICMP Ping | `true` | `quick`, `path`, `precise` | `[]` | `LOW` | `USER` | P0-01, P0-03 | G1, G2 | `not-started` |
| 3 | `G-NET` | `dns_lookup` | DNS 조회 | `false` | (사용자 선택) | `[]` | `LOW` | `USER` | P0-01, P0-05, 14.1 | G1, G2 | `not-started` |
| 4 | `G-PATH` | `icmp_traceroute` | ICMP 경로 추적 | `false` | `path`, `precise` | `[]` | `MEDIUM` | `USER` | P0-04, P0-11, 14.1 | G1, G3 | `not-started` |
| 5 | `G-PATH` | `tcp_traceroute` | TCP 경로 추적 | `false` | `path`, `precise` | `["validated_tcp_ttl_backend"]` | `HIGH` | `CONDITIONAL` | P0-04, P0-11, 14.3 | G1, G3 | `not-started` |
| 6 | `G-PATH` | `route_table` | 라우팅 테이블 | `true` | `quick`, `path`, `precise` | `[]` | `LOW` | `USER` | P0-05, 14.1 | G1, G2 | `not-started` |
| 7 | `G-PATH` | `nic_inventory` | NIC/게이트웨이 | `true` | `quick`, `path`, `precise` | `[]` | `LOW` | `USER` | P0-05, 14.1 | G1, G2 | `not-started` |
| 8 | `G-PKT` | `packet_capture` | 패킷 캡처 | `false` | `precise` | `["capture_consent", "npcap", "capture_privilege"]` | `HIGH` | `CONDITIONAL` | P0-07, 13.1, 14.1 | G0, G4 | `blocked` |
| 9 | `G-PKT` | `syn_rst_analysis` | SYN/RST 분석 | `false` | `precise` | `["packet_evidence"]` | `MEDIUM` | `USER` | P0-02, P0-07, P0-11 | G1, G4 | `not-started` |
| 10 | `G-PKT` | `firewall_log` | 로컬 방화벽 로그 | `false` | `precise` | `[]` | `LOW` | `CONDITIONAL` | 4.2, 14.1, UC-02 | G1, G4, G5 | `not-started` |
| 11 | `G-PKT` | `listening_check` | 리스닝 검사 | `false` | `precise` | `[]` | `LOW` | `USER` | P0-06, 14.1, UC-02 | G1, G2, G5 | `not-started` |
| 12 | `G-PAIR` | `agent_session` | Agent 세션 | `false` | `paired` | `[]` | `LOW` | `USER` | P0-08, 6.1, 13.1 | G1, G5 | `not-started` |
| 13 | `G-PAIR` | `import_bundle` | 결과 ZIP 가져오기 | `false` | `paired` | `[]` | `LOW` | `USER` | P0-09, 14.1, UC-02 | G1, G5 | `not-started` |
| 14 | `G-PAIR` | `packet_compare` | 패킷 비교 | `false` | `paired` | `["packet_evidence"]` | `MEDIUM` | `USER` | P0-08, 4.2, UC-02 | G1, G5 | `not-started` |
| 15 | `G-PAIR` | `clock_skew` | 시계 오차 검사 | `false` | `paired` | `[]` | `LOW` | `USER` | P0-08, 4.2, 9, 14.1 | G1, G5 | `not-started` |
| 16 | `G-OPS` | `tcp_monitor` | 반복 TCP | `false` | (사용자 선택 / P1 연계) | `[]` | `LOW` | `USER` | 2.2, 13.1, 14.1 | G1, G7 | `not-started` |
| 17 | `G-OPS` | `config_change` | 구성 변경 감지 | `false` | (사용자 선택 / P1 연계) | `[]` | `LOW` | `USER` | 2.2, 14.1 | G1, G7 | `not-started` |
| 18 | `G-OPS` | `history_query` | 이력 조회 | `false` | (사용자 선택 / P1 연계) | `[]` | `LOW` | `USER` | 2.2, 6.1, 14.1 | G1, G6 | `not-started` |
| 19 | `G-EVID` | `result_json` | 결과 JSON | `true` | `quick`, `path`, `precise`, `paired` | `[]` | `LOW` | `USER` | P0-10, 7.1, 14.1 | G1, G2, G6 | `not-started` |
| 20 | `G-EVID` | `pdf_report` | PDF 보고서 | `false` | (사용자 선택) | `[]` | `MEDIUM` | `USER` | P0-10, 7.2, 13.1 | G1, G6 | `not-started` |
| 21 | `G-EVID` | `pcap_export` | PCAP 내보내기 | `false` | (사용자 선택) | `["packet_evidence"]` | `LOW` | `USER` | P0-07, P0-10, 7.2 | G1, G4, G6 | `not-started` |
| 22 | `G-EVID` | `hash_verify` | 해시 검증 | `false` | (사용자 선택) | `[]` | `LOW` | `USER` | P0-10, 7.2, 10.4 | G1, G5, G6 | `not-started` |
| 23 | `G-EVID` | `policy_check` | 정책 검증 | `false` | (사용자 선택) | `[]` | `LOW` | `USER` | P0-12, UC-03, 14.1 | G1, G6 | `not-started` |

---

## 4. 단계별 게이트 및 v1.1 성능/선택 요구사항 요약 추적표

| 추적 ID | 구분 | 요구사항 요약 | 관련 문서 및 절 | status |
|---|---|---|---|---|
| **GATE-G0** | 기본 게이트 | 요구사항·위협 모델·지원 OS/권한·Npcap 정책 확정 (G0 설계 문서 작성, 개발 호스트 Win10 Pro 19045 확인/런타임 미검증, 코어 비어 있음·G1 미통과; 적용 라이선스 검토/타 OS 실측/서명은 분리 보류, 최종 판정은 부모 결정) | [architecture.md](./architecture.md), [threat-model.md](./threat-model.md), [adr/README.md](./adr/README.md) | `partial` |
| **GATE-G1** | 기본 + v1.1 게이트 | 핵심 DTO/오류 분류/JSON Schema/테스트 픽스처 및 6그룹·23기능·4프리셋 레지스트리, v1.0 호환 변환기 | [gate-checklist.md](./gate-checklist.md) G1, G1-v1.1 | `not-started` |
| **GATE-G2** | 기본 + v1.1 게이트 | TCP·NIC·라우트·ICMP 단독 진단, 선택 기능만 실행(`SKIPPED_BY_USER`), 선행 수집 1회 공유 | [gate-checklist.md](./gate-checklist.md) G2, G2-v1.1 | `not-started` |
| **GATE-G3** | 기본 + v1.1 게이트 | 경로 추적(`icmp_traceroute`, `tcp_traceroute`), 비활성 프로브 0회, 무언 ICMP 대체 금지 | [gate-checklist.md](./gate-checklist.md) G3, G3-v1.1 | `not-started` |
| **GATE-G4** | 기본 + v1.1 게이트 | 선택적 패킷 캡처 지연 로딩, 비선택 시 캡처 0회, 프로파일 복원 시 `capture_approved` 제거, 내부 사용/번들 전 조직 Npcap 적용 라이선스 검토 선행 조건 | [gate-checklist.md](./gate-checklist.md) G4, G4-v1.1 | `blocked` |
| **GATE-G5** | 기본 + v1.1 게이트 | 양방향 오프라인 ZIP 병합, 출처 보존, 시계 오차 `null` 처리, NAT/비대칭 경로 처리, 7중 ZIP 보안 검증 | [gate-checklist.md](./gate-checklist.md) G5, G5-v1.1 | `not-started` |
| **GATE-G6** | 기본 + v1.1 게이트 | PDF·증거 ZIP 생성, 선택 범위 명시, 미실행 위조 금지, `SHA256SUMS.txt` 검증, 기본 마스킹 ON 및 반출 경고 | [gate-checklist.md](./gate-checklist.md) G6, G6-v1.1 | `not-started` |
| **GATE-G7** | 기본 + v1.1 게이트 | 실제 2-VLAN 실험실 테스트, Win11/Server 2016+ 실측(pending), 성능 목표 예산(유휴 80MiB/30MiB, UI 4회/초, 시작/정리 3초) 및 24시간 누수 측정 | [gate-checklist.md](./gate-checklist.md) G7, G7-v1.1 | `blocked` |
| **GATE-G8** | 기본 + v1.1 게이트 | 코드 서명, MSI/EXE 설치·업데이트·제거 검증, Npcap 미설치 클린 실행, 사내 배포 체크리스트 최종 승인 | [gate-checklist.md](./gate-checklist.md) G8, G8-v1.1 | `blocked` |
