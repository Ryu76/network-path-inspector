> **G0 설계 시점 문서**: 아래 표의 상태는 최초 설계 당시 기록이다. 현재 로컬 수용 판정은 G0 개발 범위/G1 오프라인 기반 통과이며, 최신 실제 수치·소스·미완료 범위는 `PROGRESS.md` 및 `artifacts/g1-gate-report.json`을 기준으로 한다. 전체 P0·실제 통신·설치·운영 완료를 의미하지 않는다.

# Network Path Inspector (NPI) 단계별 품질 게이트 체크리스트 (G0 ~ G8 & v1.1)

- 문서 버전: 1.1.0-g0
- 기준 PRD: `PRD.md` (10.2절, 10.3절, 10.4절, 13.2절, 15절, 16절)
- 기준 인터페이스 계약: `contracts/g1-interface-contract.json` (`contract_version: "g1-1.1.0"`)
- 상태값 규칙: 모든 행의 상태(`status`)는 오직 `not-started`, `partial`, `implemented`, `blocked` 중 하나로만 표기한다.
- 증거 인정 및 상태 결정 원칙: **현재 코어는 비어 있으며 G1도 아직 통과되지 않았다. 다른 격리된 워크트리(worktree)에서 작성 중인 소스 코드는 부모 워크스페이스의 통합 컴파일 및 테스트 실행 증거가 확인되기 전까지 `implemented` 증거로 인정하지 않으며, G0를 포함한 모든 게이트의 통과 및 상태 변경은 부모가 최종 결정한다.**

---

## 1. 로컬 G0 개발 수용 기준 vs 운영/배포 준비 선행 조건 (이중 경계)

요구사항을 임의로 약화시키지 않기 위해, 현재 로컬 개발 환경에서 즉시 진행 가능한 **G0 개발 수용 범위**와 외부 승인·장비·라이선스 검토가 필요한 **운영 배포 선행 조건(Deferred Deployment Prerequisites)** 을 다음과 같이 분리하여 관리한다.

| 선행 조건 ID | 항목 (PRD 16절) | 로컬 G0 개발 수용 기준 (Development Acceptance) | 운영/배포 준비 완료 조건 (Production Readiness) | 관련 게이트 | status |
|---|---|---|---|---|---|
| **PRE-01** | 타깃 아키텍처 및 OS 지원 범위 | `x86_64-pc-windows-msvc` (x64 전용) 타깃 고정. **Windows 10 Pro (Build 19045)** 는 현재 **개발 호스트 환경으로만 확인됨(confirmed development host only)** 을 의미하며, **NPI 런타임 호환성이 검증된 것이 아님**(현재 코어 비어 있음·G1 미통과). | **Windows 11** 및 **Windows Server 2016 이상** 테스트는 현재 미실시(`test pending`) 상태이며, G1~G6 런타임 구현 및 타깃 OS 호스트에서의 실제 실행·설치·API 호환성 테스트 통과 후에만 공식 지원 주장 허용. | G0, G7, G8 | `blocked` |
| **PRE-02** | Npcap 캡처 드라이버 및 라이선스 | **선택적 외부 기설치 어댑터** 전용 정책 유지. 번들 재배포·무인 설치(`/S`)·라이선스 대리 동의·권한 상승·드라이버 변경 금지. 미설치 시 `UNAVAILABLE` 및 우아한 성능 저하 설계. | 수집된 1차 근거(`E:/harnes/network-path-inspector/.harness/references/npcap-redistribution.txt`, `https://npcap.com/oem/redist.html`)만으로 무료/데모 라이선스 적용 가능성 및 예외를 확인하지 않은 채 모든 내부 사용자에게 OEM 구매를 강제한다고 단정하지 않음. 단, 내부 운영 사용 또는 번들링/배포 전 조직 차원에서 **적용 가능한 Npcap 라이선스(무료/데모 적용 범위 vs OEM Internal-use / OEM Redistribution)** 를 반드시 검토·확인해야 함. | G0, G4, G8 | `blocked` |
| **PRE-03** | 보고서 마스킹 및 원본 증거 반출 | 보고서 기본 마스킹 **ON** 설계. 원본 증거(PCAPNG/JSON)는 로컬 비공개 보관 및 반출 시 **명시적 노출 경고** 강제. **허위 익명성 보장 금지**. | G6에서 마스킹 필터 단위/골든마스터 검증 및 반출 경고 UI/CLI 동작 실측 검증. | G0, G6 | `partial` |
| **PRE-04** | 양방향 협업 및 네트워크 정책 | **오프라인 파일 병합(`paired_offline`) 기본**. 인바운드 관리 포트·웹서비스·클라우드 자동 업로드 없음. Agent도 기본 리스닝 없음. | 온라인 협업 관리 서버(P1)는 별도 보안 심의 승인 전까지 구축·연동 보류. | G0, G5 | `partial` |
| **PRE-05** | 코드 서명 및 배포 패키지 | 로컬 G1~G7 검증에는 **서명되지 않은 로컬 개발 빌드(Unsigned Local Dev Build)** 만 사용. | G8 통과 전 조직 코드 서명 인증서(Authenticode/EV) 서명 적용, MSI/EXE 설치·업데이트·제거 검증 및 배포 승인 필수. | G0, G8 | `blocked` |

---

## 2. 기본 단계별 게이트 체크리스트 (G0 ~ G8, PRD 10.2절)

> **게이트 진행 규칙**: 선행 게이트 실패 시 다음 단계 진행을 금지하며 원인과 보완 내역을 기록한다. 현재 시점에서는 G0 아키텍처·위협 모델·ADR 문서만 본 워크트리에서 작성되었고 컴파일된 코어/런타임은 없으며 G1도 미통과 상태이므로, G0는 `partial`(부모 검토 및 외부 배포/라이선스 검토/타 OS 실측 조건 분리 대기), G1~G8은 `not-started` 또는 `blocked`로 유지한다.

| Gate | 단계 명칭 | 필수 검증 항목 및 합격 조건 | 산출물 / 검증 주체 | 블로커 및 보류 사유 | status |
|---|---|---|---|---|---|
| **G0** | 요구사항·위협 모델·지원 OS/권한·Npcap 정책 확정 | - `architecture.md`, `threat-model.md`, `adr/ADR-0001~0006`, `gate-checklist.md`, `requirement-traceability.md` 작성<br>- `contracts/g1-interface-contract.json` (6그룹, 23기능, 4프리셋) 정합성 확인<br>- 개발 호스트(Win10 Pro 19045 x64 확인, 런타임 미검증)·미서명 빌드·Npcap 무번들 경계와 배포 선행 조건 분리 | `docs/**` (아키텍처 워크트리 작성, 부모 최종 판정) | G0 문서화는 작성되었으나 코어는 비어 있고 G1 미통과 상태이며, 조직의 Npcap 적용 라이선스 검토·코드 서명·Win11/Server 2016+ 실측 환경은 미확보 상태임(최종 상태 승격은 부모가 결정). | `partial` |
| **G1** | 핵심 데이터 모델·오류 분류·JSON Schema 및 테스트 픽스처 | - `Target`, `Limits`, `Profile`, `Evidence`, `Finding`, `FeatureResult`, `Session` DTO 및 검증기<br>- Winsock 오류 매핑(`10061`->`REFUSED`, `10060`->`TIMED_OUT` 등) 및 `OBSERVED`/`INFERRED`/`UNKNOWN` 분류 규칙<br>- `evidence_ids` 실재성 검증, `synthetic: true` 픽스처 분리, `clock_offset_ms` 미확인 시 `null` 유지<br>- 구버전 `schema_version=1.0` -> `1.1` 호환 변환기<br>- 소켓/OS/캡처/PDF/모니터링 부작용 0건 확인 | 부모 워크스페이스 (`cargo test`, 프론트엔드 계약 테스트) | 현재 코어는 비어 있으며 G1 미통과 상태임; 타 격리 워크트리의 초안 코드는 부모 통합 테스트 통과 전까지 구현 증거로 불인정. | `not-started` |
| **G2** | TCP·NIC·라우트·ICMP 단독 진단 구현 | - `127.0.0.1`/`::1` 제한된 단일 대상 로컬 루프백 시험(부모 주관)<br>- `tcp_connect`, `icmp_ping`, `dns_lookup`, `nic_inventory`, `route_table` 읽기 전용 수집<br>- 캡처 미실행 시 소켓 `REFUSED`만으로 `SYN`/`RST` 관찰 단정 0건 검증 | 부모 워크스페이스 (단위·통합·특성화 테스트) | G1 통합 통과 후 부모가 루프백 환경에서 실행 필요. | `not-started` |
| **G3** | 경로 추적 구현 및 혼합 사례 검증 | - `icmp_traceroute` (TTL 1..30) 및 `tcp_traceroute` (`validated_tcp_ttl_backend` 검증)<br>- ICMP 비응답 + TCP 연결 성공 혼합 사례에서 정상 구분 검증<br>- 마지막 응답 HOP 또는 미응답 HOP을 차단 장비로 단정하는 문구 0건 검증 | 부모 워크스페이스 (경로 추적 단위·통합·부정 테스트) | G2 통과 및 `validated_tcp_ttl_backend` 검증 후 진행. | `not-started` |
| **G4** | 선택적 패킷 캡처 구현 및 예외 검증 | - 기설치 Npcap 감지, `capture_consent` + `capture_privilege` 검증, 대상 IP/포트 BPF 필터 적용<br>- 50 MiB(`52,428,800` bytes) / 30초 상한 스트리밍 저장, 드롭 통계(`capture_drops`) 기록<br>- Npcap 미설치·권한 부족 시 `UNAVAILABLE` 표시 및 기본 진단 정상 동작 확인 | 부모 워크스페이스 (결함 주입 및 캡처 어댑터 테스트) | Npcap 드라이버 설치/권한 상승 금지 규칙 및 사용/번들 전 조직 차원의 Npcap 적용 라이선스 검토(`PRE-02`) 미확보. | `blocked` |
| **G5** | 양방향 오프라인 병합 및 상관 분석 | - 클라이언트/서버 동일 `session_id` 결과 ZIP 오프라인 병합(`import_bundle`, `packet_compare`, `clock_skew`)<br>- 시계 오차(`clock_offset_ms`, `clock_uncertainty_ms`), NAT 5-tuple 불일치(`매칭 불확실`), 비대칭 경로 처리<br>- 서버 `SYN` 미관찰 시 NIC/필터/드롭 가능성 우선 안내 검증<br>- 악성 ZIP(경로 조작, 심볼릭 링크, 압축 폭탄, 중복 엔트리, 해시 불일치, 비정상 Unicode) 차단 검증 | 부모 워크스페이스 (오프라인 병합 및 보안 퍼징/단위 테스트) | G1~G4 선행 게이트 미완료. | `not-started` |
| **G6** | PDF·증거 ZIP 생성 및 해시·재현성 검증 | - `result_json`, `pdf_report`, `pcap_export`, `hash_verify`, `policy_check` 구현<br>- `NPI_YYYYMMDD_<session-id>.zip` 산출물 구조 및 `SHA256SUMS.txt` 전수 일치 검증<br>- 원본과 정규화 데이터 분리, 캡처 미실행 시 가짜 PCAP 생성 금지<br>- 기본 마스킹 ON 및 반출 전 노출 경고 동작 검증 | 부모 워크스페이스 (골든 마스터, 해시 검증, 마스킹 테스트) | G1~G5 선행 게이트 미완료. | `not-started` |
| **G7** | 실제 두 VLAN 실험실 테스트 및 회귀 검증 | - 동일 VLAN 성공, VLAN 간 허용, VLAN ACL 차단, 서버 로컬 방화벽 차단, 서버 포트 미리스닝, 비대칭 경로 시나리오 실험실 검증<br>- Windows 11 및 Windows Server 2016+ 호환성 실측 | 부모 워크스페이스 및 승인된 격리 실험실 | 운영망/임의 대역 접속 금지 규칙으로 인해 현재 샌드박스에서 실행 불가; 승인된 2-VLAN 실험실 및 타깃 OS 호스트 테스트(`PRE-01`, 현재 pending) 필요. | `blocked` |
| **G8** | 서명·배포·설치/제거 검증 및 운영 체크리스트 | - EXE/MSI 설치 패키지 빌드, 설치·업데이트·제거 smoke test<br>- 코드 서명 인증서 적용 및 검증<br>- Npcap 적용 라이선스 조직 검토 완료 확인 및 운영 배포 체크리스트 승인 | 부모 워크스페이스 및 배포 승인권자 | 코드 서명 인증서(`PRE-05`), Npcap 조직 적용 라이선스 검토(`PRE-02`), 타깃 OS 런타임 검증(`PRE-01`) 미확보. | `blocked` |

---

## 3. v1.1 추가 품질·선택 실행·성능 게이트 체크리스트 (PRD 13.2절, 14절, 15절)

| Gate ID | 추가 검증 영역 | 세부 합격 조건 (Acceptance Criteria) | 검증 방법 | status |
|---|---|---|---|---|
| **G1-v1.1** | 기능 레지스트리·그룹·프리셋 스키마 | - 6개 그룹(`G-NET`, `G-PATH`, `G-PKT`, `G-PAIR`, `G-OPS`, `G-EVID`) 및 23개 기능 ID 중복 없음<br>- 의존성/요구사항 순환(cycle) 없음<br>- `quick-default` 5개 기능(`tcp_connect`, `icmp_ping`, `nic_inventory`, `route_table`, `result_json`) 등 4대 프리셋 일치<br>- 구버전 `schema_version=1.0` 가져오기 시 원본 보존 및 미확인 필드 `UNKNOWN`/`null` 변환 | 스키마 단위 테스트 및 JSON 계약 대조 | `not-started` |
| **G2-v1.1** | 선택 실행·그룹 조회 및 상태 보존 | - 앱 시작 시 선택 모듈 초기화 0회(`Registry default != execution`)<br>- 선택된 기능만 실행하고 미선택 진단 기능은 프로브 0회 및 `SKIPPED_BY_USER` 표시<br>- 선행 로컬 인벤토리 수집은 세션당 최대 1회 내부 공유하되 미선택 기능 결과 상태를 덮어쓰지 않음<br>- `SKIPPED_BY_USER`, `UNAVAILABLE`, `ERROR`, `CANCELLED`를 `PASS`/`FAIL`로 위장하지 않음 | 오케스트레이터 모의(Mock) 실행 및 카운터 검증 | `not-started` |
| **G3-v1.1** | 경로 기능 개별 비활성화 및 폴백 금지 | - `icmp_traceroute` 또는 `tcp_traceroute` 개별 비활성화 시 해당 프로브 패킷 0회 송신<br>- `tcp_traceroute`에서 `validated_tcp_ttl_backend` 미충족 시 `UNAVAILABLE` 기록, 조용히 ICMP 결과로 대체 금지 | 프로브 호출 횟수 스파이(Spy) 및 부정(Negative) 테스트 | `not-started` |
| **G4-v1.1** | 캡처 지연 로딩·권한 부족·프로파일 복원 안전 | - `packet_capture` 비선택 또는 미동의 시 Npcap 초기화/캡처 시작 0회<br>- 프로파일 복원 시 `capture_approved`를 `false`로 강제 초기화하고 `HIGH` 비용 기능 자동 활성화 차단<br>- Npcap 부재/권한 부족 시 기본 TCP/ICMP/라우팅 진단 정상 완료 | 지연 로딩 라이프사이클 및 프로파일 복원 단위 테스트 | `not-started` |
| **G5-v1.1** | 양방향 그룹/기능 결과 병합 및 보안 | - 클라이언트/서버 출처(`host_role`) 보존, 동일 기능 결과 병합 시 덮어쓰기 방지<br>- 시계 오차 미확인 시 `null` 유지(`0` 금지)<br>- 번들 내 외부 리소스(URL/실행 파일/UNC) 자동 열기 0건 | 오프라인 병합 및 보안 경계 테스트 | `not-started` |
| **G6-v1.1** | 선택 결과 내보내기 및 전체 보고서 무결성 | - 보고서에 선택된 기능 범위와 미실행(`SKIPPED_BY_USER`/`UNAVAILABLE`) 명시<br>- 캡처 미실행 시 빈 PCAP 파일 위조 생성 금지<br>- `SHA256SUMS.txt` 해시 전수 일치 및 기본 마스킹 ON 검증 | 보고서 빌더 및 해시 검증 테스트 | `not-started` |
| **G7-v1.1** | 성능 예산·자원 누수·UI 스로틀 시험 | - GUI 유휴(80 MiB 이하, CPU 1% 이하, 10분), 단독 일반 진단(120 MiB 이하, CPU 5% 이하, 30회), 정밀 캡처(200 MiB 이하), Headless Agent 유휴(30 MiB 이하, CPU 1% 이하, 10분)<br>- 시작 시간 콜드 스타트 20회 P95 3초 이내, 취소 후 3초 이내 핸들·스레드·파일 잠금 해제<br>- UI 이벤트 갱신 최대 4회/초(`ui_updates_per_second: 4`) 준수<br>- 24시간 반복 모니터링 누수 추세 평가 (성능 최적화 전 정확성 회귀 통과 필수) | Windows 성능 카운터 및 장시간 부하/취소 시험 (부모 주관) | `not-started` |
| **G8-v1.1** | 설치·업데이트·제거 및 프로파일 정책 | - Npcap 미설치 클린 환경에서 설치 및 기본 실행 성공<br>- 업데이트/제거 시 사용자 프로파일 및 로컬 증거 보존/제거 옵션 동작 확인 | 클린 VM 설치/제거 스모크 테스트 | `blocked` |

---

## 4. 빌드 품질 게이트 체크리스트 (PRD 10.4절)

모든 코드 병합 및 게이트 승격 시 부모 워크스페이스에서 다음 품질 게이트를 실행하고 로그를 기록해야 한다.

| 항목 ID | 검사 명령 / 도구 | 합격 기준 | status |
|---|---|---|---|
| **BQ-01** | `cargo fmt --check` | 포맷 불일치 0건 | `not-started` |
| **BQ-02** | `cargo clippy` | 정의된 경고 정책 위반 0건, 실패 우회 플래그 금지 | `not-started` |
| **BQ-03** | `cargo test` | G1~G6 단위·통합·부정·골든마스터 테스트 100% 통과 (실패 테스트 삭제/기대값 변조 금지) | `not-started` |
| **BQ-04** | 프론트엔드 `lint` / `typecheck` / `test` | TypeScript 타입 오류 0건, Vitest 계약·UI 회귀 테스트 100% 통과 | `not-started` |
| **BQ-05** | JSON Schema & SHA-256 & 마스킹 검증 | `contracts/g1-interface-contract.json` 정합성, 번들 `SHA256SUMS.txt` 일치, 기본 마스킹 ON 동작 확인 | `not-started` |
| **BQ-06** | Windows 설치 패키지 Smoke Test | 로컬 개발 빌드(G8 전 미서명, G8 시 서명) 패키징 및 기동 시 프로브 0회 확인 | `not-started` |
