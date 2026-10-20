# Network Path Inspector (NPI) 위협 모델 및 보안 경계 (Threat Model)

- 문서 버전: 1.1.0-g0
- 기준 PRD: `PRD.md` (버전 1.1.0)
- 기준 인터페이스 계약: `contracts/g1-interface-contract.json` (`contract_version: "g1-1.1.0"`)
- 상태: G0 위협 분석 및 통제 설계 확정 (런타임 검증은 G1~G8 단계별 게이트에서 수행)

---

## 1. 위협 모델링 범위 및 신뢰 경계 (Trust Boundaries)

NPI는 사내망/폐쇄망의 클라이언트 PC와 서버 구간에서 네트워크 경로 장애를 진단하고 제3자(방화벽 운영 업체 등)에게 제출할 증빙 번들을 생성·병합하는 도구이다. 따라서 다음과 같은 4가지 핵심 신뢰 경계를 가진다.

```mermaid
flowchart LR
    subgraph TB1["신뢰 경계 1: 사용자 입력 및 프로파일"]
        U_IN["Target 입력 (IP/도메인, 포트)\n프로파일 JSON 불러오기\n정책 통보 메모"]
    end

    subgraph TB2["신뢰 경계 2: NPI 로컬 프로세스 및 저장소"]
        CORE["NPI Core & UI / Agent\n(일반 사용자 권한 기본)"]
        LOCAL_STORE["로컬 증거 저장소\n(원본 PCAPNG/JSON vs 정규화 데이터)"]
    end

    subgraph TB3["신뢰 경계 3: 네트워크 및 OS 커널 경계"]
        NET["대상 호스트 (단일 IP:Port)\n중간 라우터 / 방화벽 / NAT"]
        NPCAP_DRV["외부 기설치 Npcap 드라이버\n(선택적/조건부 권한)"]
    end

    subgraph TB4["신뢰 경계 4: 외부 교환 번들 (ZIP Import/Export)"]
        IMPORT_ZIP["외부/타 호스트 결과 ZIP\n(비신뢰 입력으로 취급)"]
        EXPORT_ZIP["업체 제출용 보고서/ZIP\n(민감 정보 유출 경계)"]
    end

    U_IN -->|"G1 엄격한 스키마 검증"| CORE
    CORE <-->|"원자적 읽기/쓰기"| LOCAL_STORE
    CORE -->|"제한된 프로브 (Semaphore/Timeout)"| NET
    NPCAP_DRV -.->|"BPF 필터링 패킷 스트림"| CORE
    IMPORT_ZIP -->|"ZIP 샌드박스 검증기"| CORE
    CORE -->|"기본 마스킹 ON + 반출 경고"| EXPORT_ZIP
```

1. **신뢰 경계 1 (사용자 및 프로파일 입력)**: 사용자가 입력한 대상 호스트 문자열, 저장된 프로파일 JSON, 방화벽 업체 정책 메모.
2. **신뢰 경계 2 (로컬 프로세스 및 파일시스템)**: 일반 사용자 권한의 NPI 프로세스, 로컬 SQLite WAL 저장소, 임시 작업 디렉터리.
3. **신뢰 경계 3 (네트워크 및 커널 캡처 드라이버)**: 대상 서버, 중간 네트워크 장비, 외부 설치된 Npcap 드라이버 및 패킷 스트림(비신뢰 네트워크 트래픽).
4. **신뢰 경계 4 (오프라인 병합용 외부 ZIP 번들 및 반출 보고서)**: 타 호스트(서버/클라이언트)에서 가져오는 결과 ZIP 파일(`import_bundle`)과 외부 업체로 반출되는 보고서 번들(`report.pdf`, `session.json`, `*.pcapng`).

---

## 2. 자산(Assets) 식별

1. **운영 네트워크 및 대상 서버의 가용성**: 진단 프로브로 인해 운영 DB(Oracle 등)나 네트워크 장비에 부하·장애가 발생하지 않아야 한다.
2. **호스트 OS 보안 및 설정 무결성**: 로컬 방화벽 정책, 라우팅 테이블, 레지스트리, 인증서 저장소, 시스템 서비스 상태가 변경되지 않아야 한다.
3. **내부망 토폴로지 및 민감 데이터 기밀성**: 내부 IP 대역, 호스트명, 패킷 페이로드, 계정/인증 정보가 무단 노출되거나 외부로 자동 전송되지 않아야 한다.
4. **진단 증거 및 판정의 무결성(Provenance & Integrity)**: 수집된 원본 측정값과 패킷 증거가 변조·오염되지 않고, 측정 사실(`OBSERVED`)과 추론(`INFERRED`), 미확인(`UNKNOWN`)이 왜곡되지 않아야 한다.

---

## 3. 주요 위협 분석 및 완화 통제 (STRIDE 기반)

### 3.1 결과 ZIP 번들 가져오기 (`import_bundle`) 보안 위협
오프라인 양방향 진단(`paired_offline`) 시 외부 호스트에서 전달받은 ZIP 파일은 **완전한 비신뢰 입력(Untrusted Input)** 으로 취급해야 한다.

| 위협 ID | 위협 유형 | 공격 시나리오 및 위험 | 필수 설계 통제 (Mitigations) | 관련 게이트 |
|---|---|---|---|---|
| **TM-ZIP-01** | **경로 조작 (Zip Slip / Path Traversal)** | ZIP 엔트리 이름에 `../`, `..\`, 절대 경로(`/etc/...`, `C:\...`), 드라이브 문자, 또는 Windows UNC 경로(`\\server\share`)를 포함하여 작업 디렉터리 외부에 임의 파일을 덮어씀. | 엔트리 경로 정규화 후 상대 안전 경로(`artifact_path: relative safe path`)만 허용. `..` 세그먼트, 루트/드라이브 접두사, 백슬래시 제어 시 즉시 전체 가져오기 거부(`ERROR`). | G1, G5, G6 |
| **TM-ZIP-02** | **심볼릭 링크 및 재분석 지점 (Symlink / Reparse Point)** | ZIP 내부에 심볼릭 링크 또는 Windows 정션(junction) 엔트리를 포함시킨 뒤 후속 엔트리를 통해 민감한 시스템 파일을 읽거나 덮어씀. | ZIP 헤더 속성에서 심볼릭 링크/특수 파일 플래그 감지 시 즉시 차단. 파일 추출 시에도 OS 수준에서 재분석 지점 따라가기(follow symlink) 금지. | G5, G6 |
| **TM-ZIP-03** | **압축 폭탄 (Zip Bomb) 및 자원 고갈** | 수 메가바이트의 ZIP이 해제 시 수 기가바이트로 팽창하거나 수만 개의 미세 파일로 디스크/메모리/아이노드를 고갈시킴. | 1) 총 아카이브 압축 해제 크기 상한(예: 세션당 PCAP 50 MiB × 2 + 메타데이터 여유분을 고려한 엄격한 총량 제한), 2) 단일 엔트리 최대 바이트 제한(`capture_max_bytes = 52,428,800` 등), 3) 최대 엔트리 개수 제한(허용 목록 파일만 수용), 4) 스트리밍 바이트 카운터로 한도 초과 즉시 중단 및 임시 파일 삭제. | G5, G6 |
| **TM-ZIP-04** | **중복 엔트리 및 스푸핑 (Duplicate Entries)** | 동일 ZIP 내에 `session.json` 또는 `SHA256SUMS.txt`를 두 번 이상 포함시켜 검증기(첫 번째 엔트리 검사)와 파서(두 번째 엔트리 로드) 간의 불일치(TOCTOU/Parser differential) 유발. | ZIP 중앙 디렉터리 스캔 시 정규화된 대소문자 비구분(case-insensitive on Windows) 경로 기준으로 **중복 엔트리 이름이 단 1건이라도 존재하면 즉시 전체 번들 거부**. | G5, G6 |
| **TM-ZIP-05** | **해시 커버리지 누락 및 변조 (`SHA256SUMS.txt`)** | `SHA256SUMS.txt`에 일부 파일만 등록하고 변조된 파일을 추가하거나, 해시 목록과 실제 파일 내용이 불일치함. | 1) 번들 내 모든 데이터 파일(`report.pdf`, `session.json`, `measurements.jsonl`, `*.pcapng`, `system_snapshot.json`, `diagnostic.log`, `limitations.json`)이 `SHA256SUMS.txt`에 1:1로 포함되어야 함(미등록 파일 또는 누락 파일 존재 시 실패), 2) 스트리밍 SHA-256 재계산 후 상수 시간 비교. | G5, G6 |
| **TM-ZIP-06** | **악성 Unicode 및 비정상 페이로드** | 파일명이나 JSON 문자열(`host_alias`, `statement`, 정책 메모 등)에 NUL 바이트(`\0`), 양방향 제어 문자(Bidi override `U+202E`), 제어 문자, 비정상 UTF-8 시퀀스, 또는 HTML/스크립트 태그를 삽입해 UI/PDF 렌더러에서 XSS 또는 화면 위조 유발. | 1) 모든 JSON 텍스트는 유효한 UTF-8 및 NFC 정규화 검증, 2) 파일명에는 영숫자·하이픈·언더스코어·점만 허용, 3) Bidi 제어 문자 및 제어 문자 제거/거부, 4) React UI 및 PDF 템플릿에서 모든 문자열을 순수 텍스트로 이스케이프(HTML raw 삽입 금지). | G1, G5, G6 |
| **TM-ZIP-07** | **번들 내 외부 리소스 임의 실행/열기** | 가져온 JSON/PDF/로그 내부에 포함된 외부 URL(`http://`, `file://`, `\\unc\`), 실행 파일 경로, 또는 HTML/PDF 내 외부 이미지·폰트·스크립트 참조를 자동으로 열거나 실행함. | **번들에서 파생된 어떠한 경로·URL·파일에 대해서도 `shell::open`이나 외부 프로세스 실행, 원격 네트워크 요청을 절대 수행하지 않음**. 오직 내장 파서(JSON, PCAPNG/PCAP)로 읽기 전용 파싱만 수행. | G5, G6 |

---

### 3.2 진단 정확성 왜곡 및 증거 오염 위협

| 위협 ID | 위협 유형 | 공격/오류 시나리오 | 필수 설계 통제 (Mitigations) | 관련 게이트 |
|---|---|---|---|---|
| **TM-ACC-01** | **증거 없는 확정 판정 (False OBSERVED)** | 캡처를 켜지 않은 상태에서 소켓 `REFUSED(10061)`나 `TIMED_OUT(10060)`만으로 "SYN 송신 확인", "서버가 RST 전송", "방화벽이 차단"이라고 보고서에 출력하여 분쟁 유발. | `contracts/g1-interface-contract.json` 안전 규칙 강제: `SOCKET` 증거만으로는 소켓 호출 결과만 `OBSERVED`로 기록 가능. 와이어 패킷(`SYN`/`RST`) 관찰 진술은 반드시 실제 `PACKET` 종류의 `Evidence`가 존재할 때만 허용. | G1, G2, G4 |
| **TM-ACC-02** | **마지막 응답 HOP = 차단 장비 오판** | ICMP/TCP Traceroute가 특정 HOP 이후 응답하지 않을 때 해당 라우터/방화벽을 차단 장비로 지목함. | 모든 미응답 구간은 `UNKNOWN`으로 분류하고, "ICMP/TCP TTL 만료 응답 비활성화 또는 경로상 필터링 가능성"을 `limitations[]`에 명시. 자동 차단 지점 확정 문구 생성 금지(P0-11). | G1, G3 |
| **TM-ACC-03** | **서버 SYN 미관찰 = 미도착 단정** | 양방향 진단에서 서버 캡처 파일에 `SYN`이 없을 때 네트워크 구간 손실로 단정함. | 서버 측 잘못된 NIC 선택, BPF 필터 조건 불일치, 커널/드라이버 패킷 드롭(`capture_drops > 0`), 비대칭 라우팅 가능성을 먼저 점검 항목(`next_checks[]`)과 한계(`limitations[]`)에 기록(PRD 4.2절). | G4, G5 |
| **TM-ACC-04** | **원본 증거와 정규화/합성 데이터의 혼입** | 테스트용 합성 픽스처(`synthetic: true`)나 구버전(1.0) 변환 데이터가 실제 측정 증거(`synthetic: false`)로 위장되거나, 정규화 과정에서 원본 데이터가 덮어써짐. | 1) 원본 캡처/입력 파일과 정규화된 `measurements.jsonl`/`session.json`을 별도 경로로 분리 보관, 2) `Evidence.synthetic` 불리언 필드 필수 검증 및 `synthetic: true` 증거의 실측 위장 금지, 3) 시계 오차(`clock_offset_ms`, `clock_uncertainty_ms`) 및 자원 측정치 미확인 시 `0`이 아닌 `null` 유지. | G1, G5, G6 |
| **TM-ACC-05** | **보고서 범위 누락 및 미실행 위장** | 사용자가 일부 기능만 선택 실행했음에도 전체 기능을 검사해 통과한 것처럼 보고서를 생성하거나, 미선택/미지원 기능을 `PASS`로 표기함. | 보고서 상단에 선택된 프로파일(`profile_id`), 실제 선택 기능 목록(`selected_features[]`), 호스트 역할(`host_role`), 수집 시각·시간대·툴 버전·캡처 필터·드롭 통계를 명시. 미선택은 `SKIPPED_BY_USER`, 의존성/권한 부족은 `UNAVAILABLE`, 오류는 `ERROR`, 취소는 `CANCELLED`로 고정 표기. | G1, G2, G6 |

---

### 3.3 개인정보·내부망 정보 노출 및 권한/운영 위협

| 위협 ID | 위협 유형 | 공격/오류 시나리오 | 필수 설계 통제 (Mitigations) | 관련 게이트 |
|---|---|---|---|---|
| **TM-PRV-01** | **보고서 반출 시 내부망 정보 노출 및 허위 익명성 맹신** | 업체 제출용 PDF/ZIP에 내부 서버 IP, 호스트명, 패킷 페이로드가 그대로 노출되거나, 반대로 사용자가 "마스킹 기능"만 믿고 원본 PCAP까지 완전 익명화된 것으로 오해함. | 1) **기본 보고서 마스킹 ON** (IP/호스트명/민감 페이로드 마스킹 기본 활성화), 2) 원본 증거(PCAPNG, 원본 로그)는 로컬 비공개 저장소에 유지하되 외부 ZIP 반출 시 **개인정보·내부망 정보 노출에 대한 명시적 경고 및 사용자 확인** 필수, 3) **허위 익명성 보장(False Anonymity Guarantee) 금지**: 마스킹을 켜더라도 패킷 타이밍·길이·헤더 특성 및 원본 PCAP 반출 시 내부 정보가 식별될 수 있음을 경고문에 명시(ADR-0006). | G0, G6 |
| **TM-PRV-02** | **자격증명 수집 및 DB 프로토콜 침해** | 사용자가 대상 입력란에 `oracle://user:pass@host:1526/sid` 형태를 입력하여 계정/비밀번호가 로그와 보고서에 남거나, 도구가 DB 로그인을 시도해 계정 잠금을 유발함. | 1) `Target.host` 검증기에서 URI 스킴(`://`), 경로(`/`), 자격증명(`@`, `:`), 공백, CIDR(`/`), 쉼표 목록을 원천 거부, 2) DB 계정·비밀번호 입력 UI 및 저장 필드 일절 없음, 3) 오직 TCP 3-way 핸드셰이크 수준까지만 검사(P0-13). | G1, G2 |
| **TM-OPS-01** | **무단 대역 스캔 및 운영망 과부하** | 도구가 서브넷 전체를 스캔하거나 과도한 동시 연결·무한 재시도로 방화벽 세션 테이블이나 서버를 고갈시킴. | 단일 목적지(` max_concurrent_dest = 1`), 동시 TCP 프로브 최대 4개(`max_concurrent_tcp = 4`), 최대 30 HOP(`max_hops = 30`), 기본 재시도 0회(상한 3회, 지터/백오프 필수), 캡처 최대 30초/50 MiB 제한. | G1, G2, G3 |
| **TM-OPS-02** | **프로파일 복원 시 고위험/캡처 기능 자동 실행** | 이전에 캡처를 승인했거나 고부하 기능(`packet_capture`, `tcp_traceroute`)을 켰던 프로파일을 복원할 때 사용자 인지 없이 즉시 패킷 캡처나 고비용 프로브가 활성화됨. | 프로파일 복원 시 `capture_approved`를 무조건 `false`로 강제 박탈(strip)하고, `cost_class == "HIGH"` 또는 `permission_level == "CONDITIONAL"` 기능은 체크 해제하거나 실행 전 명시적 재확인(reconfirmation)을 거치도록 강제(ADR-0004). | G1, G2, G4 |
| **TM-SYS-01** | **권한 상승, 드라이버 설치 및 OS 설정 변경** | 도구가 스스로 UAC 관리자 권한 상승을 시도하거나, Npcap 무인 설치(`/S`), 방화벽 규칙 추가, 라우팅 변경을 수행함. | 기본 실행은 일반 사용자(`USER`) 권한 고정. 관리자 권한이나 Npcap이 필요한 기능은 현재 상태를 읽기 전용으로만 확인하고 부족 시 `UNAVAILABLE` 및 안내 메시지만 표시. OS 설정 변경 코드 작성 및 실행 절대 금지. | G0~G8 전체 |
| **TM-NET-01** | **인바운드 리스닝 포트 및 클라우드 유출** | 진단 도구나 Agent가 서버에 새로운 인바운드 관리 포트를 열어 공격 표면(Attack Surface)을 만들거나, 진단 결과를 외부 클라우드로 자동 전송함. | 인바운드 리스닝 소켓 생성 금지, 내장 웹서버 금지, 외부 텔레메트리/자동 업로드 금지. 양방향 진단은 오프라인 ZIP 파일 병합(`paired_offline`)으로만 수행. | G0, G5 |

---

## 4. 로컬 증거 보존 및 수명주기 보안

1. **원자적 저장 및 충돌 방지**:
   - 모든 세션은 고유 UUID(`session_id`)를 부여받으며, 파일 기록 시 `<target>.tmp.<uuid>`에 먼저 기록하고 fsync 후 원자적 이름 변경을 수행한다.
   - 기존 원본 캡처 파일이나 세션 결과를 덮어쓰지 않는다(PRD 13.1절).
2. **작업 취소 및 비정상 종료 시 안전한 해제**:
   - 사용자가 진단을 중지하거나 타임아웃·용량 상한(50 MiB) 도달, 앱 종료, 시스템 절전 진입 시 모든 백그라운드 Tokio 태스크와 Npcap 캡처 핸들을 3초 이내에 해제(목표 예산)하고, 그때까지 수집된 부분 결과는 `CANCELLED` 상태로 보존한다.
3. **보관 주기와 사용자 삭제 권한**:
   - 로컬 이력 및 로그 기본 보관 기간은 30일(`log_retention_days: 30`)이며, 사용자가 언제든지 개별 세션 및 원본 PCAP 파일을 영구 삭제할 수 있는 인터페이스를 제공한다.

---

## 5. 출처 사실 vs 설계 선택 vs 미검증 구분 요약

- **출처 사실 (Source Facts)**:
  - Npcap 무료/데모 버전은 재배포 및 무인 설치(`/S`)를 제공하지 않으며, Windows에서 다중 Npcap 커널 필터 드라이버 인스턴스 로드는 성능 저하와 필터 슬롯 고갈을 유발한다(`.harness/references/npcap-redistribution.txt`, `https://npcap.com/oem/redist.html`).
  - Tauri는 CSP(Content Security Policy), Capabilities, Permissions, Asset protocol scope 등 프론트엔드-백엔드 간 권한 격리 메커니즘을 제공한다(`.harness/references/tauri-prerequisites.txt`, `https://tauri.app/start/prerequisites/`).
- **설계 선택 (Design Choices)**:
  - 외부 ZIP 번들 가져오기(`import_bundle`)에 대해 Zip Slip, Symlink, Zip Bomb, 중복 엔트리, `SHA256SUMS.txt` 전수 대조, Unicode 정규화/이스케이프, 외부 리소스 열기 금지의 7중 방어선을 아키텍처 필수 요구사항으로 채택했다.
  - 보고서 기본 마스킹을 ON으로 설정하되, 원본 증거 반출 시 명시적 경고를 표시하고 허위 익명성 보장을 하지 않기로 결정했다.
- **미검증 사항 (Unverified / Deferred)**:
  - 위 ZIP 샌드박스 파서 및 마스킹 필터의 실제 코드 구현과 퍼징/결함 주입(Fault Injection) 테스트는 G1/G5/G6 단계에서 수행되어야 하며 현재(`G0`)는 설계 기준만 확정된 상태(`not-started`)이다.
