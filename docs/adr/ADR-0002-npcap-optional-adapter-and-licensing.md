# ADR-0002: Npcap 선택적 외부 설치 어댑터 연동 및 라이선스 승인 분리

- 상태: Accepted (G0 Baseline / 라이선스 검토 분리)
- 작성일: 2026-10-20
- 관련 요구사항: PRD 1.3, 2.1 (P0-07), 6.1, 8, 10.2 (G0, G4, G8), 13.1, 15 (G4, G8), 16.2

## 1. 배경 및 문제 (Context)
- `PRD.md` P0-07은 선택적 패킷 캡처 시 Npcap 설치·권한 확인, BPF 필터링, PCAPNG/PCAP 저장, 실패 시 명확한 안내를 요구하며, 16.2절은 "Npcap 설치/라이선스/배포 허용 범위(조직 정책 확인)"를 구현 전 결정 사항으로 명시한다.
- 또한 안전 규칙(`AGENTS.md` 및 `contracts/g1-interface-contract.json`)은 Npcap/드라이버/서비스 설치 및 관리자 권한 상승을 금지하고, G0에서 Npcap 라이선스 승인을 임의로 가정하지 않도록 규정한다.

## 2. 출처 사실 (Source Facts)
유일한 1차 수집 근거인 Npcap 공식 OEM 재배포 안내 문서(`https://npcap.com/oem/redist.html`, 로컬 사본 `E:/harnes/network-path-inspector/.harness/references/npcap-redistribution.txt`)에서 확인된 사실은 다음과 같다:
1. 무료/데모(free/demo) Npcap은 무인 설치 기능(`/S`, silent installer)을 포함하지 않으며 일반적으로 제품 내 포함 재배포(redistribution)를 허용하지 않는다. 또한 무료 라이선스의 조건과 제한은 수시로 변경될 수 있다.
2. 해당 문서는 조직 외부 재배포용 **Npcap OEM Redistribution License**와 외부 재배포 없이 조직 내부(임직원, 계약자 등)에서 사용하는 경우를 위한 **Npcap OEM Internal-use License** 상품을 안내한다. 단, 수집된 `npcap-redistribution.txt`만으로는 무료/데모 라이선스의 구체적 적용 가능 범위와 예외 조항을 모두 확인할 수 없으므로, 모든 내부 사용자가 예외 없이 OEM 라이선스를 유상 구매해야 한다고 단정할 수 없다.
3. 별도의 Npcap OEM SDK는 존재하지 않으며, 일반 공개 Npcap SDK로 컴파일된 소프트웨어는 무료/데모 Npcap과 Npcap OEM 모두에 호환된다고 명시되어 있다.
4. Windows 커널 필터 드라이버 슬롯 제한, 다중 인스턴스 로드 시 성능 저하, EV 인증서 물리 USB 키 서명 및 Microsoft 증명 서명 절차 때문에 애플리케이션 전용 사설 브랜딩(private branded) 드라이버는 제공되지 않으며, 시스템에 설치된 단일 Npcap 드라이버를 애플리케이션들이 공유한다.

*(주의: 수집된 `E:/harnes/network-path-inspector/.harness/references/npcap-redistribution.txt`에 명시되지 않은 세부 무료 EULA 조항이나 강제 구매 의무를 임의로 창작·단정하지 않는다.)*

## 3. 결정 (Decision)
1. **선택적 외부 기설치 어댑터(Optional External-Installed Adapter) 전용 구조 (변경 없음)**:
   - NPI는 설치 패키지(EXE/MSI) 내부에 Npcap 설치 프로그램을 **번들링하거나 재배포하지 않는다**.
   - NPI는 Npcap 자동/무인 설치(`/S`)를 실행하지 않으며, 사용자를 대신하여 Npcap 라이선스에 동의하지 않고, 관리자 권한 상승(UAC elevation)이나 커널 드라이버/서비스 시작·변경을 수행하지 않는다.
2. **지연 로딩(Lazy Loading) 및 우아한 성능 저하(Graceful Degradation) 설계 목표**:
   - 앱 시작 시 또는 `packet_capture` 기능이 선택되지 않은 경우 Npcap DLL(`wpcap.dll`, `Packet.dll`)을 로드하거나 초기화하지 않도록 설계한다(G4 캡처 시작 0회 수용 목표).
   - 사용자가 `packet_capture`를 선택하고 명시적 캡처 동의(`capture_approved: true`)를 부여했을 때만 호스트에 이미 설치된 Npcap 존재 여부와 캡처 권한(`capture_privilege`)을 읽기 전용으로 확인하도록 설계한다.
   - Npcap이 미설치되어 있거나 권한이 부족하면 `packet_capture` 및 `packet_evidence` 요구 기능(`syn_rst_analysis`, `packet_compare`, `pcap_export`)을 `UNAVAILABLE` 상태로 기록하고 사유와 대안을 안내하며, 나머지 기본 진단(`tcp_connect`, `icmp_ping`, `route_table`, `nic_inventory` 등)은 영향을 받지 않도록 설계한다.
3. **조직 차원의 적용 라이선스 검토 분리 (Deferred Prerequisite)**:
   - 모든 내부 사용자에게 OEM 구매를 일괄 강제한다고 선언하지 않는다. 대신 조직이 실제 캡처 기능을 내부 운영에 사용하거나 패키징/배포 방식을 결정하기 전에, 무료/데모 라이선스 적용 가능 여부·예외 조항 및 **Npcap OEM 라이선스(Internal-use 또는 Redistribution)** 필요 여부를 조직 법무/보안/구매 부서에서 먼저 검토·확인하도록 G4/G8 선행 조건(`blocked`)으로 유지한다.

## 4. 결과 및 영향 (Consequences — 설계 목표 및 수용 검증 계획)
- **현재 구현 상태 한계**: 현재 G0 시점에는 컴파일된 코어/런타임 코드가 전혀 없으며 G1도 아직 통과되지 않았으므로, 아래 항목은 현재 작동 중이거나 보장된 런타임 사실이 아니라 **G1~G4 및 G8에서 검증할 명시적 설계 목표(Design Goals) 및 수용 계획(Planned Acceptance Criteria)** 이다.
- **G2/G4 수용 목표**: Npcap이 설치되지 않은 환경에서도 기본 연결·경로·인벤토리 진단 기능이 독립적으로 수행되고 캡처 의존 기능만 `UNAVAILABLE`로 분류되는지 G2/G4 테스트에서 검증할 예정이다.
- **위험 완화 목표 및 게이트 추적**: 번들 제외·자동 설치 금지·권한 상승 금지를 통해 드라이버 변경 및 재배포 조건 위반 위험을 줄이는 것을 설계 목표로 하며, 조직의 적용 라이선스 검토 미완료 상태는 `docs/gate-checklist.md`의 G4/G8 블로커(`blocked`)로 추적한다.
