# ADR-0002: Npcap 선택적 외부 설치 어댑터 연동 및 라이선스 승인 분리

- 상태: Accepted (G0 Baseline / 라이선스 승인 분리)
- 작성일: 2026-10-20
- 관련 요구사항: PRD 1.3, 2.1 (P0-07), 6.1, 8, 10.2 (G0, G4, G8), 13.1, 15 (G4, G8), 16.2

## 1. 배경 및 문제 (Context)
- `PRD.md` P0-07은 선택적 패킷 캡처 시 Npcap 설치·권한 확인, BPF 필터링, PCAPNG/PCAP 저장, 실패 시 명확한 안내를 요구하며, 16.2절은 "Npcap 설치/라이선스/배포 허용 범위(조직 정책 확인)"를 구현 전 결정 사항으로 명시한다.
- 또한 안전 규칙(`AGENTS.md` 및 `contracts/g1-interface-contract.json`)은 Npcap/드라이버/서비스 설치 및 관리자 권한 상승을 금지하고, G0에서 Npcap 라이선스 승인을 임의로 가정하지 않도록 규정한다.

## 2. 출처 사실 (Source Facts)
Npcap 공식 OEM 재배포 라이선스 문서(`https://npcap.com/oem/redist.html`, 로컬 사본 `.harness/references/npcap-redistribution.txt`)에서 확인된 사실은 다음과 같다:
1. 무료/데모(free/demo) Npcap은 무인 설치 기능(`/S`, silent installer)을 포함하지 않으며 일반적으로 제품 내 포함 재배포(redistribution)를 허용하지 않는다. 또한 무료 라이선스의 조건과 제한은 수시로 변경될 수 있다.
2. 자사 제품에 Npcap을 포함하여 조직 외부로 배포하려면 **Npcap OEM Redistribution License**가 필요하며, 외부 재배포 없이 조직 내부(임직원, 계약자 등)에서만 사용하는 경우에는 **Npcap OEM Internal-use License** 대상이 된다.
3. 별도의 Npcap OEM SDK는 존재하지 않으며, 일반 공개 Npcap SDK로 컴파일된 소프트웨어는 무료/데모 Npcap과 Npcap OEM 모두에 100% 호환된다.
4. Windows 커널 필터 드라이버 슬롯 제한, 다중 인스턴스 로드 시 성능 저하, EV 인증서 물리 USB 키 서명 및 Microsoft 증명 서명 절차 때문에 애플리케이션 전용 사설 브랜딩(private branded) 드라이버는 제공되지 않으며, 시스템에 설치된 단일 Npcap 드라이버를 애플리케이션들이 공유한다.

*(주의: 수집된 `npcap-redistribution.txt`에 명시되지 않은 세부 무료 EULA 조항은 임의로 창작하거나 추정하지 않는다.)*

## 3. 결정 (Decision)
1. **선택적 외부 기설치 어댑터(Optional External-Installed Adapter) 전용 구조**:
   - NPI는 설치 패키지(EXE/MSI) 내부에 Npcap 설치 프로그램을 **번들링하거나 재배포하지 않는다**.
   - NPI는 Npcap 자동/무인 설치(`/S`)를 실행하지 않으며, 사용자를 대신하여 Npcap 라이선스에 동의하지 않고, 관리자 권한 상승(UAC elevation)이나 커널 드라이버/서비스 시작·변경을 수행하지 않는다.
2. **지연 로딩(Lazy Loading) 및 우아한 성능 저하(Graceful Degradation)**:
   - 앱 시작 시 또는 `packet_capture` 기능이 선택되지 않은 경우 Npcap DLL(`wpcap.dll`, `Packet.dll`)을 로드하거나 초기화하지 않는다(G4 캡처 시작 0회 보장).
   - 사용자가 `packet_capture`를 선택하고 명시적 캡처 동의(`capture_approved: true`)를 부여했을 때만 호스트에 이미 설치된 Npcap 존재 여부와 캡처 권한(`capture_privilege`)을 읽기 전용으로 확인한다.
   - Npcap이 미설치되어 있거나 권한이 부족하면 `packet_capture` 및 `packet_evidence` 요구 기능(`syn_rst_analysis`, `packet_compare`, `pcap_export`)을 `UNAVAILABLE` 상태로 기록하고 사유와 대안을 안내하며, 나머지 기본 진단(`tcp_connect`, `icmp_ping`, `route_table`, `nic_inventory` 등)은 정상 수행한다.
3. **조직 라이선스 승인 분리 (Deferred Prerequisite)**:
   - 사내 또는 고객사 환경에서 Npcap을 사용하여 패킷 캡처를 운영하거나 배포하기 전에 조직 법무/보안/구매 부서를 통한 정확한 **Npcap 라이선스(OEM Internal-use 또는 OEM Redistribution) 검토 및 승인**을 G4 운영 실측 및 G8 배포 게이트의 별도 필수 선행 조건(`blocked`)으로 유지한다.

## 4. 결과 및 영향 (Consequences)
- Npcap이 없는 개발/운영 PC에서도 NPI의 핵심 연결·경로·인벤토리 진단이 100% 안전하게 작동한다.
- 무단 드라이버 설치나 라이선스 위반 위험이 원천 차단되며, 라이선스 미승인 상태가 G4/G8 체크리스트에 투명하게 추적된다.
