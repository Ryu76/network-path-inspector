# Network Quick Check (`apps/network-quick-check`)

## 1. 개요
Network Quick Check는 별도의 설치 과정 없이 Windows 단일 실행 파일(EXE)을 복사하여 즉시 IP:Port 통신 상태를 진단할 수 있도록 기획된 경량 네트워크 진단 도구입니다.

- **현재 단계**: 공유 Core의 TCP·Ping·로컬 정보·필수/선택 DNS·선택 ICMP Trace 실행기 연결까지 제한 범위 수용. 제품 GUI·EXE는 아직 미구현이며 전체 QG2는 실환경 검증 전 미수용. 최신 근거는 아래 후속 판정 및 `artifacts/qg2e-trace-runner-acceptance.json`이다.
- **공통 기반**: `crates/network-core` facade를 통해 기존 `npi-core` 및 `npi-probes` 구현을 재사용(기존 Inspector는 그대로 보존).
- **의존성 배제**: WebView, Npcap, Agent, PDF, SQLite 라이브러리를 일체 포함하지 않음.

## 2. 설계 및 계약 문서 (상대 링크)
- [아키텍처 사양서](../../docs/quick-check/architecture.md)
- [위협 분석 및 보안 원칙](../../docs/quick-check/threat-model.md)
- [품질 게이트 계획](../../docs/quick-check/gates.md)
- [요구사항 추적성 매트릭스](../../docs/quick-check/requirement-traceability.md)
- [설계 결정 기록 (ADR)](../../docs/quick-check/decisions.md)
- [인터페이스 계약](../../contracts/quick-check-interface-v0.1.json)
- [Network Path Inspector Harness PRD v1.2](../../docs/requirements/Network_Path_Inspector_Harness_PRD_v1.2.md)

## 3. 작업자 주의사항
- 본 디렉터리의 실제 구현 코드 및 테스트 실행은 부모 작업자/별도 worker의 검증 계획에 따라 순차 진행됩니다.
- 단독 진단은 서버 수신 여부를 알 수 없으므로 연결 실패를 방화벽 차단으로 단정하지 않습니다.
- 운영 환경 무변경 원칙을 준수하며 시스템 정책/방화벽/라우팅 변경을 일체 수행하지 않습니다.

## 후속 QG0 설계 검토 판정
- 2026-10-21T11:53:32.980216+09:00: 독립 재검토 `deleg_149f9737`에서 문서 누락4건 해소/추가확정P1 없음. 부모 감독자가 **로컬 개발 설계·시험계획 범위만 수용**했다. 위의 제안/검토대기는 최초 작성 시점이며 후속 판정 근거는 `artifacts/qg0-design-acceptance.json`이다.
- 실제 일반사용자 실행·지원OS·단일EXE/VM·성능과 QG1 이후 기능 수용은 별개로 미검증이다. 운영 설정 변경 권한을 부여하지 않는다. CRT 정적링크는 여전히 검토 설정이다.

## QG1 후속 수용 판정
- 2026-10-21T12:20:11.599115+09:00: 공유 Core facade와 Quick DTO/JSON 계약 범위만 수용. 독립 QA 결함은 실행 재현→보정→독립 재검토로 해소. 근거 `artifacts/qg1-acceptance.json`. 기존 표의 root미통합/검증중은 당시 기록이며 현재의 QG1 판정은 이 기록을 따른다.
- GUI/EXE·무설치·지원 OS·QG2 이후 기능 및 실제 VLAN/DROP 시험 완료를 의미하지 않는다.

## 선택 ICMP Trace 실행기 root 조합회귀·제한 범위 수용 — 2026-10-22T15:20:15.712288+09:00
- 최종독립재QA deleg_45855748 두검토자 findings=[]·원문/성공단언/실제resolve목적지guard·직접ctxport/순차조회·Notify Pending취소·예산fixture 모두해소확인. 부모동일sourceSHA재계산후runner source/tests 정확2파일만root선택통합했다. manifest/lock/lib·기존DNS/Trace엔진불변.
- root workspace 415PASS/0FAIL/22ignored; 별도명시native 22PASS/0FAIL; 독립Trace경계14/DNS경계6PASS; strictClippy/fmt exit0. 22 native에는새runner5가포함되고경계suite도별도이므로합산제품인증률로표현하지않음. Inspector보호61파일SHA불변.
- 수용은선택Trace연결+기존DNS실행정책보존범위만. Trace미선택호출0·domain첫검증IP만·IP상세DNS독립·raw/canonical무보정·실측IPnonnull·OS코드None/원시exit구분·완료DNS와진행중await/drain/보관한도유지. Notify취소는합성future증거이지실제OS프로세스취소인증아님.
- source보존local commit 613d07da26aecb0a06d7c43da56120ef8135aa05, 전용worktree clean. root는기존작업을그대로보존해dirty일수있으며전체branch merge/원격push/배포없음. acceptance artifact: artifacts/qg2e-trace-runner-acceptance.json. 이전DNS수용source는역사로보존하고최신동일DNS정책근거는이수용을참조한다.
- 전체QG2는승인실VLAN/DROP/ICMP차단·다중NIC/VPN등환경검증부재로미수용. 제품동일EXE resolver dispatch/Win32GUI/TXT·CSV/PE·서명/VM·일반사용자/성능과Inspector전체G2미완료.

