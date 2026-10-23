# Network Quick Check (`apps/network-quick-check`)

## 1. 개요
Network Quick Check는 별도의 설치 과정 없이 Windows 단일 실행 파일(EXE)을 복사하여 즉시 IP:Port 통신 상태를 진단할 수 있도록 기획된 경량 네트워크 진단 도구입니다.

- **현재 단계**: 공유 Core의 선택 실행기와 제품 동일 EXE DNS worker 진입점·현재 EXE backend factory까지 제한 범위 수용. worker 통신을 검증한 개발용 debug EXE는 있으나, 사용자가 진단을 시작하는 경로와 GUI·배포용 제품은 아직 미구현이다. 전체 QG2도 실환경 검증 전 미수용이다. 최신 근거는 `artifacts/qg2f-app-entry-acceptance.json`이다.
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


## 제품 동일 EXE DNS worker 진입점 root 조합회귀·제한 범위 수용 — 2026-10-22T16:26:35.728972+09:00
- deleg_c26f9c10 최종두정적QA 모두findings=[]·기존7종해소. 부모가최종4appSHA/전용worktree clean/실제순수12·CLI38·소유localhost IPC1/기존lock24패키지전체불변을확인한뒤app4+workspace/lock2만root선택통합했다. Core/resolver/Inspector소스변경0·Inspector보호61SHA불변.
- root workspace427PASS/23ignored;명시native23PASS/0ignored;Trace경계14/DNS경계6PASS;strictClippy/fmt exit0. 고정root제품EXE의명령행38PASS와부모boundedChild감독기6PASS도다시실행했다. native23은기존22+새제품worker IPC1이며app12는427에포함·서로합산하지않음.
- 수용은엄격worker selector/arity/원본host·port사전검증/거부원문비반사/단일JSON·16384byte/write·flush실패/현재EXE backend factory/동일제품EXE localhost IPC만. noargs/help는정적stderr안내만하며진단을자동실행하지않는다. factory만으로명시진단run_quick종단경로가구현됐다고주장하지않음.
- 부모QA증거수집첫시도는잘린human transcript본문JSON파싱오류로root수정전중단했다. 완전한async최종응답에서정규화한판정과잘린transcriptSHA/완료prefix를구분해보존·복구했으며제품실패/QA미수신을성공으로위장하지않았다. artifacts/qg2f-app-entry-final-review-delivery.json 참조.
- source보존local commit a04f9da59a6875d4fc4a1f7d6f162bce6b83168f;root는기존미커밋변경보존·전체branch merge/원격push/배포없음. artifacts/qg2f-app-entry-acceptance.json. 전체QG2실VLAN/DROP/ICMP차단·다중NIC/VPN미수용,GUI/QG3/명시진단시작경로/TXT·CSV/Release/PE/CRT/서명/VM·일반사용자/성능미완료. debug EXE는worker기반확인용이며배포용진단제품이아니다.


## 승인된 TCP 공개변경·양제품 실제 projector 순수 replay root 제한 수용 — 2026-10-23T10:56:57.010993+09:00
- 사용자명시「허용」범위대로Inspector apply_tcp_result에pub 4바이트만추가·함수본문/상태/오류/측정동작완전불변. root원본보호60SHA불변+승인된engine1개가시성예외를별도기록했고원래보호baseline61목록/해시는수정하지않았다. 기존61불변은이전시점이며최신판정은60+1승인delta다.
- Flash test1파일작성·부모기대문구정정/실제중복·nullablemeta/모든matrix raw/OScode/duration/stale/불변성보강·동일source실행을거쳤다. 가시성QA deleg_6b0609ec 및최종test QA deleg_fa9790f8 두검토모두findings=[]·실제두함수호출/독립기대값/제품별차이무보정/순수성확인. QA요청뒤doc공백한줄차이는역SHA증명·실행코드/단언변경0.
- root workspace433PASS/23ignored·명시native23PASS/0ignored·Trace경계14/DNS경계6PASS·strictClippy/fmt exit0. 고정root제품EXE CLI38PASS·bounded감독기6PASS도재실행. 새replay6은433에포함되며native수추가0·서로합산하지않음. 함수공개전E0603와최초5PASS1FAIL/Clippy101증거는보존했다.
- 제품코드/시험은engine와새replay시험2파일만선택통합·Cargo/lock/계약/worker source불변. 보존local commit 6ce05a322823659b53df6d5a6032ee6673dcd692·전용worktree clean;root는기존미커밋작업보존·원격push/배포/전체branch merge없음. artifacts/qg2g-tcp-replay-acceptance.json.
- 수용은같은원시DTO→양실제projector의순수characterization과승인된public접근만. CANCELLED/LOCAL_ERROR/DNS_ERROR/unknown의기존제품별차이를그대로명시하며실제순차TCP결과일치/패킷관측/EngineEnvelope·Archive·Session저장검증으로승격하지않는다. PRD23.4보조순수근거이지전체통합수용아님.
- 전체QG2실환경·GUI/QG3·제품진단시작경로/TXT·CSV/Release/PE/CRT/서명/VM·일반사용자/OS지원/성능미완료. 이전worker기반과공용resolver/Trace정책수용은불변으로유지했다.


## 소유 IPv4/IPv6 양제품 실제 TCP 비교 root 제한 수용 — 2026-10-23T12:44:22.467960+09:00
- 최종독립QA deleg_5a10ae9f 두검토모두findings=[]·실행안전true·초기F1~F4해소/기존3000ms입력채택은판정정규화나제품성능목표완화아님을확인. 부모고정SHA e926cb55d672b81d655160d9d4330a651877528d4de42eb82df34a9c84720f5c source로실행/원문증거대조후새test1파일만root선택통합했다. production/기존test/manifest/lock변경0.
- root 기본회귀434PASS/27ignored·명시native27PASS/0ignored(기존23+새IPv4/IPv6성공/거부4)·Trace경계14/DNS경계6PASS·strictClippy/fmt exit0. 실제root제품EXE CLI38PASS·bounded감독기6PASS도재검증. 새pure1은434에포함·새native4는27에포함·합산통계로과장하지않음.
- 실제run_profile메모리EngineEnvelope의TCPraw와실제run_quick/native결과를각자기대값/귀속/OS원문/nullable/전체raw에대조·같은Inspectorraw→실제Quickprojector replay는별도정확동등축. 성공각acceptpeer·실제EOF/수신애플리케이션바이트0관찰. 다른native시점elapsed/clientport전체의동일/상이조건요구0·TCP외프로브0. Archive/정규Session/패킷/서비스정상인증아님.
- 초기직렬화byte오판4FAIL→전체JSON값동등성수정뒤1000ms2PASS2FAIL(TIMED_OUT)→제품기존기본입력3000ms4PASS의실패/특성규명기록을보존했다. 이후F2~F4추가강화동일SHA로W/root모두재실행. 1000ms거부조건통과를주장하지않고3000ms의DROP성능시험으로치환하지도않는다. bound/nonlisten은독점예약/모든race제거보장아님.
- Inspector원본60SHA+기승인pub4byte1예외불변·원래baseline61해시목록미수정. Wclean/보존localcommit 8e9d76fedafe3645e89631acf7fe0baef0a159ae·root기존미커밋변경보존·원격push/배포/전체branch merge없음. artifacts/qg2h-tcp-native-acceptance.json.
- 전체QG2실VLAN/DROP/ICMP차단/다중NIC/VPN·제품EXE명시진단시작/GUI/QG3이후·Release/PE/CRT/서명/VM·일반사용자/OS지원/성능미완료. timestamp/source_host는이번null입력범위만·connect_once반환직전DTO별도capture/OS즉시회수인증아님.

