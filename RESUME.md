# NPI 개발 재개 및 승인 경계

## 최종 인수인계 — 아래의 과거 진행 상태보다 우선
- **G0 개발 범위 / G1 오프라인 기반 통과**. 실제 전체 PRD·운영·설치 완료 아님.
- 루트 통합 소스의 최종 검증: Rust90/90, UI27/27, 별도 컴파일 독립 Rust81/81, Schema24/24. fmt/strictClippy/guardlint/typecheck/build/schemaCLI exit0.
- 최종 근거: `artifacts/g1-gate-report.json`; 작업 기록 `작업내용/NPI_2026-10-20_001.md`.
- `g01d`, `g01wsa` 등 모든 프로젝트 actor는 종료됐다. 자동 재개 예약/상주 개발 작업 없음. 기존 별도 CLI 세션은 미변경.
- 현재 루트 `crates/`, `ui/`, `schemas/`, `fixtures/`가 최종 QA 수정을 포함한다. worktree는 역사·검토용으로 남겼고 루트보다 뒤처질 수 있으므로 무조건 재통합하지 않는다. `tools/integrate_g01.py`는 이미 실행된 일회성 도구라 재실행 차단.
- 공통 계약 최종 `g1-1.1.2`: nullable unknown role/timezone, RESET 결과/WSA10054, DNS11002/11003 보정. Root의 Clippy 기계 수정 및 Finding.statement 대 limitations 인용 검사 경계 수정을 보존한다.
- G2는 **NOT_STARTED_PENDING_LOCAL_VERIFICATION_APPROVAL**. HTTP/브라우저 명령 승인 시간 초과와 별도 사용자 질문 무응답은 승인이 아니다. 새 명시 승인 전 동일 목적의 우회/재시도·실제 통신 검증 금지.
- 다음에 사용자 승인이 명시되면 루트 기계 판정과 실제 Git 상태를 먼저 확인하고 G2의 실제 TCP/ICMP/NIC/라우팅·Agent/네이티브 UI 연결을 구현·시험한다. G3 이후는 각 선행 게이트 통과 전 진행하지 않는다.

## 과거 작업 이력 (이하의 현재/진행 중 표기는 작성 당시 상태)

## 단일 기준
- 사용자 요청: 첨부 PRD v1.1 기반 Network Path Inspector 개발, AI Pro 여러 세션 병렬 실행.
- 프로젝트: `E:/harnes/network-path-inspector` — LibMate/SeatMate와 별개다.
- 원문: `PRD.md`, SHA-256 `faffff45de66126dad6a0a81045dd22b536e9739e78947b426bd42d4a0ef7aa1`.
- 실행기: `tools/ai_pro_harness.py`, 모델 `gemini-4-argon-high`, `--sandbox --mode accept-edits`, 명시 effort/권한 우회 없음.
- 전역 CLI의 기존 `permission_mode=always-proceed`가 시작 이벤트에 나타남. 전역 설정을 변경하지 않았다. FILE ONLY 지시/독립 worktree/종료 후 도구·경로 감사를 OS 강제 격리라고 표현하지 않는다.

## 현재 게이트
- **전체 G1 미통과**, G2 실제 진단 구현·프로브 미시작. P0 전체/설치 패키지/실서버·VLAN/성능 인증 미완료.
- G0 설계·위협 모델·ADR·추적표 11문서 작성 후 과도한 안전/라이선스/OS 완료 표현을 AI Pro로 보정. 아직 부모 최종 수용 판정 전.
- Rust core atom1 TCP 분류·23기능 레지스트리: 15 테스트 통과, fmt 보정 후 clippy `-D warnings` 통과, `0ede43d`.
- Rust core atom2 프로파일/레지스트리 DTO·검증: 신규 25 + 기존 15 테스트 통과, clippy `-D warnings` 통과, `24147bb`에 계약 수정과 함께 보존.
- UI: 26 테스트·guardlint(ESLint 아님)·typecheck·실제 Vite production build 통과. 처음 TS2882 CSS 타입 오류는 `vite-env.d.ts`를 AI Pro가 생성해 해결. 로그 `artifacts/commands/g01uifx1-ui-*.{json,log}`. 실제 브라우저/렌더링 미검증이며 엔진 미연결 G1 프로토타입임.
- Schema: 4개 스키마 메타스키마 검증 통과, 18개 JSON fixture 구문 파싱. 실제 Python 검증기 `tools/validate_schema.py` 생성됨. 부모 독립 22개 검사 직전 결과 17 pass / 4 fail / 1 error를 `artifacts/g1-schema-independent-before-repair.json`에 보존했다. 실패 무시/기대값 완화 없이 수정 진행 중.
- 세션 DTO/검증·legacy 변환·선택 DAG/planner/복원은 추가 병렬 구현 중. `tools/verify_independent_g1.py`는 이 공용 API 전체가 구현된 후 실행하는 독립 Rust probe이며 아직 실행 성공한 적 없다.

## 승인 미확보 — 우회/재시도 금지
1. `127.0.0.1:39201` 미리보기 HTTP 응답과 JS/CSS 파일 해시를 읽는 terminal 명령이 승인 시간 초과로 **실행되지 않음**.
2. 별도 사용자 질문도 10분 응답 시간 초과. 승인으로 취급하지 않는다.
3. 동일 HTTP 검증을 재실행하거나 브라우저/다른 명령으로 같은 결과를 얻으려 하지 않는다. HTTP/브라우저·진단망 검증은 새 명시 승인 전 보류하고, 네트워크 없는 소스/스키마/Node/Rust 검증만 진행한다.
4. 임시 Vite preview `proc_d72e0f350e9f` / PID 28012는 종료 확인: `stdin is not a tty`, exit 1. 접근 가능한 UI URL이라고 말하지 않는다. 이미 종료된 이 서버를 승인 없이 PTY 등으로 재기동하지 않는다.
5. 운영망·예시 사설 IP 접속, DB 인증/SQL, 방화벽·라우트·레지스트리·인증서 변경, 관리자 상승, Npcap/드라이버/서비스 설치·배포는 미실행/금지.

## 병렬 작업·진행 기록
- 최초 `g01`: 4세션 실제 동시 실행. architecture 완료, core 변경 0, schema/UI 부분 변경 후 print timeout. exit 0/SUCCESS여도 partial을 성공 처리하지 않음.
- `g01b`: architecture 보정 완료, core atom1 완료, UI 실제 화면+26tests 완료. schema는 존재하지 않는 추정 파일명을 200회 이상 읽다가 timeout, 변경 0. 공급자 quota/권한 실패로 오보하지 않는다.
- `g01c core`: atom2 완료.
- `g01uifx1 ui`: CSS 타입 선언 1파일 수정 완료.
- `g01s-validator schema`: 정확한 실제 파일명 5개만 주어 검증기 1파일 생성 완료. 파일명 추측 금지.
- **현재 `g01d core planner schema ui`**: 4개 독립 worktree에서 세션/legacy, DAG/planner, 재현된 schema 오류, UI nullable 계약 정렬 병렬 작업. 부모 wrapper `proc_9cd9e3fa2345`, PID 26080. 실제 actor PID/진행은 `.harness/runs/g01d-*/started.json`와 `result.json`을 읽어 확인한다. 완료 전 소스에 쓰거나 시험하지 않는다.

## worktree·Git
- root 통합 브랜치 `integration/g01` — 초기 baseline 이후 기능 통합 전, 원격 없음.
- `.worktrees/architecture` / `ai-pro/g01-architecture`: 문서 전용(보정 dirty 보존).
- `.worktrees/core` / `ai-pro/g01-core`: 검증된 atom2 기준 `24147bb`, 현재 session 작업.
- `.worktrees/planner` / `ai-pro/g1-planner`: `24147bb`에서 분리, planning.rs 및 자체 tests/lib export만.
- `.worktrees/schema` / `ai-pro/g01-schema`: WIP `fe899da`, 현재 semantic repairs.
- `.worktrees/ui` / `ai-pro/g01-ui`: `e52607b`, 현재 nullable 계약 정렬.
- WIP 커밋은 보존 목적이며 제품 완료/병합 가능 증거가 아니다. 원격 push/배포/설치 없음.

## 공통 계약 g1-1.1.1 수정
- PRD 원문은 수정하지 않았다. `contracts/g1-interface-contract.json`은 부모가 제어하는 개발 계약이다.
- legacy 원본에 로컬 시간대와 host 역할이 없으면 UTC0/client로 꾸며서는 안 되므로 `timezone_offset_minutes`, `host_role`에 null 허용. clock 오차·자원 메트릭도 미측정 null.
- IPv4-mapped IPv6 `::ffff:192.0.2.1`는 실제 IPv6 구문 파서가 허용하나 기존 schema 정규식이 거부하여 HostString 허용 문자만 보정했다.
- 부모 `tools/revise_g1_contract.py` 실행 결과 `artifacts/g1-contract-revision.json`.
- 최초 script는 파생 worktree PRD가 Git `core.autocrlf`로 CRLF 체크아웃되어 SHA가 달라 중단했다. Root 원본 SHA는 그대로였고 모든 파생 사본의 차이는 줄바꿈뿐임을 실측했다. 비교 후 파생 사본에 원본 바이트를 복사하고 `.gitattributes`의 `PRD.md -text`로 향후 변환을 막았다. 원본을 정규화/덮어쓴 것이 아니다.

## 재현한 스키마 결함
- `feature_results` 중복 ID를 조용히 덮어써 허용.
- selected_features에 dict가 들어가면 set()에서 TypeError.
- 문장 어디든 '없음' 등의 부정어가 있으면 '방화벽 차단 확정. 미확인 사항 없음.'을 허용하는 판정 우회.
- IPv4-mapped IPv6 정규식 과제한(데이터 수정 적용 후 재시험 필요).
- legacy fixture 원본 미제공 시간대0/client 추측(부모 계약·fixture null 보정; 실제 converter도 독립 검증해야 함).
- Rust는 정상 DAG를 허용하나 Python은 dependencies가 canonical 빈 배열과 같아야 한다고 해 불일치. 부모 추가 양성 회귀 필요.

## 다음 안전 실행 순서
1. g01d actor 결과/partial/scope와 `tools/audit_ai_pro_runs.py g01d`를 확인. 끝난 worktree만 시험.
2. 부모 `tools/independent_schema_tests.py`를 프로젝트 `.harness/validator-env/Scripts/python.exe`로 실행. 기존 22검사와 양성 DAG/nullable role 회귀 추가. 실패를 보존하고 원인 보정.
3. core/session 및 planner 각각 실제 cargo fmt/clippy/test. planner 새 모듈을 core에 선택 통합한 뒤 전체 API probe를 fresh build해 실행.
4. UI offline lint/typecheck/test/build 재실행. HTTP/브라우저는 승인 미확보 상태 유지.
5. 전체 G1 계약 일치·현재 소스/DLL(실행파일) 해시·모든 필수 시험을 확인한 후에만 G1 상태 판단. 아직 G2 착수 금지.
6. `PROGRESS.md` 및 `작업내용/NPI_YYYY-MM-DD_NNN.md`를 실제 결과로 갱신. 작업 중 상태와 완료를 구분하며 전체 P0 완료로 표현하지 않는다.
