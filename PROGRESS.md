# NPI 진행 기록

## 최종 로컬 G1 수용 결과
**G0 개발 범위 / G1 오프라인 기반 통과. 전체 PRD 완료가 아니다. G2는 로컬 검증 승인 미확보로 미시작 상태다.**

- 통합 루트에서 Rust **90/90**, UI **27/27**, 별도 컴파일 독립 Rust **81/81**, Schema **24/24** 통과.
- 최종 fmt·Clippy `-D warnings`·guardlint·typecheck·production build·schema CLI 모두 exit 0. 단위/반복/교차 검사를 합산해 제품 완료율로 표현하지 않는다.
- AI Pro `gemini-4-argon-high` 최대 4세션 동시 실행, 프로젝트 actor 17회. 모든 프로젝트 소유 writer 종료 확인. 기존 별도 대화형 CLI 세션은 건드리지 않음.
- 공통 계약 `g1-1.1.2`. unknown 시간대·역할은 null, OS reset과 DNS 오류를 로컬 소켓 오류로 오분류하던 문제를 독립 재현 후 보정했다. 제한사항 인용을 긍정 판정으로 잘못 검사하던 오류도 회귀로 보정했다.
- 판정 근거·명령·소스 해시: `artifacts/g1-gate-report.json`.
- 작업 기록: `작업내용/NPI_2026-10-20_001.md`.
- 현재 최종 소스는 이 루트의 `crates/`, `ui/`, `schemas/`, `fixtures/`, `tools/`다. worktree의 예전 파일로 루트의 최종 QA 수정을 덮어쓰지 않는다. 일회성 `integrate_g01.py` 재실행은 차단했다.
- HTTP/브라우저·실제 통신·Npcap·PDF/ZIP·두 VLAN·설치/서명/성능은 미검증/미구현이다. 새 명시 승인 전 HTTP 검증 재시도·다른 경로 우회 금지. 운영 설정·DB·드라이버 변경/원격 push/배포 없음.

아래 내용은 최종 수용 전 시점의 이력이며 위 판정과 기계 판정 기록으로 대체된다.

## 최신 판정 — 2026-10-20
**G0/G1 구현·독립 QA 중. 전체 G1 미통과, G2 실제 프로브 미시작. 전체 P0·설치 패키지·운영/두 VLAN 호환성 완료 아님.**

- Rust atom2 기준 `24147bb`: 신규 Profile/Registry 25 + 기존 TCP 15 = **40 실행/40 통과**, clippy `-D warnings` exit 0. 현재 추가 Session/Planner 코드는 별도 검증 전이다.
- UI: **26/26 테스트**, guardlint(ESLint 아님)/typecheck/Vite production build exit 0. 엔진 미연결 G1 프로토타입임을 표시한다. 현재 nullable 계약 정렬은 추가 회귀 전이다.
- Schema: 4종 meta 검증, 18 fixture JSON 구문 검사. 실제 Python validator의 부모 독립 22검사는 직전 **17 pass / 4 fail / 1 error**를 재현했고 결과를 보존했다. 중복 결과/잘못된 입력/확정 판정 부정어 우회/DAG 불일치 수정 중이며 성공으로 표시하지 않는다.
- 하네스 자체 정제/JSON 구조/해시·제외 경로 회귀 11/11 통과.
- 공통 계약 `g1-1.1.1`: 구버전 원본에 없는 시간대·host 역할을 UTC0/client로 꾸미지 않고 null 유지. schema·golden을 수정했고 실제 converter/UI를 일치시켜 재시험해야 한다. IPv4-mapped IPv6 정규식 과제한도 보정했다.
- 원본 PRD SHA는 그대로다. 파생 worktree의 Git CRLF 체크아웃 차이만 실측 후 원본 바이트로 복원하고 `PRD.md -text`를 적용했다.

### 현재 병렬 wave `g01d`
2026-10-20 14:30:43 KST 시작. 독립 worktree 5개 중 4개에 writer 1개씩 실행한다.
- core PID 40980: Session DTO/검증·원본 보존 legacy 변환.
- planner PID 33120: 선택 DAG 계획·위험 기능 프로파일 복원.
- schema PID 6564: 재현한 semantic 오류 수정.
- ui PID 43412: nullable 계약 정렬·G6 표기·회귀 추가.
- 부모 `proc_9cd9e3fa2345`, PID 26080. `.harness/runs/g01d-*/result.json`으로 종료/partial/scope를 확인하고 끝난 worktree만 시험한다.

### 승인 미확보 / 미검증
- 로컬 HTTP 응답·JS/CSS 해시 읽기 명령은 승인 시간 초과로 미실행. 사용자 질문도 무응답 시간 초과. **재시도·다른 도구/경로 우회 금지**. HTTP/브라우저·진단망 실측은 새 명시 승인 전 보류한다.
- 임시 Vite preview는 `stdin is not a tty`로 exit 1 종료 확인. 접근 가능한 URL 또는 실제 브라우저 검증 완료로 안내하지 않는다.
- 운영망/DB 인증·SQL/방화벽·라우팅·레지스트리·인증서 변경/Npcap 설치·권한 상승 미실행.
- Win11/Windows Server 2016+·Npcap 실캡처·두 VLAN·PDF/ZIP·설치/서명/제거·성능/24시간 모니터링 미완료.

재개 절차·정확한 이력: `RESUME.md`.

## 초기 등록 기록 (위 최신 상태로 대체됨)

G0/G1 병렬 구현 진행 중. 아직 게이트 통과·실제 네트워크 진단·설치 패키지 완료 아님.

- PRD 원문 SHA-256: `faffff45de66126dad6a0a81045dd22b536e9739e78947b426bd42d4a0ef7aa1`.
- 모델: `gemini-4-argon-high`; 실제 파일 읽기/쓰기 사전 시험 exit 0, 계약 버전·23개 기능 확인.
- 병렬 작업: architecture PID 41504 / core PID 31772 / schema PID 42868 / ui PID 3492. 모두 2026-10-20 13:38:31 KST 시작.
- 독립 worktree 4개와 공통 계약(6그룹·23기능), 로컬 통합 브랜치 `integration/g01` 준비.
- Rust 1.98.0 / Cargo 1.98.0 / Node 26.7.0 / npm 11.19.0 실제 버전 확인.
- JSON Schema 검증 전용 `.harness/validator-env`에 jsonschema 4.25.1 설치 완료. 글로벌 Python 환경에는 설치하지 않음.
- 안전 경계: 운영 대상 프로브/DB 접속/OS 정책·드라이버 설치·관리자 상승 없음. 이후 네트워크 시험은 시험자가 생성한 루프백 대상만 허용.
- 주의: CLI 시작 이벤트의 기존 전역 `permission_mode=always-proceed`를 확인함. 전역 설정은 변경하지 않았으며 `--sandbox` 유지와 FILE ONLY 지시, 종료 후 도구 호출·변경 경로 검사를 적용한다. 이를 OS 수준의 강제 파일 격리로 표현하지 않는다.
- 다음: 실제 생성된 소스·스키마·UI를 독립 컴파일/시험하고 계약 불일치를 보정한다. 실패 시 G2 진행 금지.
