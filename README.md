# Network Path Inspector

Windows 네트워크 진단 하네스. `PRD.md` v1.1이 원문 기준이다. **현재 G0/G1의 오프라인 기반 구현·검증 범위이며, 실제 TCP/ICMP 진단·캡처·PDF/ZIP·Windows 설치 패키지는 완료되지 않았다.**

## 구현한 기반
- Rust 공통 코어: DTO/입력 검증, TCP OS 오류 분류, 근거 참조·판정 규칙, 구버전 1.0 원본 보존 변환.
- 선택 실행 계획: 6그룹·23기능 레지스트리, DAG·선행 조건·캡처 동의·안전한 프로파일 복원. 계획 생성만 하며 프로브를 보내지 않는다.
- JSON Schema 및 합성 양성/음성 fixture, Rust/Python 간 교차 검증.
- React 기능 선택·그룹/기능별 조회 UI 프로토타입. 진단 시작/PDF는 미연결로 표시하며 비활성 상태다.

## 로컬 검증
검증한 개발 환경은 Windows 10 Pro 19045 x64, Rust/Cargo 1.98.0, Node 26.7.0/npm 11.19.0이다. Windows 11/Server 호환성 또는 운영 준비 완료를 의미하지 않는다.

프로젝트 루트에서:
```text
cargo fmt --check
cargo clippy --offline --workspace --all-targets -- -D warnings
cargo test --offline --workspace --all-targets
python tools/verify_independent_g1.py
python -m unittest discover -s tools/tests -v
```
최초 Cargo 의존성이 없는 PC에서는 먼저 승인된 패키지 다운로드 절차로 lockfile 의존성을 준비해야 한다. 검증은 운영 대상에 접속하지 않는다.

Schema 검증용 Python은 프로젝트 전용 환경을 사용한다:
```text
uv venv --python python .harness/validator-env
uv pip install --python .harness/validator-env/Scripts/python.exe jsonschema==4.25.1
.harness/validator-env/Scripts/python.exe tools/independent_schema_tests.py
.harness/validator-env/Scripts/python.exe tools/validate_schema.py --schema schemas/session-1.1.schema.json --instance fixtures/g1/valid_socket_connected.json
```
UI의 `ui` 디렉토리에서 `npm.cmd ci --ignore-scripts`, `npm.cmd run lint`, `npm.cmd run typecheck`, `npm.cmd test`, `npm.cmd run build`를 사용한다. `lint`는 ESLint가 아닌 프로젝트 정적 guardlint다. 현재 결과는 빌드·컴포넌트 시험이며 실제 브라우저/설치 검증이 아니다.

## 안전·진행 상태
로컬 HTTP/브라우저 검증은 승인 시간 초과로 보류됐다. 새 명시 승인 전에는 같은 검증을 다른 경로로 우회하거나 실제 진단망 시험을 시작하지 않는다. 가동 중인 검증 URL을 제공하지 않는다.

운영 DB 인증/SQL, 정책·라우팅·레지스트리·인증서 변경, Npcap 설치·권한 상승·배포는 수행하지 않았다. Npcap은 선택적 외부 기설치 어댑터 설계이며 조직 라이선스 검토가 필요하다.

현재 근거와 미완료 범위: `PROGRESS.md`, `RESUME.md`, `작업내용/`, 로컬 `artifacts/` 검증 기록. `tools/integrate_g01.py`와 `tools/revise_*.py`는 실행 이력용 일회성 개발 도구이며 정상 빌드/진단 명령이 아니다.

Gemini 4 Argon High AI Pro를 독립 worktree에서 병렬 실행하고 부모가 통합·독립 검증한다. 운영망 접속·방화벽/라우트/드라이버/DB 변경은 금지한다.
