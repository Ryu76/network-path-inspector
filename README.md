# Network Path Inspector

Windows 네트워크 진단 하네스. `PRD.md` v1.1이 원문 기준이다. **G1 오프라인 기반 수용이 완료되었으며, G2-A 개발자 CLI(소유한 리터럴 IPv4/IPv6 루프백 단일 대상 전용)의 실제 TCP 연결·ICMP 에코·NIC 인벤토리·OS 라우팅 구현 및 제한 범위 로컬 검증이 완료된 상태다. 전체 G2 진단 범위, 실사용 완제품, 네이티브 UI 연동, 패킷 캡처, PDF/ZIP 내보내기, Windows EXE/MSI 설치 패키지, 운영망/Windows 11/Server 지원, 성능 예산 인증은 완료되지 않았다.**

## 구현한 기반
- **Rust 공통 코어 (G0/G1)**: DTO/입력 검증, TCP OS 오류 분류, 근거 참조·판정 규칙, 구버전 1.0 원본 보존 변환.
- **선택 실행 계획 (G0/G1)**: 6그룹·23기능 레지스트리, DAG·선행 조건·캡처 동의·안전한 프로파일 복원.
- **JSON Schema 및 교차 검증 (G1)**: 합성 양성/음성 fixture, Rust/Python 간 독립 검증.
- **G2-A 기초 프로브 및 엔진 (`npi-probes`)**: 소유한 단일 루프백(`127.0.0.1`, `::1`) 대상 실제 측정(`tcp_connect`, `icmp_ping`, `nic_inventory`, `route_table`). 비루프백 및 도메인 즉시 거부, 호스트 네트워크 스냅샷 1회 공유, 중간 엔벨로프(`npi-g2-a-1`).
- **React UI 프로토타입 (G1)**: 기능 선택·그룹/기능별 조회 UI. 엔진 미연결 상태이며 진단 시작/PDF는 비활성 상태다.

## 로컬 검증
검증한 개발 환경은 Windows 10 Pro 19045 x64, Rust/Cargo 1.98.0, Node 26.7.0/npm 11.19.0이다. Windows 11/Server 호환성 또는 운영 완제품 준비 완료를 의미하지 않는다.

프로젝트 루트에서:
```text
cargo fmt --check
cargo clippy --offline --workspace --all-targets -- -D warnings
cargo test --offline --workspace --all-targets
python tools/verify_independent_g1.py
python -m unittest discover -s tools/tests -v
```
최초 Cargo 의존성이 없는 PC에서는 먼저 승인된 패키지 다운로드 절차로 lockfile 의존성을 준비해야 한다. 검증은 운영 대상에 접속하지 않는다.

G2-A 명시적 실제 루프백 검증 (부모 명시 실행):
```text
cargo test --offline -p npi-probes --tests -- --ignored --test-threads=1 --nocapture
```

G2-A 개발자 CLI 직접 실행 (루프백 전용 프로필 경로 전달):
```text
cargo run --offline -p npi-probes -- <profile.json>
```
*실행 흐름, 프로필 작성 규칙, 판정 분류 및 한계에 대한 상세 내용은 [docs/g2a-developer-guide.md](file:///E:/harnes/network-path-inspector/.worktrees/g2guide/docs/g2a-developer-guide.md)를 참조한다. 기존 `fixtures/g1/valid_profile_quick.json`은 도메인 대상이므로 G2-A 런타임에서 거부되며 그대로 실행할 수 없다.*

Schema 검증용 Python은 프로젝트 전용 환경을 사용한다:
```text
uv venv --python python .harness/validator-env
uv pip install --python .harness/validator-env/Scripts/python.exe jsonschema==4.25.1
.harness/validator-env/Scripts/python.exe tools/independent_schema_tests.py
.harness/validator-env/Scripts/python.exe tools/validate_schema.py --schema schemas/session-1.1.schema.json --instance fixtures/g1/valid_socket_connected.json
```

UI의 `ui` 디렉토리에서 `npm.cmd ci --ignore-scripts`, `npm.cmd run lint`, `npm.cmd run typecheck`, `npm.cmd test`, `npm.cmd run build`를 사용한다. `lint`는 ESLint가 아닌 프로젝트 정적 guardlint다.

## 안전·진행 상태
- **UI/브라우저 상태**: React 기능 선택 UI는 엔진 미연결 프로토타입이다. 후속 사용자 승인을 통해 실제 브라우저 렌더링, 반응형 레이아웃 및 정적 자산 해시가 검증되었으나, 추가 브라우저 daemon 포트 file WinError 5로 인해 보류되었다. 우회하거나 동일 목적으로 재시도하지 않으며, 현재 접근 가능한 가동 중인 검증 URL은 존재하지 않는다.
- **안전 경계 준수**: 운영망 및 임의 사설 IP 접속, 포트 스캔, 운영 DB 인증/SQL, OS 정책·방화벽·라우팅·레지스트리·인증서 변경, Npcap/드라이버/서비스 설치, 관리자 권한 상승, 원격 git push 및 배포는 일절 수행하지 않았다. Npcap은 선택적 외부 기설치 어댑터 설계이며 조직 라이선스 검토가 선행되어야 한다. 네트워크 실제 시험은 소유한 루프백(`127.0.0.1`, `::1`) 단일 대상에만 한정한다.
- **도구 및 모델**: `tools/integrate_g01.py`와 `tools/revise_*.py`는 과거 실행 이력용 일회성 개발 도구이며 일반 빌드나 진단 앱 실행기가 아니다. 현재 모델은 사용자 명시 승인을 거친 Gemini 3.8 Flash (High)이며, 부모가 통합 및 독립 검증을 통제한다.
- **현재 근거와 미완료 범위**: `PROGRESS.md`, `RESUME.md`, `docs/g2a-developer-guide.md`, `.harness/references/g2a-checkpoint.json`, 로컬 `artifacts/` 검증 기록.
