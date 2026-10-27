# Win32 입력·계획 화면 개발 체크포인트 — 2026-10-26

## 현재 판정

**구현·숨김 창 시험은 진행됐지만, 실제 화면 조작 수용은 완료되지 않았다. 메인 통합과 제품 수용은 보류한다.**

- 전용 작업 트리: `E:/harnes/network-path-inspector/.worktrees/qgguiinputs`
- 브랜치: `ai-pro/qgguiinputs`
- 로컬 WIP 보존: `0da7720fa3a943f3abeb5a34d0c12c24786bff62` — clean 확인.
- 메인은 기존 QG3A 순수 상태모델 수용의 **477 PASS / 31 ignored**를 유지한다. 아래 500 PASS는 전용 작업 트리의 새 실행 결과다.
- 원격 push·merge·배포·운영 설정 변경 없음.

## 구현 범위

입력·계획 확인 전용 Windows 네이티브 화면을 작성했다. 기존 `GuiState`와 Core의 실제 목록 파서·계획기를 소비한다.

- 여러 행 대상 입력, 추가·전체 교체·단일 선택 삭제.
- TCP·Ping·Trace·DNS·로컬 정보 선택, 시간 제한과 동시성 입력.
- 실제 Core 계획 미리보기, 오류 안내와 변경 후 재확인 표시.
- UTF-16 엄격 디코드, 입력/옵션별 잘림 상태 유지, 원자적 적용.
- 시작·중지·저장 버튼 비활성, 네트워크 진단 미연결 상시 표시.
- 계획 확인은 `begin_run`, `finish_run`, `run_quick`을 호출하지 않는다.

선택 항목의 in-place 수정, 실행 coordinator, 실제 진단/결과, 필터·복사·TXT/CSV는 이번 범위에 없다. 기본 noargs/도움말/CUI subsystem은 유지하며, 새 개발 selector 추가는 의도적인 진입점 확장이다.

## 변경 파일

작업 트리의 소스 6개:

- `apps/network-quick-check/src/lib.rs` — 좁은 GUI dispatch와 모듈 선언.
- `apps/network-quick-check/src/gui_entry.rs` — 정확한 selector·arity 및 오류 처리.
- `apps/network-quick-check/src/gui_presenter.rs` — 순수 입력·계획 프레젠터.
- `apps/network-quick-check/src/gui_presenter_tests.rs` — 순수 시험 16개.
- `apps/network-quick-check/src/native_gui.rs` — 컨트롤·메시지·수명주기.
- `apps/network-quick-check/src/native_gui_tests.rs` — 명시 실행 전용 숨김 창 시험 4개.

부모가 선행 준비한 메타데이터 2개:

- `apps/network-quick-check/Cargo.toml`
- `Cargo.lock`

Windows 전용 `windows-sys = "=0.61.2"`의 UI features를 추가했고, 기존 registry 패키지 identity/checksum과 다른 패키지 레코드는 유지했다. Core·resolver·Inspector·기존 CLI 구현·기존 상태모델·기존 시험은 불변이다. 소스 작성은 Flash High와 부모 보정 모두 포함하며 Flash 단독 작성으로 표현하지 않는다.

## 실제 실행 결과

- `cargo test --offline --locked --target-dir ... --workspace --all-targets`: **500 PASS / 0 FAIL / 35 ignored**.
  - 신규 기본 시험 23개(entry 7 + presenter 16)는 500에 포함한다.
  - GUI focused 46개는 기존 상태모델 23개를 포함하는 중복 집합이다. 합산하지 않는다.
- `cargo clippy --offline --locked --target-dir ... --workspace --all-targets -- -D warnings`: exit **0**.
- `cargo fmt --all -- --check`: exit **0**.
- `cargo build --offline --locked --target-dir ... -p network-quick-check --bin NetworkQuickCheck`: exit **0**, debug 빌드.
- `cargo test ... -p network-quick-check --lib native_gui::tests:: -- --ignored --test-threads=1`: **4 PASS / 0 FAIL**.
  - 이 4개는 기본 실행에서는 35 ignored에 포함된다. 500에 다시 합산하지 않는다.
  - 같은 생산 생성·WM_COMMAND 경로, 실제 부분 자식 생성 실패, 단일 context drop, 부모/자식 파괴, quit 정리와 unwind 정리를 검사했다.
- 이번 EXE로 기존 CLI **38개**, 개발 TCP 거부 **23개**, 새 GUI 거부 **9개**, 자식 감독기 **6개** 통과.
  - 기존 corpus 생성과 ID 순서를 유지했다. 과거 PASS를 이번 실행 수로 재사용하지 않았다.
  - literal worker 2건은 부모가 같은 포트를 소유한 `127.0.0.1`/`::1` 주소 반환만 확인했다. 연결 시도·스캔·소켓 옵션 변경·fixture 재시도 없음.
- 독립 재검토: native 안전 확정 결함 없음. 순수 검토의 `CONTRACT001`은 원래 expected-lib의 rustfmt 결과가 실제 lib와 byte 동일함을 확인한 포맷 전용 예외로 부모가 명시 수용했다. 원문 참조 파일은 고치지 않았다.

## 실패와 보정 보존

원본 compile-only는 exit101, 오류 3개/경고 143개였다. 잘못된 Win32 import, `w!` 포인터 타입 선언과 unsafe 경계를 보정했다. 원본 presenter 시험은 7 PASS / 3 FAIL로, 잘못된 bare IPv6 성공 fixture 및 `080` 거부 기대를 실제 Core 정책에 맞췄다.

독립 QA의 native 9건과 순수 3건을 보정했다. 창 파괴 결과·생존 HWND·실패 시 Box 보존, 옵션 잘림/엄격 읽기, 계획 적용 차단, 옵션 변경 stale, 소유 HWND 검증, quit 정리, 실제 부분 자식 실패 관측, 생산 메시지 시험을 추가했다. 오류는 큰 문자열을 먼저 만든 뒤 자르지 않고 제한된 `fmt::Write`로 작성 중 중단한다.

부모 보정 중 strict Clippy 실패와 시험 블록 중복 추가에 따른 compile101도 보존했다. 중복 블록의 정확 동등성을 확인한 후 하나만 제거하고 전체 회귀를 다시 실행했다. 시험 삭제·기준 완화로 실패를 지우지 않았다.

## 실제 화면 관측과 승인 경계

검증된 debug EXE를 부모 소유 프로세스로 명시 실행하고 한국어 안내, 입력/목록/옵션/계획 영역과 비활성 버튼을 이미지로 확인했다.

- background `PostMessage` 입력은 요청한 CRLF를 정확하게 전달하지 못했다. 이 관측만으로 일반 사용자 입력 자체의 결함을 확정하지 않는다.
- 뒤이은 `computer_use set_value`는 사용자 응답 없이 승인 만료됐다. **같은 입력 작업 재시도 또는 다른 경로를 통한 우회를 하지 않았다.**
- 가시 화면에서 Trace가 체크된 관측은 숨김 창 기본값 시험과 달랐다. 원인은 확정하지 않았으며 가시 화면의 손대지 않은 초기 상태를 인증하지 않는다.
- 자기 창만 닫은 뒤 실제 프로세스 exit0·stdout0·stderr0·회수 완료를 재조회했다.

따라서 실제 사용자 입력·Enter/여러 행 동작, 가시 CRUD/계획 동작 순서, Tab 이동, 리사이즈·스크롤·DPI 조건은 **미검증**이다. 숨김 창 시험으로 이를 대체하지 않는다. 승인 만료를 승인으로 간주하거나 다른 도구로 같은 결과를 얻으려 하지 않는다.

## 개발용 실행 산출물

배포본이 아닌 현재 debug EXE다. 기존 noargs 동작을 바꾸지 않으므로 개발 selector가 필요하다.

```bat
"E:\harnes\network-path-inspector\.harness\targets\qg3b-gui-inputs-shared\debug\NetworkQuickCheck.exe" --dev-gui-inputs-v1
```

SHA-256: `53efb0c6d3c3f99719b38798ca1ff84ccde6439e61896fc355366e601175e8bd`

Windows 10의 현재 호스트 관측이며 Windows 11·Server 2012/R2 이후 전체 지원 인증이 아니다. Release·CRT·서명·단일 EXE 배포 수용·VM·성능도 미완료다.

## 근거와 다음 경계

- `artifacts/qg3b-gui-inputs-parent-repair.json`
- `artifacts/qg3b-gui-inputs-final-independent-review.json`
- `artifacts/commands/qg3b-gui-inputs-parent-owned-native.json`
- `artifacts/qg3b-gui-inputs-parent-commandline.json`
- `artifacts/qg3b-gui-inputs-visible-observation.json`
- `artifacts/qg3b-gui-inputs-visible-process.json`
- `artifacts/qg3b-gui-inputs-preservation.json`
- `.harness/evidence/qg3b-visible/initial.png`
- `.harness/evidence/qg3b-visible/background-type.png`

다음은 승인 경계를 해소한 뒤 가시 기능 검증을 재개하는 것이다. 이 체크포인트는 `accepted=false`, `root_integrated=false`이며 전체 QG2/QG3·GUI/runner·제품/배포 완료가 아니다.
