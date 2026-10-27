"""예약 재개 단위의 실행 증거와 재개 경계를 보존하고 진행 기록을 갱신한다."""
import datetime
import hashlib
import json
from pathlib import Path
import subprocess

PREFIX = 'qg2j-20261023-2028'
R = Path(__file__).resolve().parents[1]
RUN = R / '.harness/runs/qg2j-20261023-2028'
W = R / '.worktrees/qgentryguard'
SOURCE = 'apps/network-quick-check/tests/public_entry_rejection.rs'
OUT = R / 'artifacts/qg2j-public-entry-acceptance.json'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
load = lambda p: json.loads(p.read_text(encoding='utf-8'))
now = datetime.datetime.now().astimezone().isoformat()
assert not OUT.exists()
root, worktree = load(RUN / 'root-execution.json'), load(RUN / 'worktree-recheck-execution.json')
assert root['status'] == worktree['status'] == 'PASS'
assert root['source_sha256'] == worktree['source_sha256'] == sha(R / SOURCE) == sha(W / SOURCE)
review = load(RUN / 'static-qa-v2.json')
assert review['safe_to_execute'] and not review['findings'] and review['source_sha256'] == sha(R / SOURCE)
frozen = load(RUN / 'frozen.json')
assert all(sha(R / path) == value for path, value in frozen['root_before_source_sha256'].items())
assert all(sha(W / path) == value for path, value in load(RUN / 'before.json').items())
protected_path = R / 'artifacts/qg0-inspector-baseline.json'
protected = load(protected_path)['protected_inspector_sha256']
assert sha(protected_path) == frozen['protected_baseline_sha256']
engine = 'crates/npi-probes/src/engine.rs'
assert all(sha(R / p) == h for p, h in protected.items() if p != engine)
body = (R / engine).read_bytes()
assert body.count(b'pub fn apply_tcp_result(') == 1
assert hashlib.sha256(body.replace(b'pub fn apply_tcp_result(', b'fn apply_tcp_result(', 1)).hexdigest() == protected[engine]

def git(*args):
    p = subprocess.run(['git', '-C', str(W), *args], capture_output=True, text=True,
                       encoding='utf-8', errors='replace', timeout=30)
    assert p.returncode == 0, p.stderr
    return p.stdout

assert not git('status', '--porcelain').rstrip('\r\n')
commit = git('rev-parse', 'HEAD').strip()
assert commit == load(RUN / 'integration.json')['preserved_commit']
assert git('diff-tree', '--no-commit-id', '--name-only', '-r', commit).strip() == SOURCE
actor = load(RUN / 'result.json')
assert actor['audit_passed'] and actor['cli_status'] == 'SUCCESS' and not actor['partial']
proof = {
    'recorded_at': now,
    'status': 'ACCEPTED_TEST_ONLY_PUBLIC_ENTRY_ERROR_BOUNDARIES',
    'scope': 'QG2 개발보조 경로 공개 entry의 Idle/Help/잘못된 인자·stderr 실패 순수 회귀시험',
    'root_integrated': True, 'accepted_test_slice': True, 'full_qg2_accepted': False, 'product_accepted': False,
    'source_sha256': {SOURCE: sha(R / SOURCE)},
    'worktree': str(W), 'branch': 'ai-pro/qgentryguard', 'preserved_commit': commit, 'worktree_clean': True,
    'actor_model': actor['model'], 'actor_exit_code': actor['exit_code'], 'actor_partial': actor['partial'],
    'actor_tool_calls': len(actor['tools']), 'actor_path_checks': actor['path_checks'], 'actor_policy_violations': actor['violations'],
    'inherited_permission_mode': actor['inherited_permission_mode'], 'os_enforced_file_isolation_claimed': False,
    'independent_reviews': ['deleg_234033d4/task-0', 'deleg_afc145f3/task-0'],
    'final_review_findings': [], 'evidence_directory': str(RUN.relative_to(R)),
    'workspace_counts': {'passed': 454, 'failed': 0, 'ignored': 31},
    'new_default_tests_in_workspace': 8, 'focused_counts': {'passed': 8, 'failed': 0, 'ignored': 0},
    'clippy_exit': 0, 'fmt_exit': 0, 'tracked_diff_check_exit': 0,
    'new_file_whitespace': {'exit_code': 1, 'output_empty': True, 'meaning': 'no-index의 정상 파일차이 반환; 공백 지적0'},
    'root_steps': root['steps'], 'worktree_steps': worktree['steps'],
    'native_tests_added': 0, 'native_executed_this_run': False,
    'historical_native_evidence': {'passed': 31, 'source': 'artifacts/qg2i-explicit-tcp-acceptance.json', 'rerun_this_slice': False},
    'historical_cli_evidence': {'legacy_cases': 38, 'explicit_reject_cases': 23, 'rerun_this_slice': False},
    'production_changes': 0, 'existing_tests_changed': 0, 'core_resolver_inspector_new_changes': 0,
    'original_inspector_unchanged': 60, 'existing_approved_pub4byte_exception_files': 1,
    'protected_baseline_regenerated': False, 'protected_baseline_sha256': sha(protected_path),
    'original_prd_sha256': sha(R / 'PRD.md'), 'immutable_worktree_source_files': len(load(RUN / 'before.json')),
    'preserved_failures': [
        'agy models 최초 timeout124 후 목록 재조회 성공·모델 전환 없음',
        'actor 전 checkout 3개 파일 CRLF/LF byte 차이: root 원본 불변·파생 W만 원본 bytes로 복원',
        '정규화된 Git index와 차이0인 준비 commit 시도 exit1; 실제 commit/제품 변경 없음',
        'worktree-execution.json: 새8PASS/전체454PASS31ignored 뒤 strictClippy vec_init_then_push exit101',
        '부모 보정 script의 최초 입력추출 정규식 단언 exit1: 제품 파일 쓰기 전에 중단·정규식 수정 후 동일 입력 목록 확인'
    ],
    'parent_test_only_repairs': ['ErrorKind::Other → Error::other 동등1건', 'legacy 선행15개 push를 순서 보존 vec! 초기화', '신규 파일 rustfmt'],
    'limitations': [
        '모든 호출은 기존 source 기준 Idle/Help/Invalid; 실제 OS 호출수 계측 증거는 아님',
        'QG2 실VLAN/DROP/ICMP차단/VPN/다중NIC·실제domain→제품worker→TCP 미수용',
        '실Console Ctrl+C/Break/전역handler 원복/OS즉시회수·정규시각 metadata 미수용',
        'GUI/QG3이후·Release/PE/CRT/서명/VM/일반사용자/지원OS/성능/배포 미수용'
    ],
    'next_safe_unit': '실환경 미수용 항목별 실행 승인·시험대상 소유 및 실행직전 목적지 강제검사 가능성을 먼저 설계 검토. 현재 literal-only 승인 아래 domain EXE 종단·VLAN/DROP를 실행하지 않음.',
    'scheduler_changes': False, 'other_profiles_changed': False, 'whole_branch_merged': False, 'remote_push_or_deploy': False
}
OUT.write_text(json.dumps(proof, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
progress = R / 'artifacts/quick-check-progress.json'
state = load(progress)
assert 'qg2_public_entry_guard' not in state
state['recorded_at'] = now
state['prior_root_validation_before_20261023_2020'] = state['latest_root_validation']
state['latest_root_validation'] = {
    'recorded_at': now, 'status': proof['status'], 'acceptance_artifact': str(OUT.relative_to(R)),
    'workspace_counts': proof['workspace_counts'], 'focused_new_tests_in_workspace': 8,
    'clippy_exit': 0, 'fmt_exit': 0, 'native_executed_this_run': False,
    'historical_native_evidence': proof['historical_native_evidence'], 'full_qg2_accepted': False
}
state['qg2_public_entry_guard'] = {k: proof[k] for k in [
    'recorded_at', 'status', 'worktree', 'branch', 'preserved_commit', 'worktree_clean', 'root_integrated',
    'source_sha256', 'actor_model', 'independent_reviews', 'workspace_counts', 'focused_counts',
    'new_default_tests_in_workspace', 'production_changes', 'original_inspector_unchanged',
    'existing_approved_pub4byte_exception_files', 'native_executed_this_run', 'full_qg2_accepted', 'product_accepted']}
state['qg2_public_entry_guard']['acceptance_artifact'] = str(OUT.relative_to(R))
progress.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8', newline='\n')
section = f'''## 예약 실제 재개: 공개 entry 거부·stderr 회귀시험 제한 수용 — {now}
- 새 전용 `.worktrees/qgentryguard` / `ai-pro/qgentryguard`에서 FILE ONLY `gemini-3.8-flash-high`가 신규 `apps/network-quick-check/tests/public_entry_rejection.rs` 1파일만 작성했다. 실제 tool10/path10·SUCCESS/exit0/partial=false·146개 기존 W 파일 불변 감사 후 독립 정적 검토 2회를 거쳤다. 기존 qgdevtcp writer/QA 재실행0·다른 일시중지 자동작업/프로필 변경0.
- 실제 공개 `entry`의 noargs/help, dev 잘못된 인자19·legacy/worker20·Windows unpaired UTF16 12호출, Interrupted/짧은쓰기·WriteZero/BrokenPipe/flush 실패의 정확 stderr bytes/종료코드·stdout write/flush 금지를 새 순수시험8개로 고정했다. 새 유효 진단/worker·네트워크/process/runtime/신호등록 호출0이라는 정적 경로 근거이며 OS 호출수 동적 실측은 아니다. 기존기대값/제품source/Core/resolver/manifest/lock 변경0.
- 최종 W와 root 모두 `cargo test --offline --locked -p network-quick-check --test public_entry_rejection`:8PASS/0FAIL/0ignored; `cargo test --offline --locked --workspace --all-targets`:454PASS/0FAIL/31ignored. 새8은454에 포함된다. `cargo clippy --offline --locked --workspace --all-targets -- -D warnings`·`cargo fmt --all --check`·`git diff --check` exit0. 신규파일 no-index 공백검사는 정상차이 exit1/지적출력0이며 UTF8·최종LF·후행공백0 확인.
- 최초 Clippy vec_init_then_push exit101 및 준비단계 모델목록 timeout124/파생checkout 개행차이/차이0 commit exit1/부모 보정script 사전단언 exit1은 보존했다. 부모가 신규시험만 Error::other 동등치환·15개vec 초기화·rustfmt로 보정하고 입력/호출/단언을 유지했으며 최종정적QA findings=[] 뒤 전 게이트를 새 이름으로 재실행했다. 실패 삭제·기준완화 없음.
- 신규시험1파일만 root 선택반영. W clean/보존local commit `{commit}`. Inspector 원본60SHA+기승인pub4byte1예외 유지·원래 baseline61 파일/SHA 재생성0·원본 PRD 불변. root 기존dirty는 보존·전체 branch merge/push/배포 없음. 근거 `artifacts/qg2j-public-entry-acceptance.json`, `.harness/runs/qg2j-20261023-2028/`, `artifacts/commands/qg2j-20261023-2028-*`.
- 이번 실제 native/CLI 재실행0. 이전 native31/CLI38/거부23은 16:52 수용의 역사 근거이며 새 실행수치가 아니다. 실VLAN/DROP/ICMP차단/VPN/다중NIC·실제domain→제품worker→TCP·Console Ctrl+C/Break/전역handler원복/OS즉시회수·정규시각metadata·GUI/QG3이후·Release/PE/CRT/서명/VM/일반사용자/성능/배포는 계속 미수용.
- 다음: 미수용 환경별 명시승인·부모소유 대상·실행직전 목적지 강제검사 가능성을 먼저 검토한다. literal-only 현재 승인으로 domain EXE 종단/VLAN/DROP를 실행하지 않으며, 이번 안전한 test-only 단위 이후 새 자동작업을 만들거나 paused job을 재개하지 않는다.

'''
for filename in ['PROGRESS.md', 'RESUME.md']:
    path = R / filename
    text = path.read_text(encoding='utf-8')
    title, rest = text.split('\n', 1)
    assert PREFIX not in text
    path.write_text(title + '\n\n' + section + rest.lstrip('\n'), encoding='utf-8', newline='\n')
log = R / '작업내용/NPI_2026-10-23_002.md'
assert not log.exists()
log.write_text('# Network Quick Check 예약 실제 재개 작업 기록\n\n' + section, encoding='utf-8', newline='\n')
print(json.dumps({'status': proof['status'], 'preserved_commit': commit, 'acceptance': str(OUT),
                  'records_updated': ['PROGRESS.md', 'RESUME.md', 'artifacts/quick-check-progress.json', str(log.relative_to(R))],
                  'source_sha256': proof['source_sha256']}, ensure_ascii=False))
