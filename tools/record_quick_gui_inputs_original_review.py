"""QG3B 작성 원본과 최초 컴파일 실패를 수용과 분리해 보존한다."""
import datetime
import hashlib
import json
import pathlib

R = pathlib.Path(__file__).resolve().parents[1]
load = lambda p: json.loads((R / p).read_text(encoding='utf-8'))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
p = load('artifacts/qg3b-gui-inputs-actor-prepared.json')
pipeline = load('artifacts/qg3b-gui-inputs-pipeline.json')
W = pathlib.Path(p['worktree'])
assert pipeline['status'] == 'AUDITED_SOURCE_READY_FOR_PARENT_REVIEW'
assert all(sha(W / path) == h for path, h in pipeline['source_sha256'].items())
assert all(sha(R / path) == h for path, h in p['root_before_sha256'].items())
assert all(sha(W / path) == h for path, h in p['immutable_source_sha256'].items())
assert all(sha(W / path) == h for path, h in p['reference_sha256'].items())
original = R / '.harness/evidence/qg3b-gui-inputs-actor-original'
assert all(sha(original / pathlib.Path(path).name) == h for path, h in pipeline['source_sha256'].items())
compile_result = load('artifacts/commands/qg3b-gui-inputs-original-compile.json')
assert compile_result['exit_code'] == 101 and not compile_result['partial']
log = pathlib.Path(compile_result['log']).read_text(encoding='utf-8')
assert log.count('error[E0432]') == 1 and log.count('error[E0308]') == 2
assert 'due to 3 previous errors; 143 warnings emitted' in log
now = datetime.datetime.now().astimezone().isoformat()
record = {'recorded_at': now, 'status': 'ORIGINAL_COMPILE_BLOCKED_INDEPENDENT_REVIEW_RUNNING',
    'worktree': str(W), 'source_sha256': pipeline['source_sha256'],
    'original_source_directory': str(original), 'source_files_preserved': len(pipeline['source_sha256']),
    'actor_tool_and_scope_audit_passed': True, 'actor_file_tool_calls': pipeline['strict_in_worktree_path_checks'],
    'immutable_source_files_verified': len(p['immutable_source_sha256']),
    'exact_binding_reference_files_verified': len(p['reference_sha256']),
    'original_compile': compile_result, 'original_compile_errors': 3, 'original_compile_warnings': 143,
    'known_compile_findings': [
        {'path': 'apps/network-quick-check/src/native_gui.rs', 'line': 53, 'code': 'E0432',
         'evidence': 'UpdateWindow imported from WindowsAndMessaging; pinned binding does not expose it there'},
        {'path': 'apps/network-quick-check/src/native_gui.rs', 'line': 63, 'code': 'E0308',
         'evidence': 'w! yields PCWSTR, not &[u16]'},
        {'path': 'apps/network-quick-check/src/native_gui.rs', 'line': 67, 'code': 'E0308',
         'evidence': 'w! yields PCWSTR, not &[u16]'}],
    'independent_reviews': ['deleg_44730bbf/task-0', 'deleg_44730bbf/task-1'],
    'review_scope': ['native lifetime/FFI/reentrancy/input/owned UI test validity',
                     'pure presenter/entry/Core policy/boundaries/test expectations'],
    'parent_source_repairs_performed': False, 'default_tests_executed': False,
    'native_tests_executed': False, 'visible_gui_verified': False,
    'root_product_source_changed': False, 'root_integrated': False, 'accepted': False,
    'full_qg2_accepted': False, 'full_qg3_accepted': False, 'product_accepted': False,
    'root_last_accepted_default_tests': {'passed': 477, 'failed': 0, 'ignored': 31,
                                        'this_slice_rerun': False}}
out = R / 'artifacts/qg3b-gui-inputs-original-review-checkpoint.json'
assert not out.exists()
out.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
progress = load('artifacts/quick-check-progress.json')
progress['recorded_at'] = now
progress['qg3_native_gui_inputs'] = record
(R / 'artifacts/quick-check-progress.json').write_text(json.dumps(progress, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
section = f'''
## QG3B 원본 작성 종료·최초 컴파일 차단·독립 QA 중 — {now}
- Flash FILEONLY 종료·허용source6개·FILE44호출·도구/경로감사통과. immutable59·참조12·root입력SHA유지. 원본6개를 .harness/evidence/qg3b-gui-inputs-actor-original 에그대로보존했다.
- 실제 최초 cargo test --offline --locked --target-dir (소유공유target) -p network-quick-check --lib --no-run 은exit101·3errors/143warnings. UpdateWindow 잘못된import(E0432),w! 반환포인터를&[u16]상수로선언2건(E0308). 경고대부분unsafe블록명시누락이며억제하지않는다. 이는새GUI실제컴파일실패이고성공처리하지않는다.
- deleg_44730bbf 읽기전용독립2QA 실행중: native수명주기/재진입/UTF16/잘림/실제UI시험과순수presenter/entry/Core정책/시험기대분리검토. 원본소스수정0·기본시험실행0·native/UI실행0·root통합/수용0.
- 부모직접읽기에서080거부오기대·unbracketedIPv6 positive·옵션lossydecode/EN_CHANGE누락·guard의DestroyWindow실패무시·시험사전Err를실제childfailure로오인할가능성을확인중이며독립QA와계약을대조한후최소보정한다. QA를기다리는동안native코드를실행하지않는다.
- 현재477PASS/31ignored는직전rootQG3A근거이며이번재실행수아님. 전체QG2/QG3·실GUI/runner/구형OS/배포는미수용. 근거 artifacts/qg3b-gui-inputs-original-review-checkpoint.json.
'''
for name, header in [('PROGRESS.md', '# NPI 진행 기록'), ('RESUME.md', '# NPI 개발 재개 및 승인 경계')]:
    path = R / name
    text = path.read_text(encoding='utf-8')
    assert 'QG3B 원본 작성 종료·최초 컴파일 차단·독립 QA 중' not in text
    assert header + '\n' in text
    path.write_text(text.replace(header + '\n', header + '\n' + section, 1), encoding='utf-8', newline='\n')
print(json.dumps({'status': record['status'], 'preserved_sources': record['source_files_preserved'],
    'original_compile_exit': compile_result['exit_code'], 'errors': 3, 'warnings': 143,
    'root_integrated': False, 'native_executed': False}, ensure_ascii=False))
