"""최종 시험 보강·실제 소유 native 실행을 보존하고 수용 전 독립 QA 대기를 기록한다."""
import datetime
import hashlib
import json
import pathlib
import subprocess

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qg2runner'
PATHS = ['crates/network-core/src/runner.rs', 'crates/network-core/tests/runner.rs']
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
run = load('artifacts/qg2e-trace-runner-final-guard-execution.json')
previous = load('artifacts/qg2e-trace-runner-parent-execution.json')
assert run['status'] == 'PURE_AND_OWNED_NATIVE_PASS_FINAL_REVIEW_PENDING'
assert all(sha(W / path) == value for path, value in run['source_sha256'].items())
assert run['source_sha256'][PATHS[0]] == previous['canonical_source_sha256'][PATHS[0]], '이번 보강 production 변경0'
before = load('artifacts/commands/qg2e-trace-runner-context-port-before-fix.json')
assert before['exit_code'] == 101 and not before['partial']
assert '0 passed; 4 failed;' in pathlib.Path(before['log']).read_text(encoding='utf-8')

def git(*args):
    p = subprocess.run(['git', '-C', str(W), *args], capture_output=True, text=True,
                       encoding='utf-8', errors='replace', timeout=40)
    assert p.returncode == 0, p.stderr
    return p.stdout.rstrip('\r\n')

assert git('branch', '--show-current') == 'ai-pro/qg2runner'
assert all(line[3:] in PATHS for line in git('status', '--porcelain').splitlines())
git('add', *PATHS)
git('-c', 'core.autocrlf=false', 'commit', '-m', 'chore: preserve tested Trace candidate pending final independent review')
assert not git('status', '--porcelain')
record = {
    'recorded_at': datetime.datetime.now().astimezone().isoformat(),
    'status': run['status'], 'source_sha256': run['source_sha256'],
    'preserved_unaccepted_commit': git('rev-parse', 'HEAD'),
    'prior_review': 'deleg_cfe9fa59', 'final_review': 'deleg_45855748',
    'findings_disposition': [
        {'id': 'TRACE-QA-001/002/03', 'state': '선행재QA에서원문비반사·native실측단언·현재native목적지TOCTOU해소확인', 'final_review_pending': True},
        {'id': 'TRACE-TEST-BUDGET-01/02', 'state': '이미실제재현후serde기반fixture교정·원래4096/보관1/누락2/호출2유지·최종실행통과', 'prior_review_read_old_fixture': True},
        {'id': 'TRACE-GUARD-PORT-02', 'state': '부모직접4회귀0pass4fail재현후testguard모든ctxport검사추가·실제DNSDTOadapter검증추가·최종실행통과'},
        {'id': 'TRACE-TEST-GUARD-02', 'state': '직접4기능비소유IP/잘못socketport거부·정확IPv4IPv6tcpTracepositive·동일mock정상사전조회후변경실제조회6변형·inner0순수회귀추가및통과'},
        {'id': 'TRACE-TEST-CANCEL-02', 'state': 'Notify첫poll→동일Arc확인→외부cancel→cleanup해제전runner미완료→해제후전체CANCELLED/DNSraw동등·후속3기능/다음대상0순수회귀통과', 'native_os_cancellation_claim': False},
    ],
    'core_counts': run['core_counts'], 'native_counts': run['test_counts']['qg2e-trace-runner-final-guard-native'],
    'execution_artifact': 'artifacts/qg2e-trace-runner-final-guard-execution.json',
    'production_changes_since_previous_parent_execution': 0,
    'accepted': False, 'root_integrated': False,
    'limitations': ['최종독립QA deleg_45855748 수신전·root조합회귀/통합전',
                    '루프백5시험만native실행했으며전체OS/운영망/VM/실제OS취소인증아님',
                    '전체QG2/GUI/단일EXE/저장·배포·성능미완료'],
}
out = R / 'artifacts/qg2e-trace-runner-final-guard-record.json'
assert not out.exists()
out.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
state = load('artifacts/quick-check-progress.json')
state['recorded_at'] = record['recorded_at']
state['qg2_trace_runner'].update(status=run['status'], independent_review='deleg_45855748',
    final_guard_record=str(out.relative_to(R)), canonical_source_sha256=run['source_sha256'],
    parent_test_counts=run['core_counts'], native_counts=record['native_counts'], native_executed=True,
    preserved_unaccepted_commit=record['preserved_unaccepted_commit'], accepted=False, root_integrated=False,
    actor_alive_at_checkpoint=False)
state['remaining_blockers'] = ['Trace 최종동일소스순수217/native소유5/Clippy·fmt통과·최종독립QA deleg_45855748 수신후 root조합회귀/통합/제한수용 전',
                               '제품helper dispatch/GUI/EXE/VM/일반사용자/실VLAN·성능·전체QG2 미완료']
(R / 'artifacts/quick-check-progress.json').write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
section = f'''\n## Trace 최종 시험 보강·소유 native 실제 통과 / 최종 QA 전 — {record['recorded_at']}
- deleg_cfe9fa59는기존원문반사/실측성공단언/현재test18·20목적지TOCTOU해소를확인했다. budget지적은부모가이미실제재현·serdefixture교정한이전소스기준으로분류. 남은직접ctxport/순차조회·직접위임guard/진짜Pending취소시험공백은확정하여부모가tests/runner.rs만보강했다. production SHA는이전부모동일소스에서불변.
- ctxport직접4시험실제0PASS4FAIL을별도보존후모든위임의ctxport검사와실제DNS DTO어댑터검사를추가했다. 직접4기능비소유127/8·IPv6·합성unicast/잘못socketport차단·IPv4IPv6positive·동일resolver정상첫조회뒤변경둘째조회6변형inner0를검증. 실제I/O는없는순수mock회귀다.
- ParentPendingTraceBackend는첫poll Notify·동일cancel Arc검증후실제로Pending을유지, 외부cancel후cleanup을풀기전20ms동안runner반환금지, 해제후전체CANCELLED DTO/완료DNS DTO전체동등·후속TCP/Ping/Host/다음target0·누락8을검증한다. 실제OS프로세스취소시험으로표현하지않는다.
- 최종동일소스 Core --all-targets {run['core_counts']['passed']}PASS/0FAIL/{run['core_counts']['ignored']}ignored, strictClippy/fmt/whitespace0. 선행QA가조건부목적지안전으로확인한정확test16~20다섯개만부모가Windows/정확helperSHA/소유127.0.0.1·::1/리스너생존을확인하고명시native실행: 5PASS/0FAIL. IPv4/IPv6·위임·localhostTrace각각실측REACHED/PASS/OBSERVED·정상exit/비절삭·stdout/최종hop/RTT/재파싱일치를단언한다.
- 최종source/tests SHA고정후추가독립QA deleg_45855748 요청. QA는읽기전용·명령0. 전용branch로컬보존commit {record['preserved_unaccepted_commit']} (미수용WIP), worktree clean확인. root통합/수용/push/배포없음. 상세기록 final-guard-record/execution artifacts. root기존DNS수용·Inspector61SHA보존, 전체QG2/GUI/EXE미완료.
\n'''
for name in ['PROGRESS.md', 'RESUME.md']:
    path = R / name
    first, rest = path.read_text(encoding='utf-8').split('\n', 1)
    path.write_text(first + '\n' + section + rest, encoding='utf-8', newline='\n')
path = R / '작업내용/NPI_2026-10-22_001.md'
path.write_text(path.read_text(encoding='utf-8') + section, encoding='utf-8', newline='\n')
print(json.dumps({'status':record['status'], 'core_counts':record['core_counts'], 'native_counts':record['native_counts'],
                  'preserved_commit':record['preserved_unaccepted_commit'], 'worktree_clean':True,
                  'final_review':record['final_review'], 'root_integrated':False, 'accepted':False}, ensure_ascii=False))
