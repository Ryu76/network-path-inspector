"""예약 재개: 새 전용 worktree의 공개 진입점 회귀시험만 FILE ONLY로 작성한다."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

R = Path(__file__).resolve().parents[1]
W = R / '.worktrees/qgentryguard'
PREFIX = 'qg2j-20261023-2028'
RUN = R / '.harness/runs' / PREFIX
MODEL = 'gemini-3.8-flash-high'
OUTPUT = 'apps/network-quick-check/tests/public_entry_rejection.rs'
READS = ['AGENTS.md', 'apps/network-quick-check/Cargo.toml',
         'apps/network-quick-check/src/lib.rs', 'apps/network-quick-check/src/diagnostic_cli.rs']
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
now = lambda: datetime.datetime.now().astimezone().isoformat()

def save(name, value):
    p = RUN / name
    assert not p.exists(), str(p)
    p.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

def git(*args, cwd=R):
    p = subprocess.run(['git', *args], cwd=cwd, capture_output=True, text=True,
                       encoding='utf-8', errors='replace', timeout=30)
    assert p.returncode == 0, p.stderr
    return p.stdout

def snapshot(root):
    return {p.relative_to(root).as_posix(): sha(p) for p in root.rglob('*') if p.is_file()
            and not any(x in {'.git', '.harness', '.worktrees', 'target', 'node_modules', 'dist', '__pycache__'}
                        for x in p.relative_to(root).parts)}

def prepare():
    recovering = W.exists() and RUN.exists()
    assert recovering or (not W.exists() and not RUN.exists())
    accepted = json.loads((R / 'artifacts/qg2i-explicit-tcp-final-delivery-check.json').read_text(encoding='utf-8'))
    assert all(sha(R / p) == h for p, h in accepted['source_sha256'].items())
    old = R / '.worktrees/qgdevtcp'
    assert git('rev-parse', 'HEAD', cwd=old).strip() == accepted['preserved_source_commit']
    assert not git('status', '--porcelain', cwd=old).rstrip('\r\n')
    if not recovering:
        RUN.mkdir(parents=True)
        save('root-status-before.json', {'status': git('status', '--porcelain'), 'branch': git('branch', '--show-current').strip()})
        save('worktree-list-before.json', {'worktrees': git('worktree', 'list', '--porcelain')})
        git('-c', 'core.autocrlf=false', 'worktree', 'add', '-b', 'ai-pro/qgentryguard', str(W), accepted['preserved_source_commit'])
    else:
        assert git('branch', '--show-current', cwd=W).strip() == 'ai-pro/qgentryguard'
        assert git('rev-parse', 'HEAD', cwd=W).strip() == accepted['preserved_source_commit']
        assert not (RUN / 'started.json').exists()
    assert not git('status', '--porcelain', cwd=W).rstrip('\r\n')
    before = snapshot(W)
    assert OUTPUT not in before
    assert all(sha(W / p) == h for p, h in accepted['source_sha256'].items())
    assert sha(W / 'PRD.md') == sha(R / 'PRD.md')
    protected_path = R / 'artifacts/qg0-inspector-baseline.json'
    protected = json.loads(protected_path.read_text(encoding='utf-8'))['protected_inspector_sha256']
    engine = 'crates/npi-probes/src/engine.rs'
    approval = json.loads((R / 'artifacts/qg2g-tcp-replay-acceptance.json').read_text(encoding='utf-8'))
    newline_deltas = []
    for path, original_sha in protected.items():
        if path == engine:
            continue
        assert sha(R / path) == original_sha
        if sha(W / path) != original_sha:
            source, derived = (R / path).read_bytes(), (W / path).read_bytes()
            assert source.replace(b'\r\n', b'\n') == derived.replace(b'\r\n', b'\n')
            newline_deltas.append({'path': path, 'root_sha256': original_sha, 'checkout_sha256': sha(W / path), 'newline_only': True})
    if newline_deltas:
        save('initial-preflight-checkout-failure.json', {'exit_code': 1, 'actor_started': False,
             'reason': 'Git checkout newline-only byte differences; root protection intact', 'deltas': newline_deltas})
        for delta in newline_deltas:
            path = delta['path']
            (W / path).write_bytes((R / path).read_bytes())
        git('-c', 'core.autocrlf=false', 'add', '--', *[x['path'] for x in newline_deltas], cwd=W)
        if git('diff', '--cached', '--name-only', cwd=W).strip():
            git('-c', 'core.autocrlf=false', 'commit', '-m', 'chore: preserve authoritative baseline bytes for entry guard QA', cwd=W)
        assert not git('status', '--porcelain', cwd=W).rstrip('\r\n')
    before = snapshot(W)
    assert all(sha(R / p) == h and sha(W / p) == h for p, h in protected.items() if p != engine)
    assert sha(W / engine) == sha(R / engine) == approval['source_sha256'][engine]
    # 승인 예외를 제거한 전체 bytes가 원래 보호 해시와 같은지 확인한다.
    b = (W / engine).read_bytes()
    assert b.count(b'pub fn apply_tcp_result(') == 1
    assert hashlib.sha256(b.replace(b'pub fn apply_tcp_result(', b'fn apply_tcp_result(', 1)).hexdigest() == protected[engine]
    inputs = [(W / p).as_posix() for p in READS]
    assert all(Path(p).is_file() for p in inputs)
    prompt = f'''당신은 Network Quick Check QG2 공개 진입점 오류계약 회귀시험 FILE ONLY 작성자다.
전용 worktree: {W.as_posix()}. 먼저 {inputs[0]}를 읽고 다른 제공 입력을 읽어라.
허용 READ 정확목록: {json.dumps(inputs, ensure_ascii=False)}.
허용 CREATE/EDIT 단 하나의 새 파일: {(W / OUTPUT).as_posix()}.
모든 경로는 위 전용 worktree 내 절대경로. PRD/문서의 타경로를 따라가지 말라. command/run_command/terminal/PowerShell/git/cargo/test/build/network/install/manage_task/재위임/다른 agent/계정·자격증명 읽기 모두 금지. FILE read/write/edit 외 도구 금지. 기존 lib/diagnostic/Core/resolver/Inspector/manifest/lock/기존시험/문서는 읽기목록외 접근 및 수정 금지. sandbox/전역권한 변경 금지.
목표는 기존 동작을 바꾸지 않는 characterization 회귀시험이다. private 모듈 복사/include 또는 public API 확장 없이 network_quick_check::entry 실제 공개 함수만 호출한다. 네트워크/파일/프로세스/시간조회/신호등록/runtime 생성0. 새 dependency0. 유효 dev TCP 인자와 유효 worker 인자는 절대 entry에 전달하지 말라. 거부형 host는 비정상문법만, 포트부정행렬의 host는 정확127.0.0.1만 쓴다. 도메인해석/소켓없음. 이 시험만으로 OS 호출수를 실측했다고 주장하지 말라. 실행 전 부모가 모든 호출 인자가 Idle/Help/Invalid인지 정적 감사한다.
정확히8개의 #[test] 함수(Windows 전용 unpaired UTF16 시험1 포함), ignore0:
1 idle: stdout은 write/flush에 panic하는 sentinel, stderr는 Interrupted1회+짧은쓰기2바이트 반복+flush성공. entry([],...) exit0, 정확NOARGS_STDERR bytes, flush1회, 중복/누락0.
2 help: 같은 sentinel/짧은쓰기+Interrupted1회. entry([--help]) exit0, 정확HELP_STDERR, flush1회.
3 dev 인자거부: 인자부족/초과4 sentinel, 호스트 malformed URI/userinfo/bracket/CIDR/줄바꿈/NUL, 그리고 literal127.0.0.1에 port 0,65536,-1,+80,080, 80,80공백,비ASCII숫자,긴overflow문자열. 실제entry exit2, stdout write/flush0, 정확INVALID_STDERR, flush1; 새 문자열은 합성 marker만. 외부IP/유효domain 호출0. 행렬 개수는 실제vec.len으로 검증·임의 기대성공 삭제금지.
4 legacy/worker 인자거부: --run, selector 오타/인자결합, --help 추가인자, worker 부족/초과 및 invalid host/port. 유효worker는0. entry exit2/고정문구/반사0. 각 호출마다 새로운 writer, stdout untouched.
5 #[cfg(windows)] unpaired UTF16 from_wide D800/DC00를 dev/worker의 selector,host,port 각위치에 넣어 실제entry exit2. 유효 문자열로 수리하지 말라. stdout untouched, 정확INVALID_STDERR. 행렬은 두 selector x 두unpaired x 세위치 =12 호출; selector위치의나머지host는127.0.0.1/port80.
6 stderr WriteZero: idle/help/dev invalid/legacy invalid 네 경로, 0bytes 또는5bytes prefix 뒤 write=Ok(0). exit1, flush0, 받은 bytes는 정확정적문구prefix, 다른 오류문구 덧쓰기0, stdout untouched. partial UTF8일수있으므로 lossy 문자열로 정규화하지 말고 bytes비교.
7 stderr BrokenPipe: 같은4경로, 0bytes 또는5bytes prefix뒤 Err(BrokenPipe), exit1/flush0/정확prefix/stdout0. 에러text는 합성marker·어떤추가반사도0.
8 stderr flush실패: 같은4경로, 전체정적문구 쓰기뒤 flush Err, exit1/flush1, bytes는 정확원문전체, 추가오류문구0/stdout0.
표준 std::io::Write/write_all 실제 동작을 검사하며 제품 제어흐름을 재구현하지 말라. 반복 fixture(helper)로 줄이되 테스트 의미를 숨기지 않는다. 부정행렬을 조건부 실행/skip/unwrap_or로 통과시키지 말라. stdout sentinel은 write뿐 아니라 flush도 panic하도록 한다. 주석 한국어·UTF8·마지막LF·후행공백0·Clippy suppression0. production/기존기대값/계약수정0. compile/test는 부모만 한다. 코드 작성 후 변경경로와 검증필요점만 짧게 보고. 통과/수용 주장금지.
'''
    (RUN / 'prompt.md').write_text(prompt, encoding='utf-8', newline='\n')
    save('before.json', before)
    save('frozen.json', {'recorded_at': now(), 'stage': PREFIX, 'role': 'qgentryguard', 'model': MODEL,
                        'worktree': str(W), 'baseline_commit': accepted['preserved_source_commit'],
                        'root_before_source_sha256': {p: sha(R / p) for p in before if (R / p).is_file()},
                        'actor_reads': READS, 'actor_writes': [OUTPUT], 'protected_baseline_sha256': sha(protected_path),
                        'runtime_budget': {'observed_agent_timeout_seconds': os.environ.get('HERMES_AGENT_TIMEOUT'),
                                           'actor_print_timeout_seconds': 240, 'parent_timeout_seconds': 270},
                        'accepted': False, 'root_integrated': False})
    print(json.dumps({'prepared': str(RUN), 'worktree': str(W), 'immutable_files': len(before)}, ensure_ascii=False))

def actor():
    f = json.loads((RUN / 'frozen.json').read_text(encoding='utf-8'))
    assert not (RUN / 'started.json').exists()
    prompt = (RUN / 'prompt.md').read_text(encoding='utf-8')
    env = {k: v for k, v in os.environ.items() if not re.search(r'token|password|secret|credential|api.?key|authorization|private.?key', k, re.I)}
    scratch = Path('C:/Users/HODI/AppData/Local/hermes/cache/scratch') / PREFIX
    scratch.mkdir(parents=True, exist_ok=True)
    env.update(TMP=str(scratch), TEMP=str(scratch), TMPDIR=str(scratch))
    argv = ['E:/antigravity-cli/agy.exe', '--model', MODEL, '--sandbox', '--mode', 'accept-edits',
            '--output-format', 'stream-json', '--print-timeout', '240s', '--print=' + prompt]
    p = subprocess.Popen(argv, cwd=W, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    save('started.json', {'pid': p.pid, 'supervisor_pid': os.getpid(), 'worktree': str(W), 'model': MODEL,
                         'stage': PREFIX, 'role': 'qgentryguard', 'started_at': now()})
    print('ACTOR_PID=' + str(p.pid), flush=True)
    partial = False
    try:
        out, err = p.communicate(timeout=270)
    except subprocess.TimeoutExpired:
        partial = True
        subprocess.run(['taskkill.exe', '/PID', str(p.pid), '/T', '/F'], capture_output=True, timeout=20)
        out, err = p.communicate(timeout=20)
    text = out.decode('utf-8', 'replace')
    stderr = err.decode('utf-8', 'replace')
    (RUN / 'stdout.jsonl').write_text(text, encoding='utf-8')
    (RUN / 'stderr.log').write_text(stderr, encoding='utf-8')
    partial |= any(x in (text + stderr).lower() for x in ['print timeout', 'returning partial output', 'the stream was interrupted'])
    after = snapshot(W)
    save('after.json', after)
    before = json.loads((RUN / 'before.json').read_text(encoding='utf-8'))
    changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
    records = []
    for line in text.splitlines():
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    initial = next((x.get('init', {}) for x in records if x.get('event') == 'init'), {})
    final = next((x.get('result', x) for x in reversed(records) if x.get('event', x.get('type')) == 'result'), {})
    violations, tools, checks = [], [], []
    allowed_tools = {'read_file', 'view_file', 'write_file', 'write_to_file', 'edit_file', 'replace_file_content', 'multi_replace_file_content', 'finish'}
    writes = allowed_tools - {'read_file', 'view_file', 'finish'}
    for record in records:
        step = record.get('step_update', {})
        if step.get('step_type') != 'tool' or step.get('state') != 'ACTIVE':
            continue
        info = step.get('tool_info', {})
        name = step.get('tool_name', info.get('name', ''))
        tools.append(name)
        if name not in allowed_tools:
            violations.append({'forbidden_tool': name})
        for key, value in info.get('parameters', {}).items():
            if key.lower() not in {'path', 'absolutepath', 'targetfile', 'file_path', 'directorypath', 'searchdirectory'} or not isinstance(value, str):
                continue
            path = Path(value)
            relative = path.resolve().relative_to(W.resolve()).as_posix() if path.is_absolute() and path.resolve().is_relative_to(W.resolve()) else None
            checks.append(relative)
            if relative not in ([OUTPUT] if name in writes else READS + [OUTPUT]):
                violations.append({'path_outside_manifest': value, 'tool': name})
    if initial.get('model') != MODEL or Path(initial.get('cwd', '')).resolve() != W.resolve():
        violations.append({'invalid_init': initial})
    if changed != [OUTPUT] or not tools or not checks:
        violations.append({'changed_paths_or_empty_tools': changed})
    assert all(sha(R / path) == h for path, h in f['root_before_source_sha256'].items())
    okay = p.returncode == 0 and not partial and final.get('status') == 'SUCCESS' and not violations
    result = {'finished_at': now(), 'exit_code': p.returncode, 'partial': partial, 'cli_status': final.get('status'),
              'model': MODEL, 'inherited_permission_mode': initial.get('permission_mode'),
              'os_enforced_file_isolation_claimed': False, 'changed_paths': changed,
              'source_sha256': {path: after.get(path) for path in changed}, 'tools': tools,
              'path_checks': len(checks), 'violations': violations, 'audit_passed': okay,
              'root_integrated': False, 'accepted': False, 'status': 'AUDITED_STATIC_QA_PENDING' if okay else 'BLOCKED_PRESERVED'}
    save('result.json', result)
    print(json.dumps(result, ensure_ascii=False), flush=True)
    sys.exit(0 if okay else 1)

if __name__ == '__main__':
    {'prepare': prepare, 'actor': actor}[sys.argv[1]]()
