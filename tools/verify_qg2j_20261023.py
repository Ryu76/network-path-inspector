"""FILE ONLY 감사·독립 정적 QA 뒤 공개 진입점 순수 회귀를 실제 실행한다."""
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
PREFIX = 'qg2j-20261023-2028'
RUN = R / '.harness/runs' / PREFIX
W = R / '.worktrees/qgentryguard'
SOURCE = 'apps/network-quick-check/tests/public_entry_rejection.rs'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
now = lambda: datetime.datetime.now().astimezone().isoformat()
load = lambda name: json.loads((RUN / name).read_text(encoding='utf-8'))

def execute(phase):
    assert phase in {'worktree-recheck', 'root'}
    cwd = W if phase == 'worktree-recheck' else R
    result = load('result.json')
    review = load('static-qa-v2.json')
    assert result['audit_passed'] and review['safe_to_execute'] and not review['findings']
    assert review['source_sha256'] == sha(cwd / SOURCE)
    before = load('before.json')
    assert all(sha(W / p) == h for p, h in before.items())
    if phase == 'root':
        assert load('worktree-recheck-execution.json')['status'] == 'PASS'
        assert sha(R / SOURCE) == sha(W / SOURCE)
    out = RUN / (phase + '-execution.json')
    assert not out.exists()
    target = R / '.harness/targets' / (PREFIX + ('-worktree' if phase.startswith('worktree') else '-root'))
    scratch = Path('C:/Users/HODI/AppData/Local/hermes/cache/scratch') / (PREFIX + '-' + phase)
    scratch.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update(CARGO_TARGET_DIR=str(target), TMP=str(scratch), TEMP=str(scratch), TMPDIR=str(scratch))
    gates = [
        ('focused', ['cargo', 'test', '--offline', '--locked', '-p', 'network-quick-check', '--test', 'public_entry_rejection']),
        ('workspace', ['cargo', 'test', '--offline', '--locked', '--workspace', '--all-targets']),
        ('clippy', ['cargo', 'clippy', '--offline', '--locked', '--workspace', '--all-targets', '--', '-D', 'warnings']),
        ('fmt', ['cargo', 'fmt', '--all', '--check']),
        ('diff-check', ['git', 'diff', '--check']),
        ('new-file-whitespace', ['git', 'diff', '--no-index', '--check', '--', 'NUL', SOURCE]),
    ]
    state = {'started_at': now(), 'phase': phase, 'source_sha256': sha(cwd / SOURCE), 'status': 'RUNNING',
             'steps': [], 'native_executed': False, 'production_changes': 0, 'accepted': False}
    def save():
        tmp = out.with_suffix('.tmp')
        tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        tmp.replace(out)
    save()
    try:
        for label, argv in gates:
            stem = R / 'artifacts/commands' / (PREFIX + '-' + phase + '-' + label)
            assert not stem.with_suffix('.json').exists() and not stem.with_suffix('.log').exists()
            started, begin = now(), time.monotonic()
            print('STEP ' + phase + '-' + label, flush=True)
            child = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            partial = False
            try:
                stdout, stderr = child.communicate(timeout=210)
            except subprocess.TimeoutExpired:
                partial = True
                subprocess.run(['taskkill.exe', '/PID', str(child.pid), '/T', '/F'], capture_output=True, timeout=20)
                stdout, stderr = child.communicate(timeout=20)
            log = stdout.decode('utf-8', 'replace') + '\n' + stderr.decode('utf-8', 'replace')
            stem.with_suffix('.log').write_text(log, encoding='utf-8')
            meta = {'command': argv, 'cwd': str(cwd), 'started_at': started, 'pid': child.pid,
                    'exit_code': child.returncode, 'partial': partial, 'elapsed_seconds': round(time.monotonic()-begin, 3),
                    'log': str(stem.with_suffix('.log'))}
            counts = re.findall(r'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', log)
            if counts:
                meta['counts'] = {k: sum(int(x[i]) for x in counts) for i, k in enumerate(['passed', 'failed', 'ignored'])}
            stem.with_suffix('.json').write_text(json.dumps(meta, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
            state['steps'].append(meta)
            save()
            print(json.dumps(meta, ensure_ascii=False), flush=True)
            if label == 'new-file-whitespace':
                assert child.returncode in {0, 1} and not log.strip() and not partial
            else:
                assert child.returncode == 0 and not partial, label
            if label == 'focused':
                assert meta.get('counts') == {'passed': 8, 'failed': 0, 'ignored': 0}
            if label == 'workspace':
                assert meta.get('counts') == {'passed': 454, 'failed': 0, 'ignored': 31}
        raw = (cwd / SOURCE).read_bytes()
        text = raw.decode('utf-8')
        assert raw.endswith(b'\n') and not raw.startswith(b'\xef\xbb\xbf')
        assert all(line == line.rstrip() for line in text.splitlines())
        assert sha(cwd / SOURCE) == review['source_sha256']
        assert all(sha(W / p) == h for p, h in before.items())
        frozen = load('frozen.json')
        assert all(sha(R / p) == h for p, h in frozen['root_before_source_sha256'].items())
        assert sha(R / 'artifacts/qg0-inspector-baseline.json') == frozen['protected_baseline_sha256']
        state['status'] = 'PASS'
    except Exception as error:
        state.update(status='FAILED_PRESERVED', error=str(error))
    state['finished_at'] = now()
    save()
    print(json.dumps(state, ensure_ascii=False), flush=True)
    sys.exit(0 if state['status'] == 'PASS' else 1)

if __name__ == '__main__':
    execute(sys.argv[1])
