"""검증된 GUI 상태모델 소스를 전용 branch에만 보존한다. 통합·수용은 하지 않는다."""
import datetime
import hashlib
import json
import pathlib
import subprocess

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qgguistate'
load = lambda p: json.loads((R / p).read_text(encoding='utf-8'))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
p = load('artifacts/qg3a-gui-state-prepared.json')
v = load('artifacts/qg3a-gui-state-parent-repair.json')
assert all(sha(W / path) == h for path, h in v['source_sha256'].items())
assert all(sha(R / path) == h for path, h in p['root_before_sha256'].items())
assert all(sha(W / path) == h for path, h in p['immutable_source_sha256'].items())


def git(*args):
    result = subprocess.run(['git', '-C', str(W), *args], capture_output=True,
                            text=True, encoding='utf-8', errors='replace', timeout=60)
    assert result.returncode == 0, result.stderr
    return result.stdout.rstrip('\r\n')


assert git('branch', '--show-current') == 'ai-pro/qgguistate'
assert not git('diff', '--cached', '--name-only')
status = git('status', '--porcelain', '-z')
paths = sorted(row[3:] for row in status.split('\0') if row)
assert paths == sorted(p['actor_writes']), paths
for path in p['actor_writes']:
    data = (W / path).read_bytes()
    text = data.decode('utf-8')
    assert data.endswith(b'\n') and all(line == line.rstrip() for line in text.splitlines())
git('add', '--', *p['actor_writes'])
assert sorted(git('diff', '--cached', '--name-only').splitlines()) == sorted(p['actor_writes'])
git('diff', '--cached', '--check')
git('-c', 'core.autocrlf=false', 'commit', '-m', 'feat: add pure GUI input and run lifecycle state model')
commit = git('rev-parse', 'HEAD')
assert not git('status', '--porcelain')
assert all(sha(W / path) == h for path, h in v['source_sha256'].items())
state = {'recorded_at': datetime.datetime.now().astimezone().isoformat(),
         'status': 'LOCAL_SOURCE_PRESERVED_FINAL_QA_PENDING', 'preserved_commit': commit,
         'worktree': str(W), 'worktree_clean': True, 'branch': 'ai-pro/qgguistate',
         'source_sha256': v['source_sha256'], 'focused_counts': v['execution']['focused']['counts'],
         'workspace_counts': v['execution']['workspace']['counts'],
         'final_review': 'deleg_a604a8b4', 'final_review_received': False,
         'root_integrated': False, 'accepted': False, 'remote_push_or_deploy': False,
         'full_qg2_accepted': False, 'full_qg3_accepted': False, 'product_accepted': False}
out = R / 'artifacts/qg3a-gui-state-preservation.json'
assert not out.exists()
out.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
progress = load('artifacts/quick-check-progress.json')
progress['recorded_at'] = state['recorded_at']
progress['qg3_gui_state'].update(state)
progress['qg3_gui_state'].update(source_compiled=True, new_gui_tests_all_passed=True,
    parent_repair='artifacts/qg3a-gui-state-parent-repair.json', strict_clippy_exit=0, fmt_exit=0)
(R / 'artifacts/quick-check-progress.json').write_text(json.dumps(progress, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
summary = f'''
## 2026-10-26 GUI 상태모델 보정·W 회귀 통과 / 최종 독립 QA 대기
- 독립 원본 QA deleg_07610d09의 생산계약 확정위반0·신규시험6지적을 대조하여 부모가 시험만 교정·보강했다. 080은Core정책대로port80·원문보존 positive추가, MAX/MAX+1동일초기상태,합산100/101·목록간중복·혼합오류전체불변,실패ID미소비/이전report·Busy/stale/clone격리·전체raw/한도/누락/호출수·유효옵션경계를 검증했다. 원본15PASS1FAIL은그대로보존했다.
- 동일최종SHA의W focused{state['focused_counts']['passed']}PASS/0FAIL, workspace{state['workspace_counts']['passed']}PASS/0FAIL/{state['workspace_counts']['ignored']}ignored, strictClippy/fmt exit0. focused는workspace에포함한다. 부모생산수정은actor원문의정확한rustfmt출력과byte동일함을별도copy로증명했다. lib한줄노출·기존57입력불변·Core/resolver/Inspector/기존CLI/manifest/lock신규변경0.
- 전용W clean/로컬보존commit {commit}. 최종 독립 QA deleg_a604a8b4 두검토 진행중·요청뒤source변경0. 아직root통합/수용0·root기존454PASS/31ignored는역사근거다. 이번native실행0·이전native31을재실행수치로쓰지않는다.
- GUI내부상태모델뿐이며Win32화면/실제runner/취소OS회수·전체QG2/전체QG3/OS지원/배포완료아님. 다음은최종QA결과대조→source3선택통합→root전체회귀/Clippy/fmt→제한수용이다.
'''
for name, header in [('PROGRESS.md', '# NPI 진행 기록'), ('RESUME.md', '# NPI 개발 재개 및 승인 경계')]:
    path = R / name
    text = path.read_text(encoding='utf-8')
    assert 'GUI 상태모델 보정·W 회귀 통과 / 최종 독립 QA 대기' not in text
    path.write_text(text.replace(header + '\n', header + '\n' + summary, 1), encoding='utf-8', newline='\n')
print(json.dumps(state, ensure_ascii=False))
