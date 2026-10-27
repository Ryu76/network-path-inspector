"""QG3B Win32 입력·계획 화면의 격리 입력/정확한 바인딩/부모 의존성을 준비한다."""
import datetime
import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tomllib

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qgguiinputs'
STAGE, ROLE = 'qg3inputs', 'qgguiinputs'
APP = 'apps/network-quick-check/'
WRITES = [APP + 'src/' + name for name in ['lib.rs', 'gui_entry.rs', 'gui_presenter.rs',
          'gui_presenter_tests.rs', 'native_gui.rs', 'native_gui_tests.rs']]
META = [APP + 'Cargo.toml', 'Cargo.lock']
OUT = R / 'artifacts/qg3b-gui-inputs-prepared.json'
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
load = lambda p: json.loads((R / p).read_text(encoding='utf-8'))


def git(*args):
    result = subprocess.run(['git', *args], capture_output=True, text=True,
                            encoding='utf-8', errors='replace', timeout=60)
    assert result.returncode == 0, result.stderr
    return result.stdout.rstrip('\r\n')


assert not OUT.exists()
RESUME = sys.argv[1:] == ['--resume-parent-lock-only']
assert not sys.argv[1:] or RESUME
assert W.exists() == RESUME
assert not (R / '.harness/runs' / (STAGE + '-' + ROLE)).exists()
assert not (R / '.harness/prompts' / (STAGE + '-' + ROLE + '.md')).exists()
assert all(not (R / path).exists() for path in WRITES[1:])
a = load('artifacts/qg3a-gui-state-acceptance.json')
assert a['accepted'] and a['root_integrated'] and not a['full_qg3_accepted']
assert all(sha(R / path) == h for path, h in a['source_sha256'].items())
assert not git('-C', a['worktree'], 'status', '--porcelain')
assert git('-C', a['worktree'], 'rev-parse', 'HEAD') == a['preserved_source_commit']
processes = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
    '$p=Get-CimInstance Win32_Process | Where-Object { $_.Name -ieq "agy.exe" -and $_.CommandLine -match "--print=" }; @($p | Select-Object ProcessId,Name) | ConvertTo-Json -Compress'],
    capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=30)
assert processes.returncode == 0 and not json.loads(processes.stdout or '[]'), 'active print actor; preserve and stop'
old = load('artifacts/qg3a-gui-state-prepared.json')
paths = set(old['root_before_sha256']) | set(a['source_sha256'])
root_before = {path: sha(R / path) for path in sorted(paths)}
protected = load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
engine = 'crates/npi-probes/src/engine.rs'
assert all(sha(R / path) == value for path, value in protected.items() if path != engine)
engine_original = R / '.harness/baselines/qg2g-tcp-replay-root/engine.rs'
assert sha(engine_original) == protected[engine]
assert (R / engine).read_bytes() == engine_original.read_bytes().replace(b'fn apply_tcp_result(', b'pub fn apply_tcp_result(', 1)
if RESUME:
    assert git('-C', str(W), 'branch', '--show-current') == 'ai-pro/qgguiinputs'
    assert git('-C', str(W), 'rev-parse', 'HEAD') == a['preserved_source_commit']
    assert all(sha(W / path) == h for path, h in root_before.items() if path not in META)
    assert sorted(line[3:] for line in git('-C', str(W), 'status', '--porcelain').splitlines()) == sorted(META)
else:
    git('-C', str(R), 'worktree', 'add', '-b', 'ai-pro/qgguiinputs', str(W), a['preserved_source_commit'])
    assert not git('-C', str(W), 'status', '--porcelain')
    for path in sorted(paths):
        (W / path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(R / path, W / path)
        assert sha(W / path) == root_before[path]
    checkout_status = git('-C', str(W), 'status', '--porcelain')
    if checkout_status:
        dirty = [line[3:] for line in checkout_status.splitlines()]
        assert sorted(dirty) == ['AGENTS.md', 'contracts/quick-check-interface-v0.1.json'], dirty
        for path in dirty:
            head = subprocess.check_output(['git', '-C', str(W), 'show', 'HEAD:' + path])
            assert head.replace(b'\r\n', b'\n') == (R / path).read_bytes().replace(b'\r\n', b'\n')
        git('-C', str(W), 'add', '--', *dirty)
        assert not git('-C', str(W), 'status', '--porcelain'), 'input normalization must be index no-op'
features = ['Win32_Foundation', 'Win32_Graphics_Gdi', 'Win32_System_LibraryLoader',
            'Win32_UI_WindowsAndMessaging', 'Win32_UI_Controls', 'Win32_UI_Input_KeyboardAndMouse']
manifest = W / META[0]
text = (R / META[0]).read_text(encoding='utf-8')
assert '[target.' not in text and 'windows-sys' not in text
text += '\n# 네이티브 입력 화면만 사용하는 고정 Win32 바인딩. 부모가 준비한다.\n'
text += '[target.\'cfg(windows)\'.dependencies]\nwindows-sys = { version = "=0.61.2", features = ' + json.dumps(features) + ' }\n'
if RESUME:
    assert manifest.read_text(encoding='utf-8') == text
else:
    manifest.write_text(text, encoding='utf-8', newline='\n')
for name, argv in ([] if RESUME else [('qg3b-gui-parent-lock', ['cargo', 'generate-lockfile', '--offline']),
        ('qg3b-gui-parent-windows-metadata', ['cargo', 'metadata', '--offline', '--locked', '--filter-platform', 'x86_64-pc-windows-msvc', '--format-version', '1']),
        ('qg3b-gui-parent-metadata-check', ['cargo', 'check', '--offline', '--locked', '--target-dir', str(R / '.harness/targets/qg3b-gui-inputs-shared'), '-p', 'network-quick-check'])]):
    result = subprocess.run([sys.executable, 'tools/run_command_evidence.py', '--cwd', str(W),
        '--name', name, '--timeout', '180', '--', *argv], cwd=R, timeout=210)
    assert result.returncode == 0, name
oldlock = tomllib.loads((R / 'Cargo.lock').read_text(encoding='utf-8'))
newlock = tomllib.loads((W / 'Cargo.lock').read_text(encoding='utf-8'))
identity = lambda p: (p['name'], p['version'], p.get('source'), p.get('checksum'))
if RESUME:
    removed = {identity(p) for p in oldlock['package']} - {identity(p) for p in newlock['package']}
    added = {identity(p) for p in newlock['package']} - {identity(p) for p in oldlock['package']}
    assert len(removed) == len(added) == 1 and next(iter(removed))[:2] == ('libc', '0.2.189') and next(iter(added))[:2] == ('libc', '0.2.191')
    retained = R / '.harness/evidence/qg3b-parent-initial-libc-lock'
    retained.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(W / 'Cargo.lock', retained / 'Cargo.lock')
    failure = {'status': 'PARENT_LOCK_IDENTITY_GUARD_BLOCKED_BEFORE_ACTOR',
        'removed': [list(x) for x in removed], 'added': [list(x) for x in added],
        'unwanted_lock_sha256': sha(retained / 'Cargo.lock'),
        'reason': 'offline generate-lockfile selected cached newer transitive libc; preserve original package identity',
        'actor_started': False, 'root_changed': False, 'product_test_failure': False}
    (R / 'artifacts/qg3b-gui-parent-lock-preflight-failure.json').write_text(json.dumps(failure, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    for name, argv in [('qg3b-gui-parent-lock-pin-libc', ['cargo', 'update', '--offline', '-p', 'libc', '--precise', '0.2.189']),
            ('qg3b-gui-parent-windows-metadata-v2', ['cargo', 'metadata', '--offline', '--locked', '--filter-platform', 'x86_64-pc-windows-msvc', '--format-version', '1']),
            ('qg3b-gui-parent-metadata-check-v2', ['cargo', 'check', '--offline', '--locked', '--target-dir', str(R / '.harness/targets/qg3b-gui-inputs-shared'), '-p', 'network-quick-check'])]:
        result = subprocess.run([sys.executable, 'tools/run_command_evidence.py', '--cwd', str(W),
            '--name', name, '--timeout', '180', '--', *argv], cwd=R, timeout=210)
        assert result.returncode == 0, name
    newlock = tomllib.loads((W / 'Cargo.lock').read_text(encoding='utf-8'))
assert {identity(p) for p in oldlock['package']} == {identity(p) for p in newlock['package']}
for package in oldlock['package']:
    current = next(x for x in newlock['package'] if identity(x) == identity(package))
    if current != package:
        assert package['name'] == 'network-quick-check'
        assert set(current.get('dependencies', [])) - set(package.get('dependencies', [])) == {'windows-sys'}
        assert set(package.get('dependencies', [])) <= set(current.get('dependencies', []))
assert all(sha(R / path) == h for path, h in root_before.items())
assert all(sha(W / path) == h for path, h in root_before.items() if path not in META)
git('-C', str(W), 'add', '--', *META)
assert set(git('-C', str(W), 'diff', '--cached', '--name-only').splitlines()) == set(META)
git('-C', str(W), '-c', 'core.autocrlf=false', 'commit', '-m', 'chore: pin native GUI input Windows binding features')
assert not git('-C', str(W), 'status', '--porcelain')
ref = W / '.harness/inputs/qg3b-win32'
ref.mkdir(parents=True)
vendor = pathlib.Path('C:/Users/HODI/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/windows-sys-0.61.2')
vendor_files = ['Cargo.toml', 'src/lib.rs', 'src/core/mod.rs',
    'src/Windows/Win32/Foundation/mod.rs', 'src/Windows/Win32/System/LibraryLoader/mod.rs',
    'src/Windows/Win32/UI/WindowsAndMessaging/mod.rs', 'src/Windows/Win32/UI/Controls/mod.rs',
    'src/Windows/Win32/UI/Input/KeyboardAndMouse/mod.rs', 'src/Windows/Win32/Graphics/Gdi/mod.rs']
api_names = {'RegisterClassW', 'WNDCLASSW', 'CREATESTRUCTW', 'MINMAXINFO', 'MSG', 'WNDPROC',
    'CreateWindowExW', 'DefWindowProcW', 'GetMessageW', 'TranslateMessage', 'DispatchMessageW',
    'DestroyWindow', 'PostQuitMessage', 'PostMessageW', 'ShowWindow', 'UpdateWindow',
    'GetWindowLongPtrW', 'SetWindowLongPtrW', 'SendMessageW', 'GetWindowTextLengthW',
    'GetWindowTextW', 'SetWindowTextW', 'EnableWindow', 'MoveWindow', 'GetClientRect',
    'IsDialogMessageW', 'GetModuleHandleW', 'GetStockObject', 'LoadCursorW', 'SetLastError', 'GetLastError',
    'EM_SETLIMITTEXT', 'EN_MAXTEXT', 'BM_GETCHECK', 'BM_SETCHECK', 'BST_CHECKED',
    'LB_ADDSTRING', 'LB_RESETCONTENT', 'LB_GETCURSEL', 'LB_SETCURSEL', 'LB_GETCOUNT',
    'LBS_NOTIFY', 'ES_MULTILINE', 'ES_AUTOVSCROLL', 'ES_READONLY', 'BS_AUTOCHECKBOX',
    'WM_NCCREATE', 'WM_NCDESTROY', 'WM_CREATE', 'WM_DESTROY', 'WM_COMMAND', 'WM_SIZE', 'WM_CLOSE',
    'WM_GETMINMAXINFO', 'WM_SETFONT', 'EN_CHANGE', 'BN_CLICKED', 'LBN_SELCHANGE',
    'GWLP_USERDATA', 'DEFAULT_GUI_FONT', 'HWND', 'HINSTANCE', 'HMENU', 'WPARAM', 'LPARAM', 'LRESULT'}
index = ['# 정확한 windows-sys 0.61.2 로컬 원문 위치', 'EnableWindow/SetFocus는 UI/Input/KeyboardAndMouse에 있다. EM_SETLIMITTEXT는 UI/Controls에 있다. WNDCLASSW/RegisterClassW에는 Gdi feature가 필요하다.']
for path in vendor_files:
    source, dest = vendor / path, ref / 'windows-sys-0.61.2' / path
    assert source.is_file()
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, dest)
    lines = source.read_text(encoding='utf-8').splitlines()
    for number, line in enumerate(lines, 1):
        if any(re.search(r'\b' + re.escape(name) + r'\b', line) for name in api_names) and ('fn ' in line or line.startswith(('pub const', 'pub struct', 'pub type'))):
            index.append(f'{dest.as_posix()}:{number}: {line}')
(ref / 'api-index.md').write_text('\n'.join(index) + '\n', encoding='utf-8')
original_lib = (R / APP / 'src/lib.rs').read_text(encoding='utf-8')
expected = original_lib.replace('pub mod gui_state;\n', 'mod gui_entry;\nmod gui_presenter;\n#[cfg(windows)]\nmod native_gui;\npub mod gui_state;\n', 1)
expected = expected.replace('    entry_with_worker(\n', '    if let Some(code) = gui_entry::try_entry(args, stderr) {\n        return code;\n    }\n    entry_with_worker(\n', 1)
expected = expected.replace('/// - 해당 selector가 아닌 경우 기존의 레거시 worker/idle/help 진입 로직인 `entry_with_worker`로\n', '/// - 입력·계획 GUI selector는 별도의 GUI 분기로만 실행하며 실제 진단을 시작하지 않습니다.\n/// - 그 밖의 경우 기존의 레거시 worker/idle/help 진입 로직인 `entry_with_worker`로\n', 1)
assert expected != original_lib
(ref / 'expected-lib.rs').write_text(expected, encoding='utf-8', newline='\n')
record = {'recorded_at': datetime.datetime.now().astimezone().isoformat(),
    'status': 'PREPARED_NATIVE_GUI_INPUTS_PARENT_METADATA_ONLY', 'stage': STAGE, 'role': ROLE,
    'worktree': str(W), 'branch': 'ai-pro/qgguiinputs', 'baseline_commit': git('-C', str(W), 'rev-parse', 'HEAD'),
    'model': 'gemini-3.8-flash-high', 'actor_writes': WRITES, 'parent_metadata_changes': {path: sha(W / path) for path in META},
    'root_before_sha256': root_before,
    'immutable_source_sha256': {path: sha(W / path) for path in paths if path not in WRITES},
    'reference_sha256': {path.relative_to(W).as_posix(): sha(path) for path in ref.rglob('*') if path.is_file()},
    'reference_directory': str(ref), 'windows_sys_features': features,
    'registry_package_identities_checksums_and_nonapp_records_unchanged': True,
    'parent_dependency_checks_are_not_new_gui_execution': True,
    'read_only_design_review': 'deleg_90377070', 'design_representation': 'parent_selected_scope_normalized_from_review',
    'root_product_source_changed': False, 'actor_started': False, 'root_integrated': False, 'accepted': False,
    'full_qg2_accepted': False, 'full_qg3_accepted': False, 'product_accepted': False}
OUT.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'status': record['status'], 'baseline_commit': record['baseline_commit'],
    'source_inputs': len(root_before), 'binding_reference_files': len(record['reference_sha256']),
    'parent_metadata_changes': META}, ensure_ascii=False))
