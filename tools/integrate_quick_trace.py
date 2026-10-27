"""독립 재검토가 끝난 Trace 두 파일과 기존 Win32 의존 edge만 선택 통합한다."""
import datetime
import hashlib
import json
import pathlib
import shutil
import subprocess
import tomllib

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qgtrace'
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
proof = load('artifacts/qg2c-trace-final-repaired-execution.json')
dns = load('artifacts/qg2c-dns-acceptance.json')
for relative, expected in dns['source_sha256'].items():
    assert sha(R / relative) == expected, relative
protected = load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(sha(R / relative) == expected for relative, expected in protected.items())
for relative, expected in proof['source_sha256'].items():
    assert sha(W / relative) == expected and not (R / relative).exists(), relative
for name in ['qg2c-trace-final-all-targets', 'qg2c-trace-final-boundaries', 'qg2c-trace-final-native',
             'qg2c-trace-final-recheck-clippy', 'qg2c-trace-final-recheck-whitespace']:
    command = load('artifacts/commands/' + name + '.json')
    assert command['exit_code'] == 0 and not command['partial'], name
assert load('artifacts/qg2tracefinalfix-actor-policy-audit.json')['all_actor_policy_checks_passed']
for name in ['qg2c-trace-integrated-workspace', 'qg2c-trace-integrated-native',
             'qg2c-trace-integrated-clippy', 'qg2c-trace-integrated-fmt', 'qg2c-trace-integrated-boundaries']:
    assert not (R / 'artifacts/commands' / (name + '.json')).exists(), name
manifest = R / 'crates/network-core/Cargo.toml'
lib = R / 'crates/network-core/src/lib.rs'
lock = R / 'Cargo.lock'
before_paths = [manifest, lib, lock]
before = {path.relative_to(R).as_posix(): sha(path) for path in before_paths}
old_manifest = tomllib.loads(manifest.read_text(encoding='utf-8'))
trace_manifest = tomllib.loads((W / 'crates/network-core/Cargo.toml').read_text(encoding='utf-8'))
windows = trace_manifest.pop('target')
expected = dict(old_manifest)
expected['dependencies'] = {key: value for key, value in old_manifest['dependencies'].items() if key != 'network-resolver'}
assert trace_manifest == expected, '기존 의존성 변경을 수용하지 않음'
assert windows == {'cfg(windows)': {'dependencies': {'windows-sys': {'version': '=0.61.2', 'features': [
    'Win32_Foundation', 'Win32_Security', 'Win32_System_JobObjects', 'Win32_System_Threading',
    'Win32_System_Pipes', 'Win32_System_SystemInformation']}}}}
old_lock = tomllib.loads(lock.read_text(encoding='utf-8'))
old_packages = {(item['name'], item['version'], item.get('source')): item for item in old_lock['package']}
now = datetime.datetime.now().astimezone().isoformat()
record = {'recorded_at': now, 'state': 'PREPARING', 'before_sha256': before,
          'source_proof': 'artifacts/qg2c-trace-final-repaired-execution.json',
          'independent_review': 'deleg_7622500b', 'findings': [],
          'resolved_final_findings': ['TRACE-P1-NEGATIVE-TTL', 'P2-terminal-drain-error-not-failclosed',
                                      'P2-job-assignment-failure-skips-drain'],
          'review_limitations': '독립 정적검토이며 실제 Win32 오류/Job 실패 주입을 실행한 증거는 아님',
          'accepted': False, 'full_qg2_accepted': False}
output = R / 'artifacts/qg2c-trace-integration.json'
assert not output.exists()
output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
for relative in proof['source_sha256']:
    (R / relative).parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(W / relative, R / relative)
text = manifest.read_text(encoding='utf-8')
text += "\n[target.'cfg(windows)'.dependencies]\nwindows-sys = { version = \"=0.61.2\", features = [\"Win32_Foundation\", \"Win32_Security\", \"Win32_System_JobObjects\", \"Win32_System_Threading\", \"Win32_System_Pipes\", \"Win32_System_SystemInformation\"] }\n"
manifest.write_text(text, encoding='utf-8', newline='\n')
assert 'pub mod traceroute;' not in lib.read_text(encoding='utf-8')
lib.write_text(lib.read_text(encoding='utf-8') + '\n// 단독 ICMP 경로 측정. 응답 없는 홉은 차단 증거가 아니다.\npub mod traceroute;\n', encoding='utf-8', newline='\n')
process = subprocess.run(['cargo', 'metadata', '--offline', '--filter-platform', 'x86_64-pc-windows-msvc',
                          '--format-version', '1'], cwd=R, capture_output=True, timeout=60)
assert process.returncode == 0, process.stderr.decode('utf-8', 'replace')
new_packages = {(item['name'], item['version'], item.get('source')): item
                for item in tomllib.loads(lock.read_text(encoding='utf-8'))['package']}
assert old_packages.keys() == new_packages.keys(), '새 외부 package/version 추가 금지'
for key, previous in old_packages.items():
    current = dict(new_packages[key])
    if key[0] == 'network-core':
        assert 'windows-sys' in current['dependencies']
        current['dependencies'] = [item for item in current['dependencies'] if item != 'windows-sys']
    assert current == previous, key
for relative, expected in proof['source_sha256'].items():
    assert sha(R / relative) == expected
assert all(sha(R / relative) == expected for relative, expected in protected.items())
record.update(state='INTEGRATED_FOR_ROOT_REGRESSION_NOT_ACCEPTED',
              source_sha256={relative: sha(R / relative) for relative in [*proof['source_sha256'], *before]},
              inspector_changed=0, dependency_change='이미 잠긴 windows-sys 0.61.2의 Win32 feature/직접 edge만 추가, package/version 변경0')
output.write_text(json.dumps(record, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
print(json.dumps({'state': record['state'], 'source_and_test_files': 2,
                  'inspector_unchanged': len(protected), 'external_versions_changed': 0}, ensure_ascii=False))
