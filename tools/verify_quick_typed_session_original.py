"""QG3E 원본을 보존하고 부모가 cfg(test) 등록 후 컴파일만 수행한다."""
import datetime, hashlib, json, pathlib, shutil, subprocess, sys
R = pathlib.Path(__file__).resolve().parents[1]
def load(n): return json.loads((R/n).read_text(encoding='utf-8'))
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
p = load('artifacts/qg3e-session-bridge-prepared.json')
a = load('artifacts/qg3e-session-bridge-pipeline.json')
W = pathlib.Path(p['worktree'])
assert a['status'] == 'AUDITED_TYPED_SESSION_SOURCE_NOT_COMPILED_NOT_EXECUTED'
assert all(sha(W/n) == h for n,h in {**p['immutable_sha256'], **p['reference_sha256']}.items())
assert all(sha(W/n) == h for n,h in a['source_sha256'].items())
assert all(sha(R/n) == h for n,h in p['root_before_sha256'].items())
saved = R/'.harness/evidence/qg3e-session-actor-original'
saved.mkdir(parents=True, exist_ok=False)
for n in p['actor_writes']: shutil.copyfile(W/n, saved/pathlib.Path(n).name)
lib = W/'apps/network-quick-check/src/lib.rs'
shutil.copyfile(lib, saved/'lib-before-registration.rs')
text = lib.read_text(encoding='utf-8')
anchor = 'pub mod gui_result_render;\n'
assert text.count(anchor) == 1
lib.write_text(text.replace(anchor, anchor+'#[cfg(test)]\nmod gui_run_session;\n', 1), encoding='utf-8', newline='\n')
name = 'qg3e-session-original-compile'
cmd = [sys.executable, 'tools/run_command_evidence.py', '--cwd', str(W), '--name', name, '--timeout', '180', '--', 'cargo', 'test', '--offline', '--locked', '--target-dir', str(R/'.harness/targets/qg3e-session-shared'), '-p', 'network-quick-check', '--lib', '--no-run']
r = subprocess.run(cmd, cwd=R, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=215)
c = load('artifacts/commands/'+name+'.json')
assert r.returncode == c['exit_code']
assert all(sha(W/n) == h for n,h in a['source_sha256'].items())
record = dict(recorded_at=datetime.datetime.now().astimezone().isoformat(), worktree=str(W), source_sha256=a['source_sha256'], evidence_dir=str(saved), compile=c, tests_executed=False, native_executed=False, root_integrated=False, accepted=False, product_accepted=False)
out = R/'artifacts/qg3e-session-original-compile.json'
assert not out.exists()
out.write_text(json.dumps(record, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
print(pathlib.Path(c['log']).read_text(encoding='utf-8'))
print(json.dumps(record, ensure_ascii=False))
