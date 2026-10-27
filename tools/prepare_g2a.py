"""Create isolated G2-A actor worktrees without altering prior actors."""
import datetime,json,pathlib,shutil,subprocess
R=pathlib.Path(__file__).resolve().parents[1]
def git(*args):
 p=subprocess.run(['git','-C',str(R),*args],capture_output=True,encoding='utf-8',errors='replace',check=True);return p.stdout.strip()
assert git('status','--porcelain') in ('', '?? tools/prepare_g2a.py'), 'Preserve unexpected dirty root before bootstrap'
assert git('rev-parse','HEAD').startswith('3dfe6ed')
git('switch','-c','integration/g2')
(R/'docs/g2a-contract.md').write_bytes((R/'.harness/g2-interface.md').read_bytes())
manifest=R/'Cargo.toml';text=manifest.read_text(encoding='utf-8');assert 'members = ["crates/npi-core"]' in text;manifest.write_text(text.replace('members = ["crates/npi-core"]','members = ["crates/npi-core", "crates/npi-probes"]'),encoding='utf-8',newline='\n')
p=R/'crates/npi-probes/src';p.mkdir(parents=True,exist_ok=False)
(p.parent/'Cargo.toml').write_text('''[package]
name = "npi-probes"
version.workspace = true
edition.workspace = true
publish = false

[dependencies]
npi-core = { path = "../npi-core" }
serde.workspace = true
serde_json.workspace = true
tokio = { version = "=1.52.3", features = ["rt", "net", "time", "macros", "sync"] }

[target.'cfg(windows)'.dependencies]
windows-sys = { version = "=0.61.2", features = ["Win32_Foundation", "Win32_NetworkManagement_IpHelper", "Win32_NetworkManagement_Ndis", "Win32_Networking_WinSock", "Win32_System_IO"] }
''',encoding='utf-8',newline='\n')
(p/'lib.rs').write_text('''//! G2-A 실제 단일 대상 측정. 기본 검증 대상은 루프백으로 한정한다.
pub mod tcp;
pub mod icmp;
pub mod host;
pub mod engine;
''',encoding='utf-8',newline='\n')
refs=R/'.harness/references/g2-bindings';refs.mkdir(parents=True,exist_ok=False)
src=next((pathlib.Path.home()/'.cargo/registry/src').glob('*/windows-sys-0.61.2/src/Windows/Win32'))
for rel in ['Foundation','NetworkManagement/IpHelper','NetworkManagement/Ndis','Networking/WinSock','System/IO']:
 shutil.copyfile(src/rel/'mod.rs',refs/(rel.replace('/','_')+'.rs'))
# Cache exact dependencies only; never run network probes at preparation.
p=subprocess.run(['cargo','generate-lockfile','--offline'],cwd=R,capture_output=True,encoding='utf-8',errors='replace');assert p.returncode==0,p.stdout+p.stderr
# Add scoped G2 roles to both execution and independent event audit policies.
rules='\'g2tcp\':(\'crates/npi-probes/src/tcp.rs\',\'crates/npi-probes/tests/tcp.rs\'),\'g2icmp\':(\'crates/npi-probes/src/icmp.rs\',\'crates/npi-probes/tests/icmp.rs\'),\'g2host\':(\'crates/npi-probes/src/host.rs\',\'crates/npi-probes/tests/host.rs\'),\'g2engine\':(\'crates/npi-probes/src/engine.rs\',\'crates/npi-probes/src/main.rs\',\'crates/npi-probes/tests/engine.rs\'),'
for rel,anchor in [('tools/ai_pro_harness.py','allowed={'),('tools/audit_ai_pro_runs.py','RULES={')]:
 f=R/rel;s=f.read_text(encoding='utf-8');assert s.count(anchor)==1;f.write_text(s.replace(anchor,anchor+rules),encoding='utf-8',newline='\n')
git('add','Cargo.toml','Cargo.lock','crates/npi-probes','docs/g2a-contract.md','tools/ai_pro_harness.py','tools/audit_ai_pro_runs.py')
git('diff','--cached','--check')
git('commit','-m','chore: prepare isolated G2-A measurement contracts and dependency baseline')
roles=['g2tcp','g2icmp','g2host','g2engine']
for role in roles:
 w=R/'.worktrees'/role;git('worktree','add','-b','ai-pro/'+role,str(w),'HEAD')
 prompt=f'''You are AI Pro Gemini 4 Argon High. Project root is {w}. FILE TOOLS ONLY. No command, test, terminal, network, installing, agents, git, or credentials. Read AGENTS.md then docs/g2a-contract.md. Implement ONLY your {role} section exactly, including tests. Read known exact existing inputs listed in contract, and bindings under E:/harnes/network-path-inspector/.harness/references/g2-bindings as necessary. Other modules are being created independently: never create or change them, lib.rs/Cargo.toml, G1 core, contracts, docs, or policy. At most one guessed absent path; enumerate instead. Keep API contract exact, safety/unknowns strict, no fabricated measurements. Ordinary tests no network; real loopback/native calls #[ignore] parent explicitly runs. Focus on compile-ready implementation within current bounded run. Final Korean short changed paths and caveats; do not claim tests ran. Scope: '''
 scopes={'g2tcp':'crates/npi-probes/src/tcp.rs, crates/npi-probes/tests/tcp.rs','g2icmp':'crates/npi-probes/src/icmp.rs, crates/npi-probes/tests/icmp.rs','g2host':'crates/npi-probes/src/host.rs, crates/npi-probes/tests/host.rs','g2engine':'crates/npi-probes/src/engine.rs, crates/npi-probes/src/main.rs, crates/npi-probes/tests/engine.rs'}
 (R/'.harness/prompts'/('g2a-'+role+'.md')).write_text(prompt+scopes[role]+'\n',encoding='utf-8',newline='\n')
record={'at':datetime.datetime.now().astimezone().isoformat(),'user_authorization':'계속 진행해 쉬지 말고','scope':'development and controlled local loopback/http/browser only; no operations changes','baseline':git('rev-parse','HEAD'),'roles':roles,'dependency_install_network':False,'g1_accepted_commit':'3dfe6ed'}
(R/'.harness/g2a-preparation.json').write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
print(json.dumps(record,ensure_ascii=False,indent=2))
