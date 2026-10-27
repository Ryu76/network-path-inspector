"""Prepare the next independent DNS module without touching active repair worktrees."""
import pathlib,subprocess,shutil
R=pathlib.Path(__file__).resolve().parents[1];w=R/'.worktrees/g2dns';assert not w.exists()
subprocess.run(['git','-C',str(R),'worktree','add','-b','ai-pro/g2dns',str(w),'HEAD'],check=True,capture_output=True)
for rel in ['Cargo.toml','Cargo.lock','docs/g2a-contract.md','docs/g2b-dns-contract.md']:
 dest=w/rel;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(R/rel,dest)
shutil.copytree(R/'crates/npi-probes',w/'crates/npi-probes',dirs_exist_ok=True)
rule="'g2dns':('crates/npi-probes/src/dns.rs','crates/npi-probes/tests/dns.rs'),"
for rel,anchor in [('tools/ai_pro_harness.py','allowed={'),('tools/audit_ai_pro_runs.py','RULES={')]:
 p=R/rel;s=p.read_text(encoding='utf-8');assert s.count(anchor)==1;p.write_text(s.replace(anchor,anchor+rule),encoding='utf-8',newline='\n')
prompt='''You are AI Pro. FILE TOOLS ONLY, no command, test, network, subprocess execution, git, agents, installation, credentials. Worktree E:/harnes/network-path-inspector/.worktrees/g2dns. Read exact existing AGENTS.md, docs/g2a-contract.md, docs/g2b-dns-contract.md, crates/npi-probes/src/lib.rs, Cargo.toml and crates/npi-probes/Cargo.toml. Implement ONLY dns.rs module and tests/dns.rs per G2-B DNS contract. API exact. No main/lib/engine/manifest changes; separate integration writer will wire helper mode later. No stub helper executable, no fake production output. Pure tests default no processes/network/DNS. Domain DNS is inside owned child ONLY; parent has kill/wait/reader reaping and deadline/cancel. Reader concurrent bounded16KiB, no deadlock on output limit. Korean comments and limitations. Return changed paths and any concrete remaining blocker, do not claim tests ran. New outputs ONLY crates/npi-probes/src/dns.rs and crates/npi-probes/tests/dns.rs. Note terminal hidden helper flag will be connected later; do not attempt it yourself.\n'''
(R/'.harness/prompts/g2dns-g2dns.md').write_text(prompt,encoding='utf-8',newline='\n');print('g2dns isolated worktree and exact two-file scope prepared; active repair roles unaffected')
