"""Compile one finished module in a clearly isolated QA crate; no missing-module stubs."""
import argparse,hashlib,json,pathlib,shutil,subprocess,sys
R=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('module',choices=['tcp','icmp','host','dns']);p.add_argument('--stage',default='g2a');a=p.parse_args();role='g2'+a.module
result=json.loads((R/'.harness/runs'/(a.stage+'-'+role)/'result.json').read_text(encoding='utf-8'));assert result['exit_code']==0 and not result['partial'] and not result['scope_violations']
audit=json.loads((R/'artifacts'/(a.stage+'-actor-policy-audit.json')).read_text(encoding='utf-8'));assert next(x for x in audit['actors']if x['role']==role)['passed']
q=R/'.harness/qa'/role;q.mkdir(parents=True,exist_ok=False);(q/'src').mkdir();(q/'tests').mkdir()
for section in ['src','tests']:
 src=R/'.worktrees'/role/'crates/npi-probes'/section/(a.module+'.rs');shutil.copyfile(src,q/section/src.name)
(q/'src/lib.rs').write_text('pub mod '+a.module+';\n',encoding='utf-8',newline='\n')
manifest='''[package]
name="npi-probes"
version="0.1.0"
edition="2024"
[workspace]
[dependencies]
npi-core={path="E:/harnes/network-path-inspector/crates/npi-core"}
serde={version="=1.0.228",features=["derive"]}
serde_json="=1.0.149"
tokio={version="=1.52.3",features=["rt","net","time","macros","sync"]}
[target.'cfg(windows)'.dependencies]
windows-sys={version="=0.61.2",features=["Win32_Foundation","Win32_NetworkManagement_IpHelper","Win32_NetworkManagement_Ndis","Win32_Networking_WinSock","Win32_System_IO"]}
'''
(q/'Cargo.toml').write_text(manifest,encoding='utf-8',newline='\n')
cmd=[sys.executable,str(R/'tools/run_command_evidence.py'),'--cwd',str(q),'--name',a.stage+'-'+a.module+'-isolated-tests','--timeout','240','--','cargo','test','--offline','--all-targets'];code=subprocess.run(cmd).returncode
print(json.dumps({'module':a.module,'qa_crate':str(q),'exit_code':code,'source_sha256':hashlib.sha256((q/'src'/(a.module+'.rs')).read_bytes()).hexdigest(),'scope':'finished module only; not integrated G2 acceptance'}));sys.exit(code)
