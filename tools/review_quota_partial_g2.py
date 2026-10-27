"""Review a quota-interrupted, file-policy-clean diff in QA only; never mark actor successful."""
import datetime,hashlib,json,pathlib,shutil,subprocess,sys
R=pathlib.Path(__file__).resolve().parents[1];role='g2hostclean';stage='g2hostclean-fallback1';folder=R/'.harness/runs'/(stage+'-'+role)
meta=json.loads((folder/'result.json').read_text(encoding='utf-8'));assert meta['exit_code']!=0 and not meta['scope_violations'];audit=json.loads((R/'artifacts'/(stage+'-actor-policy-audit.json')).read_text(encoding='utf-8'));actor=next(x for x in audit['actors']if x['role']==role);assert not actor['violations']and actor['cli_status']=='ERROR';assert 'Individual quota reached'in(folder/'stderr.log').read_text(encoding='utf-8')
Q=R/'.harness/qa/g2-quota-partial';assert not Q.exists();shutil.copytree(R/'crates/npi-probes',Q)
rows=[]
for writer,component in [('g2hostclean','host'),('g2engine','engine')]:
 for section in ['src','tests']:
  relative='crates/npi-probes/'+section+'/'+component+'.rs';src=R/'.worktrees'/writer/relative;dst=Q/section/(component+'.rs');dst.read_text(encoding='utf-8');shutil.copyfile(src,dst);rows.append({'writer':writer,'path':relative,'sha256':hashlib.sha256(src.read_bytes()).hexdigest()})
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
windows-sys={version="=0.61.2",features=["Win32_Foundation","Win32_NetworkManagement_IpHelper","Win32_NetworkManagement_Ndis","Win32_Networking_WinSock","Win32_System_IO","Win32_System_Threading"]}
'''
(Q/'Cargo.toml').write_text(manifest,encoding='utf-8',newline='\n')
p=Q/'tests/independent_cancel.rs';s=p.read_text(encoding='utf-8');assert '../../../fixtures/g1/valid_profile_quick.json'in s;p.write_text(s.replace('../../../fixtures/g1/valid_profile_quick.json','E:/harnes/network-path-inspector/fixtures/g1/valid_profile_quick.json'),encoding='utf-8',newline='\n')
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'actor_exit_code':meta['exit_code'],'actor_success':False,'tool_policy_violations':actor['violations'],'selected_partial_files':rows,'qa_crate':str(Q),'product_integration':False,'g2_accepted':False,'cancel_test_fixture_path_adjusted_in_qa_only':True}
(R/'artifacts/g2-quota-partial-review.json').write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
cmd=[sys.executable,str(R/'tools/run_command_evidence.py'),'--cwd',str(Q),'--name','g2a-quota-partial-tests','--timeout','240','--','cargo','test','--offline','--all-targets'];raise SystemExit(subprocess.run(cmd).returncode)
