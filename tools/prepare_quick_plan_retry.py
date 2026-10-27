"""경로 감사 거부된 planner와 분리한 새 문서 writer 기준을 준비한다."""
import hashlib,json,pathlib,shutil,subprocess
R=pathlib.Path(__file__).resolve().parents[1];w=R/'.worktrees/qgplan2';assert not w.exists()
p=subprocess.run(['git','-C',str(R),'worktree','add','-b','ai-pro/qgplan2',str(w),'HEAD'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60);assert p.returncode==0,p.stderr
# 보호된 AGENTS.md는 체크아웃 그대로 유지하고 수정하지 않는다.
rel=pathlib.Path('docs/requirements/Network_Path_Inspector_Harness_PRD_v1.2.md');dst=w/rel;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes((R/rel).read_bytes())
refs=w/'.harness/references';refs.mkdir(parents=True,exist_ok=True)
contract=w/'contracts/quick-check-interface-v0.1.json';contract.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(R/'.harness/references/qg1-contract.json',contract)
for name in ['qg1-contract.json','qg0-primary-sources.json']:shutil.copyfile(R/'.harness/references'/name,refs/name)
for rel in ['Cargo.toml','crates/npi-core/Cargo.toml','crates/npi-probes/Cargo.toml']:
 dst=w/rel;dst.read_bytes();dst.write_bytes((R/rel).read_bytes())
subprocess.run(['git','-C',str(w),'add','contracts/quick-check-interface-v0.1.json','docs/requirements','Cargo.toml','crates/npi-core/Cargo.toml','crates/npi-probes/Cargo.toml'],check=True,capture_output=True,timeout=30)
subprocess.run(['git','-C',str(w),'-c','core.autocrlf=false','commit','-m','chore: prepare clean Quick Check planning retry'],check=True,capture_output=True,timeout=30)
status=subprocess.run(['git','-C',str(w),'status','--porcelain'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=20);assert not status.stdout,status.stdout
record={'role':'qgplan','stage':'qg01','accepted':False,'reason':'FILE ONLY read-outside-worktree audit failure; source files and logs preserved; allowlist not relaxed','replacement_worktree':str(w),'rejected_output_not_copied':True}
(R/'artifacts/qg01-planner-rejection.json').write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print('qgplan 거부 diff 보존; 새 qgplan2 clean 준비; 보호 지시 파일 변경 없음')
