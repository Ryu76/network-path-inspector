"""PRD v1.2 원문과 Inspector 보호 baseline을 보존하고 QG0/QG1 병렬 기준을 준비한다."""
import datetime,hashlib,json,pathlib,shutil,subprocess
R=pathlib.Path(__file__).resolve().parents[1]
source=pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/documents/doc_e75b10a58045_Network_Path_Inspector_Harness_PRD_v1.2.md')
content=source.read_bytes();assert b'1.2.0'in content
relative=pathlib.Path('docs/requirements/Network_Path_Inspector_Harness_PRD_v1.2.md')
destination=R/relative;destination.parent.mkdir(parents=True,exist_ok=True)
if destination.exists():assert destination.read_bytes()==content
else:destination.write_bytes(content)
sha=hashlib.sha256(content).hexdigest()
protected={}
for folder in ['crates/npi-core','crates/npi-probes','ui/src','ui/scripts','schemas','fixtures/g1','contracts']:
 for p in (R/folder).rglob('*'):
  if p.is_file():protected[p.relative_to(R).as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
for rel in ['PRD.md','ui/package.json','ui/package-lock.json','start_npi.bat']:
 p=R/rel;protected[rel]=hashlib.sha256(p.read_bytes()).hexdigest()
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'prd_v12_sha256':sha,'protected_inspector_sha256':protected,'quick_scope':'QG0/QG1 only; no GUI/EXE or full product acceptance','inspector_runtime_changes_allowed':False}
A=R/'artifacts';A.mkdir(exist_ok=True);out=A/'qg0-inspector-baseline.json';assert not out.exists(),'기존 baseline 보존';out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
contract={'contract_version':'qg1-0.1.0','schema_version':'1.0','product':'network-quick-check','prd_version':'1.2.0','prd_sha256':sha,'facade_package':'network-core','facade_scope':'reuse npi-core and npi-probes library implementations without changing or copying them','required_fields':['schema_version','product','session_id','timestamp_iso8601','source_host','target_host','resolved_ip','target_port','feature','status','elapsed_ms','os_error_code','details','evidence_level'],'nullable_fields':['timestamp_iso8601','source_host','resolved_ip','elapsed_ms','os_error_code'],'status_values':['PASS','FAIL','WARN','SKIPPED','UNKNOWN'],'evidence_values':['OBSERVED','INFERRED','UNKNOWN'],'feature_values':['tcp_connect','icmp_ping','icmp_traceroute','dns_lookup','local_network'],'tcp_status_mapping':{'CONNECTED':['PASS','OBSERVED'],'REFUSED':['FAIL','OBSERVED'],'RESET':['FAIL','OBSERVED'],'TIMED_OUT':['FAIL','OBSERVED'],'UNREACHABLE':['FAIL','OBSERVED'],'DNS_ERROR':['FAIL','OBSERVED'],'LOCAL_ERROR':['UNKNOWN','OBSERVED'],'CANCELLED':['UNKNOWN','UNKNOWN'],'unrecognized':['UNKNOWN','UNKNOWN']},'limits_proposal':{'max_targets':100,'default_concurrency':4,'max_concurrency':4,'default_tcp_timeout_ms':3000,'default_features':['tcp_connect','icmp_ping']},'details_contract':'object containing outcome, limitations and raw_measurement; raw socket error and source DTO retained; no packet observation claims','stage_exclusions':['no actual DNS invocation, sockets, GUI, traceroute, exports, or helper subprocess in default QG1 tests','no Tauri/WebView/Npcap/Agent/PDF/SQLite/database dependency','no existing DTO/schema/contract mutation','no core or GUI stubs pretending runtime implementation']}
H=R/'.harness';(H/'references').mkdir(parents=True,exist_ok=True)
(H/'references/qg1-contract.json').write_text(json.dumps(contract,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
for role in ['qgcore','qgplan']:
 w=R/'.worktrees'/role;assert not w.exists(),f'기존 worktree 보존: {w}'
 p=subprocess.run(['git','-C',str(R),'worktree','add','-b','ai-pro/'+role,str(w),'HEAD'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60);assert p.returncode==0,p.stderr
 for rel in protected:
  # 기존 checkout의 동일 경로를 보호 baseline 바이트로 맞춘다.
  src=R/rel;dst=w/rel;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(src.read_bytes())
 for rel in ['Cargo.toml','Cargo.lock',str(relative)]:
  src=R/rel;dst=w/rel;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(src.read_bytes())
 refs=w/'.harness/references';refs.mkdir(parents=True,exist_ok=True);shutil.copyfile(H/'references/qg1-contract.json',refs/'qg1-contract.json')
 # worktree 정책만 두 제품 범위를 명시한다. root 기존 정책은 별도 검토 후 갱신한다.
 agent=w/'AGENTS.md';text=agent.read_text(encoding='utf-8');text+='\n## QG0/QG1 승인 범위\n- 같은 프로젝트의 Part B Network Quick Check를 별도 제품으로 준비한다. 원문 docs/requirements/Network_Path_Inspector_Harness_PRD_v1.2.md와 .harness/references/qg1-contract.json 준수.\n- 기존 Inspector 기능/DTO/프로브/스키마/PRD.md 바이트 변경 금지. Quick Check에 웹뷰/Npcap/Agent/PDF/SQLite 의존성 금지.\n';agent.write_text(text,encoding='utf-8',newline='\n')
 if role=='qgcore':
  manifest=w/'Cargo.toml';text=manifest.read_text(encoding='utf-8').replace('"crates/npi-probes"]','"crates/npi-probes", "crates/network-core"]');manifest.write_text(text,encoding='utf-8',newline='\n')
 subprocess.run(['git','-C',str(w),'add','Cargo.toml','Cargo.lock','AGENTS.md','PRD.md','crates','contracts','schemas','fixtures','ui/src','ui/scripts','ui/package.json','ui/package-lock.json','start_npi.bat','docs/requirements'],check=True,capture_output=True,timeout=30)
 subprocess.run(['git','-C',str(w),'-c','core.autocrlf=false','commit','-m','chore: preserve Inspector baseline for '+role],check=True,capture_output=True,timeout=30)
 status=subprocess.run(['git','-C',str(w),'status','--porcelain'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=20);assert status.returncode==0 and not status.stdout,status.stdout
 print(role,'별도 clean baseline 준비 완료')
print(json.dumps({'prd_v12_sha256':sha,'protected_files':len(protected),'original_prd_unchanged':hashlib.sha256((R/'PRD.md').read_bytes()).hexdigest()==protected['PRD.md']},ensure_ascii=False))
