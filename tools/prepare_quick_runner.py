"""안정된 QG2 API 보존커밋을 기준으로 실제 실행기 전용 worktree를 준비한다."""
import hashlib,json,pathlib,shutil,subprocess
R=pathlib.Path(__file__).resolve().parents[1];w=R/'.worktrees/qg2runner';assert not w.exists()
def git(args,cwd=R):
 p=subprocess.run(['git','-C',str(cwd),*args],capture_output=True,timeout=45);assert p.returncode==0,p.stderr.decode('utf-8','replace');return p.stdout
accept=json.loads((R/'artifacts/qg1-acceptance.json').read_text(encoding='utf-8'));assert all(hashlib.sha256((R/rel).read_bytes()).hexdigest()==sha for rel,sha in accept['source_sha256'].items())
git(['worktree','add','-b','ai-pro/qg2runner',str(w),'2118fa6'])
for rel,sha in {**json.loads((R/'artifacts/qg0-inspector-baseline.json').read_text(encoding='utf-8'))['protected_inspector_sha256'],**accept['source_sha256']}.items():
 data=(R/rel).read_bytes();assert hashlib.sha256(data).hexdigest()==sha;dst=w/rel;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(data)
canonical=json.loads((R/'artifacts/qg2a-canonical-source.json').read_text(encoding='utf-8'))
for role,commit in [('qg2input','0424b8f'),('qg2measure','98e256b')]:
 for rel,info in canonical['roles'][role].items():
  data=git(['show',commit+':'+rel]);assert hashlib.sha256(data).hexdigest()==info['normalized_sha256'];dst=w/rel;dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(data)
lib=w/'crates/network-core/src/lib.rs';lib.write_text(lib.read_text(encoding='utf-8')+'\n// QG2 실행기 API는 전용 writer에서 생성하며 두 의존 모듈은 보존커밋 사본이다.\npub mod targets;\npub mod measurements;\npub mod runner;\n',encoding='utf-8',newline='\n')
manifest=w/'crates/network-core/Cargo.toml';text=manifest.read_text(encoding='utf-8');assert 'tokio'not in text;text+='\n# 기존 공통 프로브에 이미 잠긴 Tokio를 실행 스케줄러에서 직접 재사용한다.\ntokio = { version = "=1.52.3", features = ["rt", "net", "time", "macros", "sync"] }\n';manifest.write_text(text,encoding='utf-8',newline='\n')
refs=w/'.harness/references';refs.mkdir(parents=True,exist_ok=True)
for name in ['qg2a-contract.json']:shutil.copyfile(R/'.harness/references'/name,refs/name)
shutil.copyfile(R/'artifacts/qg1-acceptance.json',refs/'qg1-acceptance.json')
contract={'version':'qg2b-0.1','scope':'실제TCP/Ping/로컬수집 선택실행기;이번slice도메인resolver/Trace/DNS프로브/GUI는미지원','public_types':{'QuickRunRequest':['session_id:String','timestamp_iso8601:Option<String>','source_host:Option<String>','targets:Vec<QuickTarget>','options:QuickOptions','max_result_bytes:usize'],'ProbeCounts':['tcp_connect:usize','icmp_ping:usize','local_network:usize','dns_lookup:usize','icmp_traceroute:usize'],'QuickRunReport':['results:Vec<QuickResult>','cancelled:bool','limit_reached:bool','omitted_results:usize','errors:Vec<String>','invocations:ProbeCounts','max_active_targets:usize','targets_started:usize','targets_completed:usize','serialized_result_bytes:usize']},'public_api':['pub type ProbeFuture<\'a> = Pin<Box<dyn Future<Output=Result<QuickResult,Vec<String>>>+Send+\'a>>','pub trait QuickProbeBackend:Send+Sync { fn tcp<\'a>(&\'a self,ctx:QuickContext,target:SocketAddr,timeout:Duration,cancel:Arc<AtomicBool>)->ProbeFuture<\'a>; fn icmp<\'a>(&\'a self,ctx:QuickContext,target:IpAddr,timeout:Duration,cancel:Arc<AtomicBool>)->ProbeFuture<\'a>; fn host<\'a>(&\'a self,ctx:QuickContext,target:IpAddr,cancel:Arc<AtomicBool>)->ProbeFuture<\'a>; }','pub struct NativeProbeBackend;','pub async fn run_quick(request:&QuickRunRequest,backend:Arc<dyn QuickProbeBackend>,cancel:Arc<AtomicBool>)->Result<QuickRunReport,Vec<String>>'],'budgets':{'MIN_RESULT_BYTES':4096,'DEFAULT_MAX_RESULT_BYTES':16777216,'MAX_RESULT_BYTES':16777216,'max_targets':100,'max_concurrent_targets':4,'max_rows':500},'limitations':['현재도메인주소해석미지원은해석필수일때모든프로브시작전Err로명시;IP대상만기존native측정실행','선택한DNS/Trace는명시UNKNOWN/UNKNOWN+UNAVAILABLE행,해당backend호출0;미선택기능행/호출0','입력/metadata/옵션/메모리예산검증실패시native호출0','QG2입력/adapter두모듈은부모가보정중이다.보존사본API만사용하고그소스수정금지;수정분통합/회귀후만수용','serialized_result_bytes는직렬화된보관결과바이트상한이며프로세스RSShardcap이아님','중지/한도초과시공유cancel플래그설정가능,대기/실행작업정리;ICMP동기최대2000ms한계를표기하고즉시취소보장발명금지']}
(refs/'qg2b-runner-contract.json').write_text(json.dumps(contract,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
p=subprocess.run(['cargo','metadata','--offline','--filter-platform','x86_64-pc-windows-msvc','--format-version','1','--no-deps'],cwd=w,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30);assert p.returncode==0,p.stderr
# no-deps metadata는 lock를갱신하지않을수있으므로 기존잠금안에서새직접edge만계산한다.
git(['add','crates','Cargo.toml','Cargo.lock','contracts','schemas','fixtures','ui/src','ui/scripts','ui/package.json','ui/package-lock.json','PRD.md','start_npi.bat'],w)
git(['-c','core.autocrlf=false','commit','-m','chore: freeze QG2 runner API over isolated probe adapter baseline'],w)
assert not git(['status','--porcelain'],w).strip();print('qg2runner clean 준비. 실제 backend는수용된기존프로브만재사용,세션격리/루프백검증후통합.')
