"""writer와 분리한 DNS 공용 crate 검증 환경과 소유 loopback helper를 준비한다."""
import hashlib,json,pathlib,shutil
R=pathlib.Path(__file__).resolve().parents[1];Q=R/'.harness/qa/quick-resolver';W=R/'.worktrees/qgdns';assert not Q.exists();(Q/'src').mkdir(parents=True);(Q/'tests').mkdir();(Q/'resolver/src').mkdir(parents=True);(Q/'resolver/tests').mkdir(parents=True)
def put(rel,text):(Q/rel).write_text(text,encoding='utf-8',newline='\n')
shutil.copyfile(W/'crates/network-resolver/src/lib.rs',Q/'resolver/src/lib.rs')
put('Cargo.toml','[package]\nname="quick-resolver-qa"\nversion="0.1.0"\nedition="2024"\n[workspace]\nmembers=["resolver"]\n[workspace.package]\nversion="0.1.0"\nedition="2024"\n[workspace.dependencies]\nserde={version="=1.0.228",features=["derive"]}\nserde_json="=1.0.149"\n[dependencies]\nnetwork-resolver={path="resolver"}\n')
shutil.copyfile(W/'crates/network-resolver/Cargo.toml',Q/'resolver/Cargo.toml')
test=(W/'crates/network-resolver/tests/dns.rs').read_text(encoding='utf-8');old='''    let exe_var = match std::env::var("NPI_TEST_HELPER_EXE") {
        Ok(val) => val,
        Err(_) => {
            eprintln!("NPI_TEST_HELPER_EXE 미설정: 부모가 제품 바이너리 경로를 제공해야 격리 시험 가능");
            return;
        }
    };''';assert test.count(old)==1;test=test.replace(old,'''    let exe_var = std::env::var("NPI_TEST_HELPER_EXE")
        .expect("명시 real 시험에는 NPI_TEST_HELPER_EXE 절대 경로가 필요하며 미설정은 성공이 아니다");''');put('resolver/tests/dns.rs',test)
put('src/main.rs',r'''//! 부모 QA 전용 helper. 제품 바이너리가 아니며 localhost만 해석한다.
use std::{env,process::ExitCode,time::Duration};
fn main()->ExitCode {
 let args:Vec<String>=env::args().collect();
 if args.len()!=4 || args[1]!=network_resolver::WORKER_FLAG || !args[2].eq_ignore_ascii_case("localhost") {return ExitCode::from(2)}
 let name=env::current_exe().unwrap().file_stem().unwrap().to_string_lossy().into_owned();
 if name.contains("slow") {std::thread::sleep(Duration::from_secs(20));}
 if name.contains("overflow") {println!("{}","x".repeat(65536));return ExitCode::SUCCESS}
 if name.contains("abnormal") {return ExitCode::from(3)}
 if name.contains("corrupt") {println!("not-a-worker-payload");return ExitCode::SUCCESS}
 print!("{}",network_resolver::worker_output_line(&network_resolver::run_worker_from_args(&args[2],&args[3])));
 ExitCode::SUCCESS
}
''')
put('tests/lifecycle.rs',r'''//! 실제 child 수명주기. 외부 DNS·TCP 없이 부모 소유 localhost helper만 사용한다.
use std::{net::SocketAddr,path::{Path,PathBuf},sync::{Arc,atomic::{AtomicBool,Ordering}},time::{Duration,Instant}};
use network_resolver::*;
fn helper()->PathBuf {PathBuf::from(env!("CARGO_BIN_EXE_quick-resolver-qa"))}
struct OwnedCopy {path:PathBuf}
impl OwnedCopy {fn new(mode:&str)->Self {let path=helper().parent().unwrap().join(format!("nqc-fixture-{mode}.exe"));std::fs::copy(helper(),&path).unwrap();Self{path}}}
impl Drop for OwnedCopy {fn drop(&mut self){std::fs::remove_file(&self.path).expect("소유 fixture 실행 파일 해제·삭제");}}
fn flag()->Arc<AtomicBool>{Arc::new(AtomicBool::new(false))}
#[test] #[ignore="부모 명시: owned localhost 실제 helper"]
fn real_localhost_resolves_and_preserves_all_addresses(){let m=resolve_isolated(&helper(),"localhost",80,Duration::from_millis(3000),flag());assert_eq!(m.outcome,OUTCOME_RESOLVED,"{m:?}");assert!(!m.addresses.is_empty());assert!(m.addresses.iter().all(|a|a.parse::<SocketAddr>().unwrap().ip().is_loopback()));}
#[test] #[ignore="부모 명시: owned slow child timeout 및 재수거"]
fn real_slow_child_deadline_is_not_dns_failure(){let exe=OwnedCopy::new("slow");let start=Instant::now();let m=resolve_isolated(&exe.path,"localhost",80,Duration::from_millis(80),flag());assert_eq!(m.outcome,OUTCOME_TIMED_OUT,"{m:?}");assert!(start.elapsed()<Duration::from_secs(3));}
#[test] #[ignore="부모 명시: owned slow child 취소·재수거"]
fn real_cancelled_child_is_reaped(){let exe=OwnedCopy::new("slow-cancel");let cancel=flag();let setter=Arc::clone(&cancel);let thread=std::thread::spawn(move||{std::thread::sleep(Duration::from_millis(80));setter.store(true,Ordering::SeqCst);});let m=resolve_isolated(&exe.path,"localhost",80,Duration::from_millis(3000),cancel);thread.join().unwrap();assert_eq!(m.outcome,OUTCOME_CANCELLED,"{m:?}");assert!(m.addresses.is_empty());}
#[test] #[ignore="부모 명시: owned child 출력 상한"]
fn real_oversized_child_output_is_local_error(){let exe=OwnedCopy::new("overflow");let m=resolve_isolated(&exe.path,"localhost",80,Duration::from_millis(3000),flag());assert_eq!(m.outcome,OUTCOME_LOCAL_ERROR,"{m:?}");assert!(m.addresses.is_empty());}
#[test] #[ignore="부모 명시: owned child 비정상 종료"]
fn real_abnormal_child_exit_is_local_error(){let exe=OwnedCopy::new("abnormal");let m=resolve_isolated(&exe.path,"localhost",80,Duration::from_millis(3000),flag());assert_eq!(m.outcome,OUTCOME_LOCAL_ERROR,"{m:?}");}
#[test] #[ignore="부모 명시: owned child protocol 불량"]
fn real_corrupt_child_payload_is_local_error(){let exe=OwnedCopy::new("corrupt");let m=resolve_isolated(&exe.path,"localhost",80,Duration::from_millis(3000),flag());assert_eq!(m.outcome,OUTCOME_LOCAL_ERROR,"{m:?}");}
#[test]
fn literal_and_pre_cancel_do_not_require_executable(){for text in ["127.0.0.1","::1"]{let m=resolve_isolated(Path::new("nonexistent-owned-fixture.exe"),text,80,Duration::from_millis(500),flag());assert_eq!(m.outcome,OUTCOME_RESOLVED);assert_eq!(m.addresses.len(),1);}let cancel=Arc::new(AtomicBool::new(true));let m=resolve_isolated(Path::new("nonexistent-owned-fixture.exe"),"localhost",80,Duration::from_millis(500),cancel);assert_eq!(m.outcome,OUTCOME_CANCELLED);}
''')
record={'qa_root':str(Q),'source_sha256':hashlib.sha256((Q/'resolver/src/lib.rs').read_bytes()).hexdigest(),'tests_hardening':'명시 ignored 시험의 helper 환경변수 누락을 침묵 return에서 expect 실패로 전환','helper_scope':'QA 전용·localhost만, 제품EXE 검증 아님','product_acceptance':False};(R/'artifacts/quick-resolver-qa-prepared.json').write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps(record,ensure_ascii=False))
