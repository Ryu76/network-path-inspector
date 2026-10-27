"""DNS/Trace 신규 어댑터의 합성 독립 경계 회귀를 별도 crate에 만든다."""
import pathlib
R=pathlib.Path(__file__).resolve().parents[1]
for role,label in [('qgdns','dns'),('qgtrace','trace')]:
 q=R/'.harness/qa'/('quick-'+label+'-boundaries');assert not q.exists();(q/'src').mkdir(parents=True);(q/'tests').mkdir();(q/'src/lib.rs').write_text('// 부모의 합성 회귀 전용 crate. 네트워크 호출 없음.\n',encoding='utf-8');(q/'Cargo.toml').write_text('[package]\nname="quick-'+label+'-boundaries"\nversion="0.1.0"\nedition="2024"\n[workspace]\n[dependencies]\nnetwork-core={path="'+(R/'.worktrees'/role/'crates/network-core').as_posix()+'"}\n',encoding='utf-8')
 if label=='dns':
  text=r'''//! 직접 생성한 typed DNS 측정도 engine 불변식을 우회해서는 안 된다. 전부 합성.
use network_core::{dns::dns_to_quick_result,dns_engine::DnsMeasurement,quick::{QuickContext,QuickStatus}};
fn context(host:&str)->QuickContext{QuickContext{session_id:"boundary-synthetic".into(),timestamp_iso8601:None,source_host:None,target_host:host.into(),target_port:80}}
fn measurement(host:&str)->DnsMeasurement{DnsMeasurement{host:host.into(),port:80,outcome:"RESOLVED".into(),addresses:vec!["127.0.0.1:80".into()],elapsed_ms:1,error_code:None,error_message:None,limitations:vec!["synthetic-only".into()]}}
#[test]fn resolved_with_error_metadata_must_not_pass(){let mut m=measurement("localhost");m.error_code=Some(11001);m.error_message=Some("synthetic error".into());let r=dns_to_quick_result(&context("localhost"),&m);assert!(r.is_err()||r.unwrap().status!=QuickStatus::PASS,"RESOLVED+OS error 모순을 PASS로 승격하면 안 됨");}
#[test]fn dns_error_with_addresses_is_rejected(){let mut m=measurement("localhost");m.outcome="DNS_ERROR".into();m.error_code=Some(11001);m.error_message=Some("synthetic error".into());assert!(dns_to_quick_result(&context("localhost"),&m).is_err(),"실제 engine이 허용하지 않는 오류+주소 모순은 adapter에서도 거부");}
#[test]fn invalid_raw_host_must_not_pass(){let m=measurement("invalid host");let r=dns_to_quick_result(&context("invalid host"),&m);assert!(r.is_err()||r.unwrap().status!=QuickStatus::PASS,"engine이 거부하는 불량 raw host를 DNS 관측 PASS로 승격 금지");}
'''
 else:
  text=r'''//! 실제 도달 관측을 발명하지 않는 Trace 직접 객체/파서 경계. 전부 합성.
use network_core::{traceroute::{TraceMeasurement,TraceHop,trace_to_quick_result,parse_trace_output},quick::{QuickContext,QuickStatus}};
fn context()->QuickContext{QuickContext{session_id:"trace-synthetic-boundary".into(),timestamp_iso8601:None,source_host:None,target_host:"127.0.0.1".into(),target_port:80}}
fn measurement()->TraceMeasurement{TraceMeasurement{target:"127.0.0.1".into(),method:"ICMP_TRACERT".into(),outcome:"REACHED".into(),hops:vec![],elapsed_ms:1,exit_code:Some(0),raw_stdout:vec![],raw_stderr:vec![],output_truncated:false,limitations:vec!["synthetic-only".into()]}}
fn assert_not_pass(m:&TraceMeasurement){let r=trace_to_quick_result(&context(),m);assert!(r.is_err()||r.unwrap().status!=QuickStatus::PASS,"대상 응답 증거가 없거나 불량인 REACHED를 PASS로 승격 금지");}
#[test]fn reached_without_target_hop_never_passes(){assert_not_pass(&measurement());}
#[test]fn invalid_raw_target_never_passes(){let mut m=measurement();m.target="not-an-ip".into();assert_not_pass(&m);}
#[test]fn truncated_success_never_passes(){let mut m=measurement();m.output_truncated=true;m.hops.push(TraceHop{ttl:1,address:Some("127.0.0.1".into()),probe_times_ms:vec![Some(1);3],rtt_less_than:vec![false;3],raw_line:"1 1 ms 1 ms 1 ms 127.0.0.1".into()});assert_not_pass(&m);}
#[test]fn parser_missing_ms_units_is_rejected(){assert!(parse_trace_output("127.0.0.1".parse().unwrap(),b"1 1 2 3 127.0.0.1\r\n",30).is_err(),"단위 없는 임의 숫자를 실측 RTT로 승격 금지");}
'''
 (q/'tests/contracts.rs').write_text(text,encoding='utf-8',newline='\n')
print('순수 합성 독립 경계: DNS3건 / Trace4건 준비. 실제 I/O 없음.')
