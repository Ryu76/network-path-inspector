"""DNS actor 원본 SHA를 검증하고 Clippy 4건·rustfmt만 동등 보정한다."""
import datetime,hashlib,json,pathlib,subprocess
R=pathlib.Path(__file__).resolve().parents[1];W=R/'.worktrees/qgdns';load=lambda rel:json.loads((R/rel).read_text(encoding='utf-8'))
assert load('artifacts/qg2dnsfix-actor-policy-audit.json')['all_actor_policy_checks_passed'];run=load('.harness/runs/qg2dnsfix-qgdns/result.json');after=load('.harness/runs/qg2dnsfix-qgdns/after.json');source={rel:after[rel]for rel in run['changed_paths']}
for rel,sha in source.items():assert hashlib.sha256((W/rel).read_bytes()).hexdigest()==sha,rel
p=W/'crates/network-core/src/dns.rs';text=p.read_text(encoding='utf-8')
old='''    if measurement.host != ctx.target_host {
        if let Err(reason) = dns_engine::validate_host(&ctx.target_host) {
            errors.push(format!("컨텍스트 대상 호스트 검증 실패: {reason}"));
        }
    }''';new='''    if measurement.host != ctx.target_host
        && let Err(reason) = dns_engine::validate_host(&ctx.target_host)
    {
        errors.push(format!("컨텍스트 대상 호스트 검증 실패: {reason}"));
    }''';assert text.count(old)==1;text=text.replace(old,new)
for family in ['V4','V6']:
 old='''                        } else if let Ok(sock) = measurement.addresses[0].parse::<SocketAddr>() {
                            if sock.ip() != IpAddr::'''+family+'''(ip) {
                                errors.push(
                                    "IP 리터럴 호스트와 주소 IP가 수치적으로 일치하지 않습니다 (외부 IP 귀속 거부)."
                                        .to_string(),
                                );
                            }
                        }'''
 new='''                        } else if let Ok(sock) = measurement.addresses[0].parse::<SocketAddr>()
                            && sock.ip() != IpAddr::'''+family+'''(ip)
                        {
                            errors.push(
                                "IP 리터럴 호스트와 주소 IP가 수치적으로 일치하지 않습니다 (외부 IP 귀속 거부)."
                                    .to_string(),
                            );
                        }''';assert text.count(old)==1,family;text=text.replace(old,new)
old='''        OUTCOME_TIMED_OUT | OUTCOME_CANCELLED | OUTCOME_LOCAL_ERROR => {
            if !measurement.addresses.is_empty() {
                errors.push(format!(
                    "{} outcome에 주소 목록이 존재할 수 없습니다 (비성공 결과 주소 거부).",
                    measurement.outcome
                ));
            }
        }''';new='''        OUTCOME_TIMED_OUT | OUTCOME_CANCELLED | OUTCOME_LOCAL_ERROR
            if !measurement.addresses.is_empty() =>
        {
            errors.push(format!(
                "{} outcome에 주소 목록이 존재할 수 없습니다 (비성공 결과 주소 거부).",
                measurement.outcome
            ));
        }''';assert text.count(old)==1;text=text.replace(old,new);p.write_text(text,encoding='utf-8',newline='\n')
paths=[*source,'crates/network-resolver/src/lib.rs','crates/network-resolver/tests/dns.rs'];canonical={};before_fmt={}
for rel in paths:
 data=(W/rel).read_bytes();before_fmt[rel]=hashlib.sha256(data).hexdigest();q=subprocess.run(['rustfmt','--emit','stdout','--edition','2024'],cwd=W,input=data,capture_output=True,timeout=20);assert q.returncode==0,q.stderr;canonical[rel]=q.stdout
q=subprocess.run(['cargo','fmt','-p','network-core','-p','network-resolver'],cwd=W,capture_output=True,timeout=40);assert q.returncode==0,q.stderr
for rel,data in canonical.items():assert(W/rel).read_bytes()==data,rel
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'actor_stage':'qg2dnsfix','actor_source_sha256':source,'parent_edits':'Clippy4건: let-chain3개와match guard1개, 나머지는edition2024 rustfmt. 새제품판정/검증완화 없음.','before_fmt_sha256':before_fmt,'canonical_source_sha256':{rel:hashlib.sha256((W/rel).read_bytes()).hexdigest()for rel in paths},'static_recheck':'deleg_75f42e38는 actor 보정 의미를 검토하며 이 동등변환·정형은 부모가 별도검증','accepted':False};out=R/'artifacts/qg2c-dns-canonical-source.json';assert not out.exists();out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print('DNS Clippy4건 동등보정 및 공유resolver 포함4파일 정규형 SHA 검증 완료')
