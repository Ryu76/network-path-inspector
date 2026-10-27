"""Trace actor SHA 확인 후 Clippy 두 곳과 정형만 보정한다."""
import datetime,hashlib,json,pathlib,subprocess
R=pathlib.Path(__file__).resolve().parents[1];W=R/'.worktrees/qgtrace';load=lambda rel:json.loads((R/rel).read_text(encoding='utf-8'))
assert load('artifacts/qg2tracefix-actor-policy-audit.json')['all_actor_policy_checks_passed'];run=load('.harness/runs/qg2tracefix-qgtrace/result.json');after=load('.harness/runs/qg2tracefix-qgtrace/after.json');source={rel:after[rel]for rel in run['changed_paths']}
for rel,sha in source.items():assert hashlib.sha256((W/rel).read_bytes()).hexdigest()==sha,rel
p=W/'crates/network-core/src/traceroute.rs';text=p.read_text(encoding='utf-8');old='''fn validate_hops_consistency(target: IpAddr, hops: &[TraceHop]) -> Result<(), String> {
    let mut expected_ttl: u8 = 1;
    for hop in hops {''';new='''fn validate_hops_consistency(target: IpAddr, hops: &[TraceHop]) -> Result<(), String> {
    for (expected_ttl, hop) in (1_u8..).zip(hops.iter()) {''';assert text.count(old)==1;text=text.replace(old,new)
old='''        expected_ttl += 1;
    }
    Ok(())
}

/// 원본 표준 출력''';new='''    }
    Ok(())
}

/// 원본 표준 출력''';assert text.count(old)==1;text=text.replace(old,new)
old='''        if exit_code.is_none() {
            if let Ok(Some(st)) = child.try_wait() {
                exit_code = st.code();
            }
        }''';new='''        if exit_code.is_none()
            && let Ok(Some(st)) = child.try_wait()
        {
            exit_code = st.code();
        }''';assert text.count(old)==1;text=text.replace(old,new);p.write_text(text,encoding='utf-8',newline='\n');canonical={}
for rel in source:
 q=subprocess.run(['rustfmt','--emit','stdout','--edition','2024'],cwd=W,input=(W/rel).read_bytes(),capture_output=True,timeout=20);assert q.returncode==0,q.stderr;canonical[rel]=q.stdout
q=subprocess.run(['cargo','fmt','-p','network-core'],cwd=W,capture_output=True,timeout=30);assert q.returncode==0,q.stderr
for rel,data in canonical.items():assert(W/rel).read_bytes()==data,rel
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'stage':'qg2tracefix','actor_source_sha256':source,'parent_edits':'TTL 수동카운터를동등한zip으로,exit_code nestedif를let-chain으로변환. 나머지는edition2024 rustfmt.','canonical_source_sha256':{rel:hashlib.sha256((W/rel).read_bytes()).hexdigest()for rel in source},'accepted':False};out=R/'artifacts/qg2c-trace-canonical-source.json';assert not out.exists();out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print('Trace 2파일 actor SHA / Clippy2곳 동등변환 / 정규형 검증 완료')
