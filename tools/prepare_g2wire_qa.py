"""완료·감사된 DNS/bridge를 제품 변경 없이 독립 QA에 조합한다."""
import hashlib,json,pathlib,shutil
R=pathlib.Path(__file__).resolve().parents[1]
def approved(stage,role,rel):
 report=json.loads((R/'artifacts'/f'{stage}-actor-policy-audit.json').read_text(encoding='utf-8'))
 assert next(x for x in report['actors']if x['role']==role)['passed']
 folder=R/'.harness/runs'/f'{stage}-{role}';after=json.loads((folder/'after.json').read_text(encoding='utf-8'));src=R/'.worktrees'/role/rel
 assert hashlib.sha256(src.read_bytes()).hexdigest()==after[rel],rel
 return src
for section in ['src','tests']:
 rel=f'crates/npi-probes/{section}/dns.rs';src=approved('g2cancel-fallback2','g2dns',rel);dst=R/'.harness/qa/g2dns'/section/'dns.rs';dst.read_bytes();shutil.copyfile(src,dst)
q=R/'.harness/qa/g2wire-final';assert not q.exists(),q
for group in ['src','tests']:
 for src in (R/'.worktrees/g2bridge/crates/npi-probes'/group).glob('*.rs'):
  dst=q/group/src.name;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dst)
for rel in ['crates/npi-probes/src/main.rs','crates/npi-probes/tests/cli_dns.rs']:
 approved('g2wire-fallback2','g2bridge',rel)
for section in ['src','tests']:
 dst=q/section/'dns.rs';dst.read_bytes();shutil.copyfile(R/'.harness/qa/g2dns'/section/'dns.rs',dst)
manifest=(R/'.harness/qa/g2dns/Cargo.toml').read_text(encoding='utf-8');(q/'Cargo.toml').write_text(manifest,encoding='utf-8',newline='\n')
print('최신 DNS는 기존 격리 QA, bridge 조합은 신규 격리 QA에 복사. 제품 root 변경0.')
