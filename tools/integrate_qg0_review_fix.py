"""QG0 보정 도구·경로·SHA 감사를 확인한 두 문서만 선택 반영한다."""
import datetime,hashlib,json,pathlib
R=pathlib.Path(__file__).resolve().parents[1];stage='qg0reviewfix';role='qgplan2';folder=R/'.harness/runs'/f'{stage}-{role}'
audit=json.loads((R/'artifacts'/f'{stage}-actor-policy-audit.json').read_text(encoding='utf-8'));assert audit['all_actor_policy_checks_passed']
result=json.loads((folder/'result.json').read_text(encoding='utf-8'));before=json.loads((folder/'before.json').read_text(encoding='utf-8'));after=json.loads((folder/'after.json').read_text(encoding='utf-8'))
assert set(result['changed_paths'])=={'docs/quick-check/gates.md','docs/quick-check/requirement-traceability.md'}
for rel in result['changed_paths']:
 src=R/'.worktrees'/role/rel;dst=R/rel;data=src.read_bytes();assert hashlib.sha256(data).hexdigest()==after[rel];assert hashlib.sha256(dst.read_bytes()).hexdigest()==before[rel],f'부모변경 덮기 거부: {rel}';dst.write_bytes(data)
print('QG0 검토누락 보정2문서 선택 반영; 원본actor/실패/정책감사 증거보존')
