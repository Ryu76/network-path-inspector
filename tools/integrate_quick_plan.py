"""경로 감사에 합격한 Quick Check QG0 문서만 선택 반영한다."""
import hashlib,json,pathlib,shutil
R=pathlib.Path(__file__).resolve().parents[1];stage='qgplanretry';role='qgplan2'
audit=json.loads((R/'artifacts'/f'{stage}-actor-policy-audit.json').read_text(encoding='utf-8'));assert audit['all_actor_policy_checks_passed']
folder=R/'.harness/runs'/f'{stage}-{role}';result=json.loads((folder/'result.json').read_text(encoding='utf-8'));after=json.loads((folder/'after.json').read_text(encoding='utf-8'))
for rel in result['changed_paths']:
 assert rel.startswith('docs/quick-check/')or rel=='apps/network-quick-check/README.md'
 src=R/'.worktrees'/role/rel;assert hashlib.sha256(src.read_bytes()).hexdigest()==after[rel]
 dst=R/rel;assert not dst.exists(),f'기존 문서 보존: {rel}';dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,dst)
contract=R/'contracts/quick-check-interface-v0.1.json';assert not contract.exists();shutil.copyfile(R/'.harness/references/qg1-contract.json',contract)
print('새 QG0 문서6개 및 고정 계약 반영. 거부된 qgplan 문서는 미사용. Inspector 코드 변경0.')
