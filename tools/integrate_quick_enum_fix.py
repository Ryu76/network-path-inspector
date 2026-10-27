"""독립 재현된 enum 계약 결함의 검증된 두 파일만 root에 선택 반영한다."""
import datetime,hashlib,json,pathlib,shutil
R=pathlib.Path(__file__).resolve().parents[1];w=R/'.worktrees/qgcore'
load=lambda rel:json.loads((R/rel).read_text(encoding='utf-8'))
proof=load('artifacts/qg1-enum-canonical-source.json');assert not proof['integrated']
for name in ['qg1-enum-worker-tests-repaired','qg1-enum-worker-clippy-repaired']:
 data=load('artifacts/commands/'+name+'.json');assert data['exit_code']==0 and not data['partial']
base=load('artifacts/qg0-inspector-baseline.json')
for rel,sha in base['protected_inspector_sha256'].items():assert hashlib.sha256((R/rel).read_bytes()).hexdigest()==sha,rel
for rel,info in proof['files'].items():
 assert hashlib.sha256((w/rel).read_bytes()).hexdigest()==info['normalized_sha256'],rel
 assert hashlib.sha256((R/rel).read_bytes()).hexdigest()==info['root_before_sha256'],rel
for rel in proof['files']:shutil.copyfile(w/rel,R/rel)
proof.update(integrated=True,integrated_at=datetime.datetime.now().astimezone().isoformat(),protected_inspector_changed=0,qg1_accepted=False)
(R/'artifacts/qg1-enum-canonical-source.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print('enum 보정2파일 반영; 기존Inspector 변경0; root재시험/최종판정 대기')
