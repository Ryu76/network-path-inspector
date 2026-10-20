"""Controlled contract revision: missing source metadata must remain unknown."""
import datetime,hashlib,json,pathlib
ROOT=pathlib.Path('E:/harnes/network-path-inspector')
original_hash='faffff45de66126dad6a0a81045dd22b536e9739e78947b426bd42d4a0ef7aa1'
changes=[]
def save(path,data):
 before=hashlib.sha256(path.read_bytes()).hexdigest();path.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');changes.append({'path':str(path),'before':before,'after':hashlib.sha256(path.read_bytes()).hexdigest()})
original=(ROOT/'PRD.md').read_bytes()
assert hashlib.sha256(original).hexdigest()==original_hash
for base in [ROOT,*sorted((ROOT/'.worktrees').iterdir())]:
 if not base.is_dir():continue
 prd=base/'PRD.md';before=prd.read_bytes()
 if before!=original:
  assert before.replace(b'\r\n',b'\n')==original, 'Unexpected PRD semantic change; refuse repair'
  prd.write_bytes(original)
  changes.append({'path':str(prd),'before':hashlib.sha256(before).hexdigest(),'after':original_hash,'reason':'derived worktree CRLF checkout only; original root preserved'})
 (base/'.gitattributes').write_text('* text=auto eol=lf\nPRD.md -text\n',encoding='utf-8')
 p=base/'contracts/g1-interface-contract.json';c=json.loads(p.read_text(encoding='utf-8'));assert c['contract_version'] in ('g1-1.1.0','g1-1.1.1');c['contract_version']='g1-1.1.1';c['objects']['Session']['timezone_offset_minutes']='integer -840..840 or null; source host timezone unknown must remain null';c['objects']['Session']['host_role']='client|server|null; null when legacy source role is unknown';save(p,c)
schema=ROOT/'.worktrees/schema';p=schema/'schemas/common-1.1.schema.json';c=json.loads(p.read_text(encoding='utf-8'));c['$defs']['HostRole']['type']=['string','null'];c['$defs']['HostRole']['enum']=['client','server',None];old=c['$defs']['HostString']['pattern'];assert '[0-9a-fA-F:]+'in old;c['$defs']['HostString']['pattern']=old.replace('[0-9a-fA-F:]+','[0-9a-fA-F:.]+');save(p,c)
p=schema/'schemas/session-1.1.schema.json';c=json.loads(p.read_text(encoding='utf-8'));c['properties']['timezone_offset_minutes']['type']=['integer','null'];save(p,c)
p=schema/'fixtures/g1/legacy_session_1_0_converted_1_1.golden.json';c=json.loads(p.read_text(encoding='utf-8'));assert c['timezone_offset_minutes']==0;c['timezone_offset_minutes']=None;c['host_role']=None;c['limitations'].append('원본 로컬 시간대와 호스트 역할은 제공되지 않아 null로 보존함. UTC 0 또는 client로 추측하지 않음.');save(p,c)
out={'revision':'g1-1.1.1','recorded_at':datetime.datetime.now().astimezone().isoformat(),'reason':'PRD unknown preservation: do not fabricate timezone/role in legacy import; IPv4-mapped IPv6 accepted by semantic parser','prd_unchanged':True,'changes':changes}
(ROOT/'artifacts/g1-contract-revision.json').write_text(json.dumps(out,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps(out,ensure_ascii=False,indent=2))
