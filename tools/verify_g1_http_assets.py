"""Read only the approved loopback preview and verify exact generated asset bytes."""
import hashlib,json,pathlib,re,urllib.request,datetime
R=pathlib.Path(__file__).resolve().parents[1];D=R/'ui/dist';base='http://127.0.0.1:39201';rows=[]
def get(rel):
 assert rel.startswith('/')and not '..'in rel
 with urllib.request.urlopen(base+rel,timeout=5)as q:
  assert q.status==200;data=q.read(4*1024*1024+1)
 assert len(data)<=4*1024*1024
 p=D/rel.lstrip('/');expected=p.read_bytes();assert data==expected,rel
 rows.append({'path':rel,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest(),'disk_matches':True});return data
html=get('/index.html').decode('utf-8')
for rel in sorted(set(re.findall(r'(?:src|href)="(/assets/[^"?]+)"',html))):get(rel)
assert len(rows)>=3
report={'checked_at':datetime.datetime.now().astimezone().isoformat(),'base':base,'assets':rows,'all_match':True,'scope':'G1 production build only; no diagnostic engine'}
(R/'artifacts/g1-live-http-assets.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n');print(json.dumps(report,ensure_ascii=False,indent=2))
