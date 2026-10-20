"""Correct the G1 draft error taxonomy from captured primary Winsock docs."""
import datetime,hashlib,json,pathlib,shutil
R=pathlib.Path('E:/harnes/network-path-inspector');a=R/'artifacts';shutil.copyfile(a/'g1-independent-result.json',a/'g1-independent-before-wsa-repair.json');changes=[]
for base in [R,*sorted((R/'.worktrees').iterdir())]:
 p=base/'contracts/g1-interface-contract.json'
 if not p.is_file():continue
 c=json.loads(p.read_text(encoding='utf-8'));assert c['contract_version']=='g1-1.1.1';c['contract_version']='g1-1.1.2';c['tcp_outcomes'].insert(c['tcp_outcomes'].index('REFUSED')+1,'RESET');c['tcp_error_mapping'].update({'10054':'RESET','11002':'DNS_ERROR','11003':'DNS_ERROR'});before=hashlib.sha256(p.read_bytes()).hexdigest();p.write_text(json.dumps(c,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n');changes.append({'path':str(p),'before':before,'after':hashlib.sha256(p.read_bytes()).hexdigest()})
for base in [R,R/'.worktrees/schema']:
 p=base/'schemas/common-1.1.schema.json';c=json.loads(p.read_text(encoding='utf-8'));outcomes=c['$defs']['TcpOutcome']['enum'];outcomes.insert(outcomes.index('REFUSED')+1,'RESET');p.write_text(json.dumps(c,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
(a/'g1-winsock-taxonomy-revision.json').write_text(json.dumps({'revision':'g1-1.1.2','at':datetime.datetime.now().astimezone().isoformat(),'primary_source':'.harness/references/winsock-errors.txt','reason':'10054 is an OS-reported connection reset, not a local socket-creation/permission failure; 11002/11003 are DNS errors. RESET does not assert captured RST or its origin.','changes':changes},ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n');print(json.dumps({'revision':'g1-1.1.2','updated_contracts':len(changes),'network_probes':0}))
