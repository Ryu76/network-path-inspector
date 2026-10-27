"""QG1 schema/문서/보호 baseline을 부모가 독립 검증한다. 네트워크/GUI 실행 없음."""
import argparse,copy,datetime,hashlib,json,pathlib,re
from jsonschema import Draft202012Validator,FormatChecker
R=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--source-root',type=pathlib.Path,default=R);p.add_argument('--docs-root',type=pathlib.Path,default=R);p.add_argument('--evidence-name',default='qg1-independent-result');args=p.parse_args()
S=args.source_root;D=args.docs_root
assert args.evidence_name.replace('-','').replace('_','').isalnum()
schema=json.loads((S/'schemas/quick-check-result-1.0.schema.json').read_text(encoding='utf-8'))
Draft202012Validator.check_schema(schema)
checker=FormatChecker()
# 최소 설치 jsonschema는 선택적 RFC3339 패키지가 없으면 date-time을 조용히 생략한다.
# 외부 설치 대신 Quick 계약의 명시적 부분집합을 독립 Python 구현으로 검증한다.
@checker.checks('date-time')
def quick_datetime(value):
 if not isinstance(value,str):return True
 if not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:[Zz]|[+-][0-9]{2}:[0-9]{2})',value):return False
 offset=re.search(r'[+-]([0-9]{2}):([0-9]{2})$',value)
 if offset and (int(offset[1])>23 or int(offset[2])>59):return False
 try:datetime.datetime.fromisoformat(value.replace('t','T').replace('z','Z').replace('Z','+00:00'));return True
 except ValueError:return False
assert not checker.conforms('not-a-timestamp','date-time'),'형식 검사 누락은 실패로 처리한다'
validator=Draft202012Validator(schema,format_checker=checker)
base={'schema_version':'1.0','product':'network-quick-check','session_id':'fa50d7e5-32c8-41d4-bfcb-218211b4b3dc','timestamp_iso8601':None,'source_host':None,'target_host':'localhost','resolved_ip':'127.0.0.1','target_port':443,'feature':'tcp_connect','status':'PASS','elapsed_ms':1,'os_error_code':None,'details':{'outcome':'CONNECTED','limitations':['TEST-ONLY: 합성 계약 fixture이며 실제 네트워크 증거가 아님'],'raw_measurement':{'target':'127.0.0.1:443','outcome':'CONNECTED','local_address':None,'elapsed_ms':1,'error_code':None,'error_message':None,'application_bytes_sent':0,'limitations':['TEST-ONLY']}},'evidence_level':'OBSERVED'}
checks=[]
def check(name,value,want):
 errors=list(validator.iter_errors(value));checks.append({'name':name,'passed':bool(not errors)==want,'expected_valid':want,'errors':[e.message for e in errors]})
check('synthetic-positive-base',base,True)
for key in base:
 value=copy.deepcopy(base);del value[key];check('missing-'+key,value,False)
for key,val in [('product','network-inspector'),('schema_version','1.1'),('status','ERROR'),('status','CANCELLED'),('evidence_level','PACKET_SEEN'),('feature','packet_capture'),('target_port',0),('target_port',65536),('target_port',True),('target_port',443.5),('elapsed_ms',-1),('elapsed_ms',True),('elapsed_ms',.5),('os_error_code','10061')]:
 value=copy.deepcopy(base);value[key]=val;check('invalid-'+key+'-'+str(val),value,False)
for key,tag in [('feature','tcp_connect'),('status','PASS'),('evidence_level','OBSERVED')]:
 for invalid in [{tag:None},None,[],1,True]:
  value=copy.deepcopy(base);value[key]=invalid;check('enum-non-string-'+key+'-'+json.dumps(invalid),value,False)
for key,values in [('feature',['tcp_connect','icmp_ping','icmp_traceroute','dns_lookup','local_network']),('status',['PASS','FAIL','WARN','SKIPPED','UNKNOWN']),('evidence_level',['OBSERVED','INFERRED','UNKNOWN'])]:
 for valid in values:
  value=copy.deepcopy(base);value[key]=valid;check('enum-string-'+key+'-'+valid,value,True)
value=copy.deepcopy(base);value['unrecognized']=True;check('unknown-field-rejected',value,False)
for key in ['timestamp_iso8601','source_host','resolved_ip','elapsed_ms','os_error_code']:
 value=copy.deepcopy(base);value[key]=None;check('nullable-'+key,value,True)
for ip in ['127.0.0.1','::1']:
 value=copy.deepcopy(base);value['resolved_ip']=ip;check('resolved-'+ip,value,True)
fixtures=sorted((S/'fixtures/quick-check').glob('*.json'));assert fixtures,'실행한 fixture가 0개이면 수용 불가'
for fixture in fixtures:
 valid=fixture.name.startswith(('valid_','synthetic-valid-'));invalid=fixture.name.startswith(('invalid_','synthetic-invalid-'));assert valid or invalid,fixture.name
 check('actor-fixture-'+fixture.name,json.loads(fixture.read_text(encoding='utf-8')),valid)
baseline=json.loads((R/'artifacts/qg0-inspector-baseline.json').read_text(encoding='utf-8'))
changed=[rel for rel,sha in baseline['protected_inspector_sha256'].items()if not (R/rel).exists()or hashlib.sha256((R/rel).read_bytes()).hexdigest()!=sha]
checks.append({'name':'inspector-protected-source-unchanged','passed':not changed,'changed':changed})
trace=(D/'docs/quick-check/requirement-traceability.md').read_text(encoding='utf-8');ids=set(re.findall(r'Q-P0-\d\d',trace));expected={f'Q-P0-{i:02d}'for i in range(1,14)}
checks.append({'name':'exact-13-quick-p0-requirements','passed':ids==expected,'found':sorted(ids),'missing':sorted(expected-ids),'extra':sorted(ids-expected)})
reference=R/'docs/requirements/Network_Path_Inspector_Harness_PRD_v1.2.md'
checks.append({'name':'prd-v12-byte-preservation','passed':hashlib.sha256(reference.read_bytes()).hexdigest()==baseline['prd_v12_sha256']})
result={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'scope':'독립 합성 schema·요구추적·Inspector 소스 보존 검사. 프로브/GUI/VM/성능 수용 아님','executed':len(checks),'passed':sum(x['passed']for x in checks),'failed':sum(not x['passed']for x in checks),'checks':checks}
(R/'artifacts'/(args.evidence_name+'.json')).write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:v for k,v in result.items()if k!='checks'},ensure_ascii=False,indent=2));print(json.dumps([x for x in checks if not x['passed']],ensure_ascii=False,indent=2));raise SystemExit(0 if result['failed']==0 else 1)
