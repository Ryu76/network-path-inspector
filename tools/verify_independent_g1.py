"""Independent G1 contract regression against the compiled Rust library."""
import argparse,copy,hashlib,json,os,pathlib,shutil,subprocess,sys,datetime
ROOT=pathlib.Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser();parser.add_argument('--core-root',type=pathlib.Path,default=ROOT);args=parser.parse_args()
H=ROOT/'.harness';A=ROOT/'artifacts';A.mkdir(exist_ok=True)
contract=json.loads((ROOT/'contracts/g1-interface-contract.json').read_text(encoding='utf-8'))
probe=H/'independent-probe';(probe/'src').mkdir(parents=True,exist_ok=True)
(probe/'Cargo.toml').write_text('[package]\nname="npi-independent-g1"\nversion="0.0.0"\nedition="2024"\n[workspace]\n[dependencies]\nnpi-core={path='+json.dumps((args.core_root/'crates/npi-core').as_posix())+'}\nserde_json="=1.0.149"\n',encoding='utf-8')
shutil.copyfile(ROOT/'tools/independent_g1_probe.rs',probe/'src/main.rs')
env=os.environ.copy();env['CARGO_TARGET_DIR']=str(H/'target-independent-g1')
build=subprocess.run(['cargo','build','--offline','--manifest-path',str(probe/'Cargo.toml')],env=env,capture_output=True,encoding='utf-8',errors='replace',timeout=180)
(A/'g1-independent-build.log').write_text(build.stdout+'\n'+build.stderr,encoding='utf-8')
if build.returncode:print(build.stdout,build.stderr);sys.exit(build.returncode)
exe=H/'target-independent-g1/debug/npi-independent-g1.exe'
profile={'schema_version':'1.1','profile_id':'quick-default','label':'독립 검증','mode':'standalone','selected_features':contract['presets']['quick-default'],'capture_approved':False,'target':{'host':'127.0.0.1','port':1526,'protocol':'TCP'},'limits':contract['objects']['Limits'].copy()}
session={'schema_version':'1.1','session_id':'680e5f65-5e82-40f5-b85b-b5d13e5db061','mode':'standalone','host_role':'client','started_at_utc':'2026-10-20T00:00:00Z','timezone_offset_minutes':540,'clock_offset_ms':None,'clock_uncertainty_ms':None,'profile':profile,'evidence':[],'feature_results':[],'findings':[],'limitations':['아직 진단하지 않음'],'resource_metrics':{'peak_rss_bytes':None,'avg_cpu_percent':None,'capture_drops':None}}
cases=[]
def case(name,request,check):cases.append((name,request,check))
def valid(name,op,value):case(name,{'op':op,'value':value},lambda a:a.get('ok')is True)
def invalid(name,op,value):case(name,{'op':op,'value':value},lambda a:a.get('ok')is False and bool(a.get('errors')))
valid('default-profile-valid','validate_profile',profile);valid('unexecuted-session-valid','validate_session',session)
for port in [0,65536,-1,True,'1526',1.5]:
 p=copy.deepcopy(profile);p['target']['port']=port;invalid('invalid-port-'+str(port),'validate_profile',p)
for host in ['::1','2001:db8::1234','test.example.invalid','127.0.0.1']:
 p=copy.deepcopy(profile);p['target']['host']=host;valid('valid-host-'+host,'validate_profile',p)
for host in ['',' ','http://127.0.0.1','host/path','a@b','192.0.2.0/24','a,b','a b']:
 p=copy.deepcopy(profile);p['target']['host']=host;invalid('invalid-host-'+host,'validate_profile',p)
for field,value in [('max_hops',0),('retries',4),('max_concurrent_tcp',5),('capture_max_bytes',50*1024*1024+1),('ui_updates_per_second',5),('tcp_timeout_ms',0)]:
 p=copy.deepcopy(profile);p['limits'][field]=value;invalid('bound-'+field,'validate_profile',p)
for features in [['tcp_connect','tcp_connect'],['invented_probe']]:
 p=copy.deepcopy(profile);p['selected_features']=features;invalid('invalid-feature-array-'+','.join(features),'validate_profile',p)
for code,outcome in contract['tcp_error_mapping'].items():case('socket-code-'+code,{'op':'classify','code':int(code)},lambda a,want=outcome:a==want)
case('known-connection-reset-is-not-local-failure',{'op':'classify','code':10054},lambda a:a=='RESET')
case('temporary-dns-failure-is-dns-error',{'op':'classify','code':11002},lambda a:a=='DNS_ERROR')
case('unrecoverable-dns-failure-is-dns-error',{'op':'classify','code':11003},lambda a:a=='DNS_ERROR')
case('unknown-socket-no-success',{'op':'classify','code':None},lambda a:a=='LOCAL_ERROR')
case('cancel-precedes-deadline',{'op':'classify','code':10061,'timed_out':True,'cancelled':True},lambda a:a=='CANCELLED')
case('deadline-observation',{'op':'classify','code':None,'timed_out':True},lambda a:a=='TIMED_OUT')
case('canonical-registry-exact',{'op':'registry'},lambda a:a==contract['features'])
valid('registry-valid','validate_registry',contract['features'])
r=copy.deepcopy(contract['features']);r[0]['dependencies']=[r[1]['feature_id']];r[1]['dependencies']=[r[0]['feature_id']];invalid('registry-cycle','validate_registry',r)
r=copy.deepcopy(contract['features']);r[1]['feature_id']=r[0]['feature_id'];invalid('registry-duplicate','validate_registry',r)
r=copy.deepcopy(contract['features']);r[0]['dependencies']=['not_a_feature'];invalid('registry-missing-dependency','validate_registry',r)
for key,value in [('session_id','not-a-uuid'),('started_at_utc','2026-02-30T00:00:00Z'),('timezone_offset_minutes',900),('schema_version','9.0')]:
 s=copy.deepcopy(session);s[key]=value;invalid('invalid-session-'+key,'validate_session',s)
finding={'classification':'OBSERVED','statement':'운영체제가 연결 거부 오류를 반환함','evidence_ids':['socket-1'],'confidence':'high','limitations':['응답 생성 주체 미확인'],'next_checks':['서버 리스닝 및 정책 로그 확인']}
s=copy.deepcopy(session);s['evidence']=[{'evidence_id':'socket-1','kind':'SOCKET','artifact_path':None,'synthetic':True}];s['findings']=[finding];valid('observed-os-refusal-valid','validate_session',s)
for label,mutator in [('missing-evidence',lambda x:x.update(evidence=[])),('empty-reference',lambda x:x['findings'][0].update(evidence_ids=[])),('packet-claim-with-socket',lambda x:x['findings'][0].update(statement='SYN 송신 확인')),('fabricated-rst',lambda x:x['findings'][0].update(statement='RST 수신 확인')),('blocker-certainty',lambda x:x['findings'][0].update(statement='방화벽 차단 확정'))]:
 bad=copy.deepcopy(s);mutator(bad);invalid(label,'validate_session',bad)
def planned_ok(answer,selected):
 if not answer.get('ok'):return False
 value=answer['result'];rows=value.get('feature_results',[])
 return len(rows)==23 and len({r['feature_id']for r in rows})==23 and all(r['status']!='PASS' and r['evidence_ids']==[] for r in rows) and all(r['status']=='SKIPPED_BY_USER' for r in rows if r['feature_id']not in selected) and set(value.get('execution_order',[]))<=set(selected)
case('selected-only-no-fake-results',{'op':'plan','value':profile,'capabilities':[]},lambda a:planned_ok(a,profile['selected_features']))
p=copy.deepcopy(profile);p['selected_features']=[];case('nothing-selected-no-work',{'op':'plan','value':p,'capabilities':[]},lambda a:planned_ok(a,[])and a['result']['execution_order']==[])
p=copy.deepcopy(profile);p['selected_features']=['packet_capture'];p['capture_approved']=False
case('capture-consent-cannot-be-capability-forged',{'op':'plan','value':p,'capabilities':['capture_consent','npcap','capture_privilege']},lambda a:a.get('ok')and next(r for r in a['result']['feature_results']if r['feature_id']=='packet_capture')['status']=='UNAVAILABLE' and 'packet_capture'not in a['result']['execution_order'])
p=copy.deepcopy(profile);p['selected_features']=['tcp_connect','packet_capture','tcp_traceroute'];p['capture_approved']=True
case('restore-risk-off',{'op':'restore','value':p},lambda a:a.get('ok')and not a['result']['capture_approved']and a['result']['selected_features']==['tcp_connect'])
legacy={'schema_version':'1.0','session_id':session['session_id'],'mode':'standalone','started_at_utc':session['started_at_utc'],'source':{'host_alias':'fixture-client','ip':'192.0.2.10'},'target':{'ip':'192.0.2.11','port':1526,'protocol':'TCP'},'capture':{'enabled':False},'tests':[],'findings':[],'artifacts':[]}
case('legacy-preserved-and-unknown',{'op':'convert','value':legacy},lambda a:a.get('ok')and a['result']['original']==legacy and a['result']['converted']['schema_version']=='1.1'and a['result']['converted']['clock_offset_ms']is None and not any(r['status']=='PASS'for r in a['result']['converted']['feature_results']))
fixture_cases=0
for fixture in sorted((ROOT/'fixtures/g1').glob('*.json')):
 if not fixture.name.startswith(('valid_','invalid_')):continue
 value=json.loads(fixture.read_text(encoding='utf-8'))
 op='validate_registry' if isinstance(value,list) else 'validate_profile' if 'profile_id'in value else 'validate_session'
 expected=fixture.name.startswith('valid_')
 case('cross-language-fixture-'+fixture.name,{'op':op,'value':value},lambda answer,want=expected:answer.get('ok')is want)
 fixture_cases+=1
assert fixture_cases==16,fixture_cases
request=''.join(json.dumps(c[1],ensure_ascii=False)+'\n'for c in cases)
run=subprocess.run([str(exe)],input=request,capture_output=True,encoding='utf-8',errors='replace',timeout=30)
answers=[json.loads(line)for line in run.stdout.splitlines()];assert len(answers)==len(cases),(len(answers),len(cases),run.stderr)
checks=[]
for (name,_,check),answer in zip(cases,answers):
 try:passed=bool(check(answer));error=None
 except Exception as ex:passed=False;error=str(ex)
 checks.append({'name':name,'passed':passed,'answer':answer,'check_error':error})
result={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'source_root':str(args.core_root),'compiled_probe_sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),'executed':len(checks),'passed':sum(x['passed']for x in checks),'failed':sum(not x['passed']for x in checks),'checks':checks}
(A/'g1-independent-result.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({k:v for k,v in result.items()if k!='checks'},ensure_ascii=False,indent=2));print(json.dumps([x for x in checks if not x['passed']],ensure_ascii=False,indent=2));sys.exit(0 if result['failed']==0 else 1)
