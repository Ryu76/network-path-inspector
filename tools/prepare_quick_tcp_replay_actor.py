"""가시성 실패/성공을 검증하고, 이미 승인된 공개 함수는 고정한 채 Flash에 시험만 맡긴다."""
import datetime
import hashlib
import json
import pathlib
import subprocess

R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgtcpreplay'
ENGINE='crates/npi-probes/src/engine.rs'
TEST='crates/network-core/tests/tcp_product_projection_replay.rs'
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
prepared=load('artifacts/qg2g-tcp-replay-prepared.json')
assert load('artifacts/qg2g-tcp-replay-explicit-approval.json')['authorization_granted']
old=(R/ENGINE).read_bytes()
new=(W/ENGINE).read_bytes()
assert sha(R/ENGINE)==prepared['root_engine_sha256']
assert new==old.replace(b'fn apply_tcp_result(',b'pub fn apply_tcp_result(',1)
assert new.replace(b'pub fn apply_tcp_result(',b'fn apply_tcp_result(',1)==old
assert len(new)==len(old)+4
for name,code in [('qg2g-tcp-replay-private-before-fix',101),('qg2g-tcp-replay-public-signature',0)]:
    item=load('artifacts/commands/'+name+'.json')
    assert item['exit_code']==code and not item['partial']
    text=pathlib.Path(item['log']).read_text(encoding='utf-8')
    assert ('error[E0603]' in text and 'is private' in text) if code else ('1 passed; 0 failed;' in text)
assert all(sha(W/path)==value for path,value in prepared['frozen_source_sha256'].items() if path!=ENGINE)
assert sha(W/TEST)==prepared['parent_test_sha256']
for args in [['add',ENGINE],['-c','core.autocrlf=false','commit','-m','feat: expose approved TCP projector without changing its body']]:
    p=subprocess.run(['git','-C',str(W),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=40)
    assert p.returncode==0,p.stderr
status=subprocess.run(['git','-C',str(W),'status','--porcelain'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=40)
head=subprocess.run(['git','-C',str(W),'rev-parse','HEAD'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=40)
assert status.returncode==head.returncode==0 and not status.stdout.rstrip('\r\n')
contract={
    'version':'qg2g-tcp-product-projection-replay-0.1','recorded_at':datetime.datetime.now().astimezone().isoformat(),
    'authorization':'사용자명시허용·기존함수public만·본문/매핑/측정불변+양제품순수회귀',
    'worktree':str(W),'stage':'qg2tcpreplay','role':'qgtcpreplay','model':'gemini-3.8-flash-high',
    'baseline_commit':head.stdout.rstrip('\r\n'),'actor_writes':[TEST],
    'parent_engine_change':{'path':ENGINE,'root_original_sha256':sha(R/ENGINE),'approved_worktree_sha256':sha(W/ENGINE),
                            'added_bytes':4,'exact_change':'fn apply_tcp_result(→pub fn apply_tcp_result(','body_unchanged':True},
    'immutable_source_sha256':{path:sha(W/path) for path in prepared['frozen_source_sha256']},
    'parent_signature_test_sha256':sha(W/TEST),
    'public_apis':['npi_probes::engine::apply_tcp_result(&mut npi_core::FeatureResult,&network_core::TcpMeasurement)',
                   'network_core::tcp_to_quick_result(&network_core::QuickContext,&network_core::TcpMeasurement)'],
    'pure_rule':'일반동기test만·runtime/소켓/DNS/네이티브/프로세스/파일I/O0',
    'identity':{'feature_id':'tcp_connect','group_id':'G-NET'},
    'expected_mapping':[
        {'outcome':'CONNECTED','code':None,'inspector':['PASS','OBSERVED'],'quick':['PASS','OBSERVED']},
        {'outcome':'REFUSED','code':10061,'inspector':['FAIL','OBSERVED'],'quick':['FAIL','OBSERVED']},
        {'outcome':'RESET','code':10054,'inspector':['FAIL','OBSERVED'],'quick':['FAIL','OBSERVED']},
        {'outcome':'TIMED_OUT','codes':[None,10060],'inspector':['FAIL','OBSERVED'],'quick':['FAIL','OBSERVED']},
        {'outcome':'UNREACHABLE','codes':[10051,10065],'inspector':['FAIL','OBSERVED'],'quick':['FAIL','OBSERVED']},
        {'outcome':'LOCAL_ERROR','codes':[None,0,99999,-2147483648,2147483647],
         'inspector':'ERROR/코드Some이면OBSERVED·None이면UNKNOWN','quick':['UNKNOWN','OBSERVED']},
        {'outcome':'CANCELLED','codes':[None,0,10061],'inspector':['CANCELLED','UNKNOWN'],'quick':['UNKNOWN','UNKNOWN']},
        {'outcome':'DNS_ERROR','codes':[None,11001],'inspector':'ERROR/코드Some이면OBSERVED·None이면UNKNOWN','quick':['FAIL','OBSERVED']},
        {'outcome':'미인식빈값과비빈값','codes':[None,0,99999],'inspector':'ERROR/코드Some이면OBSERVED·None이면UNKNOWN','quick':['UNKNOWN','UNKNOWN']},
    ],
    'raw_preservation':'두실제함수에동일&measurement를전달·전후measurement전체Eq/serde동등·Quick raw_measurement전체to_value동등·OS None/Some0/i32MIN/MAX→Inspector i64무손실·elapsed 0/비영/u64MAX·IPv4/IPv6·local_address Some/None·메시지UTF8/CRLF/quote/backslash·limitations원래순서/중복/빈배열보존',
    'inspector_preservation':'FeatureResult는원시DTO컨테이너가아님. 실제apply가보존하는code/duration/limitations prefix와OS오류메시지추가·stale evidence/time초기화를검증. 원시target/local_address를row가그대로저장한다고주장하지않음. run_profile EngineEnvelope 저장경로는이replay로실행검증되지않음.',
    'forbidden':['동작/DTO/매핑수정','다른보호소스/manifest/lock/contract/README수정',
                 '상태정규화/강제동등·Inspector최종결과수작업생성·판정기복제/include추출우회',
                 '실제connect_once/run_profile/runtime/network/프로세스/OS호출·실파일읽기쓰기',
                 '기존회귀/부모public signature시험삭제·약화','성공/배포/전체QG2수용주장'],
    'accepted':False,'root_integrated':False,
}
out=R/'artifacts/qg2g-tcp-replay-actor-prepared.json'
assert not out.exists()
out.write_text(json.dumps(contract,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
ref=W/'.harness/references/tcp-product-replay-contract.json'
ref.parent.mkdir(parents=True,exist_ok=True)
assert not ref.exists()
ref.write_text(json.dumps(contract,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
reads=[TEST,ENGINE,'crates/network-core/src/quick.rs','crates/network-core/src/lib.rs',
       'crates/network-core/tests/quick_core_regression_tests.rs','crates/npi-probes/src/tcp.rs',
       'crates/npi-core/src/models.rs','crates/npi-core/src/lib.rs','contracts/quick-check-interface-v0.1.json',
       'crates/network-core/Cargo.toml','fixtures/g1/valid_registry_contract.json',
       '.harness/references/tcp-product-replay-contract.json']
assert all((W/path).is_file() for path in reads)
prompt=f'''당신은사용자가명시승인한동일원시TCP→양제품실제projector의순수회귀FILE ONLY작성자다. 전용worktree={W.as_posix()}.
FILE READ/EDIT/CREATE·내부파일탐색만. command/run_command/terminal/shell/PowerShell/manage_task/git/컴파일/시험/설치/네트워크/OS호출/계정/DB/에이전트/재위임금지·읽기용명령도금지. 모든경로는worktree내절대경로·root/다른worktree/문서링크추적금지.
수정허용정확1파일(기존입력이며부모signature시험포함):{W.as_posix()}/{TEST}. engine소스는읽기만;작성권한없음. 별도테스트파일/스크립트/manifest/lock/README/원본문서/계약/다른source변경금지.
기존읽기입력정확목록:{json.dumps([str(W/path) for path in reads],ensure_ascii=False)}. worktree AGENTS.md준수·부재파일추측읽기반복금지.
먼저.harness/references/tcp-product-replay-contract.json을읽어라. 부모가사용자허용후기존private apply_tcp_result 앞에pub 4바이트만추가했다. 원본전체bytes로pub만제거하면원본동일을기계검증했다. 실제컴파일witness는E0603 exit101→공개후signature1PASS. 기능/함수본문/DTO/상태매핑/측정동작은불변이고root에는아직공개변경을통합하지않았다. 부모는93파일동결·61개보호중engine외60개W불변·engine공개sha고정. 당신은test만작성한다.
- 부모 parent_public_projector_signature_contract 시험은삭제/약화하지말라. 추가회귀는일반#[test]동기함수로명명하고양제품실제API npi_probes::engine::apply_tcp_result와network_core::tcp_to_quick_result를모두호출해야한다. 같은measurement를두호출에넘기고원본전후전체Eq/serialized value보존을확인. 수작업Inspector최종결과/판정복제/mockprojector/include추출금지. 기존classpathcore개별매핑시험반복만으로공백해소주장금지.
- 初期rowは古いstatus/evidence/time/code/limitations等を持つ入力fixtureとして構築し、その後必ず実APIで上書きされた出力を検証する。
- 초기FeatureResult는입력fixture로만생성: feature_id tcp_connect,group_id G-NET·staleevidence/time/duration/code등을넣고실제apply가출력한status/evidence/code/duration/limitations prefix·OSmsg추가/증거와시각초기화를확인한다. measurement.limitations.clone은입력그대로순서/중복/빈배열보존돼야함. 이raw적용은G1 Session/EngineEnvelope저장실행증거가아니다.
- expected matrix는계약대로독립literal기대값을사용하고각제품status/evidence를따로assert. CONNECTED와REFUSED/RESET/TIMEOUT/UNREACHABLE정상매핑은양쪽일치, CANCELLED/LOCAL_ERROR/DNS_ERROR/미인식차이는그대로characterization해야함. testnormalizer로같게만들거나실제함수match를projector로복제금지. raw errorCode None과Some0구분·i32MIN/MAX→Inspector i64무손실검증. current frozen Quick와Inspector매핑을절대변경하지말라.
- TIMED_OUT 코드Some/None,UNREACHABLE코드2개,LOCAL_ERROR코드None/0/unknown/i32MIN/MAX,CANCELLED코드None/0/known,DNS_ERROR/미인식None/0/unknown은타입DTO replay경계이며실제connect_once가그조합을생성한다는증거아님을주석으로구분. classify코드taxonomy기존시험은이미있으니그것만재작성금지.
- IPv4/IPv6 타깃과local_address Some/None,elapsed 0/비영/u64MAX,오류메시지None/UTF8·CRLF·quote/backslash,limitations빈배열/순서중복을행렬로검증. application_bytes_sent는정상0을포함한raw전체동등성을확인. Quick details정확3키와raw_measurement전체serde_json::to_value입력동등·오류코드/elapsed보존·Context메타데이터/targetport/IP attribution도검증. Inspectorrow의target/localaddress원시저장은없으므로없는필드만들지말라.
- 원시공유타입reexport/함수포인터parent시험을통해실제한타입으로두함수에전달됨을증명. 정상공유관측의field매핑을축별로확인하되문자열DTO전체동일요구금지. 타입fixture의합성상태/evidence OBSERVED는프로젝터계약characterization이지실관측아님.
- runtime/socket/DNS/native/process/std::env::current_exe/현재시각/실파일read-write/run_profile/connect_once호출금지. 조건부return/skip/ignore·Clippy suppression금지. 외부의존추가0·이미있는serde_json/npi_core/npi_probes/network_core만사용. 테스트보조함수인수<=7·너무복잡한tuple은Case구조체로좁게정리가능하나실제projector복제금지.
한국어흐름주석·UTF8·마지막개행1개·후행공백없음. 현제품동일EXE기반root427/native23/CLI38은부모가이전에실행한기록이며당신시험결과아님. 전체QG2실환경·GUI/QG3/배포인증은이번승인에포함되지않음. 최종한국어변경경로/시험설계/부모검증필요사항만. 컴파일/실행/수용주장금지.
'''
# 다른 언어 잔여 문장을 실행 계약에 혼용하지 않는다.
prompt=prompt.replace('- 初期rowは古いstatus/evidence/time/code/limitations等を持つ入力fixtureとして構築し、その後必ず実APIで上書きされた出力を検証する。\n','')
prompt_path=R/'.harness/prompts/qg2tcpreplay-qgtcpreplay.md'
assert not prompt_path.exists()
prompt_path.write_text(prompt,encoding='utf-8',newline='\n')
print(json.dumps({'stage':contract['stage'],'baseline_commit':contract['baseline_commit'],
                  'public_only_engine_sha256':sha(W/ENGINE),'actor_writes':[TEST],
                  'signature_passed':1,'root_integrated':False,'accepted':False},ensure_ascii=False))
