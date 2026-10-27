"""실제 소유 루프백 TCP 양제품 비교 회귀 범위만 수용한다. 전체 QG2/제품 수용은 아니다."""
import datetime
import hashlib
import json
import pathlib
import subprocess

R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgtcpnative'
TEST='crates/network-core/tests/tcp_product_native_equivalence.rs'
ENGINE='crates/npi-probes/src/engine.rs'
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
p=load('artifacts/qg2h-tcp-native-root-validation.json')
assert p['status']=='ROOT_EXECUTION_PASS_ACCEPTANCE_RECORD_PENDING' and p['new_native_test_names_verified']
assert len(p['steps'])==7 and all(step['exit_code']==0 and not step['partial'] for step in p['steps'])
steps={step['name'].removeprefix('qg2h-tcp-native-root-'):step for step in p['steps']}
assert (steps['workspace']['passed'],steps['workspace']['failed'],steps['workspace']['ignored'])==(434,0,27)
assert (steps['native']['passed'],steps['native']['failed'],steps['native']['ignored'])==(27,0,0)
assert steps['trace-boundaries']['passed']==14 and steps['dns-boundaries']['passed']==6
assert all(sha(R/path)==value and sha(W/path)==value for path,value in p['source_sha256'].items())
frozen=load('artifacts/qg2h-tcp-native-actor-prepared.json')['immutable_source_sha256']
assert all(sha(R/path)==value for path,value in frozen.items())
review=load('artifacts/qg2h-tcp-native-final-independent-review.json')
assert review['findings']==[] and len(review['transcripts'])==2
assert review['safe_to_execute_default_tests'] and review['safe_to_execute_owned_native_tests']
assert all(sha(pathlib.Path(item['path']))==item['sha256'] for item in review['transcripts'].values())
cli=load('artifacts/qg2h-tcp-native-root-commandline.json')
assert cli['status']=='ROOT_COMMANDLINE_PASS_NOT_ACCEPTED' and cli['native_harness'] is None
assert len(cli['commandline_cases'])==cli['commandline_case_count']==38
assert len(cli['supervisor_self_tests'])==cli['supervisor_self_test_count']==6
assert all(item['passed'] for item in cli['commandline_cases']+cli['supervisor_self_tests'])
assert all(sha(pathlib.Path(path))==value for path,value in cli['binary_sha256'].items())
protected=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(sha(R/path)==value for path,value in protected.items() if path!=ENGINE)
previous=load('artifacts/qg2g-tcp-replay-acceptance.json')
assert all(sha(R/path)==value for path,value in previous['source_sha256'].items())
original=R/'.harness/baselines/qg2g-tcp-replay-root/engine.rs'
assert sha(original)==protected[ENGINE]
assert (R/ENGINE).read_bytes().replace(b'pub fn apply_tcp_result(',b'fn apply_tcp_result(',1)==original.read_bytes()
for args in [['status','--porcelain'],['rev-parse','HEAD']]:
    r=subprocess.run(['git','-C',str(W),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
    assert r.returncode==0,r.stderr
    if args[0]=='status':
        assert not r.stdout.rstrip('\r\n')
    else:
        head=r.stdout.rstrip('\r\n')
assert head==load('artifacts/qg2h-tcp-native-parent-execution.json')['preserved_source_commit']
now=datetime.datetime.now().astimezone()
a={'recorded_at':now.isoformat(),'decision':'ACCEPTED_OWNED_LOOPBACK_NATIVE_TCP_PRODUCT_COMPARISON_TESTS_ONLY',
   'accepted':True,'root_integrated':True,'full_qg2_accepted':False,'product_accepted':False,'qg3_started':False,
   'paths':[TEST],'source_sha256':p['source_sha256'],'production_changes':0,'existing_tests_changed':0,
   'manifest_or_lock_changed':False,'preserved_source_commit':head,
   'root_execution':p['steps'],'new_native_tests_passed':4,'new_pure_tests_passed':1,
   'root_commandline_passed':38,'supervisor_tests_passed':6,
   'scope':['실제run_profile메모리EngineEnvelope와실제run_quick NativeProbeBackend TCP만소유IPv4/IPv6대조',
       '각각CONNECTED/REFUSED10061독립기대값·정확목적지/nullable/메타/OS원문/전체raw보존',
       '같은Inspector실측raw의실제Quickprojector replay와별도native시점측정을분리',
       '성공연결각acceptpeer/EOF관측·애플리케이션수신바이트0·TCP외프로브0'],
   'protected_original_unchanged':len(protected)-1,'existing_approved_visibility_exception_files':1,
   'protected_engine_sha256':sha(R/ENGINE),'original_baseline_not_rewritten':True,
   'reviews':['deleg_f90b8199','deleg_5a10ae9f'],'final_review':'artifacts/qg2h-tcp-native-final-independent-review.json',
   'final_findings':[],'first_failures':'artifacts/qg2h-tcp-native-first-execution.json',
   'input_characterization':'artifacts/qg2h-tcp-native-parent-repair.json',
   'native_input_ms':3000,'production_timeout_constant_changed':False,'performance_threshold_changed':False,
   'initial_1000ms_refusal_condition_passed':False,
   'limits':['기본434에는새pure1포함·별도native27에는기존23+새4포함·합산제품인증통계아님',
       '1000ms임시입력TIMEOUT실패보존·10061기대와기존기본3000ms/제품성능목표불변',
       'bound/nonlisten독점예약·모든race제거·OS즉시취소·강제회수완료보장아님',
       'Quick반환DTO→report보존이며connect_once반환직전DTO별도capture아님',
       'timestamp/source_host는null입력만·non-null metadata전달전체검증아님',
       '임시루프백timeout을실DROP/VLAN/ICMP차단/패킷/서비스정상으로해석하지않음',
       '정규Session/Archive·제품EXE명시진단시작/GUI/QG3이후·전체QG2·VM/일반사용자/OS/성능/배포미완료'],
   'author_note':'Flash초안작성·부모test보정/보강·실제실행·QA/선택통합을구분·AI Pro독점작성아님'}
out=R/'artifacts/qg2h-tcp-native-acceptance.json'
assert not out.exists()
out.write_text(json.dumps(a,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
s=load('artifacts/quick-check-progress.json')
s['recorded_at']=a['recorded_at']
s['next_qg2_native_review'].update(status=a['decision'],accepted=True,root_integrated=True,
    acceptance_artifact=str(out.relative_to(R)),root_execution=p['steps'],final_findings=[],
    full_qg2_accepted=False,product_accepted=False,test_review_received=True)
s['latest_root_validation']={'acceptance_artifact':str(out.relative_to(R)),'source_sha256':a['source_sha256'],
    'workspace':steps['workspace'],'native':steps['native'],'commandline_passed':38,
    'trace_boundaries_passed':14,'dns_boundaries_passed':6,'clippy_exit':0,'fmt_exit':0,
    'full_qg2_accepted':False,'product_accepted':False}
s['remaining_blockers']=['전체QG2실VLAN/DROP/ICMP차단·VPN/다중NIC/전체환경검증부재',
    '제품EXE명시진단시작경로·GUI/QG3~7·Release/PE/CRT/서명/VM·일반사용자/OS·성능미완료']
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(s,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
section=f'''\n## 소유 IPv4/IPv6 양제품 실제 TCP 비교 root 제한 수용 — {a['recorded_at']}
- 최종독립QA deleg_5a10ae9f 두검토모두findings=[]·실행안전true·초기F1~F4해소/기존3000ms입력채택은판정정규화나제품성능목표완화아님을확인. 부모고정SHA e926cb55d672b81d655160d9d4330a651877528d4de42eb82df34a9c84720f5c source로실행/원문증거대조후새test1파일만root선택통합했다. production/기존test/manifest/lock변경0.
- root 기본회귀434PASS/27ignored·명시native27PASS/0ignored(기존23+새IPv4/IPv6성공/거부4)·Trace경계14/DNS경계6PASS·strictClippy/fmt exit0. 실제root제품EXE CLI38PASS·bounded감독기6PASS도재검증. 새pure1은434에포함·새native4는27에포함·합산통계로과장하지않음.
- 실제run_profile메모리EngineEnvelope의TCPraw와실제run_quick/native결과를각자기대값/귀속/OS원문/nullable/전체raw에대조·같은Inspectorraw→실제Quickprojector replay는별도정확동등축. 성공각acceptpeer·실제EOF/수신애플리케이션바이트0관찰. 다른native시점elapsed/clientport전체의동일/상이조건요구0·TCP외프로브0. Archive/정규Session/패킷/서비스정상인증아님.
- 초기직렬화byte오판4FAIL→전체JSON값동등성수정뒤1000ms2PASS2FAIL(TIMED_OUT)→제품기존기본입력3000ms4PASS의실패/특성규명기록을보존했다. 이후F2~F4추가강화동일SHA로W/root모두재실행. 1000ms거부조건통과를주장하지않고3000ms의DROP성능시험으로치환하지도않는다. bound/nonlisten은독점예약/모든race제거보장아님.
- Inspector원본60SHA+기승인pub4byte1예외불변·원래baseline61해시목록미수정. Wclean/보존localcommit {head}·root기존미커밋변경보존·원격push/배포/전체branch merge없음. artifacts/qg2h-tcp-native-acceptance.json.
- 전체QG2실VLAN/DROP/ICMP차단/다중NIC/VPN·제품EXE명시진단시작/GUI/QG3이후·Release/PE/CRT/서명/VM·일반사용자/OS지원/성능미완료. timestamp/source_host는이번null입력범위만·connect_once반환직전DTO별도capture/OS즉시회수인증아님.
\n'''

for name in ['PROGRESS.md','RESUME.md']:
    path=R/name
    first,rest=path.read_text(encoding='utf-8').split('\n',1)
    path.write_text(first+'\n'+section+rest,encoding='utf-8',newline='\n')
for name in ['apps/network-quick-check/README.md','docs/quick-check/gates.md']:
    path=R/name
    path.write_text(path.read_text(encoding='utf-8')+section,encoding='utf-8',newline='\n')
path=R/'작업내용'/('NPI_'+now.strftime('%Y-%m-%d')+'_001.md')
path.write_text(path.read_text(encoding='utf-8')+section,encoding='utf-8',newline='\n')
print(json.dumps({'decision':a['decision'],'workspace_passed':434,'native_passed':27,'new_native_included':4,
    'cli_passed':38,'production_changes':0,'full_qg2_accepted':False,'product_accepted':False},ensure_ascii=False))
