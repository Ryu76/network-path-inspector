"""명시 승인된 TCP 공개가시성 및 두 실제 projector 순수 replay 범위만 수용한다."""
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
proof=load('artifacts/qg2g-tcp-replay-root-validation.json')
assert proof['status']=='ROOT_EXECUTION_PASS_ACCEPTANCE_RECORD_PENDING'
assert len(proof['steps'])==7 and all(step['exit_code']==0 and not step['partial'] for step in proof['steps'])
steps={step['name'].removeprefix('qg2g-tcp-replay-root-'):step for step in proof['steps']}
assert (steps['workspace']['passed'],steps['workspace']['failed'],steps['workspace']['ignored'])==(433,0,23)
assert (steps['native']['passed'],steps['native']['failed'],steps['native']['ignored'])==(23,0,0)
assert steps['trace-boundaries']['passed']==14 and steps['dns-boundaries']['passed']==6
assert all(sha(R/path)==value and sha(W/path)==value for path,value in proof['source_sha256'].items())
assert load('artifacts/qg2g-tcp-replay-explicit-approval.json')['authorization_granted']
review=load('artifacts/qg2g-tcp-replay-final-independent-review.json')
assert review['findings']==[] and review['safe_to_execute_default_tests'] and len(review['transcripts'])==2
assert all(sha(pathlib.Path(item['path']))==item['sha256'] for item in review['transcripts'].values())
visibility=load('artifacts/qg2g-tcp-replay-visibility-review.json')
assert visibility['findings']==[] and visibility['source_sha256'][ENGINE]==sha(R/ENGINE)
cli=load('artifacts/qg2g-tcp-replay-root-commandline.json')
assert cli['status']=='ROOT_COMMANDLINE_PASS_NOT_ACCEPTED' and cli['native_harness'] is None
assert len(cli['commandline_cases'])==cli['commandline_case_count']==38
assert len(cli['supervisor_self_tests'])==cli['supervisor_self_test_count']==6
assert all(item['passed'] for item in cli['commandline_cases']+cli['supervisor_self_tests'])
assert all(sha(pathlib.Path(path))==value for path,value in cli['binary_sha256'].items())
protected=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
original=R/'.harness/baselines/qg2g-tcp-replay-root/engine.rs'
assert sha(original)==protected[ENGINE]
assert (R/ENGINE).read_bytes()==original.read_bytes().replace(b'fn apply_tcp_result(',b'pub fn apply_tcp_result(',1)
assert len((R/ENGINE).read_bytes())==len(original.read_bytes())+4
assert all(sha(R/path)==value for path,value in protected.items() if path!=ENGINE)
contract=load('artifacts/qg2g-tcp-replay-actor-prepared.json')
assert all(sha(R/path)==value for path,value in contract['immutable_source_sha256'].items())
worker=load('artifacts/qg2f-app-entry-acceptance.json')
assert all(sha(R/path)==value for path,value in worker['source_sha256'].items())
status=subprocess.run(['git','-C',str(W),'status','--porcelain'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
head=subprocess.run(['git','-C',str(W),'rev-parse','HEAD'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
assert status.returncode==head.returncode==0 and not status.stdout.rstrip('\r\n')
preserved=head.stdout.rstrip('\r\n')
assert preserved==load('artifacts/qg2g-tcp-replay-parent-execution.json')['preserved_source_commit']
now=datetime.datetime.now().astimezone()
record={'recorded_at':now.isoformat(),'slice':'QG2-G-APPROVED-TCP-PROJECTOR-PUBLIC-AND-PURE-REPLAY',
        'decision':'ACCEPTED_VISIBILITY_ONLY_TCP_PROJECTOR_AND_PURE_CROSS_PRODUCT_REPLAY_ONLY',
        'accepted':True,'root_integrated':True,'full_qg2_accepted':False,'product_accepted':False,
        'qg3_started':False,'full_prd23_4_accepted':False,'prd23_4_supporting_pure_evidence':True,
        'source_sha256':proof['source_sha256'],'preserved_source_commit':preserved,
        'approval':'artifacts/qg2g-tcp-replay-explicit-approval.json',
        'original_protection_baseline':'artifacts/qg0-inspector-baseline.json',
        'protected_original_unchanged':len(protected)-1,'approved_visibility_change_files':1,
        'approved_added_bytes':4,'function_body_unchanged':True,
        'approved_delta':{'path':ENGINE,'original_sha256':sha(original),'approved_sha256':sha(R/ENGINE),
                          'rule':'기존함수선언의pub추가만·제거하면원본전체byte동일'},
        'root_metadata_and_worker_source_unchanged':True,
        'execution':proof['steps'],'new_replay_tests_passed':6,
        'root_commandline_cases_passed':38,'supervisor_self_tests_passed':6,
        'independent_reviews':['deleg_6b0609ec','deleg_fa9790f8'],
        'final_review':'artifacts/qg2g-tcp-replay-final-independent-review.json','new_findings':[],
        'scope':['기존apply_tcp_result public접근만·본문/DTO/매핑/측정불변',
                 '같은원시TcpMeasurement를양제품실제변환함수에전달·입력전후전체보존',
                 '정상/거부/재설정/timeout/도달불가일치와CANCELLED/LOCAL_ERROR/DNS_ERROR/unknown차이명시',
                 'OS code None/Some0/미정의/i32MIN/MAX무손실·duration·UTF8·CRLF/quote/backslash·IPv4/IPv6',
                 '중복순서/빈limitations·staleevidence/time제거·nullablemetadata·Quick전체raw동등'],
        'limits':['새6test는workspace433에포함·native23은기존동일범위·CLI38/감독기6/경계14+6별도',
                  '합성DTOcharacterization이며실OS오류·TCP연결·패킷·차단장비·실시간관측증거아님',
                  'Inspectorprojector는profile/target/featureID검증/영구증거생성/Session수용API가아님',
                  'run_profile EngineEnvelope의raw저장경로와Archive/Session은이replay가실행하지않음',
                  'nullablemetadata혼합4조합전체나Inspector추가한계문구전체동등은아님',
                  '제품별상태/근거차이정규화·무조건전체DTO동등성을주장하지않음'],
        'excluded':['전체QG2실VLAN/DROP/ICMP차단·다중NIC/VPN','GUI/QG3·제품명시진단시작UI/CLI·TXT/CSV',
                    'Release/PE/CRT/서명/VM·일반사용자/OS지원·성능·Inspector전체G2이후'],
        'author_note':'Flash test작성과부모pub변경·하네스·시험정정/보강·실행/검토·선택통합을구분함·AI Pro독점작성아님'}
out=R/'artifacts/qg2g-tcp-replay-acceptance.json'
assert not out.exists()
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
state=load('artifacts/quick-check-progress.json')
state['recorded_at']=record['recorded_at']
state['inspector_changed_files']=[ENGINE]
state['inspector_original_unchanged_count']=len(protected)-1
state['shared_core_directory']='crates/network-core (IP/DNS/Trace 실행기·실제 제품 projector replay 제한 수용, 전체 QG2 미수용)'
state['next_qg2_review'].update(status=record['decision'],accepted=True,root_integrated=True,
    acceptance_artifact=str(out.relative_to(R)),latest_execution=proof,new_replay_tests_passed=6,
    preserved_source_commit=preserved,full_qg2_accepted=False,product_accepted=False,
    protected_original_unchanged=len(protected)-1,approved_visibility_change_files=1,
    blocker=None,next_decision_required=None)
state['inspector_protection']={'original_baseline_preserved':True,'original_unchanged':len(protected)-1,
    'approved_delta':record['approved_delta'],'approval':record['approval']}
state['remaining_blockers']=['전체QG2실VLAN/DROP/ICMP차단·다중NIC/VPN환경미검증',
                            '제품명시진단시작경로/GUI/QG3/TXT·CSV/Release·PE·CRT·서명/VM·일반사용자/성능미완료']
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
section=f'''\n## 승인된 TCP 공개변경·양제품 실제 projector 순수 replay root 제한 수용 — {record['recorded_at']}
- 사용자명시「허용」범위대로Inspector apply_tcp_result에pub 4바이트만추가·함수본문/상태/오류/측정동작완전불변. root원본보호60SHA불변+승인된engine1개가시성예외를별도기록했고원래보호baseline61목록/해시는수정하지않았다. 기존61불변은이전시점이며최신판정은60+1승인delta다.
- Flash test1파일작성·부모기대문구정정/실제중복·nullablemeta/모든matrix raw/OScode/duration/stale/불변성보강·동일source실행을거쳤다. 가시성QA deleg_6b0609ec 및최종test QA deleg_fa9790f8 두검토모두findings=[]·실제두함수호출/독립기대값/제품별차이무보정/순수성확인. QA요청뒤doc공백한줄차이는역SHA증명·실행코드/단언변경0.
- root workspace433PASS/23ignored·명시native23PASS/0ignored·Trace경계14/DNS경계6PASS·strictClippy/fmt exit0. 고정root제품EXE CLI38PASS·bounded감독기6PASS도재실행. 새replay6은433에포함되며native수추가0·서로합산하지않음. 함수공개전E0603와최초5PASS1FAIL/Clippy101증거는보존했다.
- 제품코드/시험은engine와새replay시험2파일만선택통합·Cargo/lock/계약/worker source불변. 보존local commit {preserved}·전용worktree clean;root는기존미커밋작업보존·원격push/배포/전체branch merge없음. artifacts/qg2g-tcp-replay-acceptance.json.
- 수용은같은원시DTO→양실제projector의순수characterization과승인된public접근만. CANCELLED/LOCAL_ERROR/DNS_ERROR/unknown의기존제품별차이를그대로명시하며실제순차TCP결과일치/패킷관측/EngineEnvelope·Archive·Session저장검증으로승격하지않는다. PRD23.4보조순수근거이지전체통합수용아님.
- 전체QG2실환경·GUI/QG3·제품진단시작경로/TXT·CSV/Release/PE/CRT/서명/VM·일반사용자/OS지원/성능미완료. 이전worker기반과공용resolver/Trace정책수용은불변으로유지했다.
\n'''
for name in ['PROGRESS.md','RESUME.md']:
    path=R/name
    first,rest=path.read_text(encoding='utf-8').split('\n',1)
    path.write_text(first+'\n'+section+rest,encoding='utf-8',newline='\n')
for name in ['docs/quick-check/gates.md','apps/network-quick-check/README.md']:
    path=R/name
    path.write_text(path.read_text(encoding='utf-8')+section,encoding='utf-8',newline='\n')
path=R/'작업내용'/('NPI_'+now.strftime('%Y-%m-%d')+'_001.md')
path.write_text(path.read_text(encoding='utf-8')+section,encoding='utf-8',newline='\n')
print(json.dumps({'decision':record['decision'],'workspace_passed':433,'native_passed':23,
    'new_replay_passed':6,'commandline_passed':38,'protected_original_unchanged':len(protected)-1,
    'approved_visibility_files':1,'full_qg2_accepted':False,'product_accepted':False},ensure_ascii=False))
