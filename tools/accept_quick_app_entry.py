"""root 조합회귀를 근거로 제품 동일EXE DNS worker 진입점의 작은 범위만 수용한다."""
import datetime
import hashlib
import json
import pathlib
import subprocess
import tomllib

R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgquickapp'
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
proof=load('artifacts/qg2f-app-entry-root-validation.json')
assert proof['status']=='ROOT_EXECUTION_PASS_ACCEPTANCE_RECORD_PENDING'
assert len(proof['steps'])==7 and all(step['exit_code']==0 and not step['partial'] for step in proof['steps'])
steps={step['name'].removeprefix('qg2f-app-entry-root-'):step for step in proof['steps']}
assert (steps['workspace']['passed'],steps['workspace']['failed'],steps['workspace']['ignored'])==(427,0,23)
assert (steps['native']['passed'],steps['native']['failed'],steps['native']['ignored'])==(23,0,0)
assert steps['trace-boundaries']['passed']==14 and steps['dns-boundaries']['passed']==6
assert all(sha(R/path)==value and sha(W/path)==value for path,value in proof['source_sha256'].items())
review=load('artifacts/qg2f-app-entry-final-independent-review.json')
assert review['review']=='deleg_c26f9c10' and review['findings']==[] and review['previous_findings_resolved']
assert len(review['transcripts'])==2
assert all(sha(pathlib.Path(item['path']))==item['sha256'] for item in review['transcripts'].values())
assert all(sha(R/path)==value for path,value in review['source_sha256'].items())
cli=load('artifacts/qg2f-app-entry-root-commandline.json')
assert cli['status']=='ROOT_COMMANDLINE_PASS_NOT_ACCEPTED'
assert len(cli['commandline_cases'])==cli['commandline_case_count']==38
assert len(cli['supervisor_self_tests'])==cli['supervisor_self_test_count']==6
assert all(case['passed'] for case in cli['commandline_cases']+cli['supervisor_self_tests'])
assert cli['native_harness'] is None
assert all(sha(pathlib.Path(path))==value for path,value in cli['binary_sha256'].items())
assert all(sha(pathlib.Path(path))==value for path,value in proof['product_binary_before_native_sha256'].items())
protected=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(sha(R/path)==value for path,value in protected.items())
frozen=load('artifacts/qg2f-app-entry-independent-review.json')['immutable_source_sha256']
assert all(sha(R/path)==value for path,value in frozen.items())
old={p['name']:p for p in tomllib.loads((R/'.harness/baselines/qg2f-app-entry-root/Cargo.lock').read_text(encoding='utf-8'))['package']}
new={p['name']:p for p in tomllib.loads((R/'Cargo.lock').read_text(encoding='utf-8'))['package']}
assert set(new)-set(old)=={'network-quick-check'} and all(new[k]==v for k,v in old.items())
status=subprocess.run(['git','-C',str(W),'status','--porcelain'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
head=subprocess.run(['git','-C',str(W),'rev-parse','HEAD'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
assert status.returncode==head.returncode==0 and not status.stdout.rstrip('\r\n')
preserved=head.stdout.rstrip('\r\n')
assert preserved==load('artifacts/qg2f-app-entry-parent-execution.json')['preserved_source_commit']
now=datetime.datetime.now().astimezone().isoformat()
record={'recorded_at':now,'slice':'QG2-F-PRODUCT-SAME-EXE-DNS-WORKER-ENTRYPOINT',
        'decision':'ACCEPTED_PRODUCT_DNS_WORKER_ENTRYPOINT_AND_CURRENT_EXE_BACKEND_FACTORY_ONLY',
        'accepted':True,'root_integrated':True,'full_qg2_accepted':False,'qg3_started':False,'product_accepted':False,
        'source_sha256':proof['source_sha256'],'binary_sha256':proof['product_binary_before_native_sha256'],
        'preserved_source_commit':preserved,'existing_lock_packages_identical':len(old),
        'inspector_protected_unchanged':len(protected),'execution':proof['steps'],
        'commandline_cases_passed':38,'supervisor_self_tests_passed':6,
        'independent_reviews':['deleg_8af528a1','deleg_a23a1e9a','deleg_c26f9c10'],
        'final_review':'artifacts/qg2f-app-entry-final-independent-review.json','new_findings':[],
        'resolved_findings':['ENTRY-STATIC-001','ENTRY-STATIC-002','ENTRY-STATIC-003','QA-01','QA-02','QA-03','QA-04','QA-05','QA-06','QA-07'],
        'scope':['정확worker flag/arity·host/port원본사전검증·불량인자비반사',
                 'noargs/help/invalid의진단·worker·factory·runtime·GUI자동실행0',
                 '공유resolver/serializer원문그대로·stdout한줄최종LF포함16384bytes·write/flush실패exit1',
                 'current_exe절대경로기반backend factory만·현재noargs/help/worker에서는미호출',
                 '별도QAhelper아닌정확제품EXE를기존NativeDnsProbeBackend가소유localhost worker로실행'],
        'limits':['factory만으로제품명시진단run_quick시작경로구현/종단검증이라주장하지않음',
                  'localhost OS해석의hosts/cache/DNS경로나양쪽주소반환/연결/패킷부재미증명',
                  'literalworker는OS이름해석아님·합성byte경계는상류512byte/주소32개수용증거아님',
                  'Windowsconsole/debug진입점검증이며GUIsubsystemIPC/단일EXE배포/서명/OS전체지원인증아님',
                  'app12는workspace427에포함·native1은rootnative23에포함·CLI38/감독기6/경계14+6별도범위',
                  'livehumantranscript본문잘림은완전한JSON저장아님·완전한async응답정규화판정과transcriptSHA를분리보존'],
        'excluded':['GUI/QG3·제품진단시작UI/CLI·TXT/CSV','전체QG2실VLAN/DROP/ICMP차단·다중NIC/VPN',
                    'Release/PE/asInvoker/CRT/서명/클린VM/일반사용자/성능·Inspector전체G2이후'],
        'parent_adjustments':['escapedJSON원문보존positive회귀','rustfmt·시험repeat_n동등1줄',
                              'workspace1등록·Cargo offline lock생성/기존24패키지완전불변확인',
                              'bounded실제Child검증기·명령행38·root조합회귀/실제native23'],
        'author_note':'Flash FILE ONLY 작성과부모하네스/회귀/기계검증·일부동등보정이결합된결과·AI Pro독점작성아님'}
out=R/'artifacts/qg2f-app-entry-acceptance.json'
assert not out.exists()
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
state=load('artifacts/quick-check-progress.json')
state['recorded_at']=now
state['qg2_app_entry'].update(status=record['decision'],accepted=True,root_integrated=True,
    acceptance_artifact=str(out.relative_to(R)),preserved_source_commit=preserved,
    final_review_received=True,latest_execution=proof,full_qg2_accepted=False,product_accepted=False,
    independent_review_status='최종두QA추가지적0·기존7종해소',qg3_started=False)
state['remaining_blockers']=['전체QG2실환경VLAN/DROP/ICMP차단·다중NIC/VPN미검증',
                            '제품명시진단시작경로/GUI/QG3/TXT·CSV/Release·PE·CRT·서명/VM·일반사용자/성능미완료']
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
section=f'''\n## 제품 동일 EXE DNS worker 진입점 root 조합회귀·제한 범위 수용 — {now}
- deleg_c26f9c10 최종두정적QA 모두findings=[]·기존7종해소. 부모가최종4appSHA/전용worktree clean/실제순수12·CLI38·소유localhost IPC1/기존lock24패키지전체불변을확인한뒤app4+workspace/lock2만root선택통합했다. Core/resolver/Inspector소스변경0·Inspector보호{len(protected)}SHA불변.
- root workspace427PASS/23ignored;명시native23PASS/0ignored;Trace경계14/DNS경계6PASS;strictClippy/fmt exit0. 고정root제품EXE의명령행38PASS와부모boundedChild감독기6PASS도다시실행했다. native23은기존22+새제품worker IPC1이며app12는427에포함·서로합산하지않음.
- 수용은엄격worker selector/arity/원본host·port사전검증/거부원문비반사/단일JSON·16384byte/write·flush실패/현재EXE backend factory/동일제품EXE localhost IPC만. noargs/help는정적stderr안내만하며진단을자동실행하지않는다. factory만으로명시진단run_quick종단경로가구현됐다고주장하지않음.
- 부모QA증거수집첫시도는잘린human transcript본문JSON파싱오류로root수정전중단했다. 완전한async최종응답에서정규화한판정과잘린transcriptSHA/완료prefix를구분해보존·복구했으며제품실패/QA미수신을성공으로위장하지않았다. artifacts/qg2f-app-entry-final-review-delivery.json 참조.
- source보존local commit {preserved};root는기존미커밋변경보존·전체branch merge/원격push/배포없음. artifacts/qg2f-app-entry-acceptance.json. 전체QG2실VLAN/DROP/ICMP차단·다중NIC/VPN미수용,GUI/QG3/명시진단시작경로/TXT·CSV/Release/PE/CRT/서명/VM·일반사용자/성능미완료. debug EXE는worker기반확인용이며배포용진단제품이아니다.
\n'''
for name in ['PROGRESS.md','RESUME.md']:
    path=R/name
    first,rest=path.read_text(encoding='utf-8').split('\n',1)
    path.write_text(first+'\n'+section+rest,encoding='utf-8',newline='\n')
for name in ['작업내용/NPI_2026-10-22_001.md','docs/quick-check/gates.md','apps/network-quick-check/README.md']:
    path=R/name
    path.write_text(path.read_text(encoding='utf-8')+section,encoding='utf-8',newline='\n')
print(json.dumps({'decision':record['decision'],'workspace_passed':427,'native_passed':23,
                  'commandline_passed':38,'inspector_unchanged':len(protected),'product_accepted':False,
                  'full_qg2_accepted':False},ensure_ascii=False))
