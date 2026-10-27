"""최종 고정 native 비교 source의 실제 시험과 전체 회귀를 보존하고 최종 QA를 기다린다."""
import datetime
import hashlib
import json
import pathlib
import re
import subprocess

R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgtcpnative'
TEST='crates/network-core/tests/tcp_product_native_equivalence.rs'
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()

def git(*args):
    p=subprocess.run(['git','-C',str(W),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=40)
    assert p.returncode==0,p.stderr
    return p.stdout.rstrip('\r\n')

repair=load('artifacts/qg2h-tcp-native-parent-repair.json')
assert all(sha(W/path)==value for path,value in repair['source_sha256'].items())
contract=load('artifacts/qg2h-tcp-native-actor-prepared.json')
assert all(sha(W/path)==value and sha(R/path)==value for path,value in contract['immutable_source_sha256'].items())
steps={}
for key,name in [('workspace','qg2h-tcp-native-final-workspace'),('new_native','qg2h-tcp-native-final-owned'),
                 ('clippy','qg2h-tcp-native-final-clippy'),('fmt','qg2h-tcp-native-final-fmt')]:
    item=load('artifacts/commands/'+name+'.json')
    assert item['exit_code']==0 and not item['partial']
    text=pathlib.Path(item['log']).read_text(encoding='utf-8')
    rows=re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;',text)
    if rows:
        item['test_counts']={key:sum(int(row[i]) for row in rows) for i,key in enumerate(['passed','failed','ignored'])}
    steps[key]=item
old=load('artifacts/qg2g-tcp-replay-acceptance.json')
old_workspace=next(step for step in old['execution'] if step['name'].endswith('-workspace'))
body=(W/TEST).read_text(encoding='utf-8')
pure_count=len(re.findall(r'^\s*#\[test\]',body,re.M))
native_count=len(re.findall(r'^\s*#\[tokio::test\]',body,re.M))
assert steps['workspace']['test_counts']=={'passed':old_workspace['passed']+pure_count,'failed':0,
                                           'ignored':old_workspace['ignored']+native_count}
assert steps['new_native']['test_counts']=={'passed':native_count,'failed':0,'ignored':0}
assert pure_count==1 and native_count==4
assert {line[3:] for line in git('status','--porcelain','--untracked-files=all').splitlines()}=={TEST}
assert body.endswith('\n') and all(line==line.rstrip(' \t') for line in body.splitlines())
git('add',TEST)
git('-c','core.autocrlf=false','commit','-m','test: preserve owned native product TCP comparisons pending final review')
assert not git('status','--porcelain')
assert sha(W/TEST)==repair['source_sha256'][TEST]
now=datetime.datetime.now().astimezone()
record={'recorded_at':now.isoformat(),'status':'NEW_NATIVE_AND_WORKSPACE_PASS_FINAL_REVIEW_PENDING',
    'worktree':str(W),'source_sha256':repair['source_sha256'],'preserved_source_commit':git('rev-parse','HEAD'),
    'worktree_clean':True,'execution':steps,'workspace_counts':steps['workspace']['test_counts'],
    'new_native_counts':steps['new_native']['test_counts'],'previous_root_native_23_not_rerun_in_this_record':True,
    'test_review':'deleg_5a10ae9f','test_review_received':False,'source_changed_after_review_request':False,
    'first_execution':'artifacts/qg2h-tcp-native-first-execution.json',
    'parent_repair':'artifacts/qg2h-tcp-native-parent-repair.json','production_changes':0,
    'inspector_original_protected_unchanged':60,'existing_approved_visibility_exception_files':1,
    'compiled':True,'native_executed':True,'root_integrated':False,'accepted':False,
    'full_qg2_accepted':False,'product_accepted':False,
    'limits':['이번4native는독립IPv4/IPv6연결성공/거부·소유loopback만',
              '1000ms실패보존·기존기본3000ms입력채택·제품상수/성능목표/REFUSED10061기대불변',
              '같은실측raw replay와별도native시점을구분·elapsed/localport무조건동등요구0',
              '새pure1은전체workspace에포함·새native4는별도·기존rootnative23은이기록에서미재실행',
              'Archive/Session/제품EXE명시진단/GUI/전체QG2/OS/VM/배포/성능수용아님']}
out=R/'artifacts/qg2h-tcp-native-parent-execution.json'
assert not out.exists()
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
state=load('artifacts/quick-check-progress.json')
state['recorded_at']=record['recorded_at']
state['next_qg2_native_review'].update(record,parent_execution=str(out.relative_to(R)),actor_alive_verified=False)
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
counts=record['workspace_counts']
section=f'''\n## 실제 양제품 TCP native4PASS·기본회귀{counts['passed']}PASS / 최종 QA 대기 — {record['recorded_at']}
- 초기정적QA deleg_f90b8199는실행안전true를제시했지만시험품질F1~F4를지적. 실제첫native0PASS4FAIL은struct/Value키순서byte오판으로재현했고, 내용JSON은4건전부동일함을실패원문byte배열에서확인했다. F1만수정후1000ms native2PASS2FAIL(거부fixture는실제TIMED_OUT)로원인을분리했다. 실패로그/원본source를보존했다.
- 임시1000ms대신제품의기존DEFAULT_TCP_TIMEOUT_MS=3000을양제품동일입력으로주었을때기존REFUSED/10061기대를그대로충족해4PASS. 제품상수·성능목표·결과판정·OS설정변경0이며루프백TIMED_OUT을실DROP검증으로승격하지않는다. 이특성규명4PASS는추가F2~F4강화전source이며최종판근거와별도다.
- 부모는새test1파일만F1전체값동등/동일표현전후byte보존·F2Envelope.target/양raw.target/resolvedIP·F3native/replay각자상태/근거/context/원시msg/limitations·F4명시null키존재를보강하고Clippy3지적과독점race과장문구를정정했다. sourceSHA {sha(W/TEST)} 고정뒤전체workspace {counts['passed']}PASS/0FAIL/{counts['ignored']}ignored·새native4PASS/0FAIL·strictClippy/fmt exit0. 같은SHA로최종독립QA deleg_5a10ae9f 두검토요청·결과수신전·요청이후변경0.
- 전용worktree clean/보존local commit {record['preserved_source_commit']}. W/root기존94source불변·Inspector원본60+기수용pub4byte1예외유지·새production변경0. root새test미통합/미수용. 기존root433/native23/CLI38수용은이전범위이고이번새native4와합산하지않음. 최종QA→선택통합→root전체native/회귀재검증전이다.
- 실제EngineEnvelope메모리raw/Quickrunner·동일실측raw replay·성공연결각acceptpeer/실제EOF 애플리케이션수신0만검증. Archive/정규Session·제품EXE명시진단시작/GUI/QG3·전체QG2실VLAN/DROP/ICMP차단/다중NIC/VPN·OS/VM/일반사용자·성능·배포인증미완료.
\n'''
for name in ['PROGRESS.md','RESUME.md']:
    path=R/name
    first,rest=path.read_text(encoding='utf-8').split('\n',1)
    path.write_text(first+'\n'+section+rest,encoding='utf-8',newline='\n')
path=R/'작업내용'/('NPI_'+now.strftime('%Y-%m-%d')+'_001.md')
path.write_text(path.read_text(encoding='utf-8')+section,encoding='utf-8',newline='\n')
print(json.dumps({'status':record['status'],'workspace_counts':counts,'new_native_counts':record['new_native_counts'],
    'preserved_source_commit':record['preserved_source_commit'],'worktree_clean':True,'root_integrated':False},ensure_ascii=False))
