"""worker 진입점 수정본의 실제 실행·회귀와 최종 독립 검토 대기 경계를 기록한다."""
import datetime
import hashlib
import json
import pathlib
import re
import subprocess
import tomllib

R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgquickapp'
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()

def git(*args):
    p=subprocess.run(['git','-C',str(W),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=40)
    assert p.returncode==0,p.stderr
    return p.stdout.rstrip('\r\n')

def evidence(name,exit_code=0):
    item=load('artifacts/commands/'+name+'.json')
    assert item['exit_code']==exit_code and not item['partial']
    return item

def counts(item):
    text=pathlib.Path(item['log']).read_text(encoding='utf-8')
    rows=re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;',text)
    assert rows
    return {key:sum(int(row[i]) for row in rows) for i,key in enumerate(['passed','failed','ignored'])}

native=load('artifacts/qg2f-app-entry-owned-native.json')
assert native['status']=='OWNED_COMMANDLINE_AND_LOCALHOST_IPC_PASS_REVIEW_PENDING'
assert len(native['commandline_cases'])==native['commandline_case_count']==38
assert len(native['supervisor_self_tests'])==native['supervisor_self_test_count']==6
assert native['native_harness']['passed']==1 and native['native_harness']['ignored']==0
assert all(case['passed'] for case in native['commandline_cases']+native['supervisor_self_tests'])
assert all(sha(W/path)==value for path,value in native['source_sha256'].items())
review=load('artifacts/qg2f-app-entry-independent-review.json')
assert all(sha(W/path)==value for path,value in review['immutable_source_sha256'].items())
protected=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(sha(R/path)==value for path,value in protected.items())
accepted=load('artifacts/qg2e-trace-runner-acceptance.json')
assert all(sha(R/path)==value for path,value in accepted['source_sha256'].items())
old={p['name']:p for p in tomllib.loads((R/'Cargo.lock').read_text(encoding='utf-8'))['package']}
new={p['name']:p for p in tomllib.loads((W/'Cargo.lock').read_text(encoding='utf-8'))['package']}
assert set(new)-set(old)=={'network-quick-check'} and all(new[k]==v for k,v in old.items())
items={key:evidence(name,exit_code) for key,name,exit_code in [
    ('actor_repair_default','qg2f-app-repair-all-targets',0),
    ('actor_repair_clippy_failure','qg2f-app-repair-clippy',101),
    ('final_app_default','qg2f-app-parent-final-all-targets',0),
    ('final_app_clippy','qg2f-app-parent-final-clippy',0),
    ('final_app_fmt','qg2f-app-parent-final-fmt',0),
    ('final_app_whitespace','qg2f-app-parent-final-whitespace',0),
    ('owned_native_driver','qg2f-app-owned-native-driver',0),
    ('workspace_default','qg2f-app-worktree-workspace-tests',0),
    ('workspace_clippy','qg2f-app-worktree-workspace-clippy',0),
]}
app_counts=counts(items['final_app_default'])
workspace_counts=counts(items['workspace_default'])
assert app_counts=={'passed':12,'failed':0,'ignored':1}
assert workspace_counts=={'passed':427,'failed':0,'ignored':23}
changes=git('status','--porcelain','--untracked-files=all').splitlines()
assert {line[3:] for line in changes}==set(review['repair_writes'])
# 수용/통합 commit이 아니라 소스와 실행 시점을 고정하는 로컬 보존 commit이다.
git('add',*review['repair_writes'])
git('-c','core.autocrlf=false','commit','-m','chore: preserve app worker validation pending final static review')
assert not git('status','--porcelain')
now=datetime.datetime.now().astimezone().isoformat()
record={'recorded_at':now,'status':'PURE_AND_OWNED_NATIVE_PASS_FINAL_REVIEW_PENDING',
        'source_sha256':native['source_sha256'],'worktree':str(W),'branch':git('branch','--show-current'),
        'preserved_source_commit':git('rev-parse','HEAD'),'worktree_clean':True,
        'actor_repair_pipeline':'artifacts/qg2f-app-entry-repair-pipeline.json',
        'parent_changes':['cargo fmt app','시험repeat().take()→repeat_n한줄동등정리·실패101로그보존'],
        'parent_production_semantic_changes':False,'evidence':items,'app_default_counts':app_counts,
        'workspace_default_counts':workspace_counts,'native_test_passed':1,'commandline_cases_passed':38,
        'supervisor_self_tests_passed':6,'owned_native':'artifacts/qg2f-app-entry-owned-native.json',
        'existing_lock_packages_identical':len(old),'protected_inspector_unchanged':len(protected),
        'final_static_review':'deleg_c26f9c10','final_static_review_received':False,
        'accepted':False,'root_integrated':False,'full_qg2_accepted':False,'product_accepted':False,
        'remaining':['최종독립QA수신·대조후만선택통합과root조합검증',
                     '전체QG2실환경·GUI/QG3·진단시작경로·배포/PE/CRT/서명/VM/성능미완료']}
out=R/'artifacts/qg2f-app-entry-parent-execution.json'
assert not out.exists()
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
state=load('artifacts/quick-check-progress.json')
state['recorded_at']=now
state['qg2_app_entry'].update(status=record['status'],actor_alive_at_checkpoint=False,
    final_review='deleg_c26f9c10',final_review_received=False,independent_review_status='수정후최종정적재검토수신대기',parent_execution=str(out.relative_to(R)),
    source_sha256=record['source_sha256'],baseline_commit=record['preserved_source_commit'],
    app_default_counts=app_counts,workspace_default_counts=workspace_counts,
    native_test_passed=1,commandline_cases_passed=38,supervisor_self_tests_passed=6,native_executed=True,
    accepted=False,root_integrated=False)
state['remaining_blockers']=record['remaining']
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
section=f'''\n## 제품 worker 진입점 실제 EXE·순수·workspace 회귀 완료 / 최종 독립QA 대기 — {now}
- Flash qg2appentryfix 종료exit0·14 FILE READ/WRITE·허용2파일변경·위반0·Inspector61불변. 부모가4SHA를직접재계산하고전체lib/native소스를읽은뒤에만format/실행했다. 이전7종지적은수정했으나최종해소판정은독립재QA deleg_c26f9c10 두검토결과수신전이므로대기.
- 수정본app순수12PASS/1native ignored. strictClippy는새시험repeat().take() lint1건으로101;부모가repeat_n한줄동등정리후최종app12PASS1ignored/strictClippy0/fmt0/whitespace0을재실행했다. 부모production추가의미변경0. 이전8PASS1FAIL과Clippy101원본은보존했다.
- 고정source로빌드한정확제품EXE·Rust harness의절대경로/파일SHA를고정하고부모boundedChild(실제Python Child 자기시험6PASS)로명령행38개를검증했다. noargs/help/잘못된flag·arity·host·port/Windows비Unicode·원문비반사와소유127.0.0.1/::1동일포트literal worker의정확JSON/최종LF/상한/exit를실제확인. 전체deadline/각stdout16KiB·stderr1KiB+sentinel/정확소유Child kill·wait·reader join만사용했다.
- 정확제품EXE를사용하는Rust ignored localhost IPC1PASS. 양쪽127.0.0.1/::1동일포트리스너를반드시확보·끝까지소유하고기존NativeDnsProbeBackend.resolve한번만실행해RESOLVED/nonempty/원문host·port/전체반환주소정확루프백/오류없음을검증했다. localhost의hosts/cache/DNS실제경로나패킷부재는증명하지않는다.
- worktree workspace전체순수427PASS/23ignored·workspace strictClippy0. app12는427에포함되며native1·CLI38·감독기6은서로다른범위로단순합산하지않는다. 기존registry/local패키지{len(old)}필드전체불변·새app1개만추가. 소스보존commit {record['preserved_source_commit']}·전용worktree clean확인.
- root는아직미통합·이번slice미수용·최종QA대기. 기존root415/native22수용과Inspector{len(protected)}SHA불변유지. GUI/진단시작UI·CLI/QG3/전체QG2/단일EXE배포인증/OS지원/서명/성능미완료.
\n'''
for name in ['PROGRESS.md','RESUME.md']:
    path=R/name
    first,rest=path.read_text(encoding='utf-8').split('\n',1)
    path.write_text(first+'\n'+section+rest,encoding='utf-8',newline='\n')
path=R/'작업내용/NPI_2026-10-22_001.md'
path.write_text(path.read_text(encoding='utf-8')+section,encoding='utf-8',newline='\n')
print(json.dumps({'status':record['status'],'workspace':workspace_counts,'app':app_counts,
                  'native':1,'commandline':38,'supervisor':6,'preserved_commit':record['preserved_source_commit'],
                  'root_integrated':False,'accepted':False},ensure_ascii=False))
