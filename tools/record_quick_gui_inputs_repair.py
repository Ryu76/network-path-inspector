"""수정된 입력 GUI source·부모 실패/회귀·미수용 경계를 고정한다."""
import datetime, hashlib, json, pathlib, re
R=pathlib.Path(__file__).resolve().parents[1]
load=lambda p:json.loads((R/p).read_text(encoding='utf-8'))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
p=load('artifacts/qg3b-gui-inputs-actor-prepared.json');W=pathlib.Path(p['worktree'])
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
assert all(sha(W/n)==h for n,h in p['immutable_source_sha256'].items())
assert all(sha(W/n)==h for n,h in p['reference_sha256'].items())
def evidence(name):
 d=load('artifacts/commands/'+name+'.json');text=pathlib.Path(d['log']).read_text(encoding='utf-8')
 rows=[tuple(map(int,m)) for m in re.findall(r'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored',text)]
 return d|{'passed':sum(x[0] for x in rows),'failed':sum(x[1] for x in rows),'ignored':sum(x[2] for x in rows)}
workspace=evidence('qg3b-gui-inputs-parent-workspace')
assert (workspace['exit_code'],workspace['passed'],workspace['failed'],workspace['ignored'])==(0,500,0,35)
initial=evidence('qg3b-gui-inputs-original-presenter-tests')
assert (initial['exit_code'],initial['passed'],initial['failed'])==(101,7,3)
steps={name:evidence('qg3b-gui-inputs-'+name) for name in ['parent-focused-v1','parent-focused-v2','parent-focused-v3','parent-clippy-v1','parent-clippy-v3','parent-fmt-check']}
assert all(steps[name]['exit_code']==0 for name in ['parent-focused-v3','parent-clippy-v3','parent-fmt-check'])
assert steps['parent-focused-v2']['exit_code']==101
source={n:sha(W/n) for n in p['actor_writes']}
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'PARENT_REPAIRED_DEFAULT_GATES_PASS_NATIVE_REVIEW_PENDING',
 'worktree':str(W),'branch':p['branch'],'source_sha256':source,'parent_metadata_changes':p['parent_metadata_changes'],
 'root_before_sha256':p['root_before_sha256'],'immutable_source_sha256':p['immutable_source_sha256'],
 'reference_sha256':p['reference_sha256'],'original_production_and_tests_preserved':True,
 'parent_repairs':['Win32 binding import and PCWSTR compilation fixes','checked HWND lifetime and safe context retention on destruction failure',
 'option/input per-field truncation latches and strict UTF16/read length checks','option EN_CHANGE/stale and exact owned sender checks',
 'shared production hidden/visible creation and WM_COMMAND tests; actual partial child failure/drop counts/own quit cleanup',
 'Core080/bracketedIPv6 fixtures; bounded Display while formatting; whole-state/exact-boundary extra tests'],
 'parent_authorship_includes_production_not_format_only':True,'original_presenter_failure':initial,'workspace':workspace,'steps':steps,
 'parent_duplicate_test_append_failure':{'evidence':'artifacts/commands/qg3b-gui-inputs-parent-focused-v2.json','exit_code':101,
 'preserved_source':'.harness/evidence/qg3b-parent-duplicate-tests.rs','repair':'exact duplicate six-test/helper block removed after equality check'},
 'independent_reviews_pending':['deleg_9c4ff836/task-0','deleg_9c4ff836/task-1'],
 'new_default_test_count':23,'gui_focused_count_including_old_state_tests':46,'new_owned_native_test_count':4,
 'native_executed':False,'visible_gui_verified':False,'root_integrated':False,'accepted':False,
 'network_diagnostics_connected':False,'full_qg2_accepted':False,'full_qg3_accepted':False,'product_accepted':False}
out=R/'artifacts/qg3b-gui-inputs-parent-repair.json';assert not out.exists();out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
progress=load('artifacts/quick-check-progress.json');progress['recorded_at']=record['recorded_at'];progress['qg3_native_gui_inputs']=record
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(progress,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
section=f'''
## QG3B 부모 보정·기본 회귀 통과·native 재검토 중 — {record['recorded_at']}
- 원본 독립QA는native9건/순수3건·native실행보류였다. 원본6개·compile101(3errors/143warnings)·focused7PASS3FAIL을보존했다. 부모가실제생산코드와시험을보정했으므로Flash독점작성/단순format보정이라고하지않는다.
- 전용W 전체기본회귀500PASS/0FAIL/35ignored,focused46PASS(기존state23+신규entry7+presenter16,workspace와중복). strictClippyalltargets/fmtcheck0. 새native4는35ignored에포함되며아직실행하지않았다.
- HWND생존·파괴실패/Boxretention/quit정리·엄격UTF16/각옵션잘림·EN_CHANGE stale·정확sender·실제childclass부분실패관측/WM_COMMAND시험·080/IPv6fixture·bounded오류format보강. 원본실패및부모strictClippy101/중복시험appendcompile101은별도보존뒤보정·재검증했다.
- deleg_9c4ff836 독립2재검토중. source6/부모metadata2만·root60입력/공유59/참조12 SHA유지. 메인통합/수용0·실제native/UI실행0. 최신root기능수용근거는여전히477/31ignored다. 전체QG2/QG3/OS/배포미수용.
- 근거 artifacts/qg3b-gui-inputs-parent-repair.json. 다음native안전QA→소유native4→실화면/기존CLI실EXE→선택통합/메인재검증순서.
'''
for name,header in [('PROGRESS.md','# NPI 진행 기록'),('RESUME.md','# NPI 개발 재개 및 승인 경계')]:
 path=R/name;text=path.read_text(encoding='utf-8');assert section not in text;path.write_text(text.replace(header+'\n',header+'\n'+section,1),encoding='utf-8',newline='\n')
print(json.dumps({'status':record['status'],'workspace_passed':500,'ignored':35,'new_default':23,'native_executed':False,'root_integrated':False},ensure_ascii=False))
