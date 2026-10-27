"""원본 결함과 부모 보정·실제 회귀·미실행 안전 게이트를 혼합하지 않고 기록한다."""
import datetime,hashlib,json,pathlib,re
R=pathlib.Path(__file__).resolve().parents[1];sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
def load(n):return json.loads((R/n).read_text(encoding='utf-8'))
def save(n,d):(R/n).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def command(name):
 row=load('artifacts/commands/'+name+'.json');text=pathlib.Path(row['log']).read_text(encoding='utf-8')
 counts=re.findall(r'test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored;',text)
 if counts:row['counts']={k:sum(int(c[i]) for c in counts) for i,k in enumerate(['passed','failed','ignored'])}
 return row
p=load('artifacts/qg3d-runtime-render-prepared.json');a=load('artifacts/qg3d-runtime-render-pipeline.json')
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
scopes={}
for role,spec in p['roles'].items():
 W=pathlib.Path(spec['worktree']);assert all(sha(W/n)==h for n,h in spec['immutable_sha256'].items() if not(role=='qgrender' and n=='apps/network-quick-check/src/lib.rs'))
 assert all(sha(W/n)==h for n,h in spec['reference_sha256'].items())
 if role=='qgrender':
  original=(R/'.harness/evidence/qg3d-atoms-original/qgrender/lib-before-registration.rs').read_text(encoding='utf-8')
  current=(W/'apps/network-quick-check/src/lib.rs').read_text(encoding='utf-8')
  assert current.count('pub mod gui_result_render;\n')==1 and current.replace('pub mod gui_result_render;\n','',1)==original
 note=load(str((W/'.harness/inputs/frozen'/('qg3d-runtime-parent-review.json' if role=='qgruntime' else 'qg3d-render-parent-review.json')).relative_to(R)))
 assert all(sha(W/n)==h for n,h in note['source_sha256'].items())
 for n,h in a['roles'][role]['source_sha256'].items():assert sha(R/'.harness/evidence/qg3d-atoms-original'/role/pathlib.Path(n).name)==h
 scopes[role]=note
cmds={n:command(n) for n in ['qg3d-runtime-original-focused','qg3d-render-mechanical-only-focused','qg3d-runtime-parent-compile-v1',
 'qg3d-runtime-parent-clippy','qg3d-render-parent-compile-v1','qg3d-render-parent-pure-v2','qg3d-render-parent-pure-v3','qg3d-render-parent-workspace','qg3d-render-parent-clippy']}
assert cmds['qg3d-runtime-original-focused']['counts']=={'passed':29,'failed':0,'ignored':0}
assert cmds['qg3d-render-mechanical-only-focused']['counts']=={'passed':12,'failed':0,'ignored':0}
assert cmds['qg3d-runtime-parent-compile-v1']['exit_code']==0
assert cmds['qg3d-runtime-parent-clippy']['exit_code']==101
assert cmds['qg3d-render-parent-workspace']['counts']=={'passed':559,'failed':0,'ignored':35}
assert cmds['qg3d-render-parent-pure-v3']['counts']=={'passed':21,'failed':0,'ignored':0}
assert cmds['qg3d-render-parent-clippy']['exit_code']==0
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'PARENT_REPAIRS_RENDER_TESTED_RUNTIME_SAFETY_RESULT_PENDING_RENDER_FINAL_QA_RUNNING',
 'original_review_batch_received':'deleg_24bbf177','original_failures_preserved':True,'scopes':scopes,'commands':cmds,
 'runtime_current_tests_written':34,'runtime_current_tests_executed':False,'runtime_current_compile_exit':0,
 'runtime_current_strict_clippy_exit':101,'runtime_clippy_remaining':'collapsible_if in cfg(test) on_runtime_drop notification; leave source frozen pending safety review result before style-only repair',
 'runtime_final_safety_review_batch':'deleg_16493768','runtime_review_result_received':False,
 'runtime_steer_not_delivered':'subagent no longer live at delivery; no conclusion inferred, await completion message',
 'render_current_focused_counts':cmds['qg3d-render-parent-pure-v3']['counts'],'render_current_workspace_counts':cmds['qg3d-render-parent-workspace']['counts'],
 'render_final_review_batch':'deleg_563bb086','render_final_review_count':2,'render_current_strict_clippy_exit':0,
 'no_new_dependency_manifest_lock_or_Core_changes':True,'parent_wrote_production_and_tests_not_flash_exclusive':True,
 'runtime_io_driver_functional_claim':'native shared builder enable_io static only; time-driver witness separate; actual socket/helper/nativebackend untested',
 'pure_render_limit':'UTF8 output byte budget is not process-wide hard memory or Win32/DPI/OS acceptance',
 'root_integrated':False,'gui_connected':False,'native_executed':False,'accepted':False,'product_accepted':False}
save('artifacts/qg3d-parent-repair-checkpoint.json',record)
progress=load('artifacts/quick-check-progress.json');progress.update(recorded_at=record['recorded_at'],qg3d_parent_repair=record)
progress['completion_continuation'].update(status=record['status'],current_review_batch={'runtime':'deleg_16493768','render':'deleg_563bb086'},current_pipeline='artifacts/qg3d-parent-repair-checkpoint.json')
save('artifacts/quick-check-progress.json',progress)
d=load('artifacts/quick-check-completion-directive-20261026.json');d.update(last_checkpoint=record['recorded_at'],status=record['status'],current_review_batch=progress['completion_continuation']['current_review_batch'])
for s in d['current_workstreams']:
 if s['id']=='execution-coordinator':s.update(status='parent_repaired_runtime_and_renderer_independent_final_reviews',next='receive final reviews -> runtime style repair and approved 34 tests -> required actual regressions -> selectively combine accepted atoms -> typed presenter/native UI execution wiring')
save('artifacts/quick-check-completion-directive-20261026.json',d)
summary=f'''
## QG3D 부모 보정·실제 renderer21/전체559·최종QA 대기 — {record['recorded_at']}
- 原QA deleg_24bbf177수신: runtime실행안전허용(내부OS driver효과는존재)·29시험실제29PASS이나초기화실패완료뒤thread종료전후속수락공백(F01)과증거F02~03미충족·수용0. renderer원본compile101(E0034)·순수안전허용→import만고친12시험실제12PASS에도상한소진후처리계속/대상별snapshot누락/이전결과귀속/문자열표시충돌미해소라수용0.
- 부모runtime source2보정: matching terminal-host 완료를받는즉시Failed/start폐쇄후원문적용·ordinary/CPU Err와구분;공개생성자의同mode값관측/time-only witness정확표현(IO는builder소스확인범위만),초기worker idlehandshake후factory0/첫1/둘째1. CPU2build/drop·첫Err후두번째success/nativePending全report+sameArc+runtimeDrop+실종료까지34시험작성. **compile-only0,현재34실시험0**. 최종안전QA **deleg_16493768** 결과수신대기. strictClippy실제101 중첩if한건은source동결때문에결과후style-only보정예정이며통과로표현하지않는다.
- 부모renderer생산직접보정: IO Write한종/상한Err전파·직렬화/순회즉시중단·全request/target/options/plan/metadata/원본DTO·JSONstringnullable/NUL/literalescape구분·busy의이전완료자료명시·완전행rollback/정확행수. 기존12시험함수유지하되바뀐quotedJSON/phase출처기대값만교정하고9보강. **순수21PASS0FAIL,해당W전체559PASS0FAIL35ignored,strictClippy0**. focused21은559에포함·합산금지. 원문Core/GuiState/manifest/lock/결과모듈변경0.
- 부모renderer첫보정에서직접serde trait의존누락compile101 발생→의존성추가없이기존serde_json+명시typedstream함수로수정. 중간macro trailingcomma compile101도보존후수정했다. 실패를actor탓/PASS로숨기지않는다. source원본3개는별도SHA불변보존.
- renderer최종독립2QA **deleg_563bb086** 실제진행중·source4e74d3fe동결. runtimee195c9be/tests f366a6c5동결유지. 새실native/socket/helper/GUI실행·메인통합·제품수용0. rootmain492/31ignored·이전host523/35ignored·기준combined538/35ignored·rendererW559/35ignored를구분한다. 기존UI입력승인timeout우회/운영網/OS정책/배포0.
- 근거 artifacts/qg3d-parent-repair-checkpoint.json 및각command.log/json. 다음최종QA회수→runtimestyle보정/안전승인범위34실시험→전체검증/선택조합→typedpresenter/nativeUI별도연결이다.
'''
for name,header in [('PROGRESS.md','# NPI 진행 기록'),('RESUME.md','# NPI 개발 재개 및 승인 경계')]:
 f=R/name;t=f.read_text(encoding='utf-8');assert t.count(header+'\n')==1
 f.write_text(t.replace(header+'\n',header+'\n'+summary,1),encoding='utf-8',newline='\n')
print(json.dumps({'status':record['status'],'runtime_compile':0,'runtime_clippy':101,'runtime_current_tests_executed':False,
 'render_focused':record['render_current_focused_counts'],'render_workspace':record['render_current_workspace_counts'],
 'render_clippy':0,'pending_review_batches':['deleg_16493768','deleg_563bb086'],'root_integrated':False},ensure_ascii=False))
