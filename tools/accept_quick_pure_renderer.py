"""독립 QA의 취소 출처 라벨 지적을 보정한 순수 renderer만 제한 수용한다."""
import datetime,hashlib,json,pathlib,re,subprocess
R=pathlib.Path(__file__).resolve().parents[1];sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
def load(n):return json.loads((R/n).read_text(encoding='utf-8'))
def save(n,d):(R/n).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def git(w,*args):
 p=subprocess.run(['git','-C',str(w),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60);assert p.returncode==0,p.stderr;return p.stdout.rstrip('\r\n')
def command(name):
 row=load('artifacts/commands/'+name+'.json');assert row['exit_code']==0 and not row['partial']
 text=pathlib.Path(row['log']).read_text(encoding='utf-8');counts=re.findall(r'test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored;',text)
 if counts:row['counts']={k:sum(int(c[i]) for c in counts) for i,k in enumerate(['passed','failed','ignored'])}
 return row
p=load('artifacts/qg3d-runtime-render-prepared.json');spec=p['roles']['qgrender'];W=pathlib.Path(spec['worktree']);lib='apps/network-quick-check/src/lib.rs';source='apps/network-quick-check/src/gui_result_render.rs'
OUT=R/'artifacts/qg3d-pure-renderer-acceptance.json';assert not OUT.exists()
assert git(W,'rev-parse','HEAD')==p['base_commit'] and git(W,'branch','--show-current')==spec['branch']
assert all(sha(W/n)==h for n,h in spec['immutable_sha256'].items() if n!=lib);assert all(sha(W/n)==h for n,h in spec['reference_sha256'].items())
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
original_lib=(R/'.harness/evidence/qg3d-atoms-original/qgrender/lib-before-registration.rs').read_text(encoding='utf-8')
current_lib=(W/lib).read_text(encoding='utf-8');assert current_lib.count('pub mod gui_result_render;\n')==1 and current_lib.replace('pub mod gui_result_render;\n','',1)==original_lib
approved=R/'.harness/evidence/qg3d-render-reviewed-before-a01/gui_result_render.rs';assert sha(approved)=='4e74d3fe12017022847a6038eecc52cbde291a06ff740b1a48c98bf64d3c3638'
old=approved.read_text(encoding='utf-8');current=(W/source).read_text(encoding='utf-8');cut='#[cfg(test)]\nmod tests {'
old_prod=old.split(cut)[0];new_prod=current.split(cut)[0]
pat=r'    writeln!\(\s*w,\s*"취소 원인은 이 필드만으로 구분하지 않음 \(사용자 요청·한도·실행 오류 가능\)"\s*\)\?;\n'
restored,count=re.subn(pat,'',new_prod);assert count==1
assert restored.replace('실행 취소 여부 (cancelled)','사용자 취소 여부 (cancelled)')==old_prod
old_names=re.findall(r'#\[test\]\s*fn (\w+)',old);new_names=re.findall(r'#\[test\]\s*fn (\w+)',current)
assert set(new_names)-set(old_names)=={'parent_system_cancelled_flag_does_not_imply_user_request'} and len(new_names)==22 and len(old_names)==21
traces={}
for i in range(2):
 trace=pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/delegation/live/deleg_563bb086')/f'task-{i}.log'
 assert 'end status=completed exit_reason=completed' in trace.read_text(encoding='utf-8')[-500:];traces[str(trace)]=sha(trace)
commands={n:command(n) for n in ['qg3d-render-a01-focused','qg3d-render-a01-workspace','qg3d-render-a01-clippy','qg3d-render-a01-fmt-check']}
assert commands['qg3d-render-a01-focused']['counts']=={'passed':22,'failed':0,'ignored':0}
assert commands['qg3d-render-a01-workspace']['counts']=={'passed':560,'failed':0,'ignored':35}
paths=[lib,source];assert set(line[3:] for line in git(W,'status','--porcelain').splitlines())==set(paths)
git(W,'add','--',*paths);git(W,'diff','--cached','--check');git(W,'commit','-m','feat(quick-check): add bounded provenance-preserving pure result renderer without inferring cancel cause')
commit=git(W,'rev-parse','HEAD');assert not git(W,'status','--porcelain')
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'ACCEPTED_PURE_GUI_RESULT_RENDERER_ONLY','accepted':True,
 'scope':'pure bounded ResultView/snapshot/phase to UTF8 display text only, including original DTO/metadata preservation and independent cancel cause',
 'worktree':str(W),'branch':spec['branch'],'preserved_commit':commit,'worktree_clean':True,'source_sha256':{n:sha(W/n) for n in paths},
 'independent_final_review_batch':'deleg_563bb086','review_trace_sha256':traces,'reviews':[{'area':'production','original_findings':['A-01 cancellation cause label'],
 'A01_parent_resolution':'label execution cancellation, explicit cause-not-inferred disclaimer and pure system-limit/error cancellation regression','post_review_production_delta_exact_label_plus_disclaimer_only':True},
 {'area':'test effect and whole-value preservation','findings':[]}],
 'review_representation':'parent normalized received review results, not reviewer verbatim JSON','original_F01_through_F05_resolved':True,
 'old_actor_compile_and_parent_repair_failures_preserved':True,'writer_credit':'Flash draft; parent production/test repairs and final A01 correction; independent reviews and actual parent tests',
 'focused_counts':commands['qg3d-render-a01-focused']['counts'],'workspace_counts':commands['qg3d-render-a01-workspace']['counts'],'focused_is_included_in_workspace':True,'commands':commands,
 'no_dependency_manifest_lock_Core_GuiState_existing_result_modules_changes':True,'parent_lib_change_exact_registration_only':True,
 'limits':['caller must pass matching completed snapshot/report; renderer does not prove matching origin','byte budget is display text only, not process memory/CPU hardcap or Win32 text/DPI acceptance','partial metadata/snapshot can remain with explicit truncation marker; partial result rows roll back'],
 'root_integrated':False,'gui_connected':False,'native_backend_measured':False,'clipboard_or_file_write_connected':False,'full_qg3_accepted':False,'full_qg5_accepted':False,'product_accepted':False,'remote_push_or_deploy':False}
save('artifacts/qg3d-pure-renderer-acceptance.json',record)
progress=load('artifacts/quick-check-progress.json');progress.update(recorded_at=record['recorded_at'],qg3d_pure_renderer_acceptance=record)
progress['completion_continuation'].update(status='RUNTIME_AND_RENDERER_ATOMS_ACCEPTED_NEXT_SELECTED_COMBINATION',current_review_batch=None)
save('artifacts/quick-check-progress.json',progress)
print(json.dumps({'status':record['status'],'commit':commit,'focused':record['focused_counts'],'workspace':record['workspace_counts'],'root_integrated':False,'gui_connected':False},ensure_ascii=False))
