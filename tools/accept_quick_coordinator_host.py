"""동결된 QG3C 부모보정본의 독립 mock host 범위만 실제 회귀와 함께 수용한다."""
import datetime,hashlib,json,pathlib,re,subprocess
R=pathlib.Path(__file__).resolve().parents[1];sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
def load(n):return json.loads((R/n).read_text(encoding='utf-8'))
def save(n,d):(R/n).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def git(w,*args):
 r=subprocess.run(['git','-C',str(w),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60)
 assert r.returncode==0,r.stderr;return r.stdout.rstrip('\r\n')
p=load('artifacts/qg3c-parent-rewrite-prepared.json');base=load('artifacts/qg3c-coordinator-repair-prepared.json');W=pathlib.Path(p['worktree'])
OUT=R/'artifacts/qg3c-coordinator-host-acceptance.json';assert not OUT.exists()
assert all(sha(W/n)==h for n,h in p['source_sha256'].items())
assert all(sha(W/n)==h for n,h in base['immutable_sha256'].items())
assert all(sha(W/n)==h for n,h in base['reference_sha256'].items())
assert all(sha(W/n)==h for n,h in p['references_sha256'].items())
main=load('artifacts/qg5a-pure-result-acceptance.json');lib='apps/network-quick-check/src/lib.rs'
assert all(sha(R/n)==h for n,h in base['root_before_sha256'].items() if n!=lib)
assert all(sha(R/n)==h for n,h in main['source_sha256'].items())
traces={}
for k in range(2):
 trace=pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/delegation/live/deleg_eed4ff20')/f'task-{k}.log'
 assert 'end status=completed exit_reason=completed' in trace.read_text(encoding='utf-8')[-500:];traces[str(trace)]=sha(trace)
commands={}
for name in ['qg3c-parent-compile-v1','qg3c-parent-clippy-v1','qg3c-parent-owned-mock-v1','qg3c-parent-workspace','qg3c-parent-fmt-check']:
 row=load('artifacts/commands/'+name+'.json');assert row['exit_code']==0 and not row['partial']
 log=pathlib.Path(row['log']).read_text(encoding='utf-8');counts=re.findall(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;',log)
 if counts:row['counts']={key:sum(int(c[j+1]) for c in counts) for j,key in enumerate(['passed','failed','ignored'])}
 commands[name]=row
assert commands['qg3c-parent-owned-mock-v1']['counts']=={'passed':23,'failed':0,'ignored':0}
assert commands['qg3c-parent-workspace']['counts']=={'passed':523,'failed':0,'ignored':35}
assert set(line[3:] for line in git(W,'status','--porcelain').splitlines())==set(p['source_sha256'])
for n in p['source_sha256']:
 text=(W/n).read_text(encoding='utf-8');assert text.endswith('\n') and all(line==line.rstrip(' \t') for line in text.splitlines())
git(W,'add','--',*p['source_sha256']);git(W,'diff','--cached','--check');git(W,'commit','-m','feat(quick-check): preserve reviewed single-run memory coordinator and deterministic shutdown tests')
commit=git(W,'rev-parse','HEAD');assert not git(W,'status','--porcelain')
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'ACCEPTED_ISOLATED_MEMORY_BACKEND_COORDINATOR_HOST_ONLY',
 'accepted':True,'root_integrated':False,'scope':'独立 GUI execution host thread/channel/start atomicity/samecancel/drain/fault and full report/snapshot ownership with actual Core run_quick and memory backend only',
 'scope_ko':'실제 Core runner와 메모리 백엔드를 사용한 독립 실행호스트의 시작·취소·결과귀속·정상/고장 종료 수명주기',
 'worktree':str(W),'branch':'ai-pro/qgcoordfix','preserved_commit':commit,'worktree_clean':True,'source_sha256':p['source_sha256'],
 'independent_safety_review_batch':'deleg_eed4ff20','review_trace_sha256':traces,'reviews':[{'area':'production/closure/channel lifecycle','execution_safety_approved':True,'findings':[]},{'area':'test synchronization/cleanup','execution_safety_approved':True,'findings':[]}],
 'review_representation':'parent normalized delivered conclusions; not reconstructed verbatim JSON',
 'old_QA01_through_QA12_resolved_static_and_current_tests_pass':True,'original_failure_evidence_preserved':True,
 'execution':commands,'focused_counts':commands['qg3c-parent-owned-mock-v1']['counts'],'workspace_counts':commands['qg3c-parent-workspace']['counts'],
 'focused_tests_in_workspace_not_additional':True,'immutable_base_files':len(base['immutable_sha256']),
 'writer_credit':'Flash original and corrective drafts preserved/rejected; parent rewrote production and tests after QA, then independent safety QA and real parent execution',
 'module_consumption':'#[cfg(test)] private library module; not normal product dispatcher or native GUI wiring',
 'actual_effects':'owned std threads/channels/CPU-only Tokio runtime/runner time measurement and bounded test timeout/panic hook output',
 'no_real_network_dns_helper_file_win32_in_new_tests':True,'no_native_tests_executed_this_slice':True,
 'root_main_separate_counts':main['receiving_root_workspace_counts'],'root_main_acceptance':'artifacts/qg5a-pure-result-acceptance.json',
 'non_ui_drain_owner_implemented':False,'native_backend_runtime_connected':False,'gui_connected':False,'full_qg2_accepted':False,'full_qg3_accepted':False,'full_qg5_accepted':False,'product_accepted':False,
 'resource_limit':'Drop requests cancellation but does not synchronously drain or guarantee immediate OS resource reclamation. Lost completion state remains Failed even after cleanup.',
 'remote_push_or_deploy':False}
save('artifacts/qg3c-coordinator-host-acceptance.json',record)
progress=load('artifacts/quick-check-progress.json');progress.update(recorded_at=record['recorded_at'],qg3c_memory_host=record)
progress['completion_continuation'].update(status='MEMORY_HOST_LOCALLY_ACCEPTED_NEXT_GUI_WIRING_PREPARATION',current_review_batch=None)
save('artifacts/quick-check-progress.json',progress)
summary=f'''
## QG3C 독립 메모리 실행호스트 실제 회귀·로컬 제한 수용 — {record['recorded_at']}
- 독립안전2QA deleg_eed4ff20 모두findings[]/정확23시험실행허용true. 동결source그대로부모timeout120초 아래실제 **23PASS0FAIL0ignored**. 실Core run_quick+메모리backend/소유thread+CPU-onlyruntime이며실socket/DNS/helper/Win32진입0. 기존500기본회귀와신규23이합쳐진W전체 **523PASS0FAIL35ignored**,strictClippy/fmt0. focused23은전체523에포함·합산금지. 기존ignored/native시험은이번실행0.
- 시작원자성/한건채널/같은cancelArc·실Pending후취소/drain·정확Empty→enqueue→finished재독·채널유실·실worker/backendDrop패닉·전체Result/snapshot/다른state격리·기존Finished실패보존·stale후속·assertunwind/Drop실종료관측시험이실제로통과했다. 원본Flash두실패·부모직접생산/시험보정·QA/실행출처를구분한다.
- Wclean 로컬commit **{commit}**. 독립memoryhost범위만acceptedtrue,**메인통합false/cfgtest소비만**. main은QG5A순수결과모듈까지492PASS31ignored별도다. 실제GUI·Native I/O driver runtime·nonUI drainowner/즉시OS회수/전체QG3/제품수용이아니다.
- 근거 artifacts/qg3c-coordinator-host-acceptance.json. 다음은GUIWIP+검증된host+메인순수결과모듈을분리보존된전용통합기준에조합하고,새실행selector/presenterbridge/nativebackendruntime/닫기drain·fatalowner이전을설계·구현한다. 기존입력전용selector/CLI/운영정책/이전UI입력승인timeout우회0 유지.
'''
for name,header in [('PROGRESS.md','# NPI 진행 기록'),('RESUME.md','# NPI 개발 재개 및 승인 경계')]:
 file=R/name;text=file.read_text(encoding='utf-8');assert text.count(header+'\n')==1
 file.write_text(text.replace(header+'\n',header+'\n'+summary,1),encoding='utf-8',newline='\n')
print(json.dumps({'status':record['status'],'commit':commit,'focused':record['focused_counts'],'workspace':record['workspace_counts'],'root_integrated':False,'gui_connected':False,'product_accepted':False},ensure_ascii=False))
