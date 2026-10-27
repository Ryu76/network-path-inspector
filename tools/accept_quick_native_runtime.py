"""QG3D runtime configuration/memory-backend 범위만 실제 회귀와 독립 QA 근거로 수용한다."""
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
p=load('artifacts/qg3d-runtime-render-prepared.json');spec=p['roles']['qgruntime'];W=pathlib.Path(spec['worktree']);OUT=R/'artifacts/qg3d-native-runtime-acceptance.json';assert not OUT.exists()
assert git(W,'rev-parse','HEAD')==p['base_commit'] and git(W,'branch','--show-current')==spec['branch']
assert all(sha(W/n)==h for n,h in spec['immutable_sha256'].items());assert all(sha(W/n)==h for n,h in spec['reference_sha256'].items())
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
review=load(str((W/'.harness/inputs/frozen/qg3d-runtime-parent-review.json').relative_to(R)))
source=W/'apps/network-quick-check/src/gui_coordinator.rs';text=source.read_text(encoding='utf-8')
pattern=r'    if had_runtime\s*&& let Some\(hook\) = &config\.on_runtime_drop \{\n        hook\(\);\n    \}'
old='    if had_runtime {\n        if let Some(hook) = &config.on_runtime_drop {\n            hook();\n        }\n    }'
reconstructed,count=re.subn(pattern,old,text);assert count==1 and hashlib.sha256(reconstructed.encode()).hexdigest()==review['source_sha256']['apps/network-quick-check/src/gui_coordinator.rs']
delta=load('artifacts/qg3d-runtime-post-review-delta.json');assert delta['exact_only_two_Q01_test_functions_changed']
tests=W/'apps/network-quick-check/src/gui_coordinator_tests.rs';assert sha(tests)==delta['current_tests_sha256']
assert sha(R/'.harness/evidence/qg3d-runtime-approved-before-q01/gui_coordinator_tests.rs')==delta['reviewed_tests_sha256']
mutation=load('artifacts/qg3d-runtime-terminal-stale-mutation.json');assert mutation['expected_failure'] and mutation['restored_exact_original'] and mutation['unmodified_production_restored_sha256']==sha(source)
trace=pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/delegation/live/deleg_16493768/task-0.log');assert 'end status=completed exit_reason=completed' in trace.read_text(encoding='utf-8')[-500:]
commands={n:command(n) for n in ['qg3d-runtime-parent-focused34','qg3d-runtime-final-focused','qg3d-runtime-final-workspace','qg3d-runtime-final-clippy','qg3d-runtime-final-fmt-check','qg3d-runtime-post-mutation-focused']}
assert commands['qg3d-runtime-final-workspace']['counts']=={'passed':549,'failed':0,'ignored':35}
assert commands['qg3d-runtime-post-mutation-focused']['counts']=={'passed':34,'failed':0,'ignored':0}
source_sha={n:sha(W/n) for n in spec['actor_writes']}
assert set(line[3:] for line in git(W,'status','--porcelain').splitlines())==set(spec['actor_writes'])
git(W,'add','--',*spec['actor_writes']);git(W,'diff','--cached','--check');git(W,'commit','-m','feat(quick-check): add lazy reusable native runtime configuration and terminal-init failure isolation')
commit=git(W,'rev-parse','HEAD');assert not git(W,'status','--porcelain')
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'ACCEPTED_ISOLATED_RUNTIME_CONFIGURATION_WITH_MEMORY_BACKEND_ONLY',
 'accepted':True,'scope':'NativeIoOnce lazy runtime configuration/reuse/terminal init failure and CPU policy preservation; actual Core runner with memory backend and time-driver first-poll witness only',
 'scope_ko':'네이티브용 런타임 구성·지연 생성/재사용·초기화 고장 수락 차단·CPU 정책 보존의 독립 호스트 범위',
 'worktree':str(W),'branch':spec['branch'],'preserved_commit':commit,'worktree_clean':True,'source_sha256':source_sha,
 'independent_safety_review_batch':'deleg_16493768','execution_safety_approved_for_original_34':True,'review_trace_sha256':{str(trace):sha(trace)},
 'review_findings':[{'id':'Q01','severity':'P2','original':'missing true terminal flag stale/duplicate regression','resolved_by_parent':'two existing manual endpoint tests now false/true with full state/cancel/lifecycle/start/snapshot/next run preservation','resolution_evidence':['artifacts/qg3d-runtime-post-review-delta.json','artifacts/qg3d-runtime-terminal-stale-mutation.json','artifacts/commands/qg3d-runtime-post-mutation-focused.json']}],
 'style_only_production_delta_restores_reviewed_sha':True,'post_review_test_changes_exactly_Q01_two_functions':True,
 'focused_counts':commands['qg3d-runtime-post-mutation-focused']['counts'],'workspace_counts':commands['qg3d-runtime-final-workspace']['counts'],'commands':commands,
 'mutation_negative_separate_from_product_tests':mutation,'focused_included_in_workspace_not_additional':True,'old_compile_clippy_failures_preserved':True,
 'writer_credit':'Flash native-mode draft, parent terminal-envelope/provenance and deterministic test repairs, independent safety review, parent Q01 negative-mutation and real regression execution',
 'module_consumption':'cfg(test) coordinator only, not normal product dispatcher or native GUI','actual_native_backend_factory_used':False,'actual_socket_dns_helper_or_gui_measurement':False,
 'driver_effects':'native runtime may initialize internal OS handles; time driver first-poll witness is not timer-expiry or socket IO certification',
 'io_enable_evidence':'shared production builder enable_io call verified statically only; no claim of functional network IO test',
 'non_ui_drain_owner_implemented':False,'immediate_os_resource_reclamation_guaranteed':False,
 'root_integrated':False,'gui_connected':False,'full_qg3_accepted':False,'product_accepted':False,'remote_push_or_deploy':False}
save('artifacts/qg3d-native-runtime-acceptance.json',record)
progress=load('artifacts/quick-check-progress.json');progress.update(recorded_at=record['recorded_at'],qg3d_native_runtime_acceptance=record)
progress['completion_continuation'].update(status='ISOLATED_NATIVE_RUNTIME_ACCEPTED_RENDER_FINAL_QA_PENDING',current_review_batch='deleg_563bb086')
save('artifacts/quick-check-progress.json',progress)
summary=f'''
## QG3D native용 runtime 구성 독립범위 수용 — {record['recorded_at']}
- 독립QA deleg_16493768: 정확34시험의부모timeout실행허용true·기존terminal수락공백F01해소확인. 남은Q01(terminalflag=true stale음성회귀)은부모가기존두manualendpoint시험을false/true로확장해전체state/cancelArc값·동일성/lifecycle/startsender/snapshot/후속실행을검증했다. 독립QA후생산변경은중첩if의논리동등Clippy형식1건뿐이며이를되돌리면QA동결SHA e195c9be로정확복원된다. 시험변경도그두함수로만제한됨을byte/SHA검증했다.
- **실제 focused34PASS0FAIL**, 해당W전체 **549PASS0FAIL35ignored**, strictClippy/fmtcheck0. stale guard앞에terminal처리를잘못넣는의도적음성변이는기대한1FAIL/exit101을실제검출→생산원문SHA정확복구→focused34전부재실행PASS. 음성변이실패와제품회귀를분리보존했다.
- clean로컬commit **{commit}**·source2·immutable156/reference12불변. artifacts/qg3d-native-runtime-acceptance.json의acceptedtrue는**runtime구성/메모리backend/actualCore독립범위만**. IOenable은공유builder소스확인, timefirstpoll은별도witness이며실socket/DNS/helper/nativebackend/GUI/OS전체인증아니다. cfgtest소비·root미통합·nonUI drainowner未구현·제품수용false.
- renderer W21/559/35ignored·Clippy0는별도근거이며최종2QA **deleg_563bb086**결과수신대기다. next는그결과확인뒤선택조합·typedpresenter/실행session/nativeUI연결. rootmain492/31ignored그대로,가시입력승인timeout우회/운영망/OS정책/배포0.
'''
for name,header in [('PROGRESS.md','# NPI 진행 기록'),('RESUME.md','# NPI 개발 재개 및 승인 경계')]:
 f=R/name;t=f.read_text(encoding='utf-8');assert t.count(header+'\n')==1
 f.write_text(t.replace(header+'\n',header+'\n'+summary,1),encoding='utf-8',newline='\n')
print(json.dumps({'status':record['status'],'commit':commit,'focused':record['focused_counts'],'workspace':record['workspace_counts'],'strict_clippy':0,'fmt_check':0,'root_integrated':False,'gui_connected':False},ensure_ascii=False))
