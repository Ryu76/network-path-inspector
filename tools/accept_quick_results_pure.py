"""QG5A 순수 결과 변환 단위만 receiving-root 실제 회귀와 함께 제한 수용한다."""
import datetime,hashlib,json,pathlib,re,subprocess
R=pathlib.Path(__file__).resolve().parents[1];sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def load(n):return json.loads((R/n).read_text(encoding='utf-8'))
def save(n,d):(R/n).write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
i=load('artifacts/qg5a-pure-result-integration.json');p=load('artifacts/qg3c-qg5a-parallel-prepared.json');W=pathlib.Path(i['preserved_worktree'])
OUT=R/'artifacts/qg5a-pure-result-acceptance.json';assert not OUT.exists()
assert i['root_integrated'] and not i['accepted']
assert all(sha(R/n)==h for n,h in i['root_source_sha256'].items())
assert all(sha(W/n)==h for n,h in i['worktree_source_sha256'].items())
lib='apps/network-quick-check/src/lib.rs';added=b'pub mod result_export;\npub mod result_view;\n'
assert (R/lib).read_bytes().count(added)==1
assert (R/lib).read_bytes().replace(added,b'',1)==pathlib.Path(i['root_lib_original_backup']).read_bytes()
assert all(sha(R/n)==h for n,h in i['root_before_sha256'].items() if n!=lib)
for key,value in i['review_trace_sha256'].items():assert sha(pathlib.Path(key))==value
for args,expected in [(['status','--porcelain'],''),(['rev-parse','HEAD'],i['preserved_commit'])]:
 result=subprocess.run(['git','-C',str(W),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
 assert result.returncode==0 and result.stdout.rstrip('\r\n')==expected
baseline=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256'];engine='crates/npi-probes/src/engine.rs'
assert len(baseline)==61 and all(sha(R/n)==h for n,h in baseline.items() if n!=engine)
original=R/'.harness/baselines/qg2g-tcp-replay-root/engine.rs';assert sha(original)==baseline[engine]
assert (R/engine).read_bytes()==original.read_bytes().replace(b'fn apply_tcp_result(',b'pub fn apply_tcp_result(',1)
commands={}
for name in ['qg5a-root-workspace','qg5a-root-clippy','qg5a-root-fmt-check']:
 row=load('artifacts/commands/'+name+'.json');assert row['exit_code']==0 and not row['partial']
 log=pathlib.Path(row['log']).read_text(encoding='utf-8');counts=re.findall(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;',log)
 if counts:row['counts']={key:sum(int(c[j+1]) for c in counts) for j,key in enumerate(['passed','failed','ignored'])}
 commands[name]=row
assert commands['qg5a-root-workspace']['counts']=={'passed':492,'failed':0,'ignored':31}
now=datetime.datetime.now().astimezone().isoformat()
state={'recorded_at':now,'status':'ACCEPTED_PURE_RESULT_VIEW_FILTER_AND_BOUNDED_TXT_CSV_MEMORY_ENCODING_ONLY','accepted':True,'root_integrated':True,
 'scope':'순수 reference view/AND literal filter/원문metadata·결과보존/UTF8 TXT·18열 CSV bounded메모리인코딩',
 'changed_source_paths':i['changed_product_paths'],'source_sha256':i['root_source_sha256'],
 'preserved_source_commit':i['preserved_commit'],'worktree':str(W),'worktree_clean':True,
 'independent_review_batch':i['independent_review_batch'],'review_A_findings':[],'review_B_blocking_findings':[],
 'resolved_original_review_ids':['QA-01','QA-02','QA-03','QA-04'],'nonblocking_QA_B_01':'부모quote-all wire검사+값동등한unquoted변이4개거부회귀시험추가로해소;생산변경0',
 'post_final_review_test_additions':1,'new_module_tests':15,'worktree_workspace_counts':{'passed':515,'failed':0,'ignored':35},
 'receiving_root_workspace_counts':commands['qg5a-root-workspace']['counts'],'root_execution':commands,
 'harness_tests_passed':39,'actor_model':'gemini-3.8-flash-high','writer_credit':'Flash FILEONLY 초안 + 부모fixture/검증기/회귀보강·Clippy정리·실행·선택통합 공동작성',
 'baseline_policy':'original protection files remain immutable; this root lib declaration delta is recorded separately, never regenerated into an old baseline',
 'unchanged_previous_root_inputs_excluding_explicit_lib_delta':len(i['root_before_sha256'])-1,
 'inspector_original_files_unchanged':60,'existing_approved_pub_four_byte_exception_files':1,
 'shared_core_resolver_inspector_measurement_manifest_lock_runtime_changes':0,
 'result_export_production_matches_rustfmt_actor_copy':True,'field_budget_claim':'bounded streaming statically reviewed; large-field fixtures returned precise TooLarge, not every small-limit attempt independently localized to that field',
 'native_tests_executed_this_slice':False,'actual_exe_cli_rerun_this_slice':False,'gui_input_wip_integrated':False,'coordinator_integrated':False,
 'gui_connected':False,'file_save_atomic_write_clipboard_connected':False,'full_qg2_accepted':False,'full_qg3_accepted':False,'full_qg5_accepted':False,'os_support_certified':False,'product_accepted':False,
 'remote_push_or_deploy':False,'remaining':['진단GUI실행/취소/창닫기drain/실결과연결','GUI필터·복사·실파일atomic저장','實환경·OS/Release/성능/최종제품검증'],
 'evidence':'artifacts/qg5a-pure-result-integration.json'}
save('artifacts/qg5a-pure-result-acceptance.json',state)
save('artifacts/qg5a-root-baseline-delta.json',{'recorded_at':now,'accepted_scope':state['scope'],'acceptance_artifact':'artifacts/qg5a-pure-result-acceptance.json',
 'original_frozen_manifest':'artifacts/qg3c-qg5a-parallel-prepared.json:root_before_sha256','original_manifest_not_modified':True,
 'existing_file_exception':{'path':lib,'before_sha256':i['root_lib_before_sha256'],'after_sha256':sha(R/lib),'byte_delta':added.decode('utf-8')},
 'new_source_files':{n:sha(R/n) for n in i['changed_product_paths'] if n!=lib},'all_other_original_frozen_inputs_unchanged':True})
progress=load('artifacts/quick-check-progress.json');progress.update(recorded_at=now,qg5a_pure_results=state)
progress['latest_root_validation']={'recorded_at':now,'status':state['status'],'acceptance_artifact':'artifacts/qg5a-pure-result-acceptance.json',
 'workspace_counts':state['receiving_root_workspace_counts'],'new_module_tests_included':15,'clippy_exit':0,'fmt_exit':0,
 'native_executed_this_run':False,'full_qg2_accepted':False,'full_qg3_accepted':False,'full_qg5_accepted':False,'product_accepted':False}
progress['completion_continuation'].update(status='PURE_RESULT_MODULES_ROOT_ACCEPTED_COORDINATOR_QA_PENDING',current_review_batch='deleg_bede6d65')
save('artifacts/quick-check-progress.json',progress)
directive=load('artifacts/quick-check-completion-directive-20261026.json');directive.update(last_checkpoint=now,status='PURE_RESULT_MODULES_ROOT_ACCEPTED_COORDINATOR_QA_PENDING',current_review_batch='deleg_bede6d65')
for s in directive['current_workstreams']:
 if s['id']=='result-view-filter-export':s.update(status='pure_modules_root_limited_accepted',next='GUI result binding and file/clipboard adapters separately tested')
save('artifacts/quick-check-completion-directive-20261026.json',directive)
summary=f'''
## QG5A 순수 결과표시·필터·TXT/CSV 메모리 변환 root 제한 수용 — {now}
- result_view.rs/result_export.rs와lib의public모듈선언2개만메인선택통합했다. 미수용QG3B실창소스/설정·coordinator는통합0,기존entry분기/worker/CLI/Core/manifest/lock변경0. 실제저장/clipboard/실GUI연결완료아니다.
- 독립최종 deleg_493912d0 A findings[]/B차단0·원본QA-01~04해소. B의LOW QA-B-01은부모quote-all wire검사와값은동일한unquoted변이4개거부회귀1시험추가로보강,그뒤생산변경0·전체재회귀.
- **메인root 492PASS0FAIL31ignored**,순수모듈15개포함;strictClippy/fmt0. qgresults W는515PASS0FAIL35ignored이며root와서로다른조합이다. focused17은기존state2와겹쳐합산금지. 하네스39PASS,실제native/제품EXE CLI이번재실행0.
- Wclean 로컬commit **{state['preserved_source_commit']}**. Flash초안+부모시험/검증보강공동작성. Inspector원본60·기승인pub4byte예외1 유지. 이전root60manifest는재생성하지않고lib선언예외·신규2source를 artifacts/qg5a-root-baseline-delta.json에따로고정했다. 기존dirtyroot의그외변경보존·원격push/배포/전체branchmerge0.
- 근거 artifacts/qg5a-pure-result-acceptance.json. 단독QG5A순수범위만acceptedtrue,전체QG2/QG3/QG5/GUI/OS/제품false. coordinator수정원본compile101·실행0이며안전QA deleg_bede6d65회수후별도보정한다.
'''
for name,header in [('PROGRESS.md','# NPI 진행 기록'),('RESUME.md','# NPI 개발 재개 및 승인 경계')]:
 file=R/name;text=file.read_text(encoding='utf-8');assert text.count(header+'\n')==1
 file.write_text(text.replace(header+'\n',header+'\n'+summary,1),encoding='utf-8',newline='\n')
for name in ['apps/network-quick-check/README.md','docs/quick-check/gates.md']:
 file=R/name;text=file.read_text(encoding='utf-8');file.write_text(text.rstrip()+'\n\n'+summary.strip()+'\n',encoding='utf-8',newline='\n')
report=R/'docs/quick-check/pure-result-export-checkpoint-2026-10-26.md';assert not report.exists();report.write_text('# QG5A 제한 수용 기록\n'+summary+'\n## 남은 경계\n- CSV 작은따옴표는전송인코딩이며소비자에서표시될수있다. 실제Excel실행방지인증아님.\n- JSON값·문자열·배열/null보존이며원본JSON키순서/공백/wirebyte보존주장0.\n- snapshot/report귀속은호출자책임,정보없으면현재시계/호스트명/draft로채우지않는다.\n- 상한은출력payload예산이며프로세스전체메모리hardcap아님.\n',encoding='utf-8')
print(json.dumps({'status':state['status'],'root_counts':state['receiving_root_workspace_counts'],'worktree_counts':state['worktree_workspace_counts'],'new_tests':15,'root_integrated':True,'accepted':True,'full_qg5_accepted':False,'product_accepted':False},ensure_ascii=False))
