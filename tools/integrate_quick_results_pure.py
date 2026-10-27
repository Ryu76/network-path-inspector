"""QG5A 순수 모듈만 보존·선택통합한다. 미수용 GUI/호스트 소스는 통합하지 않는다."""
import datetime,hashlib,json,pathlib,re,shutil,subprocess
R=pathlib.Path(__file__).resolve().parents[1];W=R/'.worktrees/qgresults';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def load(n):return json.loads((R/n).read_text(encoding='utf-8'))
def git(w,*args):
 r=subprocess.run(['git','-C',str(w),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60)
 assert r.returncode==0,r.stderr;return r.stdout.rstrip('\r\n')
p=load('artifacts/qg3c-qg5a-parallel-prepared.json');repair=load('artifacts/qg5a-parent-repair.json')
OUT=R/'artifacts/qg5a-pure-result-integration.json';assert not OUT.exists()
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
assert all(sha(W/n)==h for n,h in p['roles']['qgresults']['immutable_sha256'].items() if n!='apps/network-quick-check/src/lib.rs')
files=['apps/network-quick-check/src/lib.rs',*p['roles']['qgresults']['actor_writes']]
assert set(line[3:] for line in git(W,'status','--porcelain').splitlines())==set(files)
for name in files[1:]:assert not(R/name).exists()
assert sha(W/'apps/network-quick-check/src/gui_state.rs')==sha(R/'apps/network-quick-check/src/gui_state.rs')
assert sha(W/'apps/network-quick-check/src/result_view.rs')==repair['source_sha256']['apps/network-quick-check/src/result_view.rs']
# review뒤추가변경은cfg(test)내LOW 회귀뿐이며production전부분byte고정.
export=W/'apps/network-quick-check/src/result_export.rs'
original=R/'.harness/qa/qg5a-original-rustfmt/result_export.rs'
body=lambda file:file.read_text(encoding='utf-8').split('\n#[cfg(test)]\n',1)[0]
assert body(export)==body(original)
traces={}
for i in range(2):
 trace=pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/delegation/live/deleg_493912d0')/f'task-{i}.log'
 assert 'end status=completed exit_reason=completed' in trace.read_text(encoding='utf-8')[-500:];traces[str(trace)]=sha(trace)
commands={}
for name in ['qg5a-final-low-focused','qg5a-final-low-workspace','qg5a-final-low-clippy']:
 rec=load('artifacts/commands/'+name+'.json');assert rec['exit_code']==0 and not rec['partial']
 log=pathlib.Path(rec['log']).read_text(encoding='utf-8');summary=re.findall(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;',log)
 commands[name]={'exit_code':rec['exit_code'],'test_totals':{k:sum(int(s[i+1]) for s in summary) for i,k in enumerate(['passed','failed','ignored'])},'log':rec['log']}
assert commands['qg5a-final-low-workspace']['test_totals']=={'passed':515,'failed':0,'ignored':35}
assert commands['qg5a-final-low-focused']['test_totals']=={'passed':17,'failed':0,'ignored':0}
# 모든신규/기존수정source3의UTF8/개행/후행공백을별도확인한다.
for name in files:
 data=(W/name).read_bytes();assert data.endswith(b'\n') and not data.startswith(b'\xef\xbb\xbf')
 assert all(not line.endswith((' ','\t')) for line in data.decode('utf-8').splitlines())
git(W,'add','--',*files);git(W,'diff','--cached','--check')
git(W,'commit','-m','feat(quick-check): preserve reviewed pure result filtering and bounded TXT CSV encoding')
commit=git(W,'rev-parse','HEAD');assert not git(W,'status','--porcelain')
source_hash={n:sha(W/n) for n in files}
# baseline60은불변참조로두고이번rootlib확장예외를별도증거에기록한다.
backup=R/'.harness/evidence/qg5a-root-before';assert not backup.exists();backup.mkdir(parents=True)
lib=R/files[0];shutil.copyfile(lib,backup/'lib.rs')
root_original=lib.read_bytes();text=root_original.decode('utf-8');anchor='pub mod gui_state;\n';assert text.count(anchor)==1
expected=text.replace(anchor,anchor+'pub mod result_export;\npub mod result_view;\n',1).encode('utf-8')
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'PURE_MODULES_SELECTED_ROOT_INTEGRATION_PENDING_RECEIVER_TESTS',
 'preserved_worktree':str(W),'preserved_branch':'ai-pro/qgresults','preserved_commit':commit,'preserved_worktree_clean':True,
 'changed_product_paths':files,'worktree_source_sha256':source_hash,'root_before_sha256':p['root_before_sha256'],
 'root_lib_before_sha256':sha(lib),'root_lib_expected_sha256':hashlib.sha256(expected).hexdigest(),
 'root_lib_original_backup':str(backup/'lib.rs'),'root_lib_delta':'only public result_export and result_view module declarations after gui_state; entry dispatch unchanged',
 'core_and_guistate_same_bytes_in_receiver':True,'gui_input_and_coordinator_sources_not_integrated':True,'new_dependencies':False,
 'independent_review_batch':'deleg_493912d0','review_trace_sha256':traces,'review_representation':'parent normalized summaries; not reconstructed verbatim final JSON',
 'review_A_findings':[],'review_B_blocking_findings':[],'review_B_low_finding':'QA-B-01 quote-all wire regression gap',
 'low_resolution':'parent added wire quote-all scanner plus four unquoted mutations that generic CSV parser accepts with equal values but scanner rejects; one test PASS',
 'post_review_production_changes':False,'post_review_test_only_additions':1,'new_module_tests':15,'commands':commands,
 'metadata_budget_limit':'Huge-field fixtures yielded exact TooLarge; no claim every small budget failed inside the designated field; production streaming established by static review',
 'accepted':False,'root_integrated':False,'full_qg5_accepted':False,'gui_connected':False,'file_save_clipboard_connected':False,'product_accepted':False}
OUT.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
for name in files[1:]:shutil.copyfile(W/name,R/name)
lib.write_bytes(expected)
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items() if n!=files[0])
assert lib.read_bytes()==expected and all(sha(R/n)==source_hash[n] for n in files[1:])
record.update(root_integrated=True,root_source_sha256={n:sha(R/n) for n in files})
OUT.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':record['status'],'commit':commit,'worktree_totals':commands['qg5a-final-low-workspace']['test_totals'],
 'changed_product_paths':files,'root_integrated':True,'accepted':False},ensure_ascii=False))
