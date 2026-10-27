"""독립 재검토와 lib rustfmt-only 예외를 검증해 소유 native4 실행 게이트를 기록한다."""
import datetime,hashlib,json,pathlib,shutil,subprocess
R=pathlib.Path(__file__).resolve().parents[1]
load=lambda p:json.loads((R/p).read_text(encoding='utf-8'))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
p=load('artifacts/qg3b-gui-inputs-parent-repair.json');W=pathlib.Path(p['worktree'])
assert all(sha(W/n)==h for n,h in p['source_sha256'].items())
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
assert all(sha(W/n)==h for n,h in p['immutable_source_sha256'].items())
assert all(sha(W/n)==h for n,h in p['reference_sha256'].items())
traces={}
for index in range(2):
 path=pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/delegation/live/deleg_9c4ff836')/f'task-{index}.log'
 assert 'end status=completed exit_reason=completed' in path.read_text(encoding='utf-8')[-500:]
 traces[str(path)]=sha(path)
folder=R/'.harness/qa/qg3b-expected-lib-rustfmt';folder.mkdir(parents=True,exist_ok=False)
expected=W/'.harness/inputs/qg3b-win32/expected-lib.rs';copy=folder/'lib.rs';shutil.copyfile(expected,copy)
result=subprocess.run(['rustfmt','--edition','2024','--config','skip_children=true',str(copy)],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
assert result.returncode==0,result.stderr
assert copy.read_bytes()==(W/'apps/network-quick-check/src/lib.rs').read_bytes()
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'INDEPENDENT_STATIC_REVIEW_PASS_OWNED_NATIVE4_ALLOWED_NOT_ACCEPTED',
 'representation':'PARENT_NORMALIZED_FROM_DELIVERED_REVIEW_NOT_VERBATIM','delegation':'deleg_9c4ff836',
 'source_sha256':p['source_sha256'],'trace_sha256':traces,
 'native_review':{'safe_to_execute_default_tests':True,'safe_to_execute_owned_native_tests':True,'findings':[],
 'resolved':[f'QG3B-N{i:02}' for i in range(1,10)]},
 'pure_review':{'safe_to_execute_default_tests':True,'findings':[{'id':'CONTRACT001','severity':'low','issue':'lib module order differs from byte-frozen expected after rustfmt','disposition':'PARENT_EXPLICIT_FORMAT_ONLY_EXCEPTION_VERIFIED'}],
 'verified_topics':['actual Core080/bracketedIPv6 and full plan equality','exact MAX/MAX+1 combined bytes/count limits','Finished/Busy/protected snapshot/ID preservation','bounded Display while formatting and strict UTF16']},
 'format_exception':{'approved_by':'parent within existing formatting/selection scope','changes_semantics':False,
 'original_expected_sha256':sha(expected),'rustfmt_expected_sha256':sha(copy),'actual_lib_sha256':sha(W/'apps/network-quick-check/src/lib.rs'),
 'expected_after_rustfmt_equals_actual_bytes':True,'immutable_expected_reference_not_rewritten':True,
 'command':['rustfmt','--edition','2024','--config','skip_children=true',str(copy)],'exit_code':0},
 'execution_allowed':'exact native_gui::tests four ignored owned hidden-window cases with bounded parent process supervision',
 'native_executed':False,'root_integrated':False,'accepted':False,
 'limitations':['Review static only; parent workspace500/35ignored is separate execution evidence',
 'No injected DestroyWindow failure or callback panic certification',
 'WM_SETTEXT/notification tests are not clipboard/user typing or full GUI/DPI/OS acceptance',
 'No network diagnosis/runner connection/fullQG2/fullQG3/product acceptance']}
out=R/'artifacts/qg3b-gui-inputs-final-independent-review.json';assert not out.exists();out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':record['status'],'native_safe':True,'contract001':'rustfmt-only verified and explicitly accepted','accepted':False},ensure_ascii=False))
