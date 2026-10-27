"""부모 coordinator 보정은 Flash 원본과 분리하고 컴파일/시험실행 경계를 동결한다."""
import datetime,hashlib,json,pathlib,re
R=pathlib.Path(__file__).resolve().parents[1];W=R/'.worktrees/qgcoordfix';sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
def load(n):return json.loads((R/n).read_text(encoding='utf-8'))
p=load('artifacts/qg3c-coordinator-repair-prepared.json');accepted=load('artifacts/qg5a-pure-result-acceptance.json');compile=load('artifacts/commands/qg3c-parent-compile-v1.json')
assert compile['exit_code']==0 and not compile['partial']
assert all(sha(W/n)==h for n,h in p['immutable_sha256'].items())
assert all(sha(W/n)==h for n,h in p['reference_sha256'].items())
lib='apps/network-quick-check/src/lib.rs';assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items() if n!=lib)
assert all(sha(R/n)==h for n,h in accepted['source_sha256'].items())
trace=pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/delegation/live/deleg_bede6d65/task-0.log')
assert 'end status=completed exit_reason=completed' in trace.read_text(encoding='utf-8')[-500:]
findings={
 'QA01':'새MemoryBackend는동기즉시future와명시HeldProbe Future를trait동일경로로반환;반환형정렬',
 'QA02':'동일poll private FnOnce(&Self)hook으로일정제어,expect_err Debug부당요구없이matches검사',
 'QA03':'CompletionEnd Open/Drained/Lost;rxLost는항상Failed·실worker종료후matchingErr/snapshot확정·다른state불변',
 'QA04':'worker최외곽catch_unwind안에body/backend/config소멸포함·별도AtomicU8종료분류·UIjoin0·panicpayload비반사. 실제backendDrop panic 및idle/postreport closingpanic시험',
 'QA05':'is_shutdown_complete는worker종료/start폐쇄/inflight없음뿐아니라채널최종상태를요구. bufferedstale고장회귀·Lost는실패종결이지성공drain아님',
 'QA06':'HeldProbe Pending진입확인→Closing→생산poll첫Emptyhook에서release→workeris_finished명시확인→같은poll Applied·실Core반환전체/snapshot동등',
 'QA07':'실생산workerloop가명령수락/gate진입뒤에만omitcompletion작은고장삽입·시작성공뒤missingErr/실종료관측',
 'QA08':'Fixture release목록은worker시작전설치·HeldProbe Waker Pending대기·동일Arc·취소후release전미완료/후속probe0/실Core반환전체동등',
 'QA09':'after_send실제전송뒤flaghandshake후UIcancel·원래cancelledfalse보고서전체보존',
 'QA10':'matching manualendpoint rich Result/Err전체보존,Finished기존결과/snapshot아래Full/Disconnected/Busy/NoFeatures/Closing전체불변·실opaqueID두번실행의stale/duplicate/후속오염0',
 'QA11':'Fixture Drop이gate해제→생산fail/poll종료관측;실제assertunwind대조·명시Drop시험은외부소유JoinHandle로is_finished/試驗join확인',
 'QA12':'모든host필드/privateenvelope/InFlight은private;새타입/소비메서드pubcrate상한·lint억제0'}
review={'representation':'parent normalized received findings and repair mapping, not verbatim review JSON','original_review':'deleg_bede6d65',
 'original_execution_safety_approved':False,'original_compile_exit':101,'original_tests_executed':False,'finding_mapping':findings,
 'parent_production_and_tests_rewritten':True,'actual_current_compile_exit':0,'current_tests_executed':False,
 'scope':'actual Core runner + memory backend + owned std thread/CPU-only runtime; not GUI/nativeIO or pure-clock-free model',
 'additional_contracts':['同数字RunIdでもactive snapshot全体が違えば拒否し他state不変','mismatch実completionは破棄せずunapplied_completion bounded1へsnapshotごと保持、他stateへ強制適用0',
 '5秒の試験待機は成功判定ではなく失敗timeout。sleep0、hookだけの有限同期とfixture cleanupはUIproductionのno-opと区別',
 'Lost channelはphysical終了解放を観測してもFailedでありClosed成功にしない','Dropは非UI drainowner未実装で即時OS回収保證0'],
 'qa_must_verify_not_trust_mapping':True}
# 주석/설명은 한국어로 전달한다. 이전 동결계약 원문은 손대지 않는다.
review['additional_contracts']=[
 '같은 숫자RunId라도 active snapshot전체가 다르면 거부하며 다른state불변',
 'mismatch실완료는 버리지 않고 bounded1 unapplied_completion에 snapshot과함께보존·타state강제적용0',
 '시험5초대기는성공기준이아니라실패timeout·sleep0;시험hook의제한동기화/cleanup은기본UI no-op경로와구분',
 '채널Lost는물리적종료정리관측후에도Failed이고Closed성공이아님',
 'Drop은최후취소이며nonUI drainowner·즉시OS회수보장은후속연결범위']
ref=W/'.harness/inputs/frozen/qg3c-parent-repair-review.json';assert not ref.exists();ref.write_text(json.dumps(review,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'PARENT_REWRITE_COMPILED_NO_EXECUTION_PENDING_NEW_SAFETY_QA',
 'worktree':str(W),'source_sha256':{n:sha(W/n) for n in p['actor_writes']},'immutable_input_count':len(p['immutable_sha256']),
 'references_sha256':{ref.relative_to(W).as_posix():sha(ref)},'source_test_functions':len(re.findall(r'^#\[test\]',(W/p['actor_writes'][1]).read_text(encoding='utf-8'),re.M)),
 'original_review_trace_sha256':{str(trace):sha(trace)},'parent_review':review,'compile_command':compile,
 'main_root_evolution':'QG5A accepted lib declarations/new result modules only; original root manifest unchanged, accepted delta explicit',
 'main_root_acceptance':'artifacts/qg5a-pure-result-acceptance.json','tests_executed':False,'root_integrated':False,'accepted':False,'product_accepted':False}
OUT=R/'artifacts/qg3c-parent-rewrite-prepared.json';assert not OUT.exists();OUT.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':record['status'],'source_sha256':record['source_sha256'],'test_functions':record['source_test_functions'],'compile_exit':0,'tests_executed':False},ensure_ascii=False))
