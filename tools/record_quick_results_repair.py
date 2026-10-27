"""QG5A 보정의 실제 회귀 수·원본 보존·한계를 동결하고 QA 입력을 만든다."""
import datetime,hashlib,json,pathlib,re,subprocess
R=pathlib.Path(__file__).resolve().parents[1];W=R/'.worktrees/qgresults';sha=lambda f:hashlib.sha256(f.read_bytes()).hexdigest()
load=lambda name:json.loads((R/name).read_text(encoding='utf-8'))
p=load('artifacts/qg3c-qg5a-parallel-prepared.json');a=load('artifacts/qg3c-qg5a-parallel-pipeline.json')
OUT=R/'artifacts/qg5a-parent-repair.json';assert not OUT.exists()
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
assert all(sha(W/n)==h for n,h in p['roles']['qgresults']['immutable_sha256'].items() if n!='apps/network-quick-check/src/lib.rs')
assert all(sha(W/n)==h for n,h in p['roles']['qgresults']['reference_sha256'].items())
source=['apps/network-quick-check/src/lib.rs',*p['roles']['qgresults']['actor_writes']]
commands={}
for name in ['qg5a-original-pure-tests','qg5a-parent-pure-v1','qg5a-parent-pure-v2','qg5a-parent-clippy-v1','qg5a-parent-clippy-v2','qg5a-parent-workspace','qg5a-parent-fmt-check']:
 rec=load('artifacts/commands/'+name+'.json');log=pathlib.Path(rec['log']).read_text(encoding='utf-8')
 summaries=re.findall(r'test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;',log)
 totals={k:sum(int(v[i+1]) for v in summaries) for i,k in enumerate(['passed','failed','ignored'])}
 commands[name]={'exit_code':rec['exit_code'],'partial':rec['partial'],'test_totals':totals,'log':rec['log'],'test_summary_count':len(summaries)}
assert commands['qg5a-original-pure-tests']['test_totals']=={'passed':9,'failed':2,'ignored':0}
assert commands['qg5a-parent-pure-v1']['test_totals']=={'passed':15,'failed':1,'ignored':0}
for name in ['qg5a-parent-pure-v2','qg5a-parent-clippy-v2','qg5a-parent-workspace','qg5a-parent-fmt-check']:assert commands[name]['exit_code']==0 and not commands[name]['partial']
totals=commands['qg5a-parent-workspace']['test_totals'];assert totals=={'passed':514,'failed':0,'ignored':35},totals
# original export production은 rustfmt 외 변경이 없어야 한다.
original=R/'.harness/evidence/qg3c-qg5a-original-qgresults/result_export.rs'
prod=lambda text:text.split('\n#[cfg(test)]\n',1)[0]
# 첫 raw byte 비교 실패는 import 순서의 rustfmt 차이를 지워 통과시킨 것이 아니다.
# 독립 복사본에 같은 formatter를 적용해 본문 전체의 formatting-only 동등성을 확인한다.
import shutil
formatted=R/'.harness/qa/qg5a-original-rustfmt/result_export.rs'
assert not formatted.exists()
formatted.parent.mkdir(parents=True,exist_ok=True)
shutil.copyfile(original,formatted)
fmt=subprocess.run(['rustfmt','--edition','2024',str(formatted)],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=45)
assert fmt.returncode==0,fmt.stderr
assert prod(formatted.read_text(encoding='utf-8'))==prod((W/'apps/network-quick-check/src/result_export.rs').read_text(encoding='utf-8'))
review={
 'representation':'parent normalized findings, not verbatim original review JSON','original_batch':'deleg_e4d98270',
 'QA-01':'원본TXT 시험은Running중replace로Busy. 같은RunId finish뒤대상/options변경하여보관snapshot사용으로수정.',
 'QA-02':'원본테스트CSVparser byte-as-char로UTF8손상. bytebuffer/strictUTF8/quote-state/CRLF 음성대조군으로수정. 제품encoder손상아님.',
 'QA-03':'전체metadata expected(실제CoreSerialize report-results제외)와request/plan/filter/null전체구조비교추가,All/Filtered·cancelledfalse/true·noncontinuousduplicate/context미제공·빈/0행/None/Err검증.',
 'QA-04':'18셀전체prefix/표시값/details/raw/meta구조비교·formula/leadingapostrophe/공백tabCRLFcommaquote/UTF8negative추가.',
 'budget_hypothesis':'원시serde_json serialization중program_version/query/errors/details/raw/Err문자열에서limit128/512/2048를소진시켜TooLarge정확확인;가설결함은재현안됨·제품serializer보정0.',
 'parent_fixture_failure':'첫추가시험은invalidschema/product보안fixture를Core QuickResult Deserialize로복원하려다원래validator거부. 원본보존/정상DTOtypedroundtrip은유지하고그invalid fixture만JSON구조전체동등으로비교보정(상위validator변경0).',
 'production_changes':'result_export실행본문변경0; result_view문서목록들여쓰기,동일의미Optional조건earlyreject/lifetime생략의Clippy보정. suppression0.',
 'still_excluded':['GUI연결/실가시조작/파일쓰기/atomicwrite/clipboard/실network/완료보고서와snapshot귀속독립인증/전체QG5/메인통합/OS/제품수용']}
ref=W/'.harness/inputs/frozen/qg5a-parent-repair-review.json';assert not ref.exists();ref.write_text(json.dumps(review,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'REPAIRED_PURE_MODULES_REAL_REGRESSION_PASSED_FINAL_QA_PENDING',
 'worktree':str(W),'branch':'ai-pro/qgresults','source_sha256':{n:sha(W/n) for n in source},
 'root_before_sha256':p['root_before_sha256'],'immutable_input_count':153,'original_actor_inputs_count':154,
 'additional_reference_sha256':{ref.relative_to(W).as_posix():sha(ref)},'commands':commands,'default_workspace_totals':totals,
 'focused_filter_overlaps_two_existing_gui_state_tests':True,'new_module_tests_passed':14,
 'production_result_export_body_identical_to_actor':True,'parent_review':review,'root_integrated':False,'accepted':False,'full_qg5_accepted':False,'product_accepted':False}
OUT.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':record['status'],'workspace':totals,'new_module_tests':14,'result_export_body_unchanged':True,'source_sha256':record['source_sha256']},ensure_ascii=False))
