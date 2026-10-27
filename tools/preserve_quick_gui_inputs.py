"""GUI가시조작 미수용을 유지하며 검증된 WIP 소스만 로컬 보존한다."""
import datetime,hashlib,json,pathlib,subprocess
R=pathlib.Path(__file__).resolve().parents[1]
load=lambda p:json.loads((R/p).read_text(encoding='utf-8'))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
p=load('artifacts/qg3b-gui-inputs-parent-repair.json');W=pathlib.Path(p['worktree'])
assert all(sha(W/n)==h for n,h in p['source_sha256'].items())
assert all(sha(R/n)==h for n,h in p['root_before_sha256'].items())
assert all(sha(W/n)==h for n,h in p['immutable_source_sha256'].items())
assert all(sha(W/n)==h for n,h in p['parent_metadata_changes'].items())
assert all(sha(W/n)==h for n,h in p['reference_sha256'].items())
review=load('artifacts/qg3b-gui-inputs-final-independent-review.json');assert review['native_review']['safe_to_execute_owned_native_tests']
native=load('artifacts/commands/qg3b-gui-inputs-parent-owned-native.json');assert native['exit_code']==0 and not native['partial']
assert '4 passed; 0 failed; 0 ignored' in pathlib.Path(native['log']).read_text(encoding='utf-8')
cli=load('artifacts/qg3b-gui-inputs-parent-commandline.json');assert cli['status'].startswith('CURRENT_EXE_')
assert [len(cli[k]) for k in ['commandline_cases','explicit_reject_cases','gui_reject_cases','supervisor_self_tests']]==[38,23,9,6]
visible=load('artifacts/qg3b-gui-inputs-visible-process.json')
assert visible['status']=='OWNED_VISIBLE_GUI_EXITED' and visible['exit_code']==0 and visible['child_reaped'] and not visible['timed_out']
assert visible['stdout_bytes']==visible['stderr_bytes']==0
observation=load('artifacts/qg3b-gui-inputs-visible-observation.json');assert not observation['accepted'] and not observation['blocked_action']['retry_or_alternative_attempted']
assert sha(pathlib.Path(visible['executable']))==visible['binary_sha256']==cli['binary_sha256']
def git(*args):
 r=subprocess.run(['git','-C',str(W),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60)
 assert r.returncode==0,r.stderr
 return r.stdout.rstrip('\r\n')
assert git('branch','--show-current')=='ai-pro/qgguiinputs'
assert not git('diff','--cached','--name-only')
assert sorted(line[3:] for line in git('status','--porcelain').splitlines())==sorted(p['source_sha256'])
git('add','--',*p['source_sha256'])
assert sorted(git('diff','--cached','--name-only').splitlines())==sorted(p['source_sha256'])
git('diff','--cached','--check')
git('-c','core.autocrlf=false','commit','-m','wip: preserve input-only Win32 GUI pending visible interaction acceptance')
assert not git('status','--porcelain')
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'CLEAN_LOCAL_WIP_PRESERVED_VISIBLE_INTERACTION_NOT_ACCEPTED',
 'worktree':str(W),'branch':'ai-pro/qgguiinputs','preserved_commit':git('rev-parse','HEAD'),'worktree_clean':True,
 'source_sha256':p['source_sha256'],'parent_metadata_changes':p['parent_metadata_changes'],
 'workspace_passed':500,'workspace_failed':0,'workspace_ignored':35,'new_default_tests':23,
 'owned_native_tests':{'passed':4,'failed':0,'not_combined_with_default_count':True},
 'legacy_cli_cases':38,'explicit_tcp_reject_cases':23,'gui_reject_cases':9,'child_supervisor_tests':6,
 'strict_clippy_exit':0,'fmt_check_exit':0,'product_debug_build_exit':0,
 'visible_render_observed':True,'visible_process_exit':0,'visible_process_reaped':True,
 'visible_input_functional_acceptance':False,'consent_timeout_preserved':True,
 'binary_sha256':visible['binary_sha256'],'executable':visible['executable'],'selector':'--dev-gui-inputs-v1',
 'root_product_sources_unchanged':True,'root_integrated':False,'accepted':False,
 'network_diagnostics_connected':False,'full_qg2_accepted':False,'full_qg3_accepted':False,'product_accepted':False,
 'remaining':['visible user-input/CRUD/plan action sequence','Tab/resize/scroll/DPI checks','visible Trace initial checkbox observation discrepancy unresolved','runner/coordinator connection','full OS/Release/distribution gates'],
 'no_remote_push_merge_or_deploy':True}
out=R/'artifacts/qg3b-gui-inputs-preservation.json';assert not out.exists();out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
progress=load('artifacts/quick-check-progress.json');progress['recorded_at']=record['recorded_at'];progress['qg3_native_gui_inputs']=record
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(progress,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
section=f'''
## QG3B 입력 화면 WIP 보존·숨김시험 통과·가시조작 미수용 — {record['recorded_at']}
- 부모보정후전용W 기본전체500PASS/0FAIL/35ignored·strictClippy/fmt0·debugEXE빌드0. 500에는새기본23(entry7/presenter16)이포함된다. 새ignored소유native4는별도실제4PASS(기본합계에합산금지). 기존실제품CLI38/개발TCP거부23/새GUI거부9/감독6도이번EXE로실행PASS했다. 소켓옵션변경/fixture재시도/접속0, literalworker2건은소유127.0.0.1/::1같은port주소반환만검증했다.
- 재QA native확정결함0·기존N01~N09해소. 순수CONTRACT001은expected-lib의rustfmt후byte가실제lib와동일함을검증하고부모가format-only예외로명시수용했다. 참조원문은변경하지않았다. 원본/부모실패는기존증거그대로보존.
- 실제소유GUI PID38296을열어한국어안내/레이아웃/미연결disabled버튼을이미지확인했다. backgroundtype의CRLF가원문대로전달되지않았으며후속set_value도구승인이무응답만료됐다. 같은입력작업재시도/다른경로우회0. 초기visibleTrace체크관측은숨김default시험과달라원인미확정으로보존했다. 실제clipboard/유저입력·Tab/resize/scroll/DPI·전체가시기능수용은아니다.
- 자기창에만닫기요청후exit0/stdout0/stderr0·회수완료를재조회했다. W clean local commit {record['preserved_commit']}에source6보존(부모metadata2는선행로컬commit). root제품source변경/통합/수용0·remote push/merge/deploy0. 메인의최신수용은기존477/31ignored 그대로다.
- 다음은가시조작승인경계가해소된뒤해당검증재개이며침묵을승인으로간주하지않는다. runner/실진단연결·전체QG2/QG3·OS/Release/배포미완료. 근거 artifacts/qg3b-gui-inputs-preservation.json / visible-observation.json / parent-commandline.json.
'''
for name,header in [('PROGRESS.md','# NPI 진행 기록'),('RESUME.md','# NPI 개발 재개 및 승인 경계')]:
 path=R/name;text=path.read_text(encoding='utf-8');assert section not in text;path.write_text(text.replace(header+'\n',header+'\n'+section,1),encoding='utf-8',newline='\n')
print(json.dumps({k:record[k] for k in ['status','preserved_commit','worktree_clean','workspace_passed','root_integrated','accepted']},ensure_ascii=False))
