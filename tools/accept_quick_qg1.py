"""독립 재검토와 실행 증거의 최신 해시를 확인해 QG1 공유Core·계약만 수용한다."""
import datetime,hashlib,json,pathlib,re
R=pathlib.Path(__file__).resolve().parents[1]
def load(rel):return json.loads((R/rel).read_text(encoding='utf-8'))
proof=load('artifacts/qg1-enum-execution-checkpoint.json')
for rel,sha in proof['source_sha256'].items():assert hashlib.sha256((R/rel).read_bytes()).hexdigest()==sha,rel
baseline=load('artifacts/qg0-inspector-baseline.json')
for rel,sha in baseline['protected_inspector_sha256'].items():assert hashlib.sha256((R/rel).read_bytes()).hexdigest()==sha,rel
for name in ['qg1-root-tests-enum-fixed','qg1-enum-independent-after-fix','qg1-enum-root-strict-clippy','qg1-enum-root-fmt','qg1-inspector-loopback-real','qg1-inspector-ui-regression','qg1-inspector-ui-lint','qg1-inspector-ui-typecheck','qg1-inspector-ui-build','qg1-harness-final-regressions']:
 command=load('artifacts/commands/'+name+'.json');assert command['exit_code']==0 and not command['partial'],name
assert load('artifacts/qg1-enum-schema-final.json')['failed']==0
now=datetime.datetime.now().astimezone().isoformat()
record={'recorded_at':now,'gate':'QG1','decision':'ACCEPTED_SHARED_CORE_FACADE_AND_QUICK_RESULT_CONTRACT_ONLY','source_sha256':proof['source_sha256'],'independent_reviews':['deleg_12592897','deleg_7327958a'],'resolution':{'finding':'QG1-ENUM-01','status':'resolved','code_lines':['quick.rs:419-431','quick.rs:501-506','quick.rs:508-523'],'additional_findings':[]},'execution':{'workspace_tests':148,'workspace_separately_ignored_real':13,'explicit_loopback_real_tests':13,'quick_unit_tests':18,'independent_regressions':8,'schema_checks':77,'inspector_ui_tests':27,'harness_tests':31,'strict_clippy_exit':0,'fmt_exit':0,'ui_lint_typecheck_build_exit':0},'inspector_protected_files':len(baseline['protected_inspector_sha256']),'inspector_protected_changed':0,'dependency_change':'workspace network-core package only; existing lock packages unchanged; no Webview/Npcap/PDF/SQLite/Agent external dependency','not_accepted':['QG2 프로브 전체·다중대상 선택 실행','GUI/EXE·일반권한 실행·지원OS/VM 인증','실VLAN/DROP/ICMP차단/성능','Inspector 전체G2 완료'],'production_network_or_os_changes':False}
out=R/'artifacts/qg1-acceptance.json';assert not out.exists();out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
state=load('artifacts/quick-check-progress.json');state['recorded_at']=now;state['qg1'].update(status='ACCEPTED_SHARED_CORE_AND_CONTRACT_ONLY',accepted=True,static_review_blocking_findings_pending_resolution=0,acceptance_artifact='artifacts/qg1-acceptance.json',final_recheck_delegation='deleg_7327958a');state['remaining_blockers']=['QG2 프로브·선택실행·대상입력/주소해석 검증 대기','GUI/EXE/cleanVM/실VLAN/DROP/ICMP차단/성능 미검증'];(R/'artifacts/quick-check-progress.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
review=load('artifacts/qg1-independent-static-review.json');review.update(gate_accepted='QG1 common facade and contract only',final_recheck='deleg_7327958a',remaining_findings=[]);review['findings'][0]['status']='RESOLVED';(R/'artifacts/qg1-independent-static-review.json').write_text(json.dumps(review,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
for rel in ['docs/quick-check/gates.md','apps/network-quick-check/README.md']:
 p=R/rel;p.write_text(p.read_text(encoding='utf-8')+'\n## QG1 후속 수용 판정\n- '+now+': 공유 Core facade와 Quick DTO/JSON 계약 범위만 수용. 독립 QA 결함은 실행 재현→보정→독립 재검토로 해소. 근거 `artifacts/qg1-acceptance.json`. 기존 표의 root미통합/검증중은 당시 기록이며 현재의 QG1 판정은 이 기록을 따른다.\n- GUI/EXE·무설치·지원 OS·QG2 이후 기능 및 실제 VLAN/DROP 시험 완료를 의미하지 않는다.\n',encoding='utf-8',newline='\n')
section='\n## Quick Check QG1 공유Core·결과계약 수용 — '+now+'\n- 최종독립재검토 deleg_7327958a에서QG1-ENUM-01의실제string-only가드연결/정상열거값보존확인,추가확정차단결함0. 부모가소스18해시·Inspector61source불변·실행근거freshness확인후QG1범위만수용.\n- workspace148/명시loopback13/독립8/schema77/UI27/harness31 각각통과,strictClippy/fmt/UI lint·type·build0. 전부별개범위증거이며실제제품총합/지원OS인증아님. 근거artifacts/qg1-acceptance.json.\n- 다음안전단계QG2의입력/선택·TCP/Ping측정연계·DNS/Trace. GUI·EXE는선행QG2수용후. 운영설정변경없음/기존InspectorG2미완료보존.\n\n'
for name in ['PROGRESS.md','RESUME.md']:
 p=R/name;text=p.read_text(encoding='utf-8');first,rest=text.split('\n',1);p.write_text(first+'\n'+section+rest,encoding='utf-8',newline='\n')
p=R/'작업내용/NPI_2026-10-21_002.md';p.write_text(p.read_text(encoding='utf-8')+section,encoding='utf-8',newline='\n')
print(json.dumps({'gate':record['gate'],'decision':record['decision'],'execution':record['execution']},ensure_ascii=False,indent=2))
