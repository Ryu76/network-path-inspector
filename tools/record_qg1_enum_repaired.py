"""enum 보정의 최신 root 실행 증거를 기록한다. 독립 재검토 전 게이트 수용 금지."""
import datetime,hashlib,json,pathlib,re
R=pathlib.Path(__file__).resolve().parents[1]
def load(rel):return json.loads((R/rel).read_text(encoding='utf-8'))
def results(name):
 command=load('artifacts/commands/'+name+'.json');assert command['exit_code']==0 and not command['partial'],name
 text=(R/'artifacts/commands'/(name+'.log')).read_text(encoding='utf-8');rows=re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;',text)
 if not rows:return {'exit_code':0}
 count={key:sum(int(row[i])for row in rows)for i,key in enumerate(['passed','failed','ignored'])};assert count['passed']>0 and count['failed']==0;return count
counts={name:results(name)for name in ['qg1-root-tests-enum-fixed','qg1-enum-independent-after-fix','qg1-enum-root-strict-clippy','qg1-enum-root-fmt']}
original=load('artifacts/qg1-canonical-source.json')['files'];replacement=load('artifacts/qg1-enum-canonical-source.json');assert replacement['integrated']
current={rel:replacement['files'].get(rel,info)['normalized_sha256']for rel,info in original.items()}
assert all(hashlib.sha256((R/rel).read_bytes()).hexdigest()==sha for rel,sha in current.items())
protected=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256'];assert all(hashlib.sha256((R/rel).read_bytes()).hexdigest()==sha for rel,sha in protected.items())
schema=load('artifacts/qg1-enum-schema-final.json');assert schema['failed']==0 and schema['passed']==77
now=datetime.datetime.now().astimezone().isoformat();proof={'recorded_at':now,'stage':'qgenumfix','counts':counts,'schema_passed':schema['passed'],'source_sha256':current,'inspector_protected_changed':0,'independent_recheck':'deleg_7327958a','qg1_accepted':False,'known_runtime_limitations':['QG2以降 미구현/실VLAN·DROP·ICMP차단·VM·GUI·EXE·성능未검증'],'prior_failures_retained':['qg1-enum-before-fix:5pass3fail','qg1-enum-worker-tests:시험진단formatbrace구문3오류'],'parent_changes':'diagnostic format-string brace escapes/EOF/rustfmt only'}
(R/'artifacts/qg1-enum-execution-checkpoint.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
review=load('artifacts/qg1-independent-static-review.json');review['findings'][0]['status']='EXECUTION_REPAIRED_INDEPENDENT_RECHECK_PENDING';review.update(correction_policy_passed=True,independent_after_fix=counts['qg1-enum-independent-after-fix'],recheck_delegation='deleg_7327958a',gate_accepted=False);(R/'artifacts/qg1-independent-static-review.json').write_text(json.dumps(review,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
state=load('artifacts/quick-check-progress.json');state['recorded_at']=now;state['qg1'].update(status='ENUM_FIXED_ALL_EXECUTION_PASSED_FINAL_RECHECK_PENDING',root_tests=counts['qg1-root-tests-enum-fixed'],independent_tests=counts['qg1-enum-independent-after-fix'],core_tests_passed=18,schema_checks={'passed':77,'failed':0,'evidence':'qg1-enum-schema-final'},static_review_delegation='deleg_7327958a',static_review_blocking_findings_pending_resolution=1,strict_clippy_exit=0,fmt_exit=0,accepted=False)
state['remaining_blockers']=['QG1 enum수정후독립재검토 deleg_7327958a 대기','GUI/EXE/cleanVM/실VLAN/DROP/ICMP차단/성능 미검증'];(R/'artifacts/quick-check-progress.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
section='\n## QG1 enum 보정 통합·실행 재검증 — '+now+'\n- qgenumfix actor정책감사통과. feature/status/evidence_level에as_str검증을실제추가,정상문자열유지·비문자열거부테스트3개추가. 최초시험진단메시지formatbrace구문3오류는부모가escape/EOF/rustfmt만원자보정했고실패로그보존. root2파일SHAguard선택반영.\n- 최신root '+str(counts['qg1-root-tests-enum-fixed']['passed'])+'PASS/0FAIL/'+str(counts['qg1-root-tests-enum-fixed']['ignored'])+'실제시험분리,Core18PASS,독립8PASS,schema77PASS,strictClippy/fmt0. 앞선명시loopback13/UI27/harness31도개별보존. Inspector보호61sourceSHA변경0.\n- 독립최종재검토 deleg_7327958a대기: QG1아직수용전. 해당finding해소판정·소스freshness확인후만QG1완료및QG2진행. GUI/EXE없음/운영변경없음.\n\n'
for name in ['PROGRESS.md','RESUME.md']:
 p=R/name;text=p.read_text(encoding='utf-8');first,rest=text.split('\n',1);p.write_text(first+'\n'+section+rest,encoding='utf-8',newline='\n')
p=R/'작업내용/NPI_2026-10-21_002.md';p.write_text(p.read_text(encoding='utf-8')+section,encoding='utf-8',newline='\n')
print(json.dumps({'counts':counts,'schema':schema['passed'],'qg1_accepted':False,'recheck':'deleg_7327958a'},ensure_ascii=False,indent=2))
