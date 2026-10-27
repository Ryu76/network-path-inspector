"""검토 보정의 실측 상태를 보존한다. 미수용 게이트를 성공으로 승격하지 않는다."""
import datetime,hashlib,json,pathlib
R=pathlib.Path(__file__).resolve().parents[1];now=datetime.datetime.now().astimezone().isoformat()
def load(rel):return json.loads((R/rel).read_text(encoding='utf-8'))
baseline=load('artifacts/qg0-inspector-baseline.json');changed=[rel for rel,sha in baseline['protected_inspector_sha256'].items()if hashlib.sha256((R/rel).read_bytes()).hexdigest()!=sha];assert not changed,changed
p=R/'artifacts/quick-check-progress.json';state=load('artifacts/quick-check-progress.json')
state['recorded_at']=now;state['inspector_changed_files']=changed
state['qg0'].update(status='REVIEW_CORRECTIONS_INDEPENDENT_RECHECK_PENDING',first_review_findings=4,correction_stage='qg0reviewfix',correction_policy_passed=True,document_contract_checks=load('artifacts/qg0-review-root-docs-final.json')['passed'],recheck_delegation='deleg_149f9737',accepted=False)
started=load('.harness/runs/qgfinalfix-qgcore/started.json')
state['qg1'].update(status='TIMESTAMP_TOKEN_AND_STRICT_CLIPPY_REPAIR_PENDING',prior_contract_core_tests_passed=15,original_independent_regressions_repaired=4,latest_independent_tests={'evidence':'qg1-date-token-before-fix','passed':4,'failed':1},latest_strict_clippy={'evidence':'qg1-core-clippy-after-repair','exit_code':101,'diagnostics':8},schema_checks={'evidence':'qg1-schema-validator-fixed','passed':49,'failed':0,'datetime_format_checker_explicit':True},correction_stage=started['stage'],correction_pid=started['pid'],accepted=False)
state['remaining_blockers']=['QG0 수정 후 독립 재검토 결과 대기','QG1 timestamp 숫자토큰/year0000 거부와 strictClippy 보정 완료/감사/회귀 대기','root 공통Core 선택통합·기존Inspector 재시험 전','GUI/EXE/cleanVM/실VLAN/DROP/ICMP차단/성능 미검증']
p.write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
review=load('artifacts/qg0-independent-review.json');review.update(correction_policy_passed=True,correction_documents_integrated=True,document_contract_checks=10,recheck_delegation='deleg_149f9737',gate_accepted=False)
(R/'artifacts/qg0-independent-review.json').write_text(json.dumps(review,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
section='\n## Quick Check 독립 검토 보정 — '+now+'\n- QG0 독립검토4건P1누락을원문대조확인. 무관리자검증계획/자원·성능/붙여넣기·중복·필터·복사메타데이터/통합시나리오를Flash qg0reviewfix에서보정,실제도구·경로감사통과후두문서선택반영. 부모문서회귀10/10; 독립재검토deleg_149f9737대기, QG0수용완료아님.\n- QG1 qgcorefix는정책감사통과·unit15/독립기존4회귀pass. 그러나새timestampyear0000/숫자부호거부회귀1FAIL 및strictClippy8경고가남아qgfinalfix Flash(pid'+str(started['pid'])+')가원자보정중. schema독립49/49는명시date-time checker추가후통과;선택패키지미설치로format검사생략되던부모검증기결함도실제로수정했다.\n- Inspector보호61source SHA변경0;rootCore선택통합/GUI/EXE/무설치VM/전체제품수용은미완료. 원본실패와actor증거보존,운영정책변경없음.\n\n'
for name in ['PROGRESS.md','RESUME.md']:
 path=R/name;text=path.read_text(encoding='utf-8');first,rest=text.split('\n',1);path.write_text(first+'\n'+section+rest,encoding='utf-8',newline='\n')
report=R/'작업내용/NPI_2026-10-21_002.md';report.write_text(report.read_text(encoding='utf-8')+'\n## 후속 독립 검토 반영\n'+section,encoding='utf-8',newline='\n')
print(json.dumps({'recorded_at':now,'qg0':state['qg0']['status'],'qg1':state['qg1']['status'],'protected_changed':changed},ensure_ascii=False))
