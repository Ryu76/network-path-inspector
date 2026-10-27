"""실제 실행 PID와 제품별 게이트를 보존해 QG2 병렬 착수를 기록한다."""
import datetime,hashlib,json,pathlib
R=pathlib.Path(__file__).resolve().parents[1]
load=lambda rel:json.loads((R/rel).read_text(encoding='utf-8'))
acceptance=load('artifacts/qg1-acceptance.json');assert acceptance['decision']=='ACCEPTED_SHARED_CORE_FACADE_AND_QUICK_RESULT_CONTRACT_ONLY'
actors=[load(f'.harness/runs/qg2a-{role}/started.json')for role in ['qg2input','qg2measure']]
assert all(a['model']=='gemini-3.8-flash-high' and a['stage']=='qg2a'for a in actors)
protected=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256'];assert all(hashlib.sha256((R/rel).read_bytes()).hexdigest()==sha for rel,sha in protected.items())
now=datetime.datetime.now().astimezone().isoformat();record={'recorded_at':now,'phase':'QG2-A_INITIAL_IMPLEMENTATION','gate_accepted':False,'prerequisite':'QG1 accepted after independent recheck deleg_7327958a','actors':actors,'current_scope':['다중대상IPv4/IPv6/domain/port입력·중복제거·상한검증','선택기능만계획·필수주소해석/상세DNS분리·설정스냅샷','기존ICMP/HostSnapshot 원시측정의Quick계약매핑/메타데이터·부분실패·오류보존'],'excluded_from_this_slice':['실제다중대상실행스케줄러','신규DNS/Traceroute프로브','GUI/EXE/VM/성능/운영망·DROP정책시험'],'inspector_protected_changed':0,'contract':'.harness/references/qg2a-contract.json','independent_tests_required_before_integration':True}
out=R/'artifacts/qg2a-started.json';assert not out.exists();out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
state=load('artifacts/quick-check-progress.json');state['recorded_at']=now;state['qg2']={'status':'INPUT_SELECTION_AND_MEASUREMENT_ADAPTERS_IMPLEMENTING','actors':actors,'accepted':False,'scope_evidence':'artifacts/qg2a-started.json'};state['remaining_blockers']=['QG2신규slice의actor종료·감사·실제회귀/검토·선택통합대기','실제선택실행기/DNS/Traceroute/실VLAN/DROP/ICMP차단 미완료','GUI/EXE/cleanVM/성능 미검증'];(R/'artifacts/quick-check-progress.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
section='\n## QG2 초기 2세션 병렬 착수 — '+now+'\n- 선행 QG1은독립최종재검토후공유Core/Quick계약범위수용(artifacts/qg1-acceptance.json). 보존소스 ai-pro/qgcore commit2118fa6, 해당worktree clean확인. root기존G2 dirty변경은보존.\n- Flash High 독립worktree qg2input(pid'+str(actors[0]['pid'])+')는다중입력/중복제거/상한/기능선택계획, qg2measure(pid'+str(actors[1]['pid'])+')는기존ICMP/host원시측정→Quick계약변환을구현한다. 파일2개씩분리,lib선언만부모baseline준비. .harness/references/qg2a-contract.json API동결, 하네스31회귀exit0.\n- 이번slice는순수입력·결과매핑으로 실제프로브구현을복제하지않는다. 실제다중실행기/DNS/Trace/GUI/EXE수용아님. 배우actor의명령/시험/설치/네트워크/git/재위임금지,부모가실행·감사·선택통합.\n- source61hash불변/운영정책변경없음. 신규소스는root미반영·미검증,actor종료후테스트/Clippy/fmt/독립QA필수.\n\n'
for name in ['PROGRESS.md','RESUME.md']:
 p=R/name;text=p.read_text(encoding='utf-8');first,rest=text.split('\n',1);p.write_text(first+'\n'+section+rest,encoding='utf-8',newline='\n')
p=R/'작업내용/NPI_2026-10-21_002.md';p.write_text(p.read_text(encoding='utf-8')+section,encoding='utf-8',newline='\n')
print(json.dumps({'qg1':'accepted common facade and contract only','qg2_actor_pids':[a['pid']for a in actors],'qg2_accepted':False,'inspector_changed':0},ensure_ascii=False))
