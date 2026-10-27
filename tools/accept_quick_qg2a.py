"""독립 재검토와 최신 실행 증거로 QG2-A 작은 구현 범위만 수용한다."""
import datetime,hashlib,json,pathlib
R=pathlib.Path(__file__).resolve().parents[1];load=lambda rel:json.loads((R/rel).read_text(encoding='utf-8'))
checkpoint=load('artifacts/qg2a-execution-checkpoint.json')
for rel,sha in checkpoint['source_sha256'].items():assert hashlib.sha256((R/rel).read_bytes()).hexdigest()==sha,rel
for name in ['qg2a-root-workspace-tests','qg2a-root-strict-clippy','qg2a-root-fmt','qg2a-independent-integrated-root']:
 cmd=load('artifacts/commands/'+name+'.json');assert cmd['exit_code']==0 and not cmd['partial'],name
assert load('artifacts/qg2a-contract-schema.json')['failed']==0
baseline=load('artifacts/qg0-inspector-baseline.json');assert all(hashlib.sha256((R/rel).read_bytes()).hexdigest()==sha for rel,sha in baseline['protected_inspector_sha256'].items())
now=datetime.datetime.now().astimezone().isoformat();record={'recorded_at':now,'slice':'QG2-A','decision':'ACCEPTED_INPUT_SELECTION_PLAN_AND_ICMP_HOST_ADAPTERS_ONLY','independent_reviews':['deleg_9a34cc36','deleg_41a54dde'],'resolved_findings':['raw credential reflection in target errors','invalid route.target accepted as complete observation','malformed raw IP repaired via trim'],'new_findings':[],'execution':{'workspace_tests':checkpoint['counts']['qg2a-root-workspace-tests'],'independent_regressions':checkpoint['counts']['qg2a-independent-integrated-root'],'input_unit_tests':21,'measurement_unit_tests':29,'schema_checks':77,'strict_clippy_exit':0,'fmt_exit':0},'source_sha256':checkpoint['source_sha256'],'inspector_protected_files':len(baseline['protected_inspector_sha256']),'inspector_changed':0,'full_qg2_accepted':False,'excluded':['actual scheduler final acceptance','DNS/Traceroute implementation and acceptance','real VLAN/DROP/ICMP block integration','GUI/EXE/VM/general-user/performance certification']}
out=R/'artifacts/qg2a-acceptance.json';assert not out.exists();out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
review=load('artifacts/qg2a-independent-review.json');review.update(final_recheck='deleg_41a54dde',remaining_findings=[],slice_accepted=True,full_qg2_accepted=False)
for finding in review['findings']:finding['status']='RESOLVED'
(R/'artifacts/qg2a-independent-review.json').write_text(json.dumps(review,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
state=load('artifacts/quick-check-progress.json');state['recorded_at']=now;state['qg2'].update(status='QG2A_ACCEPTED_FULL_QG2_PENDING',input_adapter_slice_accepted=True,independent_review='deleg_41a54dde',acceptance_artifact='artifacts/qg2a-acceptance.json',accepted=False);state['remaining_blockers']=[v for v in state['remaining_blockers']if'deleg_41a54dde'not in v];(R/'artifacts/quick-check-progress.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
section='\n## QG2-A 입력/선택계획·결과어댑터 범위 수용 — '+now+'\n- 독립재검토 deleg_41a54dde에서앞선3P2모두해소/추가차단결함0. 부모가통합5파일SHA/Inspector61source보존·root198/독립3/schema77·strictClippy/fmt0의최신근거확인후이작은slice만수용했다(artifacts/qg2a-acceptance.json).\n- QG2전체완료아님. 실제runner는모의10/IPv4·IPv6ownedloopback2통과했지만독립QA deleg_d954a685와남은Clippy/시험경고보정·최종회귀가남았다. DNS/Trace·실VLAN/DROP·GUI/EXE/VM/성능은미수용.\n\n'
for name in ['PROGRESS.md','RESUME.md']:
 p=R/name;text=p.read_text(encoding='utf-8');first,rest=text.split('\n',1);p.write_text(first+'\n'+section+rest,encoding='utf-8',newline='\n')
p=R/'작업내용/NPI_2026-10-21_002.md';p.write_text(p.read_text(encoding='utf-8')+section,encoding='utf-8',newline='\n');print(json.dumps({'slice':record['slice'],'decision':record['decision'],'full_qg2_accepted':False,'runner_review':'deleg_d954a685'},ensure_ascii=False))
