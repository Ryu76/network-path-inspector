"""검증된 새 actor 시작 관찰을 진행 기록에 반영한다. 완료나 수용으로 승격하지 않는다."""
import datetime
import hashlib
import json
import pathlib
R=pathlib.Path(__file__).resolve().parents[1]
load=lambda p:json.loads((R/p).read_text(encoding='utf-8'))
p=load('artifacts/qg2i-explicit-tcp-prepared.json')
s=load('artifacts/qg2i-explicit-tcp-start-observation.json')
assert s['actor_alive'] and s['model']=='gemini-3.8-flash-high'
assert all(hashlib.sha256((R/path).read_bytes()).hexdigest()==value for path,value in p['root_before_sha256'].items())
pipeline=load('artifacts/qg2i-explicit-tcp-pipeline.json')
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),
    'status':pipeline['status'],'start_observation':'artifacts/qg2i-explicit-tcp-start-observation.json',
    'actor_pid':s['actor_pid'],'supervisor_session':s['supervisor_session'],'worktree':p['worktree'],
    'baseline_commit':p['baseline_commit'],'root_source_unchanged':True,'root_integrated':False,
    'accepted':False,'parent_new_cli_tests_executed':False}
out=R/'artifacts/qg2i-explicit-tcp-start-record.json'
assert not out.exists()
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
state=load('artifacts/quick-check-progress.json')
state['recorded_at']=record['recorded_at']
state['next_qg2_explicit_tcp_entry'].update(record,actor_started=True)
state['next_qg2_app_integration_review'].update(status='REVIEW_RECEIVED_PARENT_SCOPED_ACTOR_STARTED',
    actor_started=True,production_changed=False)
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
section=f'''\n## QG2 명시 단일 TCP 앱 경로 재개 — {record['recorded_at']}
- 최신 직접 지시 “다시 진행해”를 받아 기존 개발 범위에서 부모가 개발보조CLI --dev-tcp-once-v1 <host> <canonical-port>를 최소앱소비경로로선택했다. selector 자체를사용자가명시승인했다고표현하지않는다. 이전범위검토의결정대기표시는이재개기록으로대체하며GUI/QG3나배포범위는추가하지않는다.
- 독립설계deleg_ed3799ab 수신완료. 기존38case의selector미사용과고정Tokio1.52.3/serde_json1.0.149를부모가확인했다. 전용W .worktrees/qgdevtcp·branch ai-pro/qgdevtcp·준비commit {p['baseline_commit']}. 부모는W의appCargo/Cargo.lock2개만준비·offline lock/Windows metadata/compile exit0·기존packageidentity/checksum보존. 추가lock errno0.3.14/signal-hook-registry1.4.8은Windows실컴파일graph에는없다.
- Flash High FILE writer 실제시작 {s['started_at']}·actorPID {s['actor_pid']}·supervisor37560/{s['supervisor_session']}·생존관찰 {s['recorded_at']}. 수정허용은lib.rs 최소분기+신규private diagnostic_cli.rs+신규explicit_tcp_entry.rs(Windows ignored native4)뿐. 공유Core/Inspector/resolver/기존worker/기존시험변경금지·부모도active W에서Cargo/fmt하지않는다. 입력95개동결/actor불변94개·root source/metadata아직변경0.
- 하네스27pass. 소유신호등록프로브는실제별도child exit0·stdout고정marker·timeout/overflow0·회수확인. 이는Ctrl+C/Break실제전달/OS즉시회수/전역handler원복인증아님. 최초부모준비의TUI오인·manifest예상오류와프로브실행경로오류는actor시작전중단후정확입력/실행경로로보정했으며제품변경/시험성공으로쓰지않는다.
- writer코드아직부모검증/통합/수용전. 종료후실제tool/경로/terminal/partial/SHA감사→독립정적QA→default/소유EXE IPv4IPv6성공거부/기존native27·CLI38/Clippyfmt→작은범위선택통합순서다. 기존메인434/native27/CLI38제한수용은유지. 전체QG2실환경/실제domain→worker→TCP EXE/실Console취소/GUI/QG3/Release·배포·성능은별도미검증이다.
\n'''
for name in ['PROGRESS.md','RESUME.md']:
    path=R/name
    first,rest=path.read_text(encoding='utf-8').split('\n',1)
    path.write_text(first+'\n'+section+rest,encoding='utf-8',newline='\n')
print(json.dumps(record,ensure_ascii=False))
