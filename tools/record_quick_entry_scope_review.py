"""새 개발용 CLI 제안의 선행 확인·의존성 범위와 사용자 결정 필요 상태를 기록한다."""
import datetime
import hashlib
import json
import pathlib
import tomllib

R=pathlib.Path(__file__).resolve().parents[1]
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
accepted=load('artifacts/qg2h-tcp-native-acceptance.json')
assert accepted['accepted'] and all(sha(R/path)==value for path,value in accepted['source_sha256'].items())
app_before=load('artifacts/qg2f-app-entry-acceptance.json')['source_sha256']
assert all(sha(R/path)==value for path,value in app_before.items())
selector='--dev-tcp-once-v1'
assert selector not in (R/'tools/verify_quick_app_entry_owned_native.py').read_text(encoding='utf-8')
cli=load('artifacts/qg2h-tcp-native-root-commandline.json')
assert len(cli['commandline_cases'])==38
old=tomllib.loads((R/'Cargo.lock').read_text(encoding='utf-8'))
probe=tomllib.loads((R/'.harness/qa/quick-entry-dependency-probe/Cargo.lock').read_text(encoding='utf-8'))
old_registry={(p['name'],p['version']) for p in old['package'] if 'source' in p}
probe_registry={(p['name'],p['version']) for p in probe['package'] if 'source' in p}
added=sorted(probe_registry-old_registry)
assert added==[('errno','0.3.14'),('signal-hook-registry','1.4.8')]
assert not [pair for pair in added if pair[0] in {name for name,version in old_registry}]
commands={}
for key,name,code in [('all_targets_metadata','qg2i-entry-offline-dependency-probe',101),
    ('windows_metadata','qg2i-entry-windows-dependency-probe',0),
    ('windows_compile','qg2i-entry-windows-dependency-compile',0)]:
    item=load('artifacts/commands/'+name+'.json')
    assert item['exit_code']==code and not item['partial']
    commands[key]=item
metadata=json.loads(pathlib.Path(commands['windows_metadata']['log']).read_text(encoding='utf-8').splitlines()[0])
windows_packages={(item['name'],item['version']) for item in metadata['packages'] if item['source']}
assert not set(added)&windows_packages
transcript=pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/delegation/live/deleg_ed3799ab/task-0.log')
assert 'end status=completed' in transcript.read_text(encoding='utf-8')
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),
    'status':'SCOPED_DEVELOPER_CLI_EXTENSION_APPROVAL_REQUIRED','review':'deleg_ed3799ab',
    'review_representation':'완전한async결과의부모정규화·정적조건부제안이지구현/실행승인아님',
    'review_transcript':{'path':str(transcript),'sha256':sha(transcript)},
    'proposal':{'selector':selector,'arity':3,'single_target':True,'tcp_only':True,'domain_prerequisite_dns_only':True,
        'timeout_ms':3000,'concurrency':1,'report_bytes':32768,'wire_bytes_including_final_lf':65536,
        'output':'기존QuickRunReport compact JSON 한줄·새DTO없음','exit_codes':{'0':'report전달완료·TCP성공과무관',
            '1':'local/출력오류·report errors/limit','2':'인자거부','3':'취소report전달완료'},
        'noargs_help_invalid_worker_diagnostic_calls':0,'inspector_core_resolver_changes_allowed':False,
        'gui_qg3_started':False,'native_tests':'literal 127.0.0.1/::1 소유endpoint만·domain→TCP 실제EXE미검증'},
    'dependencies':{'tokio':'=1.52.3·앱production직접의존성및signal feature',
        'serde_json':'workspace =1.0.149·앱production직접의존성',
        'isolated_probe_added_all_target_packages':[{'name':name,'version':version} for name,version in added],
        'existing_registry_package_versions_changed':False,'new_packages_in_windows_probe_compile_graph':False,
        'offline_all_target_metadata':'errno0.3.14미캐시로실패·전체호스트검증성공주장금지',
        'offline_windows_metadata_and_compile':'실제타깃MSVC필터로성공·외부다운로드없음·앱자체구현/빌드증거아님'},
    'commands':commands,'existing_cli_cases_verified':38,
    'selector_occurs_in_existing_case_source':False,
    'compatibility_limit':'기존38입력과겹치지않지만entry의명시적새CLI계약확장·완전무변경아님',
    'unchanged_product_source_sha256':app_before,
    'pending_decision_reason':'PRD의GUI UX와별개인개발용CLI·직접의존성/lock확장을사용자가선택하도록범위확인',
    'user_explicit_cli_approval_received':False,'new_actor_started':False,'new_app_worktree_created':False,
    'production_changed':False,'root_integrated':False,'accepted':False,
    'remaining_unverified':['실제제품domain→동일EXEworker→TCP전체native안전격리',
        '실제Windows Ctrl+C/자원회수','전체QG2실환경/GUI/배포/성능·실측timestamp전체요구']}
out=R/'artifacts/qg2i-entry-scope-review.json'
assert not out.exists()
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
s=load('artifacts/quick-check-progress.json')
s['recorded_at']=record['recorded_at']
s['next_qg2_app_integration_review'].update(status=record['status'],review_received=True,
    scope_review=str(out.relative_to(R)),actor_started=False,production_changed=False,
    decision_required='개발용명시진단CLI·기존버전직접의존성/lock확장허용여부')
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(s,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
section=f'''\n## QG2 앱 명시 진단경로 조건부 설계·범위 결정 필요 — {record['recorded_at']}
- 독립읽기설계 deleg_ed3799ab는기존Core run_quick/current_exe DNSfactory를소비하는개발용single-target TCP opt-in을QG2보조통합범위로제안했다. GUI/QG3나전체QG2통과아님. selector --dev-tcp-once-v1·정확host/port만·TCP1/concurrency1/기존3000ms·도메인필수DNS만·기존worker/noargs/help/invalid 자동진단0보존·기존QuickRunReport/정해진bytes/exit·Ctrl+C취소/drain제안이다.
- 부모가38기존CLIcase원본을확인해selector미사용을검증했다. 이는entry의의도적새계약확장이며완전무변경주장이아니다. workspace serde_json=1.0.149/Tokio=1.52.3을확인. 격리의존성probe lock에는기존registry버전변경없이errno0.3.14/signal-hook-registry1.4.8이추가됐다. 전체타깃offline metadata는errno미캐시로exit101, 실제Windows MSVC필터metadata/compile은exit0·해당두패키지는Windows컴파일graph에없음·외부다운로드0. 빈프로브의의존성검증이지새앱구현성공은아니다.
- 개발용CLI는PRD GUI UX에명시된기능이아니므로공개진입점확장과직접의존성/lock변경의제한허용을사용자에게확인한다. 아직명시승인없음·새appworktree/actor0·product source/manifest/lock변경0. 기존root434/native27/CLI38·소유nativeTCP비교제한수용불변. 실제EXE domain→TCP·실제Console취소/자원회수·전체QG2실환경/GUI/배포미검증을유지한다.
\n'''
for name in ['PROGRESS.md','RESUME.md']:
    path=R/name
    first,rest=path.read_text(encoding='utf-8').split('\n',1)
    path.write_text(first+'\n'+section+rest,encoding='utf-8',newline='\n')
print(json.dumps({'status':record['status'],'selector':selector,'existing_cli_cases':38,
    'windows_offline_dependency_probe_passed':True,'product_changed':False,'new_actor_started':False},ensure_ascii=False))
