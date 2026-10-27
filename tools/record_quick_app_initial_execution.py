"""제품 entrypoint 초안의 실제 컴파일/실패와 부모 workspace·lock 변경을 보존한다."""
import datetime
import hashlib
import json
import pathlib
import re
import tomllib

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qgquickapp'
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
actor = load('artifacts/qg2f-app-entry-pipeline.json')
assert actor['status'] == 'AUDITED_SOURCE_READY_FOR_PARENT_REVIEW'
assert all(sha(W / path) == value for path, value in actor['source_sha256'].items())
assert load('artifacts/qg2appentry-actor-policy-audit.json')['all_actor_policy_checks_passed']
old_manifest = tomllib.loads((R / 'Cargo.toml').read_text(encoding='utf-8'))
new_manifest = tomllib.loads((W / 'Cargo.toml').read_text(encoding='utf-8'))
expected = json.loads(json.dumps(old_manifest))
expected['workspace']['members'].append('apps/network-quick-check')
assert new_manifest == expected
old = {p['name']:p for p in tomllib.loads((R / 'Cargo.lock').read_text(encoding='utf-8'))['package']}
new = {p['name']:p for p in tomllib.loads((W / 'Cargo.lock').read_text(encoding='utf-8'))['package']}
assert set(new) - set(old) == {'network-quick-check'}
assert all(new[name] == package for name, package in old.items())
assert new['network-quick-check']['dependencies'] == ['network-core', 'tokio']
evidence = {}
for label, name in [('lock', 'qg2f-app-parent-lock-generation'), ('default', 'qg2f-app-default-before-repair'), ('clippy', 'qg2f-app-clippy-before-repair')]:
    item = load('artifacts/commands/' + name + '.json')
    assert not item['partial']
    assert item['exit_code'] == (0 if label == 'lock' else 101)
    evidence[label] = item
text = pathlib.Path(evidence['default']['log']).read_text(encoding='utf-8')
rows = re.findall(r'test result: FAILED\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
assert len(rows) == 1
counts = {key: int(rows[0][i]) for i, key in enumerate(['passed','failed','ignored'])}
assert counts == {'passed':8,'failed':1,'ignored':0}
protected = load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(sha(R / path) == value for path, value in protected.items())
accepted = load('artifacts/qg2e-trace-runner-acceptance.json')
assert all(sha(R / path) == value for path, value in accepted['source_sha256'].items())
prepared = load('artifacts/qg2f-app-entry-prepared.json')
assert all(sha(W / path) == value for path, value in prepared['source_sha256'].items() if path not in ['Cargo.toml','Cargo.lock'])
now = datetime.datetime.now().astimezone().isoformat()
record = {
    'recorded_at':now,'status':'APP_COMPILES_PURE_TEST_AND_CLIPPY_FAILURES_REVIEW_PENDING',
    'independent_review':'deleg_a23a1e9a','actor_source_sha256':actor['source_sha256'],
    'parent_metadata_sha256':{name:sha(W / name) for name in ['Cargo.toml','Cargo.lock']},
    'parent_manifest_change':'workspace.members 한항목추가만','existing_lock_packages_identical':len(old),
    'added_lock_package':new['network-quick-check'],'evidence':evidence,'test_counts':counts,
    'all_targets_completed':False,'source_compiled':True,'native_executed':False,
    'parent_source_observations':[
        {'id':'APP-TEST-OVERFLOW-01','status':'실제재현','issue':'600주소fixture가16384bytes를넘는다는선행단언부터실패'},
        {'id':'APP-TEST-ESCAPED-NEWLINE-01','status':'정적대조·미실행분기','issue':'JSON escape된error_message의newline은실제stdout다중line이아니므로기존IPC원문보존계약과exit1기대값충돌'},
        {'id':'APP-NATIVE-IPV6-FIXTURE-01','status':'정적대조·native미실행','issue':'IPv6 bind .ok()로None이어도fixture성공가능·양쪽리스너필수계약위반'},
        {'id':'APP-API-TEST-INJECTION-01','status':'정적대조','issue':'private계약의entry_with_worker가pub로노출됨'},
        {'id':'APP-CLIPPY-01','status':'실제재현','issue':'unused PathBuf·io::Error::other·needless as_bytes 엄격Clippy실패'},
    ],
    'root_integrated':False,'accepted':False,'product_accepted':False,
    'limits':['default all-targets는lib9시험중1실패로중단·native행0','다음보정은독립QA수신뒤좁게진행','GUI/진단시작경로/배포인증/전체QG2미완료'],
}
out=R/'artifacts/qg2f-app-parent-initial-execution.json'
assert not out.exists()
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
state=load('artifacts/quick-check-progress.json')
state['recorded_at']=now
state['qg2_app_entry'].update(status=record['status'],actor_alive_at_checkpoint=False,
    independent_review='deleg_a23a1e9a',parent_execution=str(out.relative_to(R)),source_compiled=True,
    test_counts=counts,all_targets_completed=False,native_executed=False,accepted=False,root_integrated=False)
state['remaining_blockers']=['제품worker진입점초안lib시험8PASS1FAIL·Clippy실패·IPv6fixture failclosed/JSONescape/API범위소스검토·독립QA수신전',
                            '제품실제명령행/localhost IPC·전체조합회귀전·root미통합',
                            '전체QG2실환경/QG3GUI/PE·CRT·서명/VM·일반사용자·성능미완료']
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
section=f'''\n## 제품 worker 진입점 초안 감사·실제 컴파일 / 시험 실패 보존 — {now}
- Flash qg2appentry 종료exit0·17 FILE READ/WRITE·신규4파일감사통과·기준27파일불변. 부모가실제4SHA재계산후소스를읽어기본시험의domain실제호출0·합성/리터럴·메모리writer분리를확인했다. 독립계약/실행전안전QA2건 deleg_a23a1e9a 요청.
- writer종료후부모만worktree workspace.members에app추가하고cargo generate-lockfile --offline 실행. TOML의다른항목변경0·기존lock {len(old)}패키지필드전체(version/source/checksum/deps)동등·신규localapp하나/network-core+tokio의존관계만추가를기계확인. rootmanifest/lock는미변경.
- cargo test --offline --locked -p network-quick-check --all-targets 실제컴파일후lib9시험8PASS1FAIL로중단(exit101). 600주소fixture가실제16384byte를넘지않아overflow선행단언실패. strictClippy도unusedimport/동등style시험코드로exit101. 실패로그는덮지않고보존·기본suite전체통과로표현하지않음.
- 추가부모정적대조: newline error_message는JSON에서escape되어한줄IPC이므로exit1기대는원문보존계약과모순, nativeIPv6bind .ok()는양쪽소유fixture필수계약위반, privatecallback이pub로노출됨. 독립QA수신전추가보정없음. native실행0·제품명령행실행0·root미통합·미수용.
- root기존Core415/native22수용과Inspector보호{len(protected)}SHA불변. 이번worker기반의컴파일은GUI/단일EXE무설치/전체QG2완료아님. 상세 artifacts/qg2f-app-parent-initial-execution.json.
\n'''
for name in ['PROGRESS.md','RESUME.md']:
    path=R/name
    first,rest=path.read_text(encoding='utf-8').split('\n',1)
    path.write_text(first+'\n'+section+rest,encoding='utf-8',newline='\n')
path=R/'작업내용/NPI_2026-10-22_001.md'
path.write_text(path.read_text(encoding='utf-8')+section,encoding='utf-8',newline='\n')
print(json.dumps({'status':record['status'],'test_counts':counts,'existing_lock_packages_identical':len(old),
                  'native_executed':False,'accepted':False,'review':'deleg_a23a1e9a'},ensure_ascii=False))
