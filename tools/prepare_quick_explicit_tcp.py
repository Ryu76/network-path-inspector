"""사용자 재개 지시 아래 QG2 앱 소비 경로의 격리 worktree와 부모 의존성을 동결한다."""
import datetime
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import tomllib

R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgdevtcp'
STAGE='qg2explicit'
ROLE='qgdevtcp'
APP='apps/network-quick-check/'
WRITES=[APP+'src/lib.rs',APP+'src/diagnostic_cli.rs',APP+'tests/explicit_tcp_entry.rs']
META=[APP+'Cargo.toml','Cargo.lock']
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))

def git(root,*args):
    p=subprocess.run(['git','-C',str(root),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60)
    assert p.returncode==0,p.stderr
    return p.stdout.rstrip('\r\n')

out=R/'artifacts/qg2i-explicit-tcp-prepared.json'
assert not out.exists()
assert not (R/'.harness/runs'/(STAGE+'-'+ROLE)).exists()
assert all(not (R/path).exists() for path in WRITES[1:])
processes=subprocess.run(['powershell.exe','-NoProfile','-NonInteractive','-Command',
    '$p=Get-CimInstance Win32_Process | Where-Object { $_.Name -ieq "agy.exe" }; @($p | Select-Object ProcessId,ParentProcessId,Name,CommandLine) | ConvertTo-Json -Compress'],
    capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
assert processes.returncode==0
rows=json.loads(processes.stdout or '[]')
rows=rows if isinstance(rows,list) else [rows]
# 실행 중인 사용자 TUI와 FILE writer를 구분한다. TUI를 종료하거나 권한을 넓히지 않는다.
import re
active_print=[p for p in rows if re.search(r'(?:^|\s)--print(?:=|\s)',p.get('CommandLine') or '')]
assert not active_print,'동시 agy print writer 발견·기존 프로세스 보존 후 확인 필요'
unclosed=[p.parent.name for p in (R/'.harness/runs').glob('*/started.json') if not (p.parent/'result.json').exists()]
assert not unclosed,unclosed
process_summary=[{'pid':p['ProcessId'],'interactive_non_print':True} for p in rows]
previous=load('artifacts/qg2h-tcp-native-acceptance.json')
assert previous['accepted'] and all(sha(R/path)==value for path,value in previous['source_sha256'].items())
oldapp=load('artifacts/qg2f-app-entry-acceptance.json')['source_sha256']
assert all(sha(R/path)==value for path,value in oldapp.items())
engine='crates/npi-probes/src/engine.rs'
protected=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(sha(R/path)==value for path,value in protected.items() if path!=engine)
original=R/'.harness/baselines/qg2g-tcp-replay-root/engine.rs'
assert sha(original)==protected[engine]
assert (R/engine).read_bytes()==original.read_bytes().replace(b'fn apply_tcp_result(',b'pub fn apply_tcp_result(',1)
assert load('artifacts/commands/qg2i-explicit-tcp-harness-tests.json')['exit_code']==0
scope=load('artifacts/qg2i-entry-scope-review.json')
assert scope['existing_cli_cases_verified']==38 and not scope['selector_occurs_in_existing_case_source']
# 최신 직접 재개지시를 범위 안 개발 재개의 근거로 기록한다. selector 자체를 사용자가 명시 승인했다고 쓰지 않는다.
paths=set(load('artifacts/qg2h-tcp-native-actor-prepared.json')['immutable_source_sha256'])|set(previous['source_sha256'])
paths|={p.relative_to(R).as_posix() for p in (R/'crates').rglob('*.rs')}
paths|={p.relative_to(R).as_posix() for p in (R/'crates').rglob('Cargo.toml')}
root_before={path:sha(R/path) for path in sorted(paths)}
if W.exists():
    # 최초 부모 준비는 manifest 단언에서 멈췄다. 그 입력 복사본만 그대로 보존·재개한다.
    assert git(W,'branch','--show-current')=='ai-pro/qgdevtcp'
    assert git(W,'rev-parse','HEAD')==previous['preserved_source_commit']
    assert all(sha(W/path)==value for path,value in root_before.items())
else:
    git(R,'worktree','add','-b','ai-pro/qgdevtcp',str(W),previous['preserved_source_commit'])
    assert not git(W,'status','--porcelain')
for path in sorted(paths):
    (W/path).parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(R/path,W/path)
    assert sha(W/path)==root_before[path]
manifest=W/APP/'Cargo.toml'
text=manifest.read_text(encoding='utf-8')
old='[dependencies]\nnetwork-core = { path = "../../crates/network-core" }\n\n[dev-dependencies]\ntokio = { version = "=1.52.3", features = ["rt", "time"] }'
assert old in text
new='[dependencies]\nnetwork-core = { path = "../../crates/network-core" }\nserde_json = { workspace = true }\n# 명시 개발용 경로에서만 런타임·신호 수신을 시작한다. 기존 버전을 직접 선언한다.\ntokio = { version = "=1.52.3", features = ["rt", "time", "net", "signal", "sync", "macros"] }'
manifest.write_text(text.replace(old,new,1),encoding='utf-8',newline='\n')
# 기존 rt/time과 고정 버전을 보존한다. 제품은 current_thread Builder를 사용한다.
for name,argv in [('qg2i-explicit-tcp-parent-lock',['cargo','generate-lockfile','--offline']),
    ('qg2i-explicit-tcp-parent-windows-metadata',['cargo','metadata','--offline','--locked','--filter-platform','x86_64-pc-windows-msvc','--format-version','1']),
    ('qg2i-explicit-tcp-parent-metadata-compile',['cargo','check','--offline','--locked','--target','x86_64-pc-windows-msvc','-p','network-quick-check'])]:
    result=subprocess.run([sys.executable,'tools/run_command_evidence.py','--cwd',str(W),'--name',name,'--timeout','180','--',*argv],cwd=R,timeout=220)
    assert result.returncode==0,name
oldlock=tomllib.loads((R/'Cargo.lock').read_text(encoding='utf-8'))
newlock=tomllib.loads((W/'Cargo.lock').read_text(encoding='utf-8'))
identity=lambda p:(p['name'],p['version'],p.get('source'),p.get('checksum'))
oldids={identity(p) for p in oldlock['package']}
newids={identity(p) for p in newlock['package']}
assert oldids<=newids
added=sorted((p['name'],p['version']) for p in newlock['package'] if identity(p) not in oldids)
assert added==[('errno','0.3.14'),('signal-hook-registry','1.4.8')],added
for oldpackage in oldlock['package']:
    current=next(p for p in newlock['package'] if identity(p)==identity(oldpackage))
    if current!=oldpackage:
        assert oldpackage['name'] in ('tokio','network-quick-check')
        assert set(oldpackage.get('dependencies',[]))<=set(current.get('dependencies',[]))
        assert set(current.get('dependencies',[]))-set(oldpackage.get('dependencies',[]))<= {'signal-hook-registry','serde_json'}
assert all(sha(R/path)==value for path,value in root_before.items())
assert all(sha(W/path)==value for path,value in root_before.items() if path not in META)
assert all(not (W/path).exists() for path in WRITES[1:])
git(W,'add',*sorted(paths))
git(W,'-c','core.autocrlf=false','commit','-m','chore: freeze shared source and pinned app runtime dependencies for explicit TCP entry')
assert not git(W,'status','--porcelain')
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'PREPARED_FILE_ONLY_SCOPE',
    'worktree':str(W),'baseline_commit':git(W,'rev-parse','HEAD'),'stage':STAGE,'role':ROLE,'model':'gemini-3.8-flash-high',
    'user_resumption_directive_verbatim':'다시 진행해','selector_specific_human_approval_claimed':False,
    'parent_scope_decision':'기존 프로젝트 지속개발 범위에서 QG2의 명시 단일TCP 개발보조 경로를 최소 구현 방식으로 선택·GUI/배포/정책 변경 아님',
    'supersedes_scope_hold':'artifacts/qg2i-entry-scope-review.json·선행38case/고정의존성 확인 완료 후 재개 지시 수신',
    'actor_writes':WRITES,'parent_metadata_changes':{path:sha(W/path) for path in META},
    'root_before_sha256':root_before,
    'immutable_source_sha256':{path:sha(W/path) for path in sorted(paths) if path not in WRITES},
    'new_all_target_registry_packages':[{'name':name,'version':version} for name,version in added],
    'old_package_identity_and_checksums_preserved':True,'source_files_frozen':len(paths),
    'parent_metadata_compile_is_not_new_cli_execution':True,'root_original_protected_unchanged':len(protected)-1,
    'approved_visibility_exception_sha256':sha(R/engine),'actor_started':False,'root_integrated':False,'accepted':False,
    'exclusions':['GUI/QG3 이후·전체QG2','실제domain→worker→TCP제품EXE 전체native경로',
        '실제Windows Console취소 전달·자원회수 인증','실VLAN/DROP/ICMP차단/VPN/다중NIC·성능·Release/배포/OS·전체시각메타데이터']}
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
state=load('artifacts/quick-check-progress.json')
state['recorded_at']=record['recorded_at']
state['next_qg2_app_integration_review'].update(status='REVIEW_RECEIVED_AND_PARENT_SCOPED',review_received=True,
    actor_started=False,production_changed=False,scope_hold_superseded_by_resumption=True)
state['next_qg2_explicit_tcp_entry']={k:record[k] for k in ['status','worktree','baseline_commit','stage','role','actor_writes',
    'parent_metadata_changes','actor_started','root_integrated','accepted']}
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':record['status'],'baseline_commit':record['baseline_commit'],'source_files_frozen':len(paths),
    'immutable_actor_files':len(record['immutable_source_sha256']),'parent_metadata_only':META,'root_source_changed':False},ensure_ascii=False))
