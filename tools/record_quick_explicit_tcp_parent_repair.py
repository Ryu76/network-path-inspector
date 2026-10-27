"""원본 실패·정적 QA와 부모 보정을 분리해 최종 소스 및 실제 기본 회귀를 동결한다."""
import datetime
import hashlib
import json
import pathlib
import re
import subprocess
import tomllib

R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgdevtcp'
load=lambda p:json.loads((R/p).read_text(encoding='utf-8'))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
c=load('artifacts/qg2i-explicit-tcp-actor-prepared.json')
p=load('artifacts/qg2i-explicit-tcp-pipeline.json')
metadata=list(c['parent_metadata_changes'])
assert all(sha(R/path)==value for path,value in c['root_before_sha256'].items())
assert all(sha(W/path)==value for path,value in c['immutable_source_sha256'].items() if path not in metadata)
assert all(sha(R/'.harness/evidence/qg2i-explicit-tcp-actor-original'/pathlib.Path(path).name)==value for path,value in p['source_sha256'].items())
old=tomllib.loads((R/'Cargo.lock').read_text(encoding='utf-8'))
new=tomllib.loads((W/'Cargo.lock').read_text(encoding='utf-8'))
key=lambda item:(item['name'],item['version'],item.get('source'),item.get('checksum'))
oldkeys={key(item) for item in old['package']}
newkeys={key(item) for item in new['package']}
assert oldkeys<=newkeys
added=sorted((item['name'],item['version']) for item in new['package'] if key(item) not in oldkeys)
assert added==[('bytes','1.11.1'),('errno','0.3.14'),('signal-hook-registry','1.4.8')]
manifest=tomllib.loads((W/'apps/network-quick-check/Cargo.toml').read_text(encoding='utf-8'))
assert manifest['dev-dependencies']['tokio']=={'version':'=1.52.3','features':['process']}
assert 'process' not in manifest['dependencies']['tokio']['features']
commands={}
for label,name in [('actor_compile','qg2i-explicit-tcp-first-default'),('lock_guard','qg2i-explicit-tcp-repaired-default'),
    ('incomplete_compile','qg2i-explicit-tcp-repaired-default-v2'),('parent_bool_api_error','qg2i-explicit-tcp-repaired-default-v3'),
    ('fixture_mismatch','qg2i-explicit-tcp-repaired-default-v4'),('app_default_pass','qg2i-explicit-tcp-repaired-default-v5'),
    ('first_clippy','qg2i-explicit-tcp-parent-clippy'),('final_clippy','qg2i-explicit-tcp-parent-clippy-v2'),
    ('workspace','qg2i-explicit-tcp-parent-workspace')]:
    item=load('artifacts/commands/'+name+'.json')
    text=pathlib.Path(item['log']).read_text(encoding='utf-8')
    values=[tuple(map(int,row)) for row in re.findall(r'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;',text)]
    item['counts']={field:sum(row[index] for row in values) for index,field in enumerate(['passed','failed','ignored'])} if values else None
    item['log_sha256']=sha(pathlib.Path(item['log']))
    commands[label]=item
assert commands['actor_compile']['exit_code']==101
assert commands['fixture_mismatch']['counts']['failed']==1
assert commands['workspace']['exit_code']==0 and not commands['workspace']['partial']
assert commands['workspace']['counts']['failed']==0
assert commands['final_clippy']['exit_code']==0 and not commands['final_clippy']['partial']
previous=load('artifacts/qg2h-tcp-native-root-validation.json')
base=next(item for item in previous['steps'] if item['name'].endswith('-workspace'))
native_base=next(item for item in previous['steps'] if item['name'].endswith('-native'))
native_names=sorted(re.findall(r'async fn (native_ipv[46]_(?:connected|refused))\(',
    (W/'apps/network-quick-check/tests/explicit_tcp_entry.rs').read_text(encoding='utf-8')))
assert len(native_names)==4 and commands['workspace']['counts']['ignored']==native_base['passed']+len(native_names)
assert commands['workspace']['counts']['passed']>base['passed']
paths=sorted(set(c['actor_writes'])|set(metadata))
files={path:sha(W/path) for path in paths}
for path in paths:
    text=(W/path).read_text(encoding='utf-8')
    assert text.endswith('\n') and all(line.rstrip(' \t')==line for line in text.splitlines())
check=subprocess.run(['git','-C',str(W),'diff','--check'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
assert check.returncode==0,check.stdout+check.stderr
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'REPAIRED_DEFAULT_VALIDATED_NATIVE_SAFETY_REVIEW_PENDING',
    'source_sha256':files,'actor_original_sha256':p['source_sha256'],'actor_original_archive':'.harness/evidence/qg2i-explicit-tcp-actor-original',
    'immutable_source_sha256':{path:value for path,value in c['immutable_source_sha256'].items() if path not in metadata},
    'root_before_sha256':c['root_before_sha256'],'metadata_after_parent_repair':{path:files[path] for path in metadata},
    'parent_delta_version':'qg2i-explicit-tcp-entry-0.2','parent_is_coauthor':True,
    'changes':['실제E0382 counter소유권/E0560가상duration_ms 제거·기본시험 빌드 보정',
        'stderr invalid출력실패exit1·생산dispatcher를모의와공유·고정local오류표시',
        '전체payload cap writer로직렬화중상한·LF예약·2중buffer제거',
        '실제신호감독과mock이동일cancel/drainhelper공유·Arc동일성/Pending/cleanup해제/전체raw 보존',
        'Trace메서드counter실제증가·미선택feature/backend/report집계각case검증',
        'DNSfixture호스트와request정합성보정·원래불일치의TCP0음성대조군보존',
        '자식guard를Tokio process로보유·inline bounded pipe/read wait join·오류시kill/wait·서버오류도자식감독join뒤판정',
        'process기능은부모가고정Tokio dev-dependency에만추가·bytes1.11.1해석추가·offline실제빌드',
        'Clippy cloned_ref_to_slice_refs 보정·OS즉시회수과장주석제거'],
    'added_registry_packages':[{'name':name,'version':version} for name,version in added],
    'previous_package_identity_and_checksums_preserved':True,
    'dependency_limit':'bytes는dev process기능의추가lock의존성이다·별도Release normal graph/배포인증은하지않음·외부다운로드없음',
    'commands':commands,'workspace_counts':commands['workspace']['counts'],
    'new_default_passed':commands['workspace']['counts']['passed']-base['passed'],
    'expected_native_total':native_base['passed']+len(native_names),'new_native_tests':native_names,
    'new_native_executed':False,'new_native_execution_held':True,'root_integrated':False,'accepted':False,
    'limitations':['실제OS강제종료/kill실패·Tokio내부blockingIO의엄격한실시간회수인증아님',
        '실Console신호전달·실제domain→worker→TCP EXE·GUI/QG3·전체QG2실환경·성능·배포미검증']}
out=R/'artifacts/qg2i-explicit-tcp-parent-repair.json'
assert not out.exists()
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
ref=W/'.harness/references/explicit-tcp-entry-parent-delta.json'
assert not ref.exists()
ref.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
s=load('artifacts/quick-check-progress.json')
s['recorded_at']=record['recorded_at']
s['next_qg2_explicit_tcp_entry'].update(status=record['status'],workspace_counts=record['workspace_counts'],
    source_sha256=files,parent_repair=str(out.relative_to(R)),native_execution_held=True)
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(s,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':record['status'],'workspace_counts':record['workspace_counts'],'new_default_passed':record['new_default_passed'],
    'source_sha256':files,'frozen_nonmetadata_files':len(record['immutable_source_sha256']),
    'expected_native_total':record['expected_native_total'],'new_native_executed':False},ensure_ascii=False))
