"""제품 worker 진입점 수정 actor의 실제 가동과 원본 보존을 기록한다."""
import csv
import datetime
import hashlib
import io
import json
import pathlib
import subprocess

R=pathlib.Path(__file__).resolve().parents[1]
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
started=load('.harness/runs/qg2appentryfix-qgquickapp/started.json')
review=load('artifacts/qg2f-app-entry-independent-review.json')
assert started['model']=='gemini-3.8-flash-high'
assert started['stage']=='qg2appentryfix' and started['role']=='qgquickapp'
p=subprocess.run(['tasklist.exe','/FI',f"PID eq {started['pid']}",'/FO','CSV','/NH'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=20)
assert p.returncode==0
alive=any(len(row)>1 and row[1]==str(started['pid']) and row[0].lower()=='agy.exe' for row in csv.reader(io.StringIO(p.stdout)))
assert alive, '가동중이라기록하려면실제actorPID생존필수'
protected=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(sha(R/path)==value for path,value in protected.items())
accepted=load('artifacts/qg2e-trace-runner-acceptance.json')
assert all(sha(R/path)==value for path,value in accepted['source_sha256'].items())
transcripts=[pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/delegation/live/deleg_a23a1e9a')/f'task-{i}.log' for i in range(2)]
assert all(path.is_file() for path in transcripts)
now=datetime.datetime.now().astimezone().isoformat()
record={'recorded_at':now,'status':'FLASH_FILE_ONLY_REPAIR_RUNNING','started':started,'actor_alive':alive,
        'supervisor_session':'proc_b77be4a5b24c','supervisor_pid':29708,
        'pipeline':'artifacts/qg2f-app-entry-repair-pipeline.json','preserved_commit':review['preserved_commit'],
        'repair_writes':review['repair_writes'],'accepted_findings':review['accepted_findings'],
        'independent_review_transcript_sha256':{str(path):sha(path) for path in transcripts},
        'inspector_protected_unchanged':len(protected),'accepted':False,'root_integrated':False,
        'native_executed':False,'format_cargo_deferred_until_actor_ends':True}
out=R/'artifacts/qg2f-app-entry-repair-start.json'
assert not out.exists()
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
state=load('artifacts/quick-check-progress.json')
state['recorded_at']=now
state['qg2_app_entry'].update(status=record['status'],stage=started['stage'],actor_pid=started['pid'],actor_alive_at_checkpoint=alive,
    pipeline_session=record['supervisor_session'],supervisor_pid=29708,pipeline_artifact=record['pipeline'],
    baseline_commit=review['preserved_commit'],repair_writes=review['repair_writes'],
    independent_review_status='7종확정지적수용·수정작성중',native_executed=False,accepted=False,root_integrated=False)
state['remaining_blockers']=['제품worker진입점7종확정지적 Flash FILE ONLY 최소수정중·감사/순수/Clippy/native/재QA전',
                            '전체QG2실환경/QG3GUI/진단시작경로/PE·CRT·서명/VM·일반사용자·성능미완료']
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
section=f'''\n## 제품 worker 진입점 독립QA 수용·Flash 최소수정 실제 가동 — {now}
- deleg_a23a1e9a 두정적검토를대조하여7종지적을수용했다: JSONescape개행의잘못된거부시험,IPv6 fixture실패무시,시험callback public노출,overflowfixture과소,실제UTF8 MAX-1/MAX/MAX+1경계공백,기본current_exe OS조회순수성모순,unusedimport/Clippy. 부모추가escapedJSON원문보존positive1PASS·wire실제LF1개/CR0/DTO전체동등을실행확인했고실패시험은삭제하지않고수정계약으로보존.
- 미수용WIP+부모workspace/lock+positive회귀를전용branch commit {review['preserved_commit']}로보존했다. root통합/수용commit아님. 원본독립QA2transcriptSHA를상세artifact에보존했다.
- Flash High qg2appentryfix PID{started['pid']}실제생존확인·감독proc_b77be4a5b24c(PID29708). 수정은app lib/native시험2파일만,main/manifest/lock/공유엔진/README/PRD불변. actor종료/감사/실행전소스검토전Cargo/format/시험없음.
- 기본factory검사는private경로결과주입으로OS조회없는순수시험으로정리하고실제current_exe는제품factory에유지한다. ASCII/멀티바이트+escape 실제byte경계6개,비Unicode entry호출0,write/flush실패조건보강. 바이트가드용의도적큰합성payload는정상OS512-byte/주소32개계약수용증거가아님을명시한다. IPv4/IPv6양쪽동일소유포트필수·실패시재시도소진은실패로남김.
- native여전히0·root미통합·미수용. root기존415/native22제한수용과Inspector{len(protected)}SHA불변. 전체QG2실환경/GUI/QG3/배포인증은미완료.
\n'''
for name in ['PROGRESS.md','RESUME.md']:
    path=R/name
    first,rest=path.read_text(encoding='utf-8').split('\n',1)
    path.write_text(first+'\n'+section+rest,encoding='utf-8',newline='\n')
path=R/'작업내용/NPI_2026-10-22_001.md'
path.write_text(path.read_text(encoding='utf-8')+section,encoding='utf-8',newline='\n')
print(json.dumps({'status':record['status'],'actor_pid':started['pid'],'actor_alive':alive,
                  'preserved_commit':review['preserved_commit'],'accepted':False},ensure_ascii=False))
