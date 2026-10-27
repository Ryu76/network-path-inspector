"""DNS 수용 후 실제 Trace 연결 writer와 종료 연동 독립QA를 기록한다."""
import csv
import datetime
import hashlib
import io
import json
import pathlib
import subprocess

R = pathlib.Path(__file__).resolve().parents[1]
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))
run = load('.harness/runs/qg2tracewire-qg2runner/started.json')
pipeline = load('artifacts/qg2e-trace-runner-pipeline.json')
prepared = load('artifacts/qg2e-trace-runner-prepared.json')
assert run['model'] == 'gemini-3.8-flash-high'
process = subprocess.run(['tasklist.exe', '/FI', 'PID eq ' + str(run['pid']), '/FO', 'CSV', '/NH'],
                         capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=20)
assert process.returncode == 0
alive = any(len(row) > 1 and row[1] == str(run['pid']) and row[0].lower() == 'agy.exe'
            for row in csv.reader(io.StringIO(process.stdout)))
protected = load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
assert all(hashlib.sha256((R / path).read_bytes()).hexdigest() == expected for path, expected in protected.items())
dns = load('artifacts/qg2d-dns-runner-acceptance.json')
trace = load('artifacts/qg2c-trace-os-code-acceptance.json')
assert dns['accepted'] and trace['accepted']
assert all(hashlib.sha256((R / path).read_bytes()).hexdigest() == expected
           for path, expected in {**dns['source_sha256'], **trace['source_sha256']}.items())
now = datetime.datetime.now().astimezone().isoformat()
state = load('artifacts/quick-check-progress.json')
state['recorded_at'] = now
state['qg2_trace_runner'] = {
    'status': pipeline['status'], 'stage': run['stage'], 'model': run['model'],
    'actor_pid': run['pid'], 'actor_alive_at_checkpoint': alive,
    'pipeline_session': 'proc_9c8ac57a2f13', 'pipeline_artifact': 'artifacts/qg2e-trace-runner-pipeline.json',
    'baseline_commit': prepared['baseline_commit'], 'frozen_source_files': len(prepared['dependency_source_sha256']),
    'independent_review': 'deleg_1fd6a188',
    'review_gate': 'producer OS 종료대기→정책감사/불변SHA확인 후에만 candidate source 읽기',
    'execution_policy': '새native연결이므로format/compile/기본시험/native실행은소스안전검토후부모가수행',
    'accepted': False, 'root_integrated': False, 'implementation_started': True,
}
state['trace_runner_contract_review'].update(status='구현 시작·source QA 대기', implementation_started=True,
                                               frozen_contract='artifacts/qg2e-trace-runner-prepared.json')
state['remaining_blockers'] = ['선택Trace 실행기 구현·실행전 독립QA·실제전체/소유native/Clippy·root통합 전',
                               '제품동일EXE helper dispatch/GUI/단일EXE/PE·서명/일반사용자/VM/실VLAN·성능·전체QG2 미완료']
(R / 'artifacts/quick-check-progress.json').write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
section = f'''\n## 선택 Trace 실행기 실제 구현·종료 연동 QA 시작 — {now}
- 수용DNS실행기·Trace OS코드보정의root동일소스를qg2runner에동결(commit {prepared['baseline_commit']}, {len(prepared['dependency_source_sha256'])}파일SHA). Flash qg2tracewire 실제PID{run['pid']}, checkpoint실행여부={alive}. runner.rs/tests/runner.rs 두파일만수정하며root는아직수용DNS실행기380/native20범위를유지한다.
- Trace backend 기본메서드호환·명시선택·기존trace_once위임·실측raw 재어댑터/실제선택IP검증·DNS raw/역순취소보존이이번구현범위. 새DTO/manifest/Trace엔진/GUI/제품EXE변경금지.
- 새코드가실제진단에연결되므로producer감독 proc_9c8ac57a2f13는작성종료후정책/경로/불변SHA까지만검사하고format/compile/시험을멈춘다. 독립2검토자 deleg_1fd6a188는부모소유bounded OSWait 스크립트로producer종료와감사/SHA를먼저확인한뒤에만소스를검토한다. 기본pure/native격리·정확소유loopback이확인되기전실제코드를실행하지않는다.
- 종료대기게이트는실제1초 smoke에서기대WAIT_TIMEOUT/exit124를반환함을확인했고producer는계속실행. 이는제품시험실패가아니라제어경로시험이다. QA는최대550초 OSWait2회만허용하며artifact polling/일반명령/네트워크/편집없음. prompt/감사는OS강제격리보장이아님.
- Inspector보호{len(protected)}파일SHA불변·원격push/운영망/OS정책/DB변경없음. Trace실행기와전체QG2/GUI/EXE완료를미리주장하지않음.
\n'''
for name in ['PROGRESS.md', 'RESUME.md']:
    path = R / name
    original = path.read_text(encoding='utf-8')
    first, rest = original.split('\n', 1)
    path.write_text(first + '\n' + section + rest, encoding='utf-8', newline='\n')
path = R / '작업내용/NPI_2026-10-22_001.md'
path.write_text(path.read_text(encoding='utf-8') + section, encoding='utf-8', newline='\n')
print(json.dumps({'stage': run['stage'], 'actor_pid': run['pid'], 'actor_alive': alive,
                  'pipeline_status': pipeline['status'], 'independent_review': 'deleg_1fd6a188',
                  'baseline_commit': prepared['baseline_commit'], 'frozen_files': len(prepared['dependency_source_sha256']),
                  'inspector_unchanged': len(protected), 'accepted': False}, ensure_ascii=False))
