"""수용 slice의 최종 불변·새파일 공백을 확인하고 다음 읽기전용 검토를 기록한다."""
import datetime
import hashlib
import json
import pathlib

R=pathlib.Path(__file__).resolve().parents[1]
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))
accept=load('artifacts/qg2f-app-entry-acceptance.json')
assert accept['accepted'] and not accept['product_accepted'] and not accept['full_qg2_accepted']
assert all(hashlib.sha256((R/path).read_bytes()).hexdigest()==value for path,value in accept['source_sha256'].items())
paths=list(accept['source_sha256'])
for name in ['owned_bounded_child','verify_quick_app_entry_owned_native','integrate_quick_app_entry',
             'verify_quick_app_entry_root','accept_quick_app_entry','prepare_quick_app_entry_repair',
             'run_quick_app_entry_repair','record_quick_app_entry_repair_start','record_quick_app_entry_parent_execution']:
    paths.append('tools/'+name+'.py')
for name in paths:
    text=(R/name).read_text(encoding='utf-8')
    assert text.endswith('\n') and not text.endswith('\n\n'), name
    assert all(line==line.rstrip(' \t') for line in text.splitlines()), name
now=datetime.datetime.now().astimezone().isoformat()
state=load('artifacts/quick-check-progress.json')
state['recorded_at']=now
state['next_qg2_review']={'status':'READ_ONLY_DESIGN_REVIEW_DISPATCHED','delegation':'deleg_7532729a',
    'scope':'PRD23.4 동일TCP 원시측정 Inspector/Quick 판정·OS코드 보존의 기존publicAPI와시험공백 확인',
    'implementation_started':False,'runtime_or_network_executed':False,
    'constraints':['기존중복증거면그대로기록','공유엔진복제0·보호Inspector소스변경0',
                   '실제순차TCP측정의무조건동등성주장금지','QG2실환경blocked/QG3순차경계유지']}
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
section=f'''\n## 후속 QG2 test-only 동등성 공백 검토 착수 — {now}
- 제품동일EXE worker slice수용후실제source6SHA불변과신규app/하네스15파일UTF8·최종개행·후행공백검사를추가확인했다.
- 다음후보는PRD23.4 동일TCP원시측정에대한Inspector/Quick판정·OS코드보존동등성회귀다. 기존publicAPI/시험을먼저읽는독립검토 deleg_7532729a를실제요청했다. 이미있는증거면중복구현하지않고,private경계때문에불가능하면구체blocked로남긴다.
- 아직설계검토뿐·새소스작성/네트워크/추가runtime실행없음. 공유엔진복제/보호Inspector소스변경/실제순차TCP결과무조건일치주장금지. GUI/QG3나미승인실환경검증으로확대하지않음.
\n'''
for name in ['PROGRESS.md','RESUME.md']:
    path=R/name
    first,rest=path.read_text(encoding='utf-8').split('\n',1)
    path.write_text(first+'\n'+section+rest,encoding='utf-8',newline='\n')
path=R/'작업내용/NPI_2026-10-22_001.md'
path.write_text(path.read_text(encoding='utf-8')+section,encoding='utf-8',newline='\n')
print(json.dumps({'accepted_source_unchanged':len(accept['source_sha256']),'whitespace_files_verified':len(paths),
                  'next_review':'deleg_7532729a','implementation_started':False},ensure_ascii=False))
