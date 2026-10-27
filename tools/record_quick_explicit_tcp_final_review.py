"""완전한 async 최종 QA를 정규화하고 실제 동결 SHA·원본 보존을 부모가 확인한다."""
import datetime
import hashlib
import json
import pathlib
import re
R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgdevtcp'
load=lambda p:json.loads((R/p).read_text(encoding='utf-8'))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
p=load('artifacts/qg2i-explicit-tcp-parent-repair.json')
assert all(sha(W/path)==value for path,value in p['source_sha256'].items())
assert all(sha(W/path)==value for path,value in p['immutable_source_sha256'].items())
assert all(sha(R/path)==value for path,value in p['root_before_sha256'].items())
transcripts=[]
for index in range(2):
    path=pathlib.Path('C:/Users/HODI/AppData/Local/hermes/cache/delegation/live/deleg_62debd02')/f'task-{index}.log'
    assert 'end status=completed' in path.read_text(encoding='utf-8')
    transcripts.append({'path':str(path),'sha256':sha(path)})
text=pathlib.Path(p['commands']['workspace']['log']).read_text(encoding='utf-8')
binaries={}
for line in text.splitlines():
    if 'Running tests\\explicit_tcp_entry.rs (' in line:
        binaries['explicit_tcp_entry']=line.rsplit(' (',1)[1][:-1]
    if 'Running tests\\resolver_dispatch.rs (' in line:
        binaries['resolver_dispatch']=line.rsplit(' (',1)[1][:-1]
target=R/'.harness/targets/qg2i-explicit-tcp-first-default/debug'
binaries['product']=str(target/'NetworkQuickCheck.exe')
assert len(binaries)==3
for path in binaries.values():
    assert pathlib.Path(path).is_file() and pathlib.Path(path).resolve().is_relative_to(target.resolve())
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'FINAL_STATIC_REVIEWS_RECEIVED_NO_FINDINGS',
    'review':'deleg_62debd02','representation':'완전한async최종응답의부모정규화·실제tool/trace/SHA증명과구분',
    'transcripts':transcripts,'findings':[],'safe_to_execute_default_tests':True,'safe_to_execute_owned_native_tests':True,
    'resolved':['F1 E0382/E0560','F2 invalid stderr output failure','F3 bounded serialization',
        'F4 sameArc/Pending/drain/raw preservation','F5 real Trace counter','F6 Child ownership/inline pipe cleanup',
        '실제생산공유dispatcher/신호감독mock','전체wire/LF/nullable/기존core보존'],
    'source_sha256':p['source_sha256'],'active_test_binaries':binaries,
    'binary_sha256_before_native':{path:sha(pathlib.Path(path)) for path in binaries.values()},
    'parent_owned_native_scope_authorized':True,
    'authorization_scope':'이미허용된소유literal127.0.0.1/::1단일port의명시시험만부모가실행·정적QA가사용자승인이나실행성공을대체하지않음',
    'native_executed':False,'root_integrated':False,'accepted':False,
    'limitations':['실도메인제품CLI worker→TCP/실제Console신호/전역handler원복미검증',
        'kill실패·정리timeout·unwind·Tokio내부blockingIO의엄격OS즉시회수인증아님',
        '다중대상취소witness·전체QG2실환경·GUI/QG3·Release/배포/성능미수용']}
out=R/'artifacts/qg2i-explicit-tcp-final-independent-review.json'
assert not out.exists()
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':record['status'],'findings':[],'safe_default':True,'safe_owned_native':True,
    'source_sha256':record['source_sha256'],'active_test_binaries':binaries,'native_executed':False},ensure_ascii=False))
