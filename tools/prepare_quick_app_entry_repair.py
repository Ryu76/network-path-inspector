"""제품 entrypoint 확정 QA/실행 실패를 보존하고 최소 Flash 수정 계약을 준비한다."""
import datetime
import hashlib
import json
import pathlib
import re
import subprocess
import tomllib

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qgquickapp'
STAGE = 'qg2appentryfix'
OUTPUTS = ['apps/network-quick-check/Cargo.toml','apps/network-quick-check/src/lib.rs',
           'apps/network-quick-check/src/main.rs','apps/network-quick-check/tests/resolver_dispatch.rs']
REPAIR = [OUTPUTS[1], OUTPUTS[3]]
load = lambda path: json.loads((R / path).read_text(encoding='utf-8'))
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()

def git(*args):
    p = subprocess.run(['git','-C',str(W),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=40)
    assert p.returncode == 0, p.stderr
    return p.stdout.rstrip('\r\n')

assert not (R/'.harness/runs'/(STAGE+'-qgquickapp')).exists()
assert not (R/'.harness/prompts'/(STAGE+'-qgquickapp.md')).exists()
assert git('branch','--show-current') == 'ai-pro/qgquickapp'
allowed = set(OUTPUTS) | {'Cargo.toml','Cargo.lock'}
assert all(line[3:] in allowed for line in git('status','--porcelain','--untracked-files=all').splitlines())
initial = load('artifacts/qg2f-app-parent-initial-execution.json')
assert initial['source_compiled'] and initial['test_counts'] == {'passed':8,'failed':1,'ignored':0}
positive = load('artifacts/commands/qg2f-app-escaped-json-positive-control.json')
assert positive['exit_code'] == 0 and not positive['partial']
assert '1 passed; 0 failed;' in pathlib.Path(positive['log']).read_text(encoding='utf-8')
# 부모가 추가한 것은 escaped JSON positive 시험뿐이며 기존 manifest/main/native는 actor 그대로다.
for path in [OUTPUTS[0],OUTPUTS[2],OUTPUTS[3]]:
    assert sha(W/path) == initial['actor_source_sha256'][path]
old = {p['name']:p for p in tomllib.loads((R/'Cargo.lock').read_text(encoding='utf-8'))['package']}
new = {p['name']:p for p in tomllib.loads((W/'Cargo.lock').read_text(encoding='utf-8'))['package']}
assert set(new)-set(old) == {'network-quick-check'} and all(new[k]==v for k,v in old.items())
git('add', *sorted(allowed))
git('-c','core.autocrlf=false','commit','-m','chore: preserve unaccepted app entrypoint and failing output witnesses')
assert not git('status','--porcelain')
now = datetime.datetime.now().astimezone().isoformat()
review = {
    'recorded_at':now,'review':'deleg_a23a1e9a','preserved_commit':git('rev-parse','HEAD'),
    'accepted_findings':[
        {'id':'ENTRY-STATIC-001','aliases':['QA-03'],'issue':'JSON escape된개행을실제다중출력으로오판한시험'},
        {'id':'ENTRY-STATIC-002','aliases':['QA-01'],'issue':'IPv6 bind실패를.ok로무시한nativefixture'},
        {'id':'ENTRY-STATIC-003','aliases':['QA-06'],'issue':'private시험callback public노출'},
        {'id':'QA-02','issue':'실제byte상한을넘지않는overflowfixture·부모8pass1fail재현'},
        {'id':'QA-04','issue':'MAX-1/MAX/MAX+1 ASCII·멀티바이트/escape실제byte경계회귀공백'},
        {'id':'QA-05','issue':'엄격pure정의와기본current_exe OS조회모순·privatepathresult주입으로순수검사'},
        {'id':'QA-07','issue':'unusedPathBuf·strictClippy실패. purefactoryhelper에필요시실제사용가능'},
    ],
    'execution':'artifacts/qg2f-app-parent-initial-execution.json',
    'escaped_json_positive_control':positive,'remaining_findings':'수정전·모두미해소',
    'accepted':False,'root_integrated':False,'native_executed':False,
    'immutable_source_sha256':{path:sha(W/path) for path in load('artifacts/qg2f-app-entry-prepared.json')['source_sha256']},
    'repair_writes':REPAIR,'before_outputs_sha256':{path:sha(W/path) for path in OUTPUTS},
}
out = R/'artifacts/qg2f-app-entry-independent-review.json'
assert not out.exists()
out.write_text(json.dumps(review,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
refs = W/'.harness/references/quick-app-entry-repair.json'
assert not refs.exists()
refs.write_text(json.dumps(review,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
prompt = f'''당신은 제품 DNS worker 진입점의 확정결함만수정하는 FILE ONLY actor다. worktree={W.as_posix()}.
모든입출력은worktree절대경로내부만. FILE READ/EDIT/CREATE·내부탐색만허용. command/run_command/terminal/shell/PowerShell/manage_task/시험/compile/git/네트워크/설치/운영/DB/계정/에이전트/재위임절대금지·읽기용명령도금지. root/다른worktree/문서링크따라읽기금지.
허용수정정확2파일: {W.as_posix()}/{REPAIR[0]} 및 {W.as_posix()}/{REPAIR[1]}.
정확읽기입력: 위2파일,{W.as_posix()}/.harness/references/quick-app-entry-contract.json,{W.as_posix()}/.harness/references/quick-app-entry-repair.json,{W.as_posix()}/apps/network-quick-check/src/main.rs,{W.as_posix()}/apps/network-quick-check/Cargo.toml,{W.as_posix()}/crates/network-resolver/src/lib.rs,{W.as_posix()}/crates/network-core/src/runner.rs. 나머지공유source/API/manifest/lock/README/PRD/AGENTS/build/subsystem변경금지. 이미부모가workspace1추가·Cargo offline lock로기존24패키지필드전체불변과새app하나만추가검증했으니건드리지말라.
선행actor작성은정책감사통과했지만부모실제컴파일후lib8PASS1FAIL/strictClippy101이며native미실행. 부모 escapedJSON positive회귀1PASS가추가되어WIP기준에보존되었다. 이시험을약화/삭제하거나당신실행으로표현금지. 다음만최소수정:
1) ENTRY-STATIC-001/QA-03: JSON 문자열안의CR/LF/따옴표/역슬래시는기존serde_json에서escape되므로wire는한줄이고유효원문은보존해야한다. 기존multilinefixture의exit1/stdoutempty기대는계약오류다. 이fixture는exit0/stderrempty/최종LF1개·내부실제CRLF0·기존decode_worker_payload로payload전체동등을검증하도록수정/분리. 부모 parent_escaped_json_error_payload_is_preserved_as_one_line은그대로유지. 제품에원문newline거부/임의mask추가금지.
2) QA-02/04: 600짧은주소가16384bytes넘는다는첫assert부터실패했다. 실제worker_output_line(&payload).len()에맞춰fixture를조정. ASCII와한국어멀티바이트+quote/backslash/CRLF를섞은prefix각각 MAX_PAYLOAD_BYTES-1/정확MAX/MAX+1(최종LF포함)경계3개씩을정확한실제byte길이전제assert후검증. <=MAX는exit0·stdout정확expectedwire/stderrempty, >MAX는exit1/stdoutempty/정적failuremsg. UTF8 char수로계산금지·상한/exit기대완화금지. 방법: 합성payload의prefix실제직렬화basebyte를먼저측정하고ASCII padding으로정확targetbytes맞춤. 이경계fixture는출력가드검사용으로정상engine512-byte오류메시지/32주소상한을의도적으로넘는합성일수있으며그경우valid OS payload/decoder수용증거라표현하지말고주석으로구분. 정상engine제한/API는그대로. 실제JSON다중line발생은serializer특성상도달불가하므로가짜serializer나protocol복제/새공개API를만들지말라.
3) ENTRY-STATIC-002/QA-01: nativefixture IPv6.bind.ok()로None을받고성공진행하는것금지. 두TcpListener가동일port에모두성공한경우만nonOptional쌍으로보관;IPv6실패시v4해제후다음시도,총10회소진시expect실패. 둘다시험끝까지생존·주소정확127.0.0.1/::1/port검사그대로·localhost한번resolve/다른probe0/기존engine감독/ignored유지. filesystem exists대신is_file로정확제품exe파일검사강화가능. native기본실행/새Child감독금지.
4) ENTRY-STATIC-003/QA-06: entry_with_worker의pub제거하여private시험callback으로. app_api의parse_args/entry/native_backend_for_current_exe/EntryMode/EntryError공개계약유지. constants공개여부는기존사용필요가없으면private가능하나최소변경을선호. sharedAPI는수정금지.
5) QA-05: default시험에서std::env::current_exe OS조회도없도록엄격pure로맞춘다. 실제factory는current_exe한번을private purepathresulthelper에전달하고그helper가절대경로만NativeDnsProbeBackend::new로연결,Err/relativefailclosed/대체경로0을처리하도록최소분리. 기본시험은privatehelper에합성Windows절대path/상대path/io::Error를주입하여정확helper_executable동등·Err보존/상대거부를검증한다(파일조회/프로세스/native/network호출0). test harness current_exe를제품EXE증거로주장금지. 실제noargs/help/worker에서factory0그대로. productionfactory는argv0/PATH/CWD/envhelper/QAhelperfallback금지.
6) QA-07/부모Clippy: PathBuf필요없으면제거하거나위purehelper에서정당하게사용. io::ErrorKind::Other 생성은Error::other, needless as_bytes.len은String.len으로동등정리. Clippy suppression/시험삭제금지.
7) 빠진순수시험을좁게강화: Windows unpaired surrogate flag/host/port 각각parse뿐아니라entry/privatecallback에서고정stderr·stdoutempty·worker0, noargs/help/invalid 각각write/flush실패와worker출력실패시stderr마저실패해도exit1/noinputreflection. 정상부분write반복성공과writezero실패도가능하면검증. domain실제worker0·프로세스/소켓/runtime/OS조회/실제파일쓰기0.
한국어설명주석·UTF8·최종개행1개·후행공백없음·helper인수<=7·단일공유worker/검증/serializer재사용. parser/noargs/help/invalid/flag기본semantics/validpayload원문/worker재귀없음/제품basename그대로. 이것은QG2helper최소기반이지진단CLI/GUI/QG3/무설치인증아님.
최종한국어응답변경경로/보정내용/부모검증필요사항만. 실행/컴파일/시험/수용주장금지. 감독은writer종료·감사/SHA고정후실행전소스검토에서멈춘다.
'''
(R/'.harness/prompts'/(STAGE+'-qgquickapp.md')).write_text(prompt,encoding='utf-8',newline='\n')
print(json.dumps({'stage':STAGE,'preserved_commit':review['preserved_commit'],
                  'findings':len(review['accepted_findings']),'repair_writes':REPAIR,'accepted':False},ensure_ascii=False))
