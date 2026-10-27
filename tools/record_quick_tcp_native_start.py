"""실제 Flash PID·고정 source·정확한 단계 상태를 확인하고 프로젝트 진행을 기록한다."""
import ctypes
from ctypes import wintypes
import datetime
import hashlib
import json
import pathlib

R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgtcpnative'
load=lambda path:json.loads((R/path).read_text(encoding='utf-8'))
sha=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
started=load('.harness/runs/qg2tcpnative-qgtcpnative/started.json')
contract=load('artifacts/qg2h-tcp-native-actor-prepared.json')
assert started['model']==contract['model']=='gemini-3.8-flash-high'
assert started['stage']=='qg2tcpnative' and started['role']=='qgtcpnative'
assert pathlib.Path(started['worktree']).resolve()==W.resolve()
k=ctypes.WinDLL('kernel32',use_last_error=True)
k.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
k.OpenProcess.restype=wintypes.HANDLE
k.GetExitCodeProcess.argtypes=[wintypes.HANDLE,ctypes.POINTER(wintypes.DWORD)]
k.GetExitCodeProcess.restype=wintypes.BOOL
k.QueryFullProcessImageNameW.argtypes=[wintypes.HANDLE,wintypes.DWORD,wintypes.LPWSTR,ctypes.POINTER(wintypes.DWORD)]
k.QueryFullProcessImageNameW.restype=wintypes.BOOL
k.CloseHandle.argtypes=[wintypes.HANDLE]
k.CloseHandle.restype=wintypes.BOOL
handle=k.OpenProcess(0x1000,False,started['pid'])
assert handle,ctypes.get_last_error()
try:
    code=wintypes.DWORD()
    assert k.GetExitCodeProcess(handle,ctypes.byref(code)) and code.value==259
    buffer=ctypes.create_unicode_buffer(32768)
    size=wintypes.DWORD(len(buffer))
    assert k.QueryFullProcessImageNameW(handle,0,buffer,ctypes.byref(size))
    assert pathlib.Path(buffer.value).resolve()==pathlib.Path('E:/antigravity-cli/agy.exe').resolve()
finally:
    k.CloseHandle(handle)
assert all(sha(R/path)==value and sha(W/path)==value for path,value in contract['immutable_source_sha256'].items())
protected=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
engine='crates/npi-probes/src/engine.rs'
assert all(sha(R/path)==value for path,value in protected.items() if path!=engine)
assert sha(R/engine)==load('artifacts/qg2g-tcp-replay-acceptance.json')['source_sha256'][engine]
now=datetime.datetime.now().astimezone()
state=load('artifacts/quick-check-progress.json')
record={'recorded_at':now.isoformat(),'status':'FLASH_NATIVE_TEST_WRITER_RUNNING',
        'worktree':str(W),'model':started['model'],'actor_pid':started['pid'],'actor_alive_verified':True,
        'supervisor_session':'proc_ea3a654e5a65','supervisor_pid':29584,
        'immutable_source_files':len(contract['immutable_source_sha256']),
        'actor_writes':contract['actor_writes'],'actor_started_at':started['started_at'],
        'design_review_received':True,'design_review':'deleg_44dc1296',
        'actual_quick_api':'network_core::runner::run_quick',
        'native_executed':False,'root_integrated':False,'accepted':False,
        'root_original_protected_unchanged':len(protected)-1,'previous_approved_visibility_exception_files':1}
out=R/'artifacts/qg2h-tcp-native-start.json'
assert not out.exists()
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
state['recorded_at']=record['recorded_at']
state['next_qg2_native_review'].update(record)
state['next_qg2_native_review']['start_artifact']=str(out.relative_to(R))
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
section=f'''\n## 실제 IPv4/IPv6 양제품 TCP 대조 시험 작성 시작 — {record['recorded_at']}
- 이전root순수replay6개포함433PASS/native23/CLI38제한수용은유지. 다음QG2 slice는실제Inspector run_profile 반환Envelope와실제Quick run_quick을소유단일loopback목적지에순차실행하여같은조건의성공/거부와메모리raw보존을대조한다. 추가production변경0·기존공개pub4바이트예외외원본보호60SHA유지.
- 설계독립검토 deleg_44dc1296 수신·실제API는run_quick임을source로대조했고가상with_backend함수/제안의root출력경로는채택하지않았다. writer는전용W의새시험1파일만작성한다. bound/nonlisten예약은exclusive보장아님·실제REFUSED10061을요구·OS옵션/방화벽/route/registry수정금지. 두별도native시점의elapsed/localport전체동일요구금지·같은Inspector실측raw의Quickprojector replay는별도축이다.
- 전용worktree .worktrees/qgtcpnative / ai-pro/qgtcpnative / base {contract['baseline_commit']} ·94source동결. FILE ONLY FlashHigh {started['model']} 실제actorPID {started['pid']} agy.exe생존확인, supervisor proc_ea3a654e5a65/PID29584. native4ignored+wrapper부정입력pure시험계약·도구/경로/stream/partial/SHA감사후독립정적QA와부모실행예정단계다. 허용쓰기 crates/network-core/tests/tcp_product_native_equivalence.rs 하나·manifest/lock/기존test/production변경금지. 하네스선택회귀24PASS는별도근거이며새Rust/native통과주장이아니다.
- 현재새시험작성중·compile/format/native실행0·root새source통합0·미수용. activewriterW에서Cargo/metadata/format/시험금지. 실제DROP/VLAN/ICMP차단/다중NIC/VPN·제품EXE진단시작경로/GUI/QG3이후·Archive/Session·OS/VM/성능·배포미완료를그대로유지한다.
\n'''
for name in ['PROGRESS.md','RESUME.md']:
    path=R/name
    first,rest=path.read_text(encoding='utf-8').split('\n',1)
    path.write_text(first+'\n'+section+rest,encoding='utf-8',newline='\n')
path=R/'작업내용'/('NPI_'+now.strftime('%Y-%m-%d')+'_001.md')
path.write_text(path.read_text(encoding='utf-8')+section,encoding='utf-8',newline='\n')
print(json.dumps(record,ensure_ascii=False))
