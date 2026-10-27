"""Trace producer 종료를 OS 대기로 기다리고 감사·불변 SHA를 확인한다. 코드 실행 없음."""
import argparse
import ctypes
from ctypes import wintypes
import hashlib
import json
import pathlib
import sys

R = pathlib.Path(__file__).resolve().parents[1]
W = R / '.worktrees/qg2runner'
PIPELINE = R / 'artifacts/qg2e-trace-runner-pipeline.json'
EXPECTED = {'crates/network-core/src/runner.rs', 'crates/network-core/tests/runner.rs'}
READY = 'AUDITED_SOURCE_READY_FOR_PARENT_REVIEW'
p = argparse.ArgumentParser()
p.add_argument('--pid', type=int, required=True)
p.add_argument('--seconds', type=int, default=300)
a = p.parse_args()
# 실제 도구 전송 계층의 420초 제한보다 짧게 유지해 명시적 WAIT_TIMEOUT을 받는다.
assert a.pid > 0 and 1 <= a.seconds <= 360


def load_state():
    return json.loads(PIPELINE.read_text(encoding='utf-8'))


state = load_state()
if state['status'] == 'RUNNING':
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.OpenProcess(0x00100000, False, a.pid)
    if not handle:
        code = ctypes.get_last_error()
        if code != 87:
            print(json.dumps({'status': 'WAIT_HANDLE_ERROR', 'actual_os_code': code}))
            sys.exit(2)
        # 이미 종료되어 PID가 사라진 경우에만 최종 상태 파일을 확인한다. 접근 거부는 우회하지 않는다.
    else:
        try:
            result = kernel.WaitForSingleObject(handle, a.seconds * 1000)
            if result == 258:
                print(json.dumps({'status': 'WAIT_TIMEOUT', 'seconds': a.seconds}))
                sys.exit(124)
            if result != 0:
                print(json.dumps({'status': 'WAIT_FAILED', 'actual_os_code': ctypes.get_last_error()}))
                sys.exit(2)
        finally:
            kernel.CloseHandle(handle)
    state = load_state()
if state['status'] != READY:
    print(json.dumps({'status': state['status'], 'error': state.get('error'), 'review_ready': False}, ensure_ascii=False))
    sys.exit(2)
audit = json.loads((R / 'artifacts/qg2tracewire-actor-policy-audit.json').read_text(encoding='utf-8'))
assert audit['all_actor_policy_checks_passed'], '감사 실패 코드는 검토 성공으로 취급하지 않음'
assert set(state['source_sha256']) == EXPECTED
assert all(hashlib.sha256((W / path).read_bytes()).hexdigest() == expected
           for path, expected in state['source_sha256'].items()), 'candidate가 감사 뒤 변함'
print(json.dumps({'status': READY, 'review_ready': True, 'source_sha256': state['source_sha256'],
                  'worktree': str(W), 'tests_executed': False, 'accepted': False}, ensure_ascii=False))
