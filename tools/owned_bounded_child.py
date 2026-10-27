"""부모 소유 단일 프로세스의 stdout/stderr와 실행 시간을 제한한다. shell/이름검색 종료 없음."""
import subprocess
import threading
import time


def run_bounded(argv, *, cwd, timeout=5.0, stdout_limit=16384, stderr_limit=1024):
    """정확히 시작한 Child만 소유한다. 하위 프로세스 없는 검토된 프로그램에 한해 사용한다."""
    assert timeout > 0 and stdout_limit >= 0 and stderr_limit >= 0
    started = time.monotonic()
    child = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             shell=False, close_fds=True, bufsize=0,
                             creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    buffers = [bytearray(), bytearray()]
    overflow = [False, False]
    errors = []

    def collect(index, pipe, limit):
        try:
            while len(buffers[index]) <= limit:
                chunk = pipe.read(min(1024, limit + 1 - len(buffers[index])))
                if not chunk:
                    break
                buffers[index].extend(chunk)
                if len(buffers[index]) > limit:
                    overflow[index] = True
                    break
        except Exception as error:
            errors.append(type(error).__name__)
        finally:
            pipe.close()

    readers = [threading.Thread(target=collect, args=(i, pipe, limit), daemon=True)
               for i, pipe, limit in [(0, child.stdout, stdout_limit), (1, child.stderr, stderr_limit)]]
    timed_out = False
    try:
        for reader in readers:
            reader.start()
        try:
            child.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            child.kill()
            child.wait(timeout=3)
        for reader in readers:
            reader.join(timeout=3)
        assert not any(reader.is_alive() for reader in readers), '소유 Child 종료 후 reader 정리 실패'
        assert not errors, 'pipe 수집 오류: ' + ','.join(errors)
        assert child.poll() is not None
        assert len(buffers[0]) <= stdout_limit + 1 and len(buffers[1]) <= stderr_limit + 1
        return {'exit_code': child.returncode, 'stdout': bytes(buffers[0]), 'stderr': bytes(buffers[1]),
                'stdout_overflow': overflow[0], 'stderr_overflow': overflow[1], 'timed_out': timed_out,
                'pid': child.pid, 'child_reaped': True,
                'elapsed_seconds': round(time.monotonic() - started, 4)}
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=3)
