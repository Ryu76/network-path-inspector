"""의도한 Pending unwind와 준비 실패를 실제 음성 대조로 구분한다. 항상 원문 복구."""
import datetime,hashlib,json,pathlib,subprocess,sys
R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgbridge'
p=W/'apps/network-quick-check/src/gui_run_session_tests.rs'
original=p.read_bytes();text=original.decode('utf-8')
start=text.index('fn test_unwind_safety_raii_release()')
end=text.index('\n#[test]',start)
body=text[start:end]
a=body.index('        f.session')
b=body.index('        until(',a)
mutant=body[:a]+'        f.session.try_start_with(|| Err(SessionInitError::HostSpawnFailed)).unwrap();\n'+body[b:]
changed=text[:start]+mutant+text[end:]
name='qg3e-session-unwind-preparation-negative'
assert not (R/'artifacts/commands'/f'{name}.json').exists()
sha=lambda data:hashlib.sha256(data).hexdigest()
try:
    p.write_bytes(changed.encode('utf-8'))
    cmd=[sys.executable,'tools/run_command_evidence.py','--cwd',str(W),'--name',name,'--timeout','120','--','cargo','test','--offline','--locked','--target-dir',str(R/'.harness/targets/qg3e-session-shared'),'-p','network-quick-check','--lib','gui_run_session::tests::test_unwind_safety_raii_release','--','--exact','--test-threads=1']
    result=subprocess.run(cmd,cwd=R,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=150)
finally:
    p.write_bytes(original)
    assert p.read_bytes()==original
meta=json.loads((R/'artifacts/commands'/f'{name}.json').read_text(encoding='utf-8'))
log=pathlib.Path(meta['log']).read_text(encoding='utf-8')
assert result.returncode==101 and meta['exit_code']==101 and not meta['partial']
assert '0 passed; 1 failed;' in log and '준비 실패/timeout' in log
out=R/'artifacts/qg3e-session-unwind-negative.json'
assert not out.exists()
record=dict(recorded_at=datetime.datetime.now().astimezone().isoformat(),mutation='force fixed factory error before Pending',expected_failure_observed=True,test_failed=1,exact_source_restored=True,restored_sha256=sha(original),command=meta,product_test_failure=False)
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(log)
print(json.dumps(record,ensure_ascii=False))
