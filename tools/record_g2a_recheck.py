"""검증 완료 명령에서 G2-A 한정 최신 체크포인트를 만든다."""
import datetime,hashlib,json,pathlib,re,subprocess
R=pathlib.Path(__file__).resolve().parents[1]; A=R/'artifacts'
names=['g2flash-hostfinal-root-tests','g2flash-hostfinal-real','g2flash-hostfinal-clippy','g2flash-hostfinal-format','g2flash-audit-discovery-regressions','g2dns-after-fix-tests','g2dns-after-fix-clippy']
commands={}
for name in names:
 meta=json.loads((A/'commands'/f'{name}.json').read_text(encoding='utf-8'));assert meta['exit_code']==0 and not meta['partial'];commands[name]=meta

def rust_counts(name):
 text=(A/'commands'/f'{name}.log').read_text(encoding='utf-8')
 rows=re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;',text)
 assert rows
 return {k:sum(int(row[i])for row in rows)for i,k in enumerate(['passed','failed','ignored'])}
source={p.relative_to(R).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()for p in (R/'crates/npi-probes').rglob('*')if p.is_file() and p.suffix in ('.rs','.toml')}
engine_equal={}
for f in ['src/engine.rs','tests/engine.rs']:
 current=R/f'crates/npi-probes/{f}';reviewed=R/f'.worktrees/g2engine/crates/npi-probes/{f}'
 formatted=subprocess.run(['rustfmt','--emit','stdout','--edition','2024'],input=reviewed.read_text(encoding='utf-8'),capture_output=True,text=True,encoding='utf-8',errors='strict',timeout=30,check=True).stdout
 engine_equal[f]={'raw_equal':current.read_bytes()==reviewed.read_bytes(),'rustfmt_output_equal':current.read_text(encoding='utf-8')==formatted}
assert all(v['rustfmt_output_equal'] for v in engine_equal.values()),'Static review source changed beyond rustfmt; fresh review required'
result={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'status':'G2_A_LOOPBACK_RUNTIME_REVERIFIED_G2_NOT_ACCEPTED','full_g2_accepted':False,'product_complete':False,'commands':commands,'offline':rust_counts(names[0]),'explicit_real':rust_counts(names[1]),'dns_isolated':rust_counts(names[5]),'cli':json.loads((A/'g2a-live-20261020_180109/result.json').read_text(encoding='utf-8')),'harness_tests':31,'cancel_handles':{'attempts':11,'before':193,'after':193},'engine_review':{'delegation':'deleg_4dc65b8b','findings':[],'scope':'completed static review only; reviewed source and tests rustfmt output equals current root; raw bytes differ','source_equal':engine_equal},'source_sha256':source,'remaining':['DNS helper main integration and real process timeout/cancel/reap verification','domain/profile engine integration','Session1.1 and durable evidence export','native UI integration','remaining PRD G2 acceptance checks'],'safety':'owned loopback/localhost and read-only local NIC/route only; no operational DB, settings, drivers, deployment or push'}
(A/'g2a-flash-reverified.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
section='\n## Flash 보정 후 독립 재검증 — '+result['recorded_at']+'\n- root 오프라인 '+str(result['offline']['passed'])+'통과/0실패, 명시 실제 루프백/네이티브 '+str(result['explicit_real']['passed'])+'통과/0실패, 별도 CLI10/10통과. strictClippy(-D warnings)·fmt exit0. 취소11회 핸들193→193. 하네스31/31통과.\n- engine 독립 정적 QA deleg_4dc65b8b 완료/확정 차단 결함 없음; 통합 engine 및 tests는 검토 worktree의 rustfmt 출력과 일치(원본 바이트 동일 주장은 하지 않음). 이는 전체 제품/패킷/성능 인증이 아님.\n- cleanhost 최종 Flash stage는 SUCCESS/FILE ONLY 감사 통과 후 선택 통합. 이전 stream interrupted exit0 결과는 불수용으로 보존. 원본 거부 host diff는 미사용.\n- DNS의 IPv6 오기대·전체 deadline 우회·Clippy 오류를 Flash로 수정. 격리 시험 '+str(result['dns_isolated']['passed'])+'통과/0실패/실제 helper1건 대기, strictClippy exit0. 부모 독립 late-payload 회귀가 보정 전 실패/보정 후 통과. 아직 제품 main/engine 연결·실제 helper 수명 검증 전이다.\n- 근거: artifacts/g2a-flash-reverified.json 및 명령별 원본 로그. 전체 G2 미수용, G3 이후 미진행.\n\n'
for name in ['PROGRESS.md','RESUME.md']:
 p=R/name;old=p.read_text(encoding='utf-8');first,rest=old.split('\n',1);p.write_text(first+'\n'+section+rest,encoding='utf-8')
print(json.dumps({k:result[k]for k in ['recorded_at','status','offline','explicit_real','dns_isolated','engine_review']},ensure_ascii=False,indent=2))
