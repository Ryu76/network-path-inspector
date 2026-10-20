"""Publish G1 offline acceptance only from completed, nonzero real gates."""
import datetime,hashlib,json,pathlib,re,subprocess
from jsonschema import Draft202012Validator
R=pathlib.Path(__file__).resolve().parents[1];A=R/'artifacts';C=A/'commands'
def load(path):return json.loads(path.read_text(encoding='utf-8'))
def successful(name):
 v=load(C/(name+'.json'));assert v['exit_code']==0 and not v['partial'],(name,v);return v
names=['g1-final-format','g1-final2-rust-tests','g1-final2-rust-clippy','g1-final-root-ui-lint','g1-final-root-ui-typecheck','g1-final-root-ui-test','g1-final-root-ui-build','g1-schema-cli-positive']
commands={name:successful(name)for name in names}
rustlog=(C/'g1-final2-rust-tests.log').read_text(encoding='utf-8');passed=[int(x)for x in re.findall(r'test result: ok\. (\d+) passed',rustlog)];registered=[int(x)for x in re.findall(r'running (\d+) tests',rustlog)];rust_total=sum(passed);assert rust_total==sum(registered)>0
clippy=(C/'g1-final2-rust-clippy.log').read_text(encoding='utf-8');assert not re.search(r'(?m)^warning[:\[]',clippy)
uilog=(C/'g1-final-root-ui-test.log').read_text(encoding='utf-8');m=re.search(r'Tests\s+(\d+) passed \((\d+)\)',uilog);assert m and m[1]==m[2];ui_total=int(m[1]);assert ui_total>0
ind=load(A/'g1-independent-result.json');schema=load(A/'g1-schema-independent-result.json');assert ind['failed']==0 and ind['passed']==ind['executed']>0;assert schema['failed']==0 and schema['errors']==0 and schema['passed']==schema['executed']>0
for p in (R/'schemas').glob('*.json'):Draft202012Validator.check_schema(load(p))
original='faffff45de66126dad6a0a81045dd22b536e9739e78947b426bd42d4a0ef7aa1';assert hashlib.sha256((R/'PRD.md').read_bytes()).hexdigest()==original
contract=load(R/'contracts/g1-interface-contract.json');assert len(contract['features'])==23 and len({x['feature_id']for x in contract['features']})==23 and len(contract['groups'])==6
run_records=[];unfinished=[]
for p in (R/'.harness/runs').glob('*/started.json'):
 result=p.parent/'result.json'
 if not result.exists():unfinished.append(str(p.parent))
 else:run_records.append(load(result))
assert not unfinished,unfinished
for stage in ['g01d','g01wsa']:assert load(A/(stage+'-actor-policy-audit.json'))['all_actor_policy_checks_passed']
events=[]
for v in run_records:
 events.extend([(datetime.datetime.fromisoformat(v['started_at']),1),(datetime.datetime.fromisoformat(v['completed_at']),-1)])
active=0;peak=0
for _,delta in sorted(events):active+=delta;peak=max(peak,active)
assert peak>=2
sources={}
for prefix in ['crates/npi-core','schemas','fixtures/g1','ui/src','ui/tests']:
 for p in sorted((R/prefix).rglob('*')):
  if p.is_file()and not any(x in('target','node_modules','dist','__pycache__')for x in p.parts):sources[p.relative_to(R).as_posix()]=hashlib.sha256(p.read_bytes()).hexdigest()
for rel in ['Cargo.toml','Cargo.lock','contracts/g1-interface-contract.json','ui/package.json','ui/package-lock.json','tools/validate_schema.py']:sources[rel]=hashlib.sha256((R/rel).read_bytes()).hexdigest()
now=datetime.datetime.now().astimezone();branch=subprocess.check_output(['git','-C',str(R),'branch','--show-current'],encoding='utf-8',errors='replace').strip()
report={'recorded_at':now.isoformat(),'project_root':str(R),'branch':branch,'g0_status':'PASS_DEVELOPMENT_SCOPE','g1_status':'PASS_OFFLINE_FOUNDATION','g2_status':'NOT_STARTED_PENDING_LOCAL_VERIFICATION_APPROVAL','prd_version':'1.1.0','contract_version':contract['contract_version'],'schema_version':'1.1','prd_sha256':original,'full_prd_complete':False,'full_validation_complete':False,'production_ready':False,'merge_ready':False,'rust':{'registered':rust_total,'executed':rust_total,'passed':rust_total,'failed':0},'ui':{'executed':ui_total,'passed':ui_total,'failed':0,'real_browser_verified':False,'native_engine_connected':False},'independent_compiled_rust':{k:ind[k]for k in['executed','passed','failed','compiled_probe_sha256']},'schema':schema,'commands':commands,'actor_run_count':len(run_records),'maximum_parallel_actor_count':peak,'unfinished_owned_actor_runs':unfinished,'source_sha256':sources,'http_browser_verification':'BLOCKED_APPROVAL_TIMED_OUT_NO_RESPONSE_NO_RETRY','preview_server':'EXITED_1_STDIN_NOT_TTY_NOT_RESTARTED','network_measurements_performed':0,'production_settings_changed':False,'deferred_or_unimplemented':['G2 real TCP/ICMP/DNS/NIC/route execution and native bridge','G3 traceroute','G4 actual Npcap capture and licensing approval','G5 offline evidence merge/correlation','G6 PDF/ZIP/hash/masking export','G7 two-VLAN/OS/performance/24h tests','G8 signing/installer/update/uninstall']}
(A/'g1-gate-report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8',newline='\n')
logs=R/'작업내용';logs.mkdir(exist_ok=True);day=now.date().isoformat();seqs=[int(m[1])for p in logs.glob('NPI_'+day+'_*.md')if(m:=re.search(r'_(\d+)\.md$',p.name))];path=logs/f'NPI_{day}_{max(seqs,default=0)+1:03}.md'
text=f'''# NPI 오프라인 G0/G1 결과\n\n- 기록: {now.isoformat()}\n- 프로젝트: `{R}` / `{branch}`\n- 모델: Gemini 4 Argon High (`gemini-4-argon-high`), 최대 {peak}개 AI Pro 세션 실제 동시 실행, 전용 worktree별 writer 1개.\n- 판정: **G0 개발 범위 / G1 오프라인 기반 통과. 전체 PRD·운영·설치 완료 아님.**\n\n## 구현·검증\n- Rust 공통 모델/OS 오류 분류/프로파일·세션·레지스트리 검증/DAG·복원/legacy 원본 보존: {rust_total}/{rust_total}.\n- 별도 컴파일 Rust 독립 probe와 공통 fixture 교차 검증: {ind['passed']}/{ind['executed']}.\n- Python schema/semantic 독립 검사: {schema['passed']}/{schema['executed']}.\n- UI 컴포넌트: {ui_total}/{ui_total}; guardlint(ESLint 아님), typecheck, production build 성공.\n- cargo fmt/clippy `-D warnings`, schema CLI 양성 샘플 모두 exit 0.\n- 최초 실패 결과·잘못된 입력 TypeError·중복 결과·판정 부정어 우회·OS reset/DNS 오분류·제한사항 인용 오탐·Clippy 실패 이력은 artifacts에 보존했다. 테스트 삭제나 실패 허용으로 통과시키지 않았다.\n- 부모가 Compiler Clippy의 기계 적용 제안과 문서 주석 형식을 정리했으며, `--allow-dirty`는 수정 대상 허용용이지 시험 실패 무시용이 아니다. 최종 별도 strict Clippy는 경고 없이 exit 0이다.\n\n## 주요 경로\n- `crates/npi-core/src/` 및 `tests/`\n- `contracts/`, `schemas/`, `fixtures/g1/`\n- `ui/src/`, `ui/tests/`, `ui/dist/`(생성물)\n- `docs/`, `README.md`, `PROGRESS.md`, `RESUME.md`\n- `tools/`, `artifacts/g1-gate-report.json`\n\n## 승인·한계\n- 로컬 HTTP 검증 명령은 승인 시간 초과로 미실행, 별도 질문도 무응답이었다. 다른 경로로 우회/재시도하지 않았다.\n- 임시 preview는 stdin is not a tty / exit 1 종료. 접근 가능한 URL·실제 브라우저 검증 완료라고 안내하지 않는다.\n- G2 실제 통신·네이티브 엔진은 미시작. G3~G8 및 실제 Windows Server/두 VLAN·캡처·PDF/설치·성능도 미완료다.\n- 운영망/DB 접속·SQL/방화벽·라우트·레지스트리·인증서/드라이버 설치·권한 상승·배포·원격 push 없음.\n- PRD 원문 SHA `{original}` 불변. 파생 Git CRLF 차이만 확인 후 원본 바이트 복원·`PRD.md -text`로 보호했다.\n\n명령·종료코드·현재 소스 해시·분리된 수치는 `artifacts/g1-gate-report.json`을 기준으로 한다.\n'''
with path.open('x',encoding='utf-8',newline='\n')as f:f.write(text)
print(json.dumps({'g1_status':report['g1_status'],'rust':rust_total,'ui':ui_total,'independent':ind['passed'],'schema':schema['passed'],'parallel_peak':peak,'owned_runs':len(run_records),'worklog':str(path),'source_files_hashed':len(sources),'g2_status':report['g2_status'],'full_prd_complete':False},ensure_ascii=False,indent=2))
