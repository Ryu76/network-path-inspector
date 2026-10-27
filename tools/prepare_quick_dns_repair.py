"""DNS의 독립 P1 세 건과 실제 실패 회귀를 보존하고 좁은 수정 actor를 준비한다."""
import datetime,hashlib,json,pathlib,shutil,subprocess
R=pathlib.Path(__file__).resolve().parents[1];W=R/'.worktrees/qgdns';load=lambda rel:json.loads((R/rel).read_text(encoding='utf-8'))
def git(args):
 p=subprocess.run(['git','-C',str(W),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30);assert p.returncode==0,p.stderr;return p.stdout.strip()
audit=load('artifacts/qg2continue-actor-policy-audit.json');assert next(a for a in audit['actors']if a['role']=='qgdns')['passed'];after=load('.harness/runs/qg2continue-qgdns/after.json');paths=['crates/network-core/src/dns.rs','crates/network-core/tests/dns.rs']
for rel in paths:assert hashlib.sha256((W/rel).read_bytes()).hexdigest()==after[rel],rel
witness=load('artifacts/commands/qg2c-dns-all-review-witnesses-before-fix.json');assert witness['exit_code']==101 and not witness['partial']
git(['add',*paths,'Cargo.lock']);git(['-c','core.autocrlf=false','commit','-m','chore: preserve reviewed DNS adapter before typed-boundary repair']);preserved=git(['rev-parse','HEAD'])
# 수정된 실행기는 원래 별도 writer 결과이며 DNS actor 종료 뒤에만 의존 사본을 갱신한다.
runner=load('artifacts/qg2b-runner-acceptance.json');dependency_sync={}
for rel in ['crates/network-core/src/runner.rs','crates/network-core/tests/runner.rs']:
 assert hashlib.sha256((R/rel).read_bytes()).hexdigest()==runner['source_sha256'][rel];dependency_sync[rel]={'before_sha256':hashlib.sha256((W/rel).read_bytes()).hexdigest(),'after_sha256':runner['source_sha256'][rel]};shutil.copyfile(R/rel,W/rel)
# 기존 helper 시험의 침묵 성공은 부모 격리 QA에서 증명한 fail-closed 정형으로 교체한다.
shared_test=W/'crates/network-resolver/tests/dns.rs';shutil.copyfile(R/'.harness/qa/quick-resolver/resolver/tests/dns.rs',shared_test)
git(['add','crates/network-core/src/runner.rs','crates/network-core/tests/runner.rs','crates/network-resolver/tests/dns.rs']);git(['-c','core.autocrlf=false','commit','-m','chore: sync accepted scheduler and fail-closed DNS helper test']);assert not git(['status','--porcelain'])
refs=W/'.harness/references';shutil.copyfile(R/'.harness/qa/quick-dns-boundaries/tests/contracts.rs',refs/'dns-parent-boundaries.rs')
now=datetime.datetime.now().astimezone().isoformat();review={'recorded_at':now,'review_delegation':'deleg_59c8e74b','review_mode':'독립 정적 검토. 부모가 별도 합성 실행으로 검증','findings':[{'id':'QG2DNS-01','severity':'P1','scope':'RESOLVED·오류/알려진실패·주소 모순','status':'DYNAMICALLY_REPRODUCED'},{'id':'QG2DNS-02','severity':'P1','scope':'불량 raw host 및 거부 원문 비반사','status':'DYNAMICALLY_REPRODUCED'},{'id':'QG2DNS-03','severity':'P1','scope':'리터럴 host의 다른IP/추가주소 교차귀속','status':'DYNAMICALLY_REPRODUCED'}],'independent_execution':'artifacts/commands/qg2c-dns-all-review-witnesses-before-fix.json','independent_tests':{'passed':0,'failed':6},'preserved_commit':preserved,'parent_dependency_sync':dependency_sync,'parent_test_hardening':'명시 helper 시험 환경변수 미설정은 expect 실패, 침묵 return 제거','root_integrated':False,'accepted':False};(R/'artifacts/qg2c-dns-independent-review.json').write_text(json.dumps(review,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
prompt=f'''당신은 Network Quick Check DNS adapter의 독립 FILE ONLY 보정자다. 작업 root: {W.as_posix()}.
FILE READ/EDIT/CREATE 및 worktree 내부 파일 탐색만 허용. command/run_command/terminal/shell/PowerShell/manage_task/git/시험/설치/네트워크/운영/DB/자격증명/에이전트/재위임 절대금지. 읽기명령도금지. 부모가 실행·감사·통합한다. 모든 입력/출력은 이 worktree 안의 절대경로만. PRD root/링크를 따라 integration root를 읽지 말라.
수정 허용2파일: {W.as_posix()}/crates/network-core/src/dns.rs 및 {W.as_posix()}/crates/network-core/tests/dns.rs.
정확 입력: 위2파일, {W.as_posix()}/.harness/references/quick-dns-contract.json, {W.as_posix()}/.harness/references/dns-parent-boundaries.rs, {W.as_posix()}/crates/network-resolver/src/lib.rs, {W.as_posix()}/crates/network-core/src/quick.rs.
독립 QA deleg_59c8e74b P1 3건, 부모 실동작6회귀 전부FAIL(exit101)로 확인했다. 최소보정과 회귀를 추가한다.
1. 알려진 outcome 의미 검증: RESOLVED는 nonempty addresses + error_code/error_message 모두None. 알려진 비성공 DNS_ERROR/TIMED_OUT/CANCELLED/LOCAL_ERROR는 addresses 비어 있어야 한다. DNS_ERROR는 engine과 동일하게 실제 오류 메시지 근거를 요구하고 code 없는 오류는 허용한다. 빈 메시지/오류코드만 있는 모순은 거부. 미지 outcome의 UNKNOWN/UNKNOWN 정책은 보존한다. 실제engine이허용하는취소/timeout·localerror는falseFAIL/PASS로바꾸지 않는다.
2. measurement.host를 dns_engine::validate_host로 raw그대로 검증한다. 잘못된 URI/경로/자격증명/공백은 Err. resolve_for_quick도 helper 실행 전에 순수 호스트 검증. 기존 QG1 global metadata/trim 정책은 수정하지 않는다. DNS의 ctx host 불량도 오류 비교문구에서 원문이 반사되지 않도록 순수 검증한다. 검증 오류는 원문 host/address/credential을 포함하지 않는 고정 사유·필드·주소순번을 사용. 정상 port 숫자는 표시 가능. 테스트의 기존 오류 키워드(SocketAddr/포트/공백/중복/빈주소)는 유지하되 기대검증 삭제로 우회 금지.
3. 검증 host가 IPv4/IPv6 리터럴이고 RESOLVED면 addresses가 정확히 하나이며 SocketAddr.ip와 literal이 수치적으로 동일해야 한다. 다른IP나추가주소는Err. DNS 조회결과 resolved_ip=null, raw전체보존·정상도메인 다중주소·IPv6·OS오류코드 정책 유지.
4. 기존 unused mut ctx3/ctx4 제거. 명시ignored 실제helper시험의 환경변수 누락은 침묵return이아닌expect실패로 바꾸고, 실제localhost해석이관찰되면PASS/OBSERVED와 nonempty주소·nullresolved_ip를검증한다. OS실패를성공으로허용하지 않는다. 기본시험에서는외부IO0유지.
5. 부모회귀6개에 대응한 추가단위시험을생성하고정상literal IPv4/IPv6와정상multi-domain·각outcome회귀도유지한다. 검사실행/성공주장금지. lib/manifest/commonengine/runner 등 다른파일 변경금지.
한국어흐름주석·UTF8·후행공백없음·마지막개행1개. Clippy suppression금지. 완료응답은수정경로/실제수정/부모검증필요사항만 한국어로.
'''
p=R/'.harness/prompts/qg2dnsfix-qgdns.md';assert not p.exists();p.write_text(prompt,encoding='utf-8',newline='\n');state=load('artifacts/quick-check-progress.json');state['recorded_at']=now;state['qg2_dns'].update(status='THREE_P1_REPRODUCED_FIX_PREPARED',independent_findings=3,parent_boundary_tests={'passed':0,'failed':6,'evidence':'qg2c-dns-all-review-witnesses-before-fix'},review_evidence='artifacts/qg2c-dns-independent-review.json',correction_stage='qg2dnsfix');(R/'artifacts/quick-check-progress.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps({'preserved_commit':preserved,'confirmed_findings':3,'parent_failed_tests':6,'repair_stage':'qg2dnsfix'},ensure_ascii=False))
