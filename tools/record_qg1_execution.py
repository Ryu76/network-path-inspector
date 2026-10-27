"""통합 Core의 실제 시험 수·원본 해시·미수용 정적 QA 대기를 집계한다."""
import datetime,hashlib,json,pathlib,re,subprocess
R=pathlib.Path(__file__).resolve().parents[1]
def load(rel):return json.loads((R/rel).read_text(encoding='utf-8'))
def command(name):
 data=load(f'artifacts/commands/{name}.json');assert data['exit_code']==0 and not data['partial'],name
 text=(R/f'artifacts/commands/{name}.log').read_text(encoding='utf-8');return data,text
counts={}
for name in ['qg1-root-workspace-tests','qg1-inspector-loopback-real','qg1-independent-integrated-root']:
 data,text=command(name);rows=re.findall(r'test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;',text);assert rows,name
 total={key:sum(int(row[i])for row in rows)for i,key in enumerate(['passed','failed','ignored'])};assert total['passed']>0 and total['failed']==0;counts[name]=total
for name in ['qg1-root-strict-clippy','qg1-root-format','qg1-inspector-ui-regression','qg1-inspector-ui-lint','qg1-inspector-ui-typecheck','qg1-inspector-ui-build','qg1-harness-final-regressions']:command(name)
_,text=command('qg1-inspector-ui-regression');assert re.search(r'Tests\s+27 passed',text)
_,text=command('qg1-harness-final-regressions');assert 'Ran 31 tests'in text
baseline=load('artifacts/qg0-inspector-baseline.json');protected=baseline['protected_inspector_sha256'];assert all(hashlib.sha256((R/rel).read_bytes()).hexdigest()==sha for rel,sha in protected.items())
manifest=load('artifacts/qg1-canonical-source.json')['files'];bad=[]
for rel,info in manifest.items():
 p=R/rel;assert hashlib.sha256(p.read_bytes()).hexdigest()==info['normalized_sha256'],rel
 data=p.read_bytes();text=data.decode('utf-8');bad.extend([{'path':rel,'line':i}for i,line in enumerate(text.splitlines(),1)if line.rstrip(' \t')!=line]);assert data.endswith(b'\n'),rel
assert not bad,bad
p=subprocess.run(['git','diff','--check'],cwd=R,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=20);assert p.returncode==0,p.stderr
state=load('artifacts/quick-check-progress.json');state.update(recorded_at=datetime.datetime.now().astimezone().isoformat(),shared_core_directory='crates/network-core (root 선택통합·실행 회귀 완료, 독립 정적 QA 대기)',inspector_changed_files=[])
state['qg1'].update(status='INTEGRATED_EXECUTION_PASSED_STATIC_REVIEW_PENDING',correction_stage='qgfinalfix',actor_policy_passed=True,source_files_integrated=len(manifest),rustfmt_only_files=3,root_tests=counts['qg1-root-workspace-tests'],loopback_tests=counts['qg1-inspector-loopback-real'],independent_tests=counts['qg1-independent-integrated-root'],schema_checks={'passed':49,'failed':0,'evidence':'qg1-root-schema-independent'},strict_clippy_exit=0,fmt_exit=0,inspector_ui_tests=27,inspector_ui_lint_typecheck_build_exit=0,harness_tests=31,static_review_delegation='deleg_12592897',accepted=False)
state['remaining_blockers']=['QG1 통합Core 독립 정적 QA deleg_12592897 결과 대기','GUI/EXE/cleanVM/실VLAN/DROP/ICMP차단/성능 미검증']
state['integration_preparation_limitation']='첫 cargo metadata --offline 전체target분석이 미캐시 libc 다운로드를 요구해 실패. 설치/온라인재시도 없이 실제 rustc host x86_64-pc-windows-msvc filter로 동일 Windows 종속성 그래프 검증. 부분복사18파일 SHA 확인 및 최초lockhash와 bc56f27 보존본 일치 후 재개; 기존lock패키지변경0, network-core만 추가.'
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
proof={'recorded_at':state['recorded_at'],'counts':counts,'source_manifest':'artifacts/qg1-canonical-source.json','protected_inspector_files':len(protected),'protected_inspector_changed':0,'whitespace_failures':bad,'schema_passed':49,'ui_passed':27,'harness_passed':31,'dependency_evidence':'artifacts/qg1-integration.json','static_review_pending':'deleg_12592897','qg1_accepted':False}
(R/'artifacts/qg1-execution-checkpoint.json').write_text(json.dumps(proof,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
section='\n## Quick Check QG0 설계 수용 / QG1 통합 실행 검증 — '+state['recorded_at']+'\n- QG0 문서누락4건은 독립재검토 deleg_149f9737에서 모두해소/추가P1없음. 부모가 로컬개발 설계·시험계획 범위만 수용했다(artifacts/qg0-design-acceptance.json). 지원OS/일반권한/단일EXE/VM/성능 인증 아님.\n- network-core18파일을 root선택통합. 기존npi-core/npi-probes구현 re-export, Inspector61sourceSHA변경0. Cargo member1개·lock새package network-core만추가,기존dependency버전/계약불변.\n- 실제 root workspace '+str(counts['qg1-root-workspace-tests']['passed'])+'pass/'+str(counts['qg1-root-workspace-tests']['ignored'])+'real분리, 명시loopback '+str(counts['qg1-inspector-loopback-real']['passed'])+'pass, 독립재현 '+str(counts['qg1-independent-integrated-root']['passed'])+'pass. schema49/UI27/harness31 각각통과. strictClippy/fmt/GUI lint·typecheck·build exit0. cancel11회 handles193→193. 합성schema/단위와실제loopback증거를합산해제품완료로표현하지않음.\n- 날짜token/year0000·8Clippy보정과3파일rustfmt정렬을확인. 초기formatchecker의silentdate-time검사생략도 명시checker로보정. 첫전체targetoffline metadata libc미캐시실패는Windows host filter로복구,온라인설치없음.\n- QG1최종수용은 독립정적QA deleg_12592897 대기. QG2미착수/GUI·EXE없음. 원본실패·actor·하네스증거보존, 운영변경/원격push없음.\n\n'
for name in ['PROGRESS.md','RESUME.md']:
 p=R/name;text=p.read_text(encoding='utf-8');first,rest=text.split('\n',1);p.write_text(first+'\n'+section+rest,encoding='utf-8',newline='\n')
p=R/'작업내용/NPI_2026-10-21_002.md';p.write_text(p.read_text(encoding='utf-8')+section,encoding='utf-8',newline='\n')
print(json.dumps(proof,ensure_ascii=False,indent=2))
