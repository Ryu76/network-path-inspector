"""실제 root 조합 회귀를 확인한 개발보조 TCP 경로만 제한 수용하고 최신 문서를 갱신한다."""
import datetime
import hashlib
import json
import pathlib
import subprocess
R=pathlib.Path(__file__).resolve().parents[1]
W=R/'.worktrees/qgdevtcp'
load=lambda p:json.loads((R/p).read_text(encoding='utf-8'))
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
p=load('artifacts/qg2i-explicit-tcp-parent-execution.json')
v=load('artifacts/qg2i-explicit-tcp-root-validation.json')
r=load('artifacts/qg2i-explicit-tcp-final-independent-review.json')
assert v['status']=='ROOT_EXECUTION_PASS_ACCEPTANCE_RECORD_PENDING' and r['findings']==[]
assert all(item['exit_code']==0 and not item['partial'] for item in v['steps'])
assert all(sha(R/path)==value==sha(W/path) for path,value in p['source_sha256'].items())
repair=load('artifacts/qg2i-explicit-tcp-parent-repair.json')
assert all(sha(R/path)==value for path,value in repair['immutable_source_sha256'].items())
assert load('artifacts/commands/qg2i-explicit-tcp-delivery-harness.json')['exit_code']==0
steps={item['name'].removeprefix('qg2i-explicit-tcp-root-'):item for item in v['steps']}
assert {k:steps['workspace'][k] for k in ['passed','failed','ignored']}==p['workspace_counts']
assert {k:steps['native'][k] for k in ['passed','failed','ignored']}==p['native_counts']
assert steps['trace-boundaries']['passed']==14 and steps['dns-boundaries']['passed']==6
cli=load('artifacts/qg2i-explicit-tcp-root-commandline.json')
assert cli['commandline_case_count']==38 and cli['explicit_reject_case_count']==23 and cli['supervisor_self_test_count']==6
status=subprocess.run(['git','-C',str(W),'status','--porcelain'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30)
assert status.returncode==0 and not status.stdout.rstrip('\r\n')
protected=load('artifacts/qg0-inspector-baseline.json')['protected_inspector_sha256']
engine='crates/npi-probes/src/engine.rs'
assert all(sha(R/path)==value for path,value in protected.items() if path!=engine)
original=R/'.harness/baselines/qg2g-tcp-replay-root/engine.rs'
assert sha(original)==protected[engine]
assert (R/engine).read_bytes().replace(b'pub fn apply_tcp_result(',b'fn apply_tcp_result(',1)==original.read_bytes()
now=datetime.datetime.now().astimezone().isoformat()
record={'recorded_at':now,'status':'ACCEPTED_DEVELOPMENT_ONLY_EXPLICIT_SINGLE_TARGET_TCP_ENTRY',
    'scope':'QG2 보조통합용 명시 단일TCP CLI·제품 기본UX/GUI·파일내보내기 아님',
    'accepted':True,'root_integrated':True,'full_qg2_accepted':False,'product_accepted':False,'qg3_started':False,
    'source_sha256':p['source_sha256'],'preserved_source_commit':p['preserved_source_commit'],'worktree_clean':True,
    'root_validation':v,'legacy_cli_cases':38,'explicit_reject_cases':23,'supervisor_self_tests':6,
    'harness_tests':29,'new_default_tests_in_workspace':repair['new_default_passed'],'new_product_exe_native_tests_in_native':4,
    'original_inspector_unchanged':len(protected)-1,'approved_existing_pub_exception_files':1,'new_core_resolver_inspector_source_changes':0,
    'selector':'--dev-tcp-once-v1','tcp_timeout_ms':3000,'concurrency':1,'selected_features':['TcpConnect'],
    'max_result_bytes':32768,'max_stdout_wire_bytes_including_lf':65536,'metadata_timestamp_and_source_host':None,
    'writer':'gemini-3.8-flash-high FILE ONLY3파일·부모보정/보강공동작성','final_review':'deleg_62debd02',
    'selector_specific_human_approval_claimed':False,'parent_scope_basis':'사용자 다시 진행해 재개지시 아래 기존QG2 개발보조 최소소비경로 선택',
    'remaining_unverified':repair['limitations']+['실VLAN/DROP/ICMP차단/VPN/다중NIC·전체지원OS/일반사용자/클린VM',
        '정규timestamp/sourceHost 전체요구·다중대상/GUI·TXT/CSV·Release/CRT/PE/서명·성능·배포'],
    'failed_evidence_preserved':'artifacts/qg2i-explicit-tcp-parent-repair.json 및 actor-original source·명령별원본로그',
    'remote_push_or_deploy':False}
out=R/'artifacts/qg2i-explicit-tcp-acceptance.json'
assert not out.exists()
out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
section=f'''\n## 명시 개발용 단일 TCP 진단 경로 root 제한 수용 — {now}
- `--dev-tcp-once-v1 HOST PORT`를 지정했을 때만 제품 EXE가 기존 `run_quick` 및 현재 EXE DNS backend factory를 소비한다. 단일 대상·TCP만·기존 3000ms·동시성1·도메인의 필수 해석만이다. GUI/일반 사용자 기본 UX 또는 P1 JSON 파일 내보내기 기능이 아니다. 기존 noargs/help/invalid/worker의 자동 진단0과 worker 16384byte 계약은 그대로다.
- 최종 독립 QA `deleg_62debd02` 두 건 추가지적0 뒤 부모가 같은 SHA를 검증·선택 통합했다. root 기본회귀446PASS/31ignored, 명시 native31PASS/0ignored(기존27+새 실제 제품 EXE IPv4/IPv6 성공·거부4), 기존 CLI38PASS, 새 인자거부23PASS, 감독기6PASS, Trace경계14/DNS경계6PASS, strict Clippy/fmt exit0. 하네스29PASS는 별도다. 새 기본시험12는446에 포함되며 통계를 합산하지 않는다.
- JSON은 기존 `QuickRunReport` 전체 compact 한 줄+LF이고 전체 wire65536byte를 직렬화 도중 제한한다(result 보관 한도32768과 별도). exit0은 report 전달 완료이지 TCP 성공 뜻이 아니며 거부도 report의 FAIL/10061로 남는다. exit1은 출력/local/report errors/limit, exit2는 사전 인자거부, exit3은 오류 없는 취소 report 전달이다. 출력/local 오류가 취소보다 우선한다. timestamp/source_host는 null이며 정상 시각 메타데이터 전체 요구를 충족했다고 주장하지 않는다.
- 실제 성공은 소유 listener의 EOF·수신 application bytes0·accept peer와 raw local endpoint 귀속을 확인했다. 거부는 살아 있는 bound/nonlisten 포트를 유지해 실제 REFUSED10061을 요구한다. 독점예약/모든 race 제거/패킷부재/서비스정상/DB로그인 증거가 아니다. default 앱시험은 mock/메모리·I/O/time driver 없는 CPU runtime만 사용한다.
- 초기 E0382/E0560, lock guard, 불완전 빌드 timeout, 부모 bool API 오류, DNS fixture host 불일치22PASS1FAIL, 첫 Clippy101은 보존했다. 부모가 bounded writer·생산 공유 dispatcher·실제/모의 공유 취소 감독·동일Arc/Pending/drain/전체raw witness·Trace 실카운터·비동기 Child 감독을 보강했다. 기존 registry package identity/checksum은 유지하고 lock에 bytes1.11.1(dev process), errno0.3.14/signal-hook-registry1.4.8을 추가했다. Release normal graph/배포 인증은 아직 하지 않았다.
- Inspector 원본60SHA+기승인pub4byte1예외 불변·baseline61 원본 미수정. 공유 Core/resolver/Inspector 새 변경0. source3+부모 metadata2만 통합했다. Wclean/로컬 보존commit `{p['preserved_source_commit']}`·원격 push/배포/전체 branch merge 없음. 근거 `artifacts/qg2i-explicit-tcp-acceptance.json`.
- 전체QG2 실환경·실제 domain→동일EXE worker→TCP·실Console Ctrl+C/Break 전달·전역 handler 원복·OS 즉시회수·다중대상취소·GUI/QG3~7·Release/PE/CRT/서명/VM·일반사용자/OS지원/성능은 미수용이다. 모의 취소와 kill_on_drop을 이 인증으로 치환하지 않는다.
\n'''
for name in ['PROGRESS.md','RESUME.md']:
    path=R/name
    first,rest=path.read_text(encoding='utf-8').split('\n',1)
    path.write_text(first+'\n'+section+rest,encoding='utf-8',newline='\n')
for name in ['apps/network-quick-check/README.md','docs/quick-check/gates.md','작업내용/NPI_2026-10-23_001.md']:
    path=R/name
    text=path.read_text(encoding='utf-8')
    if name.endswith('README.md'):
        old=next(line for line in text.splitlines() if line.startswith('- **현재 단계**:'))
        text=text.replace(old,'- **현재 단계**: 제품 EXE의 명시 개발보조 단일 TCP 경로까지 제한 수용. 기본 실행/도움말은 자동 진단 없이 기존 안내만 유지한다. GUI·사용자 기본 UX·배포용 무설치 제품 및 전체 QG2는 아직 미수용이다. 최신 근거는 `artifacts/qg2i-explicit-tcp-acceptance.json`이다.',1)
    if name.endswith('gates.md'):
        text=text.replace('## 2. 게이트별 수용 기준 및 검증 계획 (전 단계 미검증 계획 상태)',
            '## 2. 게이트별 수용 기준 및 검증 계획 (설계/부분 수용과 전체 제품 수용 구분)',1)
        lines=text.splitlines()
        for i,line in enumerate(lines):
            replacements={'| **QG0**':' 설계·시험계획 한정 수용, 실제 일반사용자/OS 실행은 별도 미검증 ',
                '| **QG1**':' 공유 Core/DTO 계약 수용, GUI·배포 제품 수용 아님 ',
                '| **QG2**':' 공유 프로브·개발보조 TCP 앱 경로 부분 수용, 실환경 전체 QG2 미수용 '}
            for key,value in replacements.items():
                if line.startswith(key):
                    fields=line.split('|');fields[-2]=value;lines[i]='|'.join(fields)
        text='\n'.join(lines)+'\n'
        text=text.replace('- **현재 승인 상태**:\n  - 본 검증 계획은 **제안 및 부모 검토 대기** 상태이며, 현재 승인 완료 상태가 아님.',
            '- **설계·시험계획 승인 상태**:\n  - QG0 설계·시험계획 범위만 수용되었다. 실제 비상승 일반사용자·지원 OS·무설치 실행 검증은 별도로 미완료다.',1)
    path.write_text(text.rstrip()+'\n\n'+section.lstrip(),encoding='utf-8',newline='\n')
s=load('artifacts/quick-check-progress.json')
s['recorded_at']=now
s['remaining_blockers']=['전체QG2실VLAN/DROP/ICMP차단·VPN/다중NIC·전체환경검증부재',
    '실제domain→제품worker→TCP·Console신호/전역handler/OS즉시회수·정규시각메타데이터미검증',
    'GUI/QG3~7·Release/PE/CRT/서명/VM·일반사용자/지원OS·성능·배포미완료']
s['qg2']['status']='PARTIAL_PROBE_AND_EXPLICIT_TCP_APP_SLICES_ACCEPTED_FULL_QG2_BLOCKED'
s['qg2']['latest_partial_acceptance_artifact']=out.relative_to(R).as_posix()
s['qg2']['accepted']=False
s['next_qg2_app_integration_review'].update(status='COMPLETED_SCOPED_ENTRY_ACCEPTED',actor_started=True,actor_completed=True,
    production_changed=True,production_changes='앱진입source2·새test1·부모metadata2',root_integrated=True,accepted=True,decision_required=None)
s['next_qg2_explicit_tcp_entry'].update(record,actor_completed=True,actor_alive=False,parent_native_execution_held=False,
    native_execution_held=False,parent_new_cli_tests_executed=True,root_source_unchanged=False,
    independent_review='deleg_62debd02',independent_review_received=True,
    parent_metadata_changes=repair['metadata_after_parent_repair'],acceptance_artifact=out.relative_to(R).as_posix())
s['latest_root_validation']={'acceptance_artifact':out.relative_to(R).as_posix(),'source_sha256':p['source_sha256'],
    'workspace':steps['workspace'],'native':steps['native'],'commandline_passed':38,'explicit_reject_passed':23,
    'trace_boundaries_passed':14,'dns_boundaries_passed':6,'clippy_exit':0,'fmt_exit':0,
    'full_qg2_accepted':False,'product_accepted':False}
(R/'artifacts/quick-check-progress.json').write_text(json.dumps(s,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({'status':record['status'],'accepted':True,'workspace':p['workspace_counts'],'native':p['native_counts'],
    'legacy_cli':38,'new_rejections':23,'preserved_source_commit':p['preserved_source_commit'],
    'full_qg2_accepted':False,'product_accepted':False},ensure_ascii=False))
