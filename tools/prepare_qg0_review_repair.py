"""독립 QG0 검토의 확정 누락을 보존하고 이미 검토된 문서 기준에서 보정한다."""
import datetime,hashlib,json,pathlib,shutil,subprocess
R=pathlib.Path(__file__).resolve().parents[1];w=R/'.worktrees/qgplan2'
findings=[{'id':'QG0-REVIEW-01','severity':'P1','path':'docs/quick-check/gates.md','line':11,'issue':'무설치·무관리자 기본 실행 검증 계획 승인 누락'}, {'id':'QG0-REVIEW-02','severity':'P1','path':'docs/quick-check/gates.md','line':15,'issue':'QG4 메모리 상한·대상 격리·취소/종료 자원·Traceroute 자식 수명주기 및 QG7 성능 실측 누락'}, {'id':'QG0-REVIEW-03','severity':'P1','path':'docs/quick-check/requirement-traceability.md','line':16,'issue':'여러 행 붙여넣기·중복 제거·경고 필터·결과 복사·출력 메타데이터 누락'}, {'id':'QG0-REVIEW-04','severity':'P1','path':'docs/quick-check/gates.md','line':13,'issue':'IPv6·다중 IP·다중 NIC·VPN·단절 중 저장·Inspector 동등성 시나리오 배정 누락'}]
record={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'delegation':'deleg_fb3bbcbc','scope':'QG0 문서 독립 정적 검토','findings':findings,'parent_confirmed':True,'gate_accepted':False,'fix_stage':'qg0reviewfix'}
out=R/'artifacts/qg0-independent-review.json';assert not out.exists();out.write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
# 원래 root에 반영한 문서와 부모의 Traceroute 정정만 baseline으로 옮긴다.
for p in (R/'docs/quick-check').glob('*.md'):shutil.copyfile(p,w/p.relative_to(R))
shutil.copyfile(R/'apps/network-quick-check/README.md',w/'apps/network-quick-check/README.md')
refs=w/'.harness/references';refs.mkdir(parents=True,exist_ok=True);shutil.copyfile(out,refs/out.name)
for args in [['add','docs/quick-check','apps/network-quick-check/README.md'],['-c','core.autocrlf=false','commit','-m','chore: preserve QG0 plan before independent review corrections']]:
 p=subprocess.run(['git','-C',str(w),*args],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=30);assert p.returncode==0,p.stderr
p=subprocess.run(['git','-C',str(w),'status','--porcelain'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=20);assert not p.stdout,p.stdout
print('QG0 P1 누락4건 원본 검토 보존 및 clean 문서보정 기준 준비')
