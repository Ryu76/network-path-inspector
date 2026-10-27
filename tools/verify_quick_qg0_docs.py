"""QG0 독립 검토 누락의 문서 회귀. 텍스트 계약 검사이며 제품 실행 증거가 아니다."""
import argparse,datetime,json,pathlib,re
R=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--source-root',type=pathlib.Path,default=R);p.add_argument('--name',required=True);a=p.parse_args();assert re.fullmatch('[a-zA-Z0-9_-]+',a.name)
gates=(a.source_root/'docs/quick-check/gates.md').read_text(encoding='utf-8');trace=(a.source_root/'docs/quick-check/requirement-traceability.md').read_text(encoding='utf-8')
checks=[]
def need(name,text,groups):
 missing=[group for group in groups if not any(word.casefold() in text.casefold()for word in group)]
 checks.append({'name':name,'passed':not missing,'missing_alternatives':missing})
def row(text,key):
 return '\n'.join(line for line in text.splitlines()if line.startswith('|')and key in line)
need('qg0-unelevated-validation-plan-approval',row(gates,'QG0'),[['일반 사용자','비상승','무관리자'],['무설치'],['승인']])
need('qg4-memory-target-isolation-resource-lifecycle',row(gates,'QG4'),[['메모리'],['대상'],['오염','격리'],['핸들'],['프로세스'],['소켓'],['종료'],['취소']])
need('conditional-traceroute-child-lifecycle',gates,[['명령 기반','명령기반','자식 프로세스'],['숨김'],['파싱'],['타임아웃'],['자식'],['종료']])
need('qg7-performance-report',row(gates,'QG7'),[['성능'],['측정'],['보고서']])
need('qg3-bulk-target-management',row(trace,'Q-P0-08'),[['붙여넣기'],['추가'],['삭제'],['중복'],['개별'],['QG3']])
need('qg5-warning-filter',row(trace,'Q-P0-10'),[['전체'],['성공'],['실패'],['경고'],['기능'],['대상'],['QG5']])
need('qg5-copy-export-metadata',row(trace,'Q-P0-11'),[['복사'],['TXT'],['CSV'],['UTF-8','UTF8'],['설정'],['출발지'],['목적지'],['시간대','타임존'],['시각'],['버전'],['QG5']])
need('integration-scenarios-explicit',gates,[['IPv6'],['다중 IP','다중IP'],['다중 NIC','다중NIC'],['VPN'],['네트워크 단절','네트워크단절'],['저장'],['동등성'],['blocked'],['증거'],['기대']])
need('performance-measurement-conditions',gates,[['10MB','10 MB','10MiB','10 MiB'],['30MB','30 MB','30MiB','30 MiB'],['1%'],['5분'],['30회'],['100개','100대상','100건'],['P50'],['P95'],['최대'],['하드웨어'],['목표']])
ids=re.findall(r'^\|\s*\*\*(Q-P0-\d\d)\*\*',trace,re.M);expected=[f'Q-P0-{i:02d}'for i in range(1,14)]
checks.append({'name':'exactly-13-distinct-p0-rows','passed':sorted(ids)==expected,'found':ids})
result={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'source_root':str(a.source_root),'scope':'독립 QG0 문서 회귀; 실제 제품/성능/권한/VM 인증 아님','executed':len(checks),'passed':sum(c['passed']for c in checks),'failed':sum(not c['passed']for c in checks),'checks':checks}
out=R/'artifacts'/(a.name+'.json');assert not out.exists(),'과거 증거를 덮지 않는다';out.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8');print(json.dumps(result,ensure_ascii=False,indent=2));raise SystemExit(bool(result['failed']))
