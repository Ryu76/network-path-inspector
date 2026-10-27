"""Windows CMD에서 페이지 BAT의 실제 실행·거부·준비 경로를 검증한다."""
import datetime,json,os,pathlib,socket,subprocess,time,urllib.request
R=pathlib.Path(__file__).resolve().parents[1]
BAT=R/'start_npi.bat';A=R/'artifacts';A.mkdir(exist_ok=True)
data=BAT.read_bytes();assert b'\r\n'in data and data.count(b'\n')==data.count(b'\r\n') and b'\r\r\n'not in data,'BAT CRLF 검증 실패'
env=os.environ.copy();env.update(BROWSER='none',NPI_LAUNCHER_NO_PAUSE='1')
# 사용자 셸에 Node PATH가 없어도 BAT의 설치된 Hermes Node 검색이 작동해야 한다.
winroot=next(v for k,v in env.items() if k.casefold()=='systemroot')
env['PATH']=str(pathlib.Path(winroot)/'System32')
cwd=pathlib.Path(env['TMPDIR']);checks=[]
def command(args=''):
 return '"'+str(pathlib.Path(winroot)/'System32/cmd.exe')+'" /d /s /c ""'+str(BAT)+'" '+args+'"'
def check_mode(args,expected):
 p=subprocess.run(command(args),cwd=cwd,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=20)
 assert p.returncode==expected,(args,p.returncode,p.stdout,p.stderr)
 checks.append({'case':args,'exit_code':p.returncode,'passed':True})
check_mode('--check',0);check_mode('--unknown',2)
with socket.socket() as occupied:
 occupied.bind(('127.0.0.1',39201));occupied.listen(1);check_mode('--check',1)
log=A/'page-launcher-live.log'
with log.open('wb') as output:
 p=subprocess.Popen(command(),cwd=cwd,env=env,stdout=output,stderr=subprocess.STDOUT)
 try:
  deadline=time.monotonic()+25
  while True:
   if p.poll()is not None:raise RuntimeError(log.read_text(encoding='utf-8',errors='replace'))
   try:
    with urllib.request.urlopen('http://127.0.0.1:39201/',timeout=1)as response:html=response.read().decode('utf-8');assert response.status==200
    break
   except (OSError,urllib.error.URLError):
    if time.monotonic()>=deadline:raise
    time.sleep(.15)
  assert '/src/main.tsx'in html and '/@vite/client'in html
  with urllib.request.urlopen('http://127.0.0.1:39201/src/App.tsx',timeout=5)as response:app=response.read().decode('utf-8');assert response.status==200
  assert 'FeatureSelectionPanel'in app and 'ResultPanel'in app
  checks.append({'case':'no_arguments_from_unrelated_cwd','http_status':200,'current_app_modules':True,'passed':True})
 finally:
  if p.poll()is None:
   stopped=subprocess.run(['taskkill.exe','/PID',str(p.pid),'/T','/F'],capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=20)
   assert stopped.returncode==0,(stopped.stdout,stopped.stderr)
  p.wait(timeout=10)
with socket.socket()as probe:
 probe.settimeout(1);assert probe.connect_ex(('127.0.0.1',39201))!=0,'검증 프로세스 포트 종료 확인 실패'
result={'recorded_at':datetime.datetime.now().astimezone().isoformat(),'launcher':str(BAT),'crlf':True,'executed':len(checks),'passed':sum(x['passed']for x in checks),'checks':checks,'browser':'정상 BAT --open 설정; QA에서는 BROWSER=none으로 데스크톱 브라우저만 열지 않음','test_process_stopped':True,'port_closed_after_test':True}
(A/'page-launcher-verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result,ensure_ascii=False,indent=2))
