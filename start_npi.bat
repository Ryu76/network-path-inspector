@echo off
setlocal EnableExtensions DisableDelayedExpansion
chcp 65001 >nul
set "NPI_OPEN=--open"
if "%~1"=="--check" goto arguments_ok
if "%~1"=="--no-browser" set "NPI_OPEN="
if not "%~1"=="" if not "%~1"=="--no-browser" goto usage
:arguments_ok
if not "%~2"=="" goto usage
pushd "%~dp0ui" 2>nul
if errorlevel 1 (
  echo [오류] 프로젝트의 ui 폴더를 찾을 수 없습니다.
  exit /b 1
)
where node.exe >nul 2>nul
if errorlevel 1 (
  for /d %%D in ("%LOCALAPPDATA%\hermes\tools\node-*-win32-x64") do if exist "%%~fD\node.exe" set "NPI_NODE_HOME=%%~fD"
)
if defined NPI_NODE_HOME set "PATH=%NPI_NODE_HOME%;%PATH%"
where node.exe >nul 2>nul
if errorlevel 1 (
  echo [오류] Node.js를 찾을 수 없습니다. Node.js 설치 후 다시 실행하세요.
  goto failed
)
where npm.cmd >nul 2>nul
if errorlevel 1 (
  echo [오류] npm.cmd를 찾을 수 없습니다.
  goto failed
)
if not exist "node_modules\vite\bin\vite.js" (
  echo [오류] UI 의존성이 없습니다. ui 폴더에서 npm.cmd ci --ignore-scripts를 먼저 실행하세요.
  goto failed
)
node -e "const s=require('net').createServer();s.once('error',()=>process.exit(2));s.listen(39201,'127.0.0.1',()=>s.close(()=>process.exit(0)));" >nul 2>nul
if errorlevel 1 (
  echo [오류] 127.0.0.1:39201 포트를 사용할 수 없습니다. 기존 실행 창을 먼저 확인하세요.
  goto failed
)
if "%~1"=="--check" (
  echo [확인] Node.js, npm, UI 의존성, 루프백 포트 준비 완료.
  popd
  exit /b 0
)
echo Network Path Inspector 페이지를 시작합니다.
echo 주소: http://127.0.0.1:39201/
echo 이 창을 열어 두세요. 종료하려면 Ctrl+C를 누르세요.
echo 현재 UI는 개발 프로토타입이며 실제 진단 엔진 연결은 아직 완료되지 않았습니다.
call npm.cmd run dev -- --host 127.0.0.1 --port 39201 --strictPort %NPI_OPEN%
set "NPI_EXIT=%ERRORLEVEL%"
popd
exit /b %NPI_EXIT%
:failed
popd
if not "%NPI_LAUNCHER_NO_PAUSE%"=="1" pause
exit /b 1
:usage
echo 사용법: start_npi.bat [--check 또는 --no-browser]
exit /b 2
