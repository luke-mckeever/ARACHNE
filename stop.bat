@echo off
rem ARACHNE OSINT - stop the running server (Windows)
rem Usage: stop.bat            stops the server started from this folder
rem        stop.bat 9000       stops whatever ARACHNE is listening on port 9000
rem        add --no-pause to close the window straight away
setlocal
cd /d "%~dp0"
set "PIDFILE=data\arachne.pid"
set "PID="
set "PORT="
set "NOPAUSE="
for %%x in (%*) do (
  if /i "%%~x"=="--no-pause" (set "NOPAUSE=1") else (set "PORT=%%~x")
)

if not defined PORT if exist "%PIDFILE%" for /f "usebackq tokens=1,2" %%a in ("%PIDFILE%") do (set "PID=%%a" & set "PORT=%%b")
if not defined PORT set "PORT=8777"

rem Ignore a stale PID file left by a server that was killed or crashed
if defined PID (
  tasklist /FI "PID eq %PID%" /NH | findstr /c:" %PID% " >nul || set "PID="
)

rem Fall back to whatever is listening on the port
if not defined PID for /f "tokens=5" %%p in ('netstat -ano ^| findstr /r /c:"127\.0\.0\.1:%PORT% .*LISTENING" /c:"0\.0\.0\.0:%PORT% .*LISTENING"') do set "PID=%%p"

if not defined PID (
  echo ARACHNE is not running on port %PORT%.
  if exist "%PIDFILE%" del "%PIDFILE%" >nul 2>&1
  goto :end
)

taskkill /PID %PID% /T /F >nul 2>&1
if errorlevel 1 (
  echo Could not stop process %PID% - it may already have exited.
) else (
  echo ARACHNE stopped ^(process %PID%, port %PORT%^).
)
if exist "%PIDFILE%" del "%PIDFILE%" >nul 2>&1

:end
if not defined NOPAUSE timeout /t 3 >nul 2>&1
endlocal
