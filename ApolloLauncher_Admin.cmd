@echo off
setlocal EnableExtensions

cd /d "%~dp0"

set "SCRIPT=%~dp0apoolo.py"
set "RUNNER="
set "RUNNER_ARGS="

:: Prefer windowless runners to avoid any console window.
where pyw >nul 2>&1
if %errorlevel%==0 (
  set "RUNNER=pyw"
  set "RUNNER_ARGS=-3"
  goto :run
)

where pythonw >nul 2>&1
if %errorlevel%==0 (
  set "RUNNER=pythonw"
  goto :run
)

:: Try to find pythonw next to python.exe.
for /f "delims=" %%P in ('where python 2^>nul') do (
  set "PY=%%P"
  goto :gotpython
)
:gotpython
if defined PY (
  set "PYW=%PY:python.exe=pythonw.exe%"
  if exist "%PYW%" (
    set "RUNNER=%PYW%"
    goto :run
  )
)

echo pythonw.exe/pyw.exe not found. Install Python (with pythonw) or Python Launcher (pyw).
exit /b 1

:run
:: Start detached so this .cmd window closes immediately (GUI only).
start "" "%RUNNER%" %RUNNER_ARGS% "%SCRIPT%" --elevate %*
exit /b 0
