@echo off
setlocal EnableDelayedExpansion
set BAT_LOG=%TEMP%\\npcap-batch.log
echo [*] Starting install-and-run.bat >"%BAT_LOG%"

set MARKER=tools.txt
set APP_CMD=python app.py

REM Verify python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
  echo [!] Python not found on PATH. Install Python and re-run. >>"%BAT_LOG%"
  pause
  goto finish
)

REM Check if tshark or tcpdump already available
where /q tshark.exe
if %errorlevel%==0 goto have_tools
where /q tcpdump.exe
if %errorlevel%==0 goto have_tools

echo [*] tcpdump/tshark not found. Attempting install via choco, then winget...

REM Try choco first
where /q choco.exe
if %errorlevel%==0 (
  echo [*] Installing Wireshark via choco...
  choco install wireshark -y --no-progress >>"%BAT_LOG%" 2>&1
  where /q tshark.exe
  if %errorlevel%==0 goto have_tools
)

REM Fallback to winget
where /q winget.exe
if %errorlevel%==0 (
  echo [*] Installing Wireshark via winget...
  winget install --id WiresharkFoundation.Wireshark --silent --accept-package-agreements --accept-source-agreements >>"%BAT_LOG%" 2>&1
  where /q tshark.exe
  if %errorlevel%==0 goto have_tools
)

echo [!] Failed to install tcpdump/tshark. Install manually and re-run.
pause
goto finish

:have_tools
echo [*] Capture tools available.
echo [*] Ensuring npcap/npf service is running...
set NPCAP_START_LOG=%TEMP%\\npcap-start.log
set DOWNLOADS_DIR=%USERPROFILE%\\Downloads
del "%NPCAP_START_LOG%" >nul 2>&1

call :ensure_npcap_ready
echo tshark/tcpdump installed> "%MARKER%"
echo [*] Starting app with "%APP_CMD%"
%APP_CMD%
if %errorlevel% neq 0 (
  echo [!] App exited with code %errorlevel%.
  pause
)

goto finish

:finish
echo [*] Script completed. Logs at %BAT_LOG% and %NPCAP_START_LOG%. Press any key to close.
pause

endlocal

:ensure_npcap_ready
call :detect_npcap
if "%NPCAP_SERVICE%"=="" (
  call :prompt_manual_install
  goto ensure_npcap_ready
)
echo [*] Using service name: %NPCAP_SERVICE%
sc query %NPCAP_SERVICE% | find "RUNNING" >nul 2>&1
if %errorlevel% neq 0 (
  echo [*] Attempting to start %NPCAP_SERVICE%...
  net start %NPCAP_SERVICE% >"%NPCAP_START_LOG%" 2>&1
  sc query %NPCAP_SERVICE% | find "RUNNING" >nul 2>&1
  if %errorlevel% neq 0 (
    echo [!] %NPCAP_SERVICE% service not running after start attempt.
    call :prompt_manual_install
    goto ensure_npcap_ready
  )
)
echo [*] %NPCAP_SERVICE% service is running.
exit /b

:detect_npcap
set NPCAP_SERVICE=
for %%S in (npcap npf) do (
  sc query %%S >nul 2>&1
  if !errorlevel! == 0 (
    set NPCAP_SERVICE=%%S
    goto detect_done
  )
)
:detect_done
exit /b

:prompt_manual_install
if not defined NPCAP_PROMPTED (
  echo [!] Npcap not detected. Please download and install Npcap (with WinPcap compatibility) from:
  echo     https://nmap.org/npcap/
  echo [*] Opening download page...
  start "" https://nmap.org/npcap/
  set NPCAP_PROMPTED=1
) else (
  echo [*] Still waiting for Npcap installation...
)
call :wait_for_installer
if "%FOUND_INSTALLER%"=="" (
  echo [!] Still waiting for installer in %DOWNLOADS_DIR%. Press Ctrl+C to abort.
  timeout /t 5 /nobreak >nul
  goto prompt_manual_install_done
)
echo [*] Launching installer: %FOUND_INSTALLER%
start /wait "" "%FOUND_INSTALLER%"
set INSTALL_EXIT=%errorlevel%
echo [*] Installer exited with code %INSTALL_EXIT%.
if not "%INSTALL_EXIT%"=="0" (
  echo [!] Installer reported a failure. Retry after resolving any prompts.
)
:prompt_manual_install_done
set FOUND_INSTALLER=
exit /b

:wait_for_installer
set FOUND_INSTALLER=
for /f "delims=" %%F in ('dir /b /a:-d "%DOWNLOADS_DIR%\\npcap-*.exe" 2^>nul') do (
  set FOUND_INSTALLER=%DOWNLOADS_DIR%\\%%F
  goto installer_found
)
echo [*] Waiting for npcap-*.exe to appear in %DOWNLOADS_DIR%...
timeout /t 5 /nobreak >nul
goto wait_for_installer
:installer_found
exit /b
