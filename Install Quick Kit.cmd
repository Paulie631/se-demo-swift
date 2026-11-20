@echo off
setlocal
title Amazon Quick SE Demo Kit - installer
cd /d "%~dp0"
if not exist "%~dp0quick_kit.py" (
  echo.
  echo   This installer is running from inside the zip, so it can't see the rest of the kit.
  echo   Right-click the zip, choose "Extract All...", then run "Install Quick Kit.cmd" from the extracted folder.
  echo.
  pause
  exit /b 1
)
echo.
echo   Amazon Quick SE Demo Kit - installer
echo   ====================================
echo   This will:
echo     - install uv (the free tool the kit runs on) if it isn't installed yet
echo     - copy the kit to %USERPROFILE%\.quick-se-kit\app
echo     - add an "Amazon Quick Demo Console" shortcut to your desktop
echo   Nothing changes in your Zscaler tenant until you press Create in the console.
echo.
pause
if exist "%USERPROFILE%\.local\bin\uv.exe" set "PATH=%USERPROFILE%\.local\bin;%PATH%"
where uv >nul 2>nul && goto haveuv
echo.
echo   Installing uv...
powershell -NoProfile -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
if exist "%USERPROFILE%\.local\bin\uv.exe" set "PATH=%USERPROFILE%\.local\bin;%PATH%"
where uv >nul 2>nul && goto haveuv
where winget >nul 2>nul
if not errorlevel 1 (
  echo   The uv installer didn't work here. Trying winget...
  winget install --id=astral-sh.uv -e --accept-source-agreements --accept-package-agreements
  set "PATH=%LOCALAPPDATA%\Microsoft\WinGet\Links;%PATH%"
)
where uv >nul 2>nul && goto haveuv
echo.
echo   Couldn't install uv. Ask IT to allow astral.sh and github.com downloads, then run this again.
echo.
pause
exit /b 1
:haveuv
set UV_SYSTEM_CERTS=1
set UV_NATIVE_TLS=1
set PYTHONUTF8=1
echo.
echo   Preparing Python 3.12 and the kit's libraries (the first time takes a minute or two)...
uv run --quiet --python 3.12 --script "%~dp0quick_kit.py" install
if errorlevel 1 (
  echo   Install failed. The message above says why.
  pause
  exit /b 1
)
echo.
echo   Opening the console in your browser. Use Quit in the console to stop it.
start "" /min cmd /c ""%USERPROFILE%\.quick-se-kit\app\quick-kit.cmd" gui"
timeout /t 3 >nul
exit /b 0
