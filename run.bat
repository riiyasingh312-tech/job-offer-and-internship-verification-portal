@echo off
cd /d "%~dp0"
title OfferCheck - Job Offer Verification Portal

set PY=python
where python >nul 2>nul || set PY=py

echo ==========================================
echo   OfferCheck - starting up
echo ==========================================
echo.
echo Step 1: Installing required packages (first time can take 1-2 minutes)...
%PY% -m pip install -r requirements.txt
if errorlevel 1 (
  echo.
  echo [!] Install failed. Please take a screenshot of this window and send it.
  pause
  exit /b 1
)

echo.
echo Step 2: Starting the website. KEEP THIS WINDOW OPEN.
echo The browser will open automatically at http://127.0.0.1:5000
echo.
start "" cmd /c "timeout /t 5 >nul & start http://127.0.0.1:5000"
%PY% app.py
echo.
echo [!] The server stopped. If you saw an error above, send a screenshot.
pause
