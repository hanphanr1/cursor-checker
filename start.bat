@echo off
title Cursor Checker
cd /d "%~dp0"

echo ============================================================
echo   CURSOR CHECKER
echo   Captcha: yeatcloud - nocaptchaai - captchasonic - 2captcha - capsolver
echo   Pre-filter: bad format + duplicate (same user:pass)
echo   Results: results\run-DATE
echo ============================================================
echo.

set BOTS=15

echo  [1] Run accounts.txt (default)
echo  [2] Retry last retry.txt
echo.
set /p MODE="Choose [1/2] (default 1): "

set RETRIES=5
set /p RETRIES="So lan retry sau pass 1 [mac dinh 5, 0 = tat]: "
echo %RETRIES%|findstr /r "^[0-9][0-9]*$" >nul
if errorlevel 1 (
    echo [!] "%RETRIES%" khong phai so -^> dung mac dinh 5
    set RETRIES=5
)
echo [+] Bots: %BOTS%  ^| Retry rounds: %RETRIES%
echo.

if "%MODE%"=="2" goto mode_retry

echo [+] Source: accounts.txt
python checker.py --bots %BOTS% --retries %RETRIES%
goto finish

:mode_retry
set /p RETRYFILE="Path to retry.txt: "
echo [+] Source: %RETRYFILE%
python checker.py --bots %BOTS% --retries %RETRIES% --accounts "%RETRYFILE%"

:finish
echo.
echo Done. See results\run-...
pause
