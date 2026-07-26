@echo off
REM =============================================================================
REM setup.bat — One-command environment setup for FIM-PKI Sentinel (Windows)
REM Author: Dijan Ghale
REM
REM Usage: double-click setup.bat, or run from a Command Prompt:
REM     setup.bat
REM =============================================================================

echo ============================================================
echo   FIM-PKI Sentinel - Setup
echo   Author: Dijan Ghale
echo ============================================================

where python >nul 2>nul
if errorlevel 1 (
    echo Python was not found on PATH. Install Python 3.10+ from python.org
    echo and make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)

echo Creating virtual environment in .\venv ...
if not exist venv (
    python -m venv venv
)

call venv\Scripts\activate.bat

echo Installing dependencies ...
python -m pip install --upgrade pip --quiet
pip install -r requirements.txt --quiet

echo Preparing runtime directories ...
if not exist keys mkdir keys
if not exist certs mkdir certs
if not exist logs mkdir logs
if not exist CSV_logs mkdir CSV_logs
if not exist data mkdir data

echo ============================================================
echo   Setup complete.
echo ============================================================
echo.
set /p LAUNCH="Launch FIM-PKI Sentinel now? [y/N] "
if /i "%LAUNCH%"=="y" (
    python fim_gui.py
) else (
    echo You can launch it later with:
    echo     venv\Scripts\activate
    echo     python fim_gui.py
)

pause
