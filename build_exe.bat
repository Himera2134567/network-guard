@echo off
setlocal
cd /d "%~dp0"
python build.py
if errorlevel 1 (
    echo Build failed. See README.md for requirements.
    pause
    exit /b 1
)
echo Built: dist\NetworkGuard.exe
pause
