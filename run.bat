@echo off
cd /d "%~dp0"
where pythonw >nul 2>nul
if %errorlevel%==0 (
    start "" pythonw network_guard.py
    exit /b
)
where pyw >nul 2>nul
if %errorlevel%==0 (
    start "" pyw -3 network_guard.py
    exit /b
)
echo Python 3 ne naiden. Ustanovite Python 3 s python.org i vklyuchite Add Python to PATH.
pause
