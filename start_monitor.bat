
@echo off
setlocal
cd /d "%~dp0"

title AllamSec - Windows Security Monitor

echo ==========================================
echo         ALLAMSEC WINDOWS MONITOR
echo ==========================================
echo.

if not exist ".venv\Scripts\python.exe" (
    echo ERROR: AllamSec is not installed.
    echo Please run setup.bat first.
    pause
    exit /b 1
)

if not exist "config.json" (
    echo ERROR: config.json was not found.
    pause
    exit /b 1
)

echo Starting Windows Security monitoring...
echo Press CTRL+C to stop.
echo.

".venv\Scripts\python.exe" -m app.monitor_launcher

if errorlevel 1 (
    echo.
    echo ERROR: Monitoring failed.
    pause
    exit /b 1
)

endlocal
