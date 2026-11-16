
@echo off
setlocal
cd /d "%~dp0"

title AllamSec - Security Dashboard

echo ==========================================
echo         ALLAMSEC SECURITY DASHBOARD
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

echo Starting the local security dashboard...
echo.
echo Press CTRL+C to stop the dashboard.
echo.

".venv\Scripts\python.exe" -m dashboard.server

if errorlevel 1 (
    echo.
    echo ERROR: Dashboard startup failed.
    echo Review the error messages above.
    pause
    exit /b 1
)

endlocal
