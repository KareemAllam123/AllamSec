
@echo off
setlocal
cd /d "%~dp0"

title AllamSec - Installation
echo ==========================================
echo          ALLAMSEC INSTALLER
echo ==========================================
echo.

if not exist "requirements.txt" (
    echo ERROR: requirements.txt was not found.
    pause
    exit /b 1
)

where py >nul 2>&1
if not errorlevel 1 (
    set "PYTHON=py -3"
) else (
    where python >nul 2>&1
    if errorlevel 1 (
        echo ERROR: Python 3 is not installed.
        echo Install Python and try again.
        pause
        exit /b 1
    )
    set "PYTHON=python"
)

echo [1/4] Checking virtual environment...

if not exist ".venv\Scripts\python.exe" (
    %PYTHON% -m venv .venv
    if errorlevel 1 goto failed
)

echo.
echo [2/4] Updating pip...

".venv\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 goto failed

echo.
echo [3/4] Installing dependencies...

".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto failed

echo.
echo [4/4] Initializing database...

".venv\Scripts\python.exe" -c "from database.db_manager import initialize_database; initialize_database()"
if errorlevel 1 goto failed

echo.
echo ==========================================
echo      ALLAMSEC INSTALLATION COMPLETE
echo ==========================================
echo.
echo Run start_allamsec.bat to open the dashboard.
echo.
pause
exit /b 0

:failed
echo.
echo ERROR: Installation failed.
echo Review the error messages above.
pause
exit /b 1
