@echo off
setlocal
:: ==========================================
:: The Obsidian Lens - Unified Startup Script
:: ==========================================

:: 1. Check for Administrator Privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Administrative permissions confirmed.
) else (
    echo [!] Requesting administrative privileges...
    :: Re-launch this script with Administrator privileges using PowerShell
    powershell -Command "Start-Process '%~dpnx0' -Verb RunAs"
    exit /b
)

:: 2. Set working directory to the location of this script
cd /d "%~dp0"

:: 3. Start the Python Backend
echo [*] Starting Backend (Flask)...
start "Obsidian Backend" cmd /k "title Obsidian Backend && python app.py"

:: 4. Start the Next.js Frontend
echo [*] Starting Frontend (Next.js)...
cd frontend
start "Obsidian Frontend" cmd /k "title Obsidian Frontend && npm run dev"

:: 5. Finish
echo.
echo [SUCCESS] Both services are spinning up!
echo You can now close this launcher window.
timeout /t 5 >nul
exit
