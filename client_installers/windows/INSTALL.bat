@echo off
color 0A
cls
echo =========================================
echo    CodeGrey SOC Agent - Windows Setup
echo =========================================
echo.

:: Check for admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    color 0C
    echo ERROR: Administrator privileges required!
    echo.
    echo Please right-click this file and select
    echo "Run as Administrator"
    echo.
    pause
    exit /b 1
)

echo This will install the CodeGrey SOC Agent
echo.
set /p API_KEY="Enter your API Key: "
echo.

echo Installing agent...
python -m pip install requests psutil pyyaml --quiet 2>nul

:: Create config directory
mkdir "C:\ProgramData\CodeGrey" 2>nul

:: Create simple config
echo { > "C:\ProgramData\CodeGrey\agent.conf"
echo   "api_key": "%API_KEY%", >> "C:\ProgramData\CodeGrey\agent.conf"
echo   "server_url": "https://dev.codegrey.ai" >> "C:\ProgramData\CodeGrey\agent.conf"
echo } >> "C:\ProgramData\CodeGrey\agent.conf"

:: Create program directory
mkdir "C:\Program Files\CodeGrey" 2>nul

:: Copy agent
copy /Y simple_agent.py "C:\Program Files\CodeGrey\agent.py" >nul 2>&1

:: Start agent
cd "C:\Program Files\CodeGrey"
start python agent.py

color 0A
echo.
echo =========================================
echo    Installation Complete!
echo =========================================
echo.
echo Agent is now running and connected.
echo.
pause
