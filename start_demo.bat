@echo off
echo ========================================
echo CodeGrey SOC Demo Server Startup
echo ========================================

echo Creating directories...
if not exist logs mkdir logs
if not exist database mkdir database

echo Starting demo server...
echo Server will be available at: http://localhost:8443
echo API Key: ak_default_key_change_in_production
echo.
echo Press Ctrl+C to stop the server
echo.

python simple_demo_app.py

pause



