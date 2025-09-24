@echo off
REM CodeGrey SOC Server - Quick Start Script (Windows)

echo 🚀 CodeGrey SOC Server - Production Deployment
echo ==============================================

REM Check if Docker is available
docker --version >nul 2>&1
if %errorlevel% == 0 (
    echo ✅ Docker found - Using containerized deployment
    
    REM Create .env if it doesn't exist
    if not exist .env (
        echo 📝 Creating .env file from template...
        copy env.example .env
        echo ⚠️  Please edit .env file with your settings before production use!
    )
    
    REM Start with Docker Compose
    echo 🐳 Starting with Docker Compose...
    docker-compose up -d
    
    echo ✅ Server should be running on port 8443
    echo 🔍 Check status: curl http://localhost:8443/api/system/status
    echo 📊 View logs: docker-compose logs -f soc-server
    
) else (
    REM Check if Python is available
    python --version >nul 2>&1
    if %errorlevel% == 0 (
        echo 🐍 Python found - Using direct deployment
        
        REM Install dependencies
        echo 📦 Installing dependencies...
        pip install -r requirements.txt
        
        REM Create .env if it doesn't exist
        if not exist .env (
            echo 📝 Creating .env file from template...
            copy env.example .env
            echo ⚠️  Please edit .env file with your settings!
        )
        
        REM Create directories
        if not exist logs mkdir logs
        if not exist database mkdir database
        
        REM Start server
        echo 🚀 Starting server...
        python app.py
        
    ) else (
        echo ❌ Neither Docker nor Python found!
        echo Please install Docker or Python 3.8+ to continue.
        pause
        exit /b 1
    )
)

pause



