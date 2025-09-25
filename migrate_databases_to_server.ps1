# Database Migration Script for SOC Platform (Windows PowerShell)
# Migrates production databases to Amazon Linux 2023 server

Write-Host "================================================================================" -ForegroundColor Cyan
Write-Host " SOC PLATFORM DATABASE MIGRATION" -ForegroundColor Cyan
Write-Host "================================================================================" -ForegroundColor Cyan

# Configuration
$SERVER_USER = "krithika"
$SERVER_HOST = Read-Host "Enter your server IP address"
$SERVER_PATH = "/home/krithika/soc-platform-production"
$LOCAL_DB_PATH = "."

# Database files to migrate
$DATABASES = @(
    "soc_main.db",
    "network_topology.db", 
    "agent_logs.db",
    "soc_users.db"
)

# Check if databases exist locally
Write-Host "Checking local databases..." -ForegroundColor Yellow
$allDbsExist = $true

foreach ($db in $DATABASES) {
    if (Test-Path $db) {
        $size = [math]::Round((Get-Item $db).Length / 1MB, 2)
        Write-Host "  ✓ $db ($size MB)" -ForegroundColor Green
    } else {
        Write-Host "  ✗ $db - NOT FOUND" -ForegroundColor Red
        $allDbsExist = $false
    }
}

if (-not $allDbsExist) {
    Write-Host "Run 'python create_production_databases.py' first" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Server Configuration:" -ForegroundColor Yellow
Write-Host "  User: $SERVER_USER"
Write-Host "  Host: $SERVER_HOST"
Write-Host "  Path: $SERVER_PATH"
Write-Host ""

# Create backup directory on server
Write-Host "Creating backup directory on server..." -ForegroundColor Yellow
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
ssh "$SERVER_USER@$SERVER_HOST" "mkdir -p $SERVER_PATH/database_backups/$timestamp"

# Backup existing databases on server (if any)
Write-Host "Backing up existing databases on server..." -ForegroundColor Yellow
foreach ($db in $DATABASES) {
    ssh "$SERVER_USER@$SERVER_HOST" "
        if [ -f $SERVER_PATH/$db ]; then
            cp $SERVER_PATH/$db $SERVER_PATH/database_backups/$timestamp/$db.backup
            echo '  Backed up existing $db'
        fi
    "
}

# Transfer databases to server
Write-Host ""
Write-Host "Transferring databases to server..." -ForegroundColor Yellow
$transferSuccess = $true

foreach ($db in $DATABASES) {
    Write-Host "  Uploading $db..." -ForegroundColor Cyan
    
    # Use scp to transfer file
    $result = scp $db "$SERVER_USER@${SERVER_HOST}:$SERVER_PATH/"
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "    ✓ $db transferred successfully" -ForegroundColor Green
    } else {
        Write-Host "    ✗ Failed to transfer $db" -ForegroundColor Red
        $transferSuccess = $false
    }
}

if (-not $transferSuccess) {
    Write-Host "Database transfer failed. Please check your SSH connection and try again." -ForegroundColor Red
    exit 1
}

# Set proper permissions on server
Write-Host ""
Write-Host "Setting database permissions on server..." -ForegroundColor Yellow
ssh "$SERVER_USER@$SERVER_HOST" "
    cd $SERVER_PATH
    chmod 644 *.db
    chown $SERVER_USER:$SERVER_USER *.db
    echo 'Database permissions set'
"

# Verify databases on server
Write-Host ""
Write-Host "Verifying databases on server..." -ForegroundColor Yellow
ssh "$SERVER_USER@$SERVER_HOST" "
    cd $SERVER_PATH
    echo 'Database files on server:'
    for db in soc_main.db network_topology.db agent_logs.db soc_users.db; do
        if [ -f \`$db ]; then
            size=\`$(du -h \`$db | cut -f1)
            echo '  ✓ '\`$db' ('\`$size')'
        else
            echo '  ✗ '\`$db' - MISSING'
        fi
    done
"

# Test database connectivity
Write-Host ""
Write-Host "Testing database connectivity on server..." -ForegroundColor Yellow
$dbTestResult = ssh "$SERVER_USER@$SERVER_HOST" "
    cd $SERVER_PATH
    python3 -c `"
import sqlite3
import sys

databases = ['soc_main.db', 'network_topology.db', 'agent_logs.db', 'soc_users.db']
success = True

for db in databases:
    try:
        conn = sqlite3.connect(db)
        cursor = conn.cursor()
        cursor.execute('SELECT name FROM sqlite_master WHERE type=\\`"table\\`"')
        tables = cursor.fetchall()
        conn.close()
        print(f'  ✓ {db} - {len(tables)} tables')
    except Exception as e:
        print(f'  ✗ {db} - ERROR: {e}')
        success = False

if success:
    print('\\nAll databases are accessible and functional!')
    sys.exit(0)
else:
    print('\\nSome databases have issues!')
    sys.exit(1)
`"
"

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Green
    Write-Host " DATABASE MIGRATION COMPLETED SUCCESSFULLY" -ForegroundColor Green
    Write-Host "================================================================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Databases migrated:" -ForegroundColor Yellow
    foreach ($db in $DATABASES) {
        Write-Host "  • $db" -ForegroundColor White
    }
    Write-Host ""
    Write-Host "Server location: $SERVER_USER@${SERVER_HOST}:$SERVER_PATH" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Dummy users available for testing:" -ForegroundColor Yellow
    Write-Host "  • admin@codegrey.ai (password: SecureAdmin123!)" -ForegroundColor White
    Write-Host "  • soc.manager@codegrey.ai (password: SOCManager456!)" -ForegroundColor White
    Write-Host "  • senior.analyst@codegrey.ai (password: SeniorAnalyst789!)" -ForegroundColor White
    Write-Host "  • analyst@codegrey.ai (password: Analyst123!)" -ForegroundColor White
    Write-Host "  • viewer@codegrey.ai (password: Viewer456!)" -ForegroundColor White
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Yellow
    Write-Host "  1. Start your SOC platform on the server" -ForegroundColor White
    Write-Host "  2. Test login with dummy users" -ForegroundColor White
    Write-Host "  3. Begin registering real endpoints" -ForegroundColor White
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host " DATABASE MIGRATION FAILED" -ForegroundColor Red
    Write-Host "================================================================================" -ForegroundColor Red
    Write-Host "Please check the error messages above and try again." -ForegroundColor Red
    exit 1
}
