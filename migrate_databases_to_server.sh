#!/bin/bash

# Database Migration Script for SOC Platform
# Migrates production databases to Amazon Linux 2023 server

echo "================================================================================"
echo " SOC PLATFORM DATABASE MIGRATION"
echo "================================================================================"

# Configuration
SERVER_USER="krithika"
SERVER_HOST="your-server-ip"  # Replace with your actual server IP
SERVER_PATH="/home/krithika/soc-platform-production"
LOCAL_DB_PATH="."

# Database files to migrate
DATABASES=(
    "soc_main.db"
    "network_topology.db" 
    "agent_logs.db"
    "soc_users.db"
)

# Check if databases exist locally
echo "Checking local databases..."
for db in "${DATABASES[@]}"; do
    if [ -f "$db" ]; then
        size=$(du -h "$db" | cut -f1)
        echo "  ✓ $db ($size)"
    else
        echo "  ✗ $db - NOT FOUND"
        echo "Run 'python create_production_databases.py' first"
        exit 1
    fi
done

echo ""
echo "Server Configuration:"
echo "  User: $SERVER_USER"
echo "  Host: $SERVER_HOST"
echo "  Path: $SERVER_PATH"
echo ""

# Prompt for server IP if not set
if [ "$SERVER_HOST" = "your-server-ip" ]; then
    read -p "Enter your server IP address: " SERVER_HOST
fi

# Create backup directory on server
echo "Creating backup directory on server..."
ssh $SERVER_USER@$SERVER_HOST "mkdir -p $SERVER_PATH/database_backups/$(date +%Y%m%d_%H%M%S)"

# Backup existing databases on server (if any)
echo "Backing up existing databases on server..."
for db in "${DATABASES[@]}"; do
    ssh $SERVER_USER@$SERVER_HOST "
        if [ -f $SERVER_PATH/$db ]; then
            cp $SERVER_PATH/$db $SERVER_PATH/database_backups/$(date +%Y%m%d_%H%M%S)/$db.backup
            echo '  Backed up existing $db'
        fi
    "
done

# Transfer databases to server
echo ""
echo "Transferring databases to server..."
for db in "${DATABASES[@]}"; do
    echo "  Uploading $db..."
    scp "$db" $SERVER_USER@$SERVER_HOST:$SERVER_PATH/
    
    if [ $? -eq 0 ]; then
        echo "    ✓ $db transferred successfully"
    else
        echo "    ✗ Failed to transfer $db"
        exit 1
    fi
done

# Set proper permissions on server
echo ""
echo "Setting database permissions on server..."
ssh $SERVER_USER@$SERVER_HOST "
    cd $SERVER_PATH
    chmod 644 *.db
    chown $SERVER_USER:$SERVER_USER *.db
    echo 'Database permissions set'
"

# Verify databases on server
echo ""
echo "Verifying databases on server..."
ssh $SERVER_USER@$SERVER_HOST "
    cd $SERVER_PATH
    echo 'Database files on server:'
    for db in soc_main.db network_topology.db agent_logs.db soc_users.db; do
        if [ -f \$db ]; then
            size=\$(du -h \$db | cut -f1)
            echo '  ✓ '\$db' ('\$size')'
        else
            echo '  ✗ '\$db' - MISSING'
        fi
    done
"

# Test database connectivity
echo ""
echo "Testing database connectivity on server..."
ssh $SERVER_USER@$SERVER_HOST "
    cd $SERVER_PATH
    python3 -c \"
import sqlite3
import sys

databases = ['soc_main.db', 'network_topology.db', 'agent_logs.db', 'soc_users.db']
success = True

for db in databases:
    try:
        conn = sqlite3.connect(db)
        cursor = conn.cursor()
        cursor.execute('SELECT name FROM sqlite_master WHERE type=\\\"table\\\"')
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
\"
"

if [ $? -eq 0 ]; then
    echo ""
    echo "================================================================================"
    echo " DATABASE MIGRATION COMPLETED SUCCESSFULLY"
    echo "================================================================================"
    echo ""
    echo "Databases migrated:"
    for db in "${DATABASES[@]}"; do
        echo "  • $db"
    done
    echo ""
    echo "Server location: $SERVER_USER@$SERVER_HOST:$SERVER_PATH"
    echo ""
    echo "Dummy users available for testing:"
    echo "  • admin@codegrey.ai (password: SecureAdmin123!)"
    echo "  • soc.manager@codegrey.ai (password: SOCManager456!)"
    echo "  • senior.analyst@codegrey.ai (password: SeniorAnalyst789!)"
    echo "  • analyst@codegrey.ai (password: Analyst123!)"
    echo "  • viewer@codegrey.ai (password: Viewer456!)"
    echo ""
    echo "Next steps:"
    echo "  1. Start your SOC platform on the server"
    echo "  2. Test login with dummy users"
    echo "  3. Begin registering real endpoints"
    echo ""
    echo "================================================================================"
else
    echo ""
    echo "================================================================================"
    echo " DATABASE MIGRATION FAILED"
    echo "================================================================================"
    echo "Please check the error messages above and try again."
    exit 1
fi
