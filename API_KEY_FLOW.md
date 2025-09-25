# API Key Flow Documentation

## User API Keys

### Pre-configured API Keys
The following default users have pre-configured API keys:

| User | Email | Password | API Key |
|------|-------|----------|---------|
| Sagar | sagar@codegrey.ai | 123 | `usr-api-sagar-default-2024` |
| Alsaad | alsaad@codegrey.ai | 123 | `usr-api-alsaad-default-2024` |
| Krithika | krithika@codegrey.ai | 123 | `usr-api-krithika-default-2024` |

### Where API Keys are Used

1. **Database Storage**
   - Location: `master_platform.db` → `global_users` table → `api_key` column
   - Created in: `start_production_server.py` (lines 306-332)

2. **Agent Installation**
   - Users enter their API key during agent installation
   - Windows: `INSTALL.bat` prompts for API key
   - Linux: `install.sh` prompts for API key  
   - macOS: `install.command` prompts for API key

3. **API Key Validation**
   - `flask_api/routes/simple_agent_auth.py` (line 27)
   - Checks if key starts with `usr-api-`
   - Looks up tenant from user's API key
   - Auto-assigns agent to correct organization

4. **Agent Registration Flow**
   ```
   User API Key (usr-api-xxx)
        ↓
   Agent sends to /api/agent/simple-register
        ↓
   Server validates and finds tenant
        ↓
   Generates Agent Key (agt-key-xxx)
        ↓
   Agent uses Agent Key for all future calls
   ```

## How to Test

1. **Start the server:**
   ```bash
   python start_production_server.py
   ```

2. **Install an agent:**
   - Windows: Run `INSTALL.bat` as Administrator
   - Enter one of the API keys above (e.g., `usr-api-sagar-default-2024`)

3. **Agent will:**
   - Register with the CodeGrey tenant
   - Get its own agent key
   - Start sending heartbeats

## API Endpoints

- **Simple Registration**: `POST /api/agent/simple-register`
  - Requires: User API key in JSON body
  - Returns: Agent ID and Agent Key

- **Heartbeat**: `POST /api/agent/heartbeat`
  - Requires: Agent Key (not User API key)
  - Returns: Success status

## Multi-Tenancy

The User API key determines which organization/tenant the agent belongs to:
- API key → User record → Tenant ID → Tenant database
- All agents registered with a user's API key automatically join their organization
- No manual tenant configuration needed
