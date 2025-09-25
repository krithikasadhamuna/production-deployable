# SOC Platform User Authentication System

## Overview

The SOC Platform now includes a **separate User Authentication Agent** for managing SOC personnel accounts, distinct from client endpoint registration.

## Architecture

```
┌─────────────────────────────────────┐
│        SOC Platform Main           │
│     (COMPLETE_SOC_PLATFORM.py)     │
│         Port: 8080                  │
│                                     │
│  • Attack/Detection Workflows      │
│  • Network Topology               │
│  • Client Agent Management        │
│  • AI Reasoning                   │
└─────────────────────────────────────┘
                    │
                    │ Integrated
                    ▼
┌─────────────────────────────────────┐
│    User Authentication Agent       │
│   (start_user_auth_service.py)     │
│         Port: 5002                  │
│                                     │
│  • SOC Personnel Registration      │
│  • Login/Logout                    │
│  • API Key Management              │
│  • Role-Based Access Control       │
└─────────────────────────────────────┘
```

## Key Differences

| Feature | Endpoint Registration | User Registration |
|---------|----------------------|-------------------|
| **Purpose** | Client agents connecting | SOC personnel accounts |
| **Database** | `network_topology.db` | `soc_users.db` |
| **Authentication** | Agent certificates | JWT + API keys |
| **Endpoints** | `/api/backend/agent/*` | `/api/auth/auth/*` |

## User Roles

1. **admin** - Full system access
2. **soc_manager** - Team oversight and attack control
3. **senior_analyst** - Advanced analysis and attack control
4. **analyst** - Detection and incident response
5. **viewer** - Read-only access

## API Endpoints

### Registration
```bash
POST /api/auth/auth/register
Content-Type: application/json

{
  "email": "analyst@company.com",
  "password": "secure_password",
  "first_name": "John",
  "last_name": "Doe",
  "organization": "ACME Corp",
  "role": "analyst"
}
```

### Login
```bash
POST /api/auth/auth/login
Content-Type: application/json

{
  "email": "analyst@company.com",
  "password": "secure_password"
}
```

**Response:**
```json
{
  "success": true,
  "user": {
    "user_id": "user_abc123",
    "email": "analyst@company.com",
    "first_name": "John",
    "role": "analyst"
  },
  "auth": {
    "jwt_token": "eyJ0eXAiOiJKV1Q...",
    "api_key": "soc_xyz789...",
    "session_id": "session_def456",
    "expires_at": "2025-09-25T18:30:00Z"
  }
}
```

### API Key Validation
```bash
GET /api/auth/auth/validate
X-API-Key: soc_xyz789...
```

### User Profile
```bash
GET /api/auth/auth/profile
Authorization: Bearer eyJ0eXAiOiJKV1Q...
```

## Deployment

### Option 1: Integrated (Recommended)
The authentication agent is automatically integrated into `COMPLETE_SOC_PLATFORM.py`:

```bash
python3 COMPLETE_SOC_PLATFORM.py
```

**Available at:**
- Main SOC Platform: `http://localhost:8080/api/backend/`
- User Authentication: `http://localhost:8080/api/auth/`

### Option 2: Standalone Service
Run authentication as separate service:

```bash
python3 start_user_auth_service.py
```

**Available at:**
- User Authentication: `http://localhost:5002/api/auth/`

## Database Schema

### SOC Users Table
```sql
CREATE TABLE soc_users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    first_name TEXT NOT NULL,
    last_name TEXT,
    role TEXT DEFAULT 'analyst',
    organization TEXT NOT NULL,
    api_key TEXT UNIQUE NOT NULL,
    is_active BOOLEAN DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP
);
```

## Security Features

1. **Password Hashing** - bcrypt with salt
2. **JWT Tokens** - 8-hour expiration
3. **API Key Generation** - Cryptographically secure
4. **Account Lockout** - 5 failed attempts = 30min lock
5. **Session Management** - Active session tracking
6. **Role-Based Permissions** - Granular access control

## Frontend Integration

### JavaScript Example
```javascript
// Register new SOC user
const registerUser = async (userData) => {
  const response = await fetch('http://dev.codegrey.ai/api/auth/auth/register', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(userData)
  });
  return response.json();
};

// Login SOC user
const loginUser = async (email, password) => {
  const response = await fetch('http://dev.codegrey.ai/api/auth/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ email, password })
  });
  
  const result = await response.json();
  if (result.success) {
    // Store tokens
    localStorage.setItem('jwt_token', result.auth.jwt_token);
    localStorage.setItem('api_key', result.auth.api_key);
  }
  return result;
};

// Use API key for SOC operations
const getNetworkTopology = async () => {
  const apiKey = localStorage.getItem('api_key');
  const response = await fetch('http://dev.codegrey.ai/api/backend/network-topology', {
    headers: {
      'X-API-Key': apiKey
    }
  });
  return response.json();
};
```

## Testing

### Health Check
```bash
curl http://localhost:8080/api/auth/auth/health
```

### Register Test User
```bash
curl -X POST http://localhost:8080/api/auth/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@company.com",
    "password": "test123",
    "first_name": "Test",
    "organization": "Test Corp",
    "role": "analyst"
  }'
```

### Login Test User
```bash
curl -X POST http://localhost:8080/api/auth/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@company.com",
    "password": "test123"
  }'
```

## NGINX Configuration

Add to your NGINX config:

```nginx
# User Authentication endpoints
location /api/auth/ {
    proxy_pass http://127.0.0.1:8080/api/auth/;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    
    # CORS
    add_header Access-Control-Allow-Origin * always;
    add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS" always;
    add_header Access-Control-Allow-Headers "Authorization, X-API-Key, Content-Type" always;
}
```

## Summary

**Separate User Authentication Agent** - Dedicated service for SOC personnel  
**Integrated with Main Platform** - Available at `/api/auth/` endpoints  
**Complete User Management** - Registration, login, API keys, roles  
**Security Features** - JWT tokens, password hashing, account lockout  
**Role-Based Access** - 5 predefined roles with permissions  
**Database Separation** - User data separate from network topology  

**SOC personnel can now register, login, and access the platform with proper authentication!**
