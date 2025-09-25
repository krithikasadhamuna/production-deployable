# Frontend Integration Guide - CodeGrey SOC Platform

## Base URL
```
http://dev.codegrey.ai/api/backend
```

## Authentication
```javascript
// Add to all requests
headers: {
  'X-API-Key': 'api_codegrey_2024',
  'Content-Type': 'application/json'
}
```

## Core API Endpoints

### 1. Platform Health
```javascript
// GET /api/backend/health
fetch('http://dev.codegrey.ai/api/backend/health')
  .then(res => res.json())
  .then(data => {
    console.log('Platform Status:', data.status);
    console.log('Active Attacks:', data.active_attacks);
    console.log('Registered Endpoints:', data.registered_endpoints);
  });
```

### 2. Network Topology
```javascript
// GET /api/backend/network-topology
fetch('http://dev.codegrey.ai/api/backend/network-topology')
  .then(res => res.json())
  .then(topology => {
    console.log('Total Endpoints:', topology.total_endpoints);
    console.log('Network Zones:', Object.keys(topology.zones));
    console.log('Critical Assets:', topology.critical_assets);
  });
```

### 3. List Endpoints
```javascript
// GET /api/backend/endpoints
fetch('http://dev.codegrey.ai/api/backend/endpoints')
  .then(res => res.json())
  .then(endpoints => {
    endpoints.forEach(ep => {
      console.log(`${ep.hostname} (${ep.ip}) - ${ep.status}`);
    });
  });
```

## PhantomStrike AI (Attack Agent)

### Start Attack Workflow
```javascript
// POST /api/backend/langgraph/attack/start
const startAttack = async (attackRequest) => {
  const response = await fetch('http://dev.codegrey.ai/api/backend/langgraph/attack/start', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': 'api_codegrey_2024'
    },
    body: JSON.stringify({
      user_request: attackRequest,
      attack_type: 'apt',
      complexity: 'advanced'
    })
  });
  
  const result = await response.json();
  return {
    scenarioId: result.scenario_id,
    scenario: result.scenario,
    networkTopology: result.network_topology,
    message: result.message
  };
};

// Example usage
startAttack("Execute APT simulation targeting domain controllers")
  .then(result => {
    console.log('Scenario Generated:', result.scenario.name);
    console.log('Targets:', result.networkTopology.critical_assets);
  });
```

### Approve Attack Execution
```javascript
// POST /api/backend/langgraph/attack/{scenario_id}/approve
const approveAttack = async (scenarioId) => {
  const response = await fetch(`http://dev.codegrey.ai/api/backend/langgraph/attack/${scenarioId}/approve`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': 'api_codegrey_2024'
    }
  });
  
  return await response.json();
};
```

### Restore Systems
```javascript
// POST /api/backend/langgraph/attack/{scenario_id}/restore
const restoreSystems = async (scenarioId) => {
  const response = await fetch(`http://dev.codegrey.ai/api/backend/langgraph/attack/${scenarioId}/restore`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': 'api_codegrey_2024'
    }
  });
  
  return await response.json();
};
```

## GuardianAlpha AI (Detection Agent)

### Detection Status
```javascript
// GET /api/backend/langgraph/detection/status
const getDetectionStatus = async () => {
  const response = await fetch('http://dev.codegrey.ai/api/backend/langgraph/detection/status', {
    headers: { 'X-API-Key': 'api_codegrey_2024' }
  });
  
  const status = await response.json();
  return {
    isActive: status.continuous_detection,
    detectionsToday: status.detections_today,
    guardianStatus: status.guardian_alpha_status
  };
};
```

### Recent Detections
```javascript
// GET /api/backend/langgraph/detection/recent
const getRecentDetections = async () => {
  const response = await fetch('http://dev.codegrey.ai/api/backend/langgraph/detection/recent', {
    headers: { 'X-API-Key': 'api_codegrey_2024' }
  });
  
  const detections = await response.json();
  return detections.map(d => ({
    id: d.id,
    timestamp: d.timestamp,
    threatType: d.threat_type,
    severity: d.severity,
    confidence: d.confidence,
    verdict: d.verdict,
    reasoning: d.reasoning
  }));
};
```

### Start Continuous Detection
```javascript
// POST /api/backend/langgraph/detection/continuous/start
const startContinuousDetection = async () => {
  const response = await fetch('http://dev.codegrey.ai/api/backend/langgraph/detection/continuous/start', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': 'api_codegrey_2024'
    }
  });
  
  return await response.json();
};
```

## AI Reasoning Engine

### Chat Interface
```javascript
// POST /api/backend/v1/chat
const chatWithAI = async (message) => {
  const response = await fetch('http://dev.codegrey.ai/api/backend/v1/chat', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': 'api_codegrey_2024'
    },
    body: JSON.stringify({ message })
  });
  
  const result = await response.json();
  return {
    response: result.response,
    model: result.model,
    confidence: result.confidence
  };
};

// Example usage
chatWithAI("Analyze the security posture of my domain controllers")
  .then(result => {
    console.log('AI Response:', result.response);
    console.log('Confidence:', result.confidence);
  });
```

## Dashboard

### Executive Dashboard
```javascript
// GET /api/backend/dashboard/executive
const getDashboardData = async () => {
  const response = await fetch('http://dev.codegrey.ai/api/backend/dashboard/executive', {
    headers: { 'X-API-Key': 'api_codegrey_2024' }
  });
  
  const dashboard = await response.json();
  return {
    aiStatus: dashboard.ai_status,
    metrics: dashboard.metrics,
    lastSimulation: dashboard.ai_status.last_simulation,
    threatsBlocked: dashboard.metrics.total_threats_blocked
  };
};
```

## Client Agent Management

### Register New Endpoint
```javascript
// POST /api/backend/agent/register
const registerEndpoint = async (endpointData) => {
  const response = await fetch('http://dev.codegrey.ai/api/backend/agent/register', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-API-Key': 'api_codegrey_2024'
    },
    body: JSON.stringify({
      hostname: endpointData.hostname,
      ip: endpointData.ip,
      mac: endpointData.mac,
      os_type: endpointData.osType,
      os_version: endpointData.osVersion,
      capabilities: ['logs', 'execute'],
      zone: 'internal',
      importance: 'medium'
    })
  });
  
  return await response.json();
};
```

## Software Downloads

### Get Available Agents
```javascript
// GET /api/backend/software-download
const getAvailableAgents = async () => {
  const response = await fetch('http://dev.codegrey.ai/api/backend/software-download', {
    headers: { 'X-API-Key': 'api_codegrey_2024' }
  });
  
  const agents = await response.json();
  return agents.map(agent => ({
    id: agent.id,
    name: agent.name,
    version: agent.version,
    downloadUrl: agent.downloadUrl,
    os: agent.os,
    description: agent.description
  }));
};
```

## Multitenancy Support

### Tenant-Specific Endpoints
```javascript
// For tenant-specific operations, use:
const tenantBaseUrl = 'http://dev.codegrey.ai/api/backend/t/codegrey';

// Tenant health
fetch(`${tenantBaseUrl}/health`)

// All other endpoints work the same with tenant prefix
```

## Real-Time Updates

### Polling for Live Data
```javascript
// Poll for detection updates every 5 seconds
const pollDetections = () => {
  setInterval(async () => {
    const detections = await getRecentDetections();
    updateDetectionUI(detections);
  }, 5000);
};

// Poll for attack status
const pollAttackStatus = (scenarioId) => {
  const interval = setInterval(async () => {
    try {
      const response = await fetch(`http://dev.codegrey.ai/api/backend/langgraph/attack/${scenarioId}/status`);
      const status = await response.json();
      
      if (status.status === 'completed' || status.status === 'failed') {
        clearInterval(interval);
      }
      
      updateAttackStatusUI(status);
    } catch (error) {
      console.error('Status polling error:', error);
    }
  }, 2000);
};
```

## Error Handling

### Standard Error Response
```javascript
const handleAPIResponse = async (response) => {
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || 'API request failed');
  }
  return await response.json();
};

// Usage
try {
  const result = await handleAPIResponse(
    await fetch('http://dev.codegrey.ai/api/backend/health')
  );
  console.log('Success:', result);
} catch (error) {
  console.error('Error:', error.message);
}
```

## Complete Integration Example

```javascript
class SOCPlatformAPI {
  constructor(baseUrl = 'http://dev.codegrey.ai/api/backend', apiKey = 'api_codegrey_2024') {
    this.baseUrl = baseUrl;
    this.apiKey = apiKey;
  }
  
  async request(endpoint, method = 'GET', data = null) {
    const config = {
      method,
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': this.apiKey
      }
    };
    
    if (data) {
      config.body = JSON.stringify(data);
    }
    
    const response = await fetch(`${this.baseUrl}${endpoint}`, config);
    
    if (!response.ok) {
      throw new Error(`API Error: ${response.status}`);
    }
    
    return await response.json();
  }
  
  // PhantomStrike AI methods
  async startAttack(userRequest, attackType = 'apt') {
    return await this.request('/langgraph/attack/start', 'POST', {
      user_request: userRequest,
      attack_type: attackType,
      complexity: 'advanced'
    });
  }
  
  async approveAttack(scenarioId) {
    return await this.request(`/langgraph/attack/${scenarioId}/approve`, 'POST');
  }
  
  // GuardianAlpha AI methods
  async getDetectionStatus() {
    return await this.request('/langgraph/detection/status');
  }
  
  async getRecentDetections() {
    return await this.request('/langgraph/detection/recent');
  }
  
  // Network methods
  async getNetworkTopology() {
    return await this.request('/network-topology');
  }
  
  async getEndpoints() {
    return await this.request('/endpoints');
  }
  
  // Dashboard
  async getDashboard() {
    return await this.request('/dashboard/executive');
  }
}

// Usage
const soc = new SOCPlatformAPI();

// Start attack workflow
soc.startAttack("Execute APT simulation on domain controllers")
  .then(result => {
    console.log('Attack scenario generated:', result.scenario.name);
    // Show approval UI to user
    showAttackApprovalUI(result);
  });

// Get live detections
soc.getRecentDetections()
  .then(detections => {
    updateDetectionDashboard(detections);
  });
```
