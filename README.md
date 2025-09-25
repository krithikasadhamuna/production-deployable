# SOC Platform Production

## Quick Start

1. **Install Dependencies:**

Option A - Full Installation (slower but complete):
```bash
pip install -r requirements_complete.txt
```

Option B - Optimized Installation (faster, recommended):
```bash
pip install -r requirements_optimized.txt
```

Note: LangChain IS required for AI agents to work!

2. **Setup CyberSecAI Model:**
```bash
sudo ./setup_cybersec_ai.sh
```

3. **Start Server:**
```bash
python3 start_production_server.py
```

## Configuration
- Domain: dev.codegrey.ai
- Default users: sagar@codegrey.ai, alsaad@codegrey.ai, krithika@codegrey.ai (password: 123)

## Validation
```bash
python3 validate_deployment.py
```