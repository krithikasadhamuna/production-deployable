#!/bin/bash
# Setup CyberSecAI Model for SOC Platform
# This script installs Ollama and creates the CyberSecAI model

echo "=================================="
echo "CyberSecAI Model Setup"
echo "=================================="

# Check if running as root
if [ "$EUID" -eq 0 ]; then 
   echo "Running as root, good!"
else
   echo "Please run as root (use sudo)"
   exit 1
fi

# Install Ollama if not already installed
if ! command -v ollama &> /dev/null; then
    echo "Installing Ollama..."
    curl -fsSL https://ollama.ai/install.sh | sh
    
    # Start Ollama service
    systemctl enable ollama
    systemctl start ollama
    
    echo "Ollama installed successfully"
else
    echo "Ollama already installed"
fi

# Wait for Ollama to be ready
echo "Waiting for Ollama service to be ready..."
sleep 5

# Check if Ollama is running
if ! systemctl is-active --quiet ollama; then
    echo "Starting Ollama service..."
    systemctl start ollama
    sleep 5
fi

# Create the CyberSecAI model
echo "Creating CyberSecAI model..."

# Check if model already exists
if ollama list | grep -q "cybersec-ai"; then
    echo "CyberSecAI model already exists, removing old version..."
    ollama rm cybersec-ai
fi

# Create the model from Modelfile
cd /home/$(logname)/soc-platform-production/ml_models/
ollama create cybersec-ai -f CyberSecAI.modelfile

# Verify model creation
if ollama list | grep -q "cybersec-ai"; then
    echo "✅ CyberSecAI model created successfully!"
    
    # Test the model
    echo "Testing CyberSecAI model..."
    echo "What is DNS tunneling?" | ollama run cybersec-ai --verbose
    
    echo ""
    echo "=================================="
    echo "CyberSecAI Setup Complete!"
    echo "=================================="
    echo "Model: cybersec-ai"
    echo "Endpoint: http://localhost:11434"
    echo "Knowledge: MITRE ATT&CK + Security Best Practices"
    echo ""
    echo "The SOC platform will now use this model for:"
    echo "- Attack scenario generation"
    echo "- Threat detection and analysis"
    echo "- Incident response planning"
    echo "=================================="
else
    echo "❌ Failed to create CyberSecAI model"
    echo "Please check the logs and try again"
    exit 1
fi
