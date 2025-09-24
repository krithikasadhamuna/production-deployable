#!/usr/bin/env python3
"""
AI-Driven SOC Agents Startup
Starts only AI-powered agents with local cybersec-ai LLM
"""

import os
import sys
import time
import subprocess
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AIAgentsStarter:
    """Starts only AI-driven SOC agents"""
    
    def __init__(self):
        self.base_path = Path(__file__).parent
        
    def check_ollama_server(self):
        """Check if Ollama server is running"""
        try:
            import requests
            response = requests.get("http://localhost:11434/api/tags", timeout=5)
            if response.status_code == 200:
                logger.info(" Ollama server: Running")
                return True
        except Exception:
            pass
            
        logger.warning(" Ollama server not running, attempting to start...")
        return self.start_ollama_server()
    
    def start_ollama_server(self):
        """Start Ollama server"""
        try:
            subprocess.Popen(["ollama", "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(3)  # Give it time to start
            
            # Check if it started
            import requests
            response = requests.get("http://localhost:11434/api/tags", timeout=10)
            if response.status_code == 200:
                logger.info("Ollama server: Started successfully")
                return True
        except Exception as e:
            logger.error(f" Failed to start Ollama server: {e}")
        
        return False
    
    def check_cybersec_model(self):
        """Check if cybersec-ai model is available"""
        try:
            result = subprocess.run(["ollama", "list"], capture_output=True, text=True)
            if "cybersec-ai" in result.stdout:
                logger.info(" cybersec-ai model: Available")
                return True
            else:
                logger.warning(" cybersec-ai model not found")
                logger.info(" Run: ollama create cybersec-ai -f path/to/CyberSecAI.modelfile")
                return False
        except Exception as e:
            logger.error(f" Error checking model: {e}")
            return False
    
    def start_ai_agents(self):
        """Start the AI-powered SOC system"""
        logger.info(" Starting AI-Driven SOC Agents...")
        
        # Check prerequisites
        if not self.check_ollama_server():
            logger.error(" Cannot start without Ollama server")
            return False
            
        if not self.check_cybersec_model():
            logger.warning(" cybersec-ai model not available, will use fallback")
        
        # Start the main application
        try:
            logger.info(" Starting AI agents with local LLM...")
            
            # Add current directory to Python path
            sys.path.insert(0, str(self.base_path))
            
            # Import and start the main app
            from app import initialize_agent_engines, app
            
            # Initialize AI agents
            initialize_agent_engines()
            
            # Start the Flask server
            logger.info(" Starting SOC server on http://localhost:8443")
            app.run(host="0.0.0.0", port=8443, debug=False)
            
        except Exception as e:
            logger.error(f" Failed to start AI agents: {e}")
            return False
    
    def show_agent_status(self):
        """Show status of AI agents"""
        print("\n" + "="*60)
        print(" AI-DRIVEN SOC AGENTS STATUS")
        print("="*60)
        print(" Attack Agent: AI-powered (dynamic generation)")  
        print(" Detection Agent: AI-powered (cybersec-ai)")
        print(" Reasoning Agent: AI-powered (cybersec-ai)")
        print(" Playbook Engine: LLM-powered (cybersec-ai)")
        print(" Primary LLM: cybersec-ai (local)")
        print(" Fallback LLM: OpenAI (if configured)")
        print("="*60)
        print(" Your local cybersec-ai model is the brain of all agents!")
        print("="*60 + "\n")

def main():
    """Main entry point"""
    starter = AIAgentsStarter()
    
    # Show status
    starter.show_agent_status()
    
    # Start AI agents
    if starter.start_ai_agents():
        logger.info(" AI-Driven SOC agents started successfully!")
    else:
        logger.error(" Failed to start AI agents")
        sys.exit(1)

if __name__ == "__main__":
    main()
