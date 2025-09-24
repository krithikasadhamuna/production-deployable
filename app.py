#!/usr/bin/env python3
"""
CodeGrey SOC - Production Server
Main application entry point for production deployment with integrated AI agents
"""

import os
import sys
import logging
from datetime import datetime
import threading
import time
import yaml

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import our multi-tenant API
from api.multi_tenant_api import app, logger

# Import core AI agent engines
from agents.attack_agent.attack_orchestrator import AttackOrchestrator
from agents.detection_agent.detection_pipeline import DetectionPipeline
from agents.ai_reasoning_agent.reasoning_engine import ReasoningEngine
from agents.multi_tenant_agent_manager import MultiTenantAgentManager

# Global agent instances
attack_orchestrator = None
detection_pipeline = None
reasoning_engine = None
agent_manager = None

CONFIG_PATH = os.getenv('SOC_CONFIG_PATH', 'config/config.yaml')

def load_config():
    with open(CONFIG_PATH, 'r') as f:
        return yaml.safe_load(f)

config = load_config()

# Pass config to all core modules
# Example: attack_orchestrator = AttackOrchestrator(config=config)
#          detection_pipeline = DetectionPipeline(config=config)
#          reasoning_engine = ReasoningEngine(config=config)
#          agent_manager = MultiTenantAgentManager(config=config)

# Update LLM selection logic in ReasoningEngine and DetectionPipeline to use config['llm']
# Example:
#   llm_provider = config['llm']['provider']
#   if llm_provider == 'ollama':
#       use Ollama endpoint
#   elif llm_provider == 'openai':
#       use OpenAI API
#   ...
#   fallback_order = config['llm'].get('fallback_order', ['ollama', 'openai'])

def setup_production_logging():
    """Setup production logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/soc_server.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )

def ensure_directories():
    """Ensure required directories exist"""
    directories = ['logs', 'database']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)

def initialize_agent_engines():
    """Initialize all core AI agent engines"""
    global attack_orchestrator, detection_pipeline, reasoning_engine, agent_manager
    
    try:
        logger.info(" Initializing Core AI Agent Engines...")
        
        # Initialize Multi-tenant Agent Manager
        logger.info("    Starting Multi-Tenant Agent Manager...")
        agent_manager = MultiTenantAgentManager()
        
        # Initialize Attack Agent
        logger.info("    Starting Attack Orchestrator...")
        attack_orchestrator = AttackOrchestrator()
        
        # Initialize Detection Agent
        logger.info("    Starting Detection Pipeline...")
        detection_pipeline = DetectionPipeline()
        
        # Initialize AI Reasoning Engine
        logger.info("   Starting AI Reasoning Engine...")
        reasoning_engine = ReasoningEngine()
        
        logger.info(" All AI Agent Engines initialized successfully!")
        
        # Start background agent processes
        start_agent_background_processes()
        
    except Exception as e:
        logger.error(f" Failed to initialize agent engines: {e}")
        raise

def start_agent_background_processes():
    """Start background processes for continuous agent operations"""
    
    def detection_monitoring():
        """Background thread for continuous detection monitoring"""
        logger.info(" Detection monitoring thread started")
        while True:
            try:
                if detection_pipeline:
                    detection_pipeline.process_real_time_logs()
                time.sleep(10)  # Process every 10 seconds
            except Exception as e:
                logger.error(f"Detection monitoring error: {e}")
                time.sleep(30)  # Wait longer on error
    
    def reasoning_analysis():
        """Background thread for AI reasoning analysis"""
        logger.info(" AI reasoning analysis thread started")
        while True:
            try:
                if reasoning_engine:
                    reasoning_engine.analyze_security_posture()
                time.sleep(60)  # Analyze every minute
            except Exception as e:
                logger.error(f"Reasoning analysis error: {e}")
                time.sleep(120)  # Wait longer on error
    
    # Start background threads
    detection_thread = threading.Thread(target=detection_monitoring, daemon=True)
    reasoning_thread = threading.Thread(target=reasoning_analysis, daemon=True)
    
    detection_thread.start()
    reasoning_thread.start()
    
    logger.info(" Background agent processes started")

if __name__ == '__main__':
    # Setup production environment
    ensure_directories()
    setup_production_logging()
    
    logger.info("=" * 80)
    logger.info("🚀 CodeGrey SOC Server - Production Mode with AI Agents")
    logger.info("=" * 80)
    logger.info(f"Started at: {datetime.now().isoformat()}")
    logger.info(f"Python version: {sys.version}")
    logger.info(f"Working directory: {os.getcwd()}")
    
    # Initialize all AI agent engines first
    try:
        initialize_agent_engines()
    except Exception as e:
        logger.error(f"Failed to initialize AI agents: {e}")
        sys.exit(1)
    
    # Get configuration from environment variables
    host = os.getenv('SOC_HOST', '0.0.0.0')
    port = int(os.getenv('SOC_PORT', '443'))
    debug = os.getenv('SOC_DEBUG', 'false').lower() == 'true'
    
    logger.info(f"Server configuration:")
    logger.info(f"  Host: {host}")
    logger.info(f"  Port: {port}")
    logger.info(f"  Debug: {debug}")
    logger.info("")
    
    logger.info(" Core SOC Components Active:")
    logger.info("    Attack Orchestrator - Ready for scenario execution")
    logger.info("   Detection Pipeline - Monitoring for threats")
    logger.info("   AI Reasoning Engine - Analyzing security posture")
    logger.info("   Multi-Tenant Manager - Managing agent fleet")
    logger.info("")
    
    try:
        # Start the Flask application with all AI agents running
        app.run(
            host=host,
            port=port,
            debug=debug,
            threaded=True
        )
    except KeyboardInterrupt:
        logger.info("Server shutdown requested by user")
        logger.info(" Stopping AI agent engines...")
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)
