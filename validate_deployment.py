#!/usr/bin/env python3
"""
SOC Platform Production Validation Script
Performs comprehensive checks to ensure deployment readiness
"""

import os
import sys
import json
import sqlite3
from pathlib import Path
import subprocess

# Colors for output
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
RESET = '\033[0m'

def print_header():
    print(f"""
{BLUE}═══════════════════════════════════════════════════════════════
    SOC PLATFORM PRODUCTION VALIDATION
    Comprehensive Deployment Readiness Check
═══════════════════════════════════════════════════════════════{RESET}
    """)

def check_mark(status):
    return f"{GREEN}✓{RESET}" if status else f"{RED}✗{RESET}"

class DeploymentValidator:
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.errors = []
        self.warnings = []
        self.checks_passed = 0
        self.checks_failed = 0
        
    def validate_all(self):
        """Run all validation checks"""
        print_header()
        
        # Core structure checks
        print(f"\n{BLUE}[1/8] Checking Core Directory Structure...{RESET}")
        self.check_directory_structure()
        
        # LLM configuration checks
        print(f"\n{BLUE}[2/8] Validating LLM Configuration...{RESET}")
        self.check_llm_configuration()
        
        # Database schema checks
        print(f"\n{BLUE}[3/8] Checking Database Schemas...{RESET}")
        self.check_database_schemas()
        
        # API endpoints checks
        print(f"\n{BLUE}[4/8] Validating API Endpoints...{RESET}")
        self.check_api_endpoints()
        
        # Client agent checks
        print(f"\n{BLUE}[5/8] Checking Client Agents...{RESET}")
        self.check_client_agents()
        
        # ML models checks
        print(f"\n{BLUE}[6/8] Verifying ML Models...{RESET}")
        self.check_ml_models()
        
        # Dependencies checks
        print(f"\n{BLUE}[7/8] Checking Dependencies...{RESET}")
        self.check_dependencies()
        
        # Configuration files
        print(f"\n{BLUE}[8/8] Validating Configuration Files...{RESET}")
        self.check_configuration_files()
        
        # Print summary
        self.print_summary()
        
    def check_directory_structure(self):
        """Verify all required directories exist"""
        required_dirs = [
            'flask_api',
            'flask_api/routes',
            'flask_api/core',
            'agents',
            'agents/attack_agent',
            'agents/detection_agent',
            'agents/langgraph',
            'agents/langgraph/tools',
            'agents/langgraph/workflows',
            'agents/langgraph/prompts',
            'client_installers',
            'client_installers/windows',
            'client_installers/linux',
            'client_installers/macos',
            'ml_models',
            'certificates',
            'tenant_databases',
            'checkpoints',
            'golden_images',
            'logs'
        ]
        
        for dir_path in required_dirs:
            full_path = self.base_dir / dir_path
            if full_path.exists():
                print(f"  {check_mark(True)} {dir_path}")
                self.checks_passed += 1
            else:
                print(f"  {check_mark(False)} {dir_path} - MISSING")
                self.errors.append(f"Missing directory: {dir_path}")
                self.checks_failed += 1
                # Create missing directory
                full_path.mkdir(parents=True, exist_ok=True)
                print(f"    {YELLOW}→ Created missing directory{RESET}")
    
    def check_llm_configuration(self):
        """Verify LLM is configured to use cybersec-ai"""
        llm_files = [
            'agents/langgraph/tools/llm_manager.py',
            'agents/attack_agent/ai_attacker_brain.py',
            'agents/detection_agent/ai_threat_analyzer.py'
        ]
        
        for file_path in llm_files:
            full_path = self.base_dir / file_path
            if full_path.exists():
                content = full_path.read_text(encoding='utf-8')
                if 'cybersec-ai' in content:
                    print(f"  {check_mark(True)} {file_path} - Uses cybersec-ai")
                    self.checks_passed += 1
                else:
                    print(f"  {check_mark(False)} {file_path} - Not using cybersec-ai")
                    self.warnings.append(f"LLM not configured in: {file_path}")
                    self.checks_failed += 1
            else:
                print(f"  {check_mark(False)} {file_path} - File missing")
                self.errors.append(f"Missing file: {file_path}")
                self.checks_failed += 1
        
        # Check for CyberSecAI model files
        model_file = self.base_dir / 'ml_models' / 'CyberSecAI.modelfile'
        kb_file = self.base_dir / 'ml_models' / 'cybersecurity_knowledge_base.json'
        
        if model_file.exists():
            print(f"  {check_mark(True)} CyberSecAI.modelfile present")
            self.checks_passed += 1
        else:
            print(f"  {check_mark(False)} CyberSecAI.modelfile missing")
            self.errors.append("CyberSecAI model file missing")
            self.checks_failed += 1
            
        if kb_file.exists():
            print(f"  {check_mark(True)} Cybersecurity knowledge base present")
            self.checks_passed += 1
        else:
            print(f"  {check_mark(False)} Knowledge base missing")
            self.warnings.append("Cybersecurity knowledge base missing")
            self.checks_failed += 1
    
    def check_database_schemas(self):
        """Verify database tables are properly defined"""
        required_tables = [
            'users',
            'agents',
            'software_downloads',
            'agent_api_keys',
            'attack_scenarios',
            'detections',
            'network_topology'
        ]
        
        # Check in app.py for table definitions
        app_file = self.base_dir / 'flask_api' / 'app.py'
        if app_file.exists():
            content = app_file.read_text(encoding='utf-8')
            for table in required_tables:
                if f'CREATE TABLE IF NOT EXISTS {table}' in content:
                    print(f"  {check_mark(True)} Table '{table}' defined")
                    self.checks_passed += 1
                else:
                    # Check in routes
                    found = False
                    routes_dir = self.base_dir / 'flask_api' / 'routes'
                    for route_file in routes_dir.glob('*.py'):
                        if f'CREATE TABLE IF NOT EXISTS {table}' in route_file.read_text(encoding='utf-8'):
                            found = True
                            break
                    
                    if found:
                        print(f"  {check_mark(True)} Table '{table}' defined in routes")
                        self.checks_passed += 1
                    else:
                        print(f"  {check_mark(False)} Table '{table}' not defined")
                        self.warnings.append(f"Table '{table}' definition not found")
                        self.checks_failed += 1
        else:
            print(f"  {check_mark(False)} app.py missing")
            self.errors.append("flask_api/app.py missing")
            self.checks_failed += 1
    
    def check_api_endpoints(self):
        """Verify critical API endpoints are defined"""
        critical_endpoints = [
            ('/api/software-download', 'frontend_apis.py'),
            ('/agents/register', 'agent_communication.py'),
            ('/agents/<agent_id>/heartbeat', 'agent_communication.py'),
            ('/api/agents', 'frontend_apis.py'),
            ('/api/network-topology', 'frontend_apis.py')
        ]
        
        for endpoint, file_name in critical_endpoints:
            file_path = self.base_dir / 'flask_api' / 'routes' / file_name
            if file_path.exists():
                content = file_path.read_text(encoding='utf-8')
                # Simplify endpoint pattern for checking
                endpoint_pattern = endpoint.replace('<', '').replace('>', '')
                if endpoint_pattern in content:
                    print(f"  {check_mark(True)} {endpoint} in {file_name}")
                    self.checks_passed += 1
                else:
                    print(f"  {check_mark(False)} {endpoint} not found in {file_name}")
                    self.warnings.append(f"Endpoint {endpoint} not found")
                    self.checks_failed += 1
            else:
                print(f"  {check_mark(False)} {file_name} missing")
                self.errors.append(f"Route file missing: {file_name}")
                self.checks_failed += 1
    
    def check_client_agents(self):
        """Verify client agents are present and configured"""
        agents = [
            ('windows/windows_agent.py', 'Windows Agent'),
            ('linux/linux_agent.py', 'Linux Agent'),
            ('macos/macos_agent.py', 'macOS Agent')
        ]
        
        for agent_path, agent_name in agents:
            full_path = self.base_dir / 'client_installers' / agent_path
            if full_path.exists():
                content = full_path.read_text(encoding='utf-8')
                # Check for deployment key support
                if 'soc-dep-' in content or 'load_config' in content:
                    print(f"  {check_mark(True)} {agent_name} - Deployment keys supported")
                    self.checks_passed += 1
                else:
                    print(f"  {check_mark(False)} {agent_name} - No deployment key support")
                    self.warnings.append(f"{agent_name} lacks deployment key support")
                    self.checks_failed += 1
                    
                # Check for correct server URL
                if 'dev.codegrey.ai' in content:
                    print(f"  {check_mark(True)} {agent_name} - Correct server URL")
                    self.checks_passed += 1
                else:
                    print(f"  {check_mark(False)} {agent_name} - Incorrect server URL")
                    self.warnings.append(f"{agent_name} has incorrect server URL")
                    self.checks_failed += 1
            else:
                print(f"  {check_mark(False)} {agent_name} missing")
                self.errors.append(f"{agent_name} file missing")
                self.checks_failed += 1
    
    def check_ml_models(self):
        """Verify ML models are present"""
        required_models = [
            'anomaly_detector.joblib',
            'feature_scaler.joblib',
            'text_vectorizer.joblib',
            'CyberSecAI.modelfile'
        ]
        
        ml_dir = self.base_dir / 'ml_models'
        for model in required_models:
            model_path = ml_dir / model
            if not model_path.exists():
                # Check in trained_models subdirectory
                model_path = ml_dir / 'trained_models' / model
            
            if model_path.exists():
                print(f"  {check_mark(True)} {model}")
                self.checks_passed += 1
            else:
                print(f"  {check_mark(False)} {model} - Missing")
                if model == 'CyberSecAI.modelfile':
                    self.errors.append(f"Critical model missing: {model}")
                else:
                    self.warnings.append(f"ML model missing: {model}")
                self.checks_failed += 1
    
    def check_dependencies(self):
        """Verify requirements file is complete"""
        req_file = self.base_dir / 'requirements_complete.txt'
        if req_file.exists():
            content = req_file.read_text(encoding='utf-8')
            critical_packages = [
                'flask',
                'flask-cors',
                'langgraph',
                'langchain',
                'langchain-community',
                'scikit-learn',
                'numpy',
                'pandas',
                'psutil',
                'requests'
            ]
            
            for package in critical_packages:
                if package in content:
                    print(f"  {check_mark(True)} {package}")
                    self.checks_passed += 1
                else:
                    print(f"  {check_mark(False)} {package} - Not in requirements")
                    self.errors.append(f"Missing dependency: {package}")
                    self.checks_failed += 1
        else:
            print(f"  {check_mark(False)} requirements_complete.txt missing")
            self.errors.append("requirements_complete.txt missing")
            self.checks_failed += 1
    
    def check_configuration_files(self):
        """Check for critical configuration files"""
        config_files = [
            ('start_production_server.py', 'Production startup script'),
            ('setup_cybersec_ai.sh', 'CyberSecAI setup script'),
            ('production.conf', 'Production configuration')
        ]
        
        for file_name, description in config_files:
            file_path = self.base_dir / file_name
            if file_path.exists():
                content = file_path.read_text(encoding='utf-8') if file_path.suffix == '.py' else ''
                if file_name == 'start_production_server.py' and 'dev.codegrey.ai' in content:
                    print(f"  {check_mark(True)} {description} - Configured for dev.codegrey.ai")
                else:
                    print(f"  {check_mark(True)} {description}")
                self.checks_passed += 1
            else:
                print(f"  {check_mark(False)} {description} - Missing")
                if file_name == 'start_production_server.py':
                    self.errors.append(f"Critical file missing: {file_name}")
                else:
                    self.warnings.append(f"Configuration file missing: {file_name}")
                self.checks_failed += 1
    
    def print_summary(self):
        """Print validation summary"""
        print(f"\n{BLUE}═══════════════════════════════════════════════════════════════{RESET}")
        print(f"{BLUE}VALIDATION SUMMARY{RESET}")
        print(f"{BLUE}═══════════════════════════════════════════════════════════════{RESET}\n")
        
        total_checks = self.checks_passed + self.checks_failed
        success_rate = (self.checks_passed / total_checks * 100) if total_checks > 0 else 0
        
        print(f"Total Checks: {total_checks}")
        print(f"Passed: {GREEN}{self.checks_passed}{RESET}")
        print(f"Failed: {RED}{self.checks_failed}{RESET}")
        print(f"Success Rate: {GREEN if success_rate >= 80 else YELLOW if success_rate >= 60 else RED}{success_rate:.1f}%{RESET}")
        
        if self.errors:
            print(f"\n{RED}CRITICAL ERRORS ({len(self.errors)}):{RESET}")
            for error in self.errors:
                print(f"  • {error}")
        
        if self.warnings:
            print(f"\n{YELLOW}WARNINGS ({len(self.warnings)}):{RESET}")
            for warning in self.warnings:
                print(f"  • {warning}")
        
        # Final verdict
        print(f"\n{BLUE}═══════════════════════════════════════════════════════════════{RESET}")
        if not self.errors and len(self.warnings) < 3:
            print(f"{GREEN}✅ DEPLOYMENT READY!{RESET}")
            print("The SOC platform is ready for production deployment.")
        elif not self.errors:
            print(f"{YELLOW}⚠️  DEPLOYMENT READY WITH WARNINGS{RESET}")
            print("The SOC platform can be deployed but review warnings.")
        else:
            print(f"{RED}❌ NOT READY FOR DEPLOYMENT{RESET}")
            print("Critical issues must be resolved before deployment.")
        print(f"{BLUE}═══════════════════════════════════════════════════════════════{RESET}")
        
        return 0 if not self.errors else 1

if __name__ == "__main__":
    validator = DeploymentValidator()
    sys.exit(validator.validate_all())
