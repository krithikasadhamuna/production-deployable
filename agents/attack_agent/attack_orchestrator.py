#!/usr/bin/env python3
"""
Attack Orchestrator - AI-Driven Attack Simulation
Orchestrates attack scenarios using AI agents and playbooks
"""

import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from .playbook_engine import PlaybookEngine
from .dynamic_attack_generator import DynamicAttackGenerator

logger = logging.getLogger(__name__)

class AttackOrchestrator:
    """Orchestrates AI-driven attack scenarios"""
    
    def __init__(self):
        self.playbook_engine = PlaybookEngine()
        self.attack_generator = DynamicAttackGenerator()
        self.active_scenarios = {}
        logger.info("🎯 Attack Orchestrator initialized with AI agents")
    
    def list_scenarios(self) -> List[Dict]:
        """List available attack scenarios"""
        return [
            {
                "id": "scenario-001",
                "name": "APT29 Advanced Persistent Threat",
                "description": "Multi-stage APT simulation with AI-driven tactics",
                "difficulty": "Advanced",
                "duration": "120 minutes",
                "techniques": ["T1566.001", "T1059.001", "T1105", "T1071.004"]
            },
            {
                "id": "scenario-002", 
                "name": "Ransomware Attack Chain",
                "description": "Complete ransomware deployment simulation",
                "difficulty": "Intermediate",
                "duration": "60 minutes",
                "techniques": ["T1566.001", "T1204.002", "T1486", "T1490"]
            },
            {
                "id": "scenario-003",
                "name": "Insider Threat Simulation", 
                "description": "Privilege escalation and data exfiltration",
                "difficulty": "Beginner",
                "duration": "45 minutes",
                "techniques": ["T1078", "T1083", "T1041", "T1020"]
            }
        ]
    
    def execute_scenario(self, scenario_id: str, target_agent_id: str) -> Dict:
        """Execute attack scenario against target agent"""
        try:
            scenarios = {s["id"]: s for s in self.list_scenarios()}
            
            if scenario_id not in scenarios:
                return {"error": "Scenario not found", "scenario_id": scenario_id}
            
            scenario = scenarios[scenario_id]
            
            # Generate dynamic attack based on scenario
            attack_plan = self.attack_generator.generate_attack_sequence(
                scenario["techniques"],
                target_agent_id
            )
            
            # Execute using playbook engine
            execution_result = self.playbook_engine.execute_playbook(
                scenario_id,
                attack_plan,
                target_agent_id
            )
            
            # Track active scenario
            self.active_scenarios[scenario_id] = {
                "scenario": scenario,
                "target": target_agent_id,
                "status": "executing",
                "started": datetime.now().isoformat(),
                "plan": attack_plan,
                "results": execution_result
            }
            
            logger.info(f"🎯 Executing scenario {scenario_id} against {target_agent_id}")
            
            return {
                "status": "success",
                "scenario_id": scenario_id,
                "target_agent_id": target_agent_id,
                "execution_id": f"exec_{scenario_id}_{target_agent_id}",
                "estimated_duration": scenario["duration"],
                "techniques": scenario["techniques"],
                "message": f"Attack scenario '{scenario['name']}' initiated"
            }
            
        except Exception as e:
            logger.error(f"❌ Scenario execution failed: {e}")
            return {
                "status": "error",
                "error": str(e),
                "scenario_id": scenario_id
            }
    
    def get_scenario_status(self, scenario_id: str) -> Dict:
        """Get status of running scenario"""
        if scenario_id in self.active_scenarios:
            return self.active_scenarios[scenario_id]
        else:
            return {"status": "not_found", "scenario_id": scenario_id}
    
    def stop_scenario(self, scenario_id: str) -> Dict:
        """Stop running scenario"""
        if scenario_id in self.active_scenarios:
            self.active_scenarios[scenario_id]["status"] = "stopped"
            self.active_scenarios[scenario_id]["stopped"] = datetime.now().isoformat()
            
            return {
                "status": "stopped",
                "scenario_id": scenario_id,
                "message": "Attack scenario stopped"
            }
        else:
            return {"status": "not_found", "scenario_id": scenario_id}


