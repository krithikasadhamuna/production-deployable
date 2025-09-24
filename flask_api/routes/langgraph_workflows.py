#!/usr/bin/env python3
"""
LangGraph Workflow API Routes
RESTful endpoints for LangGraph-powered SOC workflows
"""

from flask import Blueprint, request, jsonify
import asyncio
import logging
from datetime import datetime
from typing import Dict, Any

# Import LangGraph agents
try:
    from agents.attack_agent.langgraph_attack_agent import langgraph_attack_agent
    from agents.detection_agent.langgraph_detection_agent import langgraph_detection_agent
    LANGGRAPH_AVAILABLE = True
except ImportError as e:
    logging.warning(f"LangGraph agents not available: {e}")
    LANGGRAPH_AVAILABLE = False

logger = logging.getLogger(__name__)

# Create blueprint
langgraph_workflows_bp = Blueprint('langgraph_workflows', __name__)

@langgraph_workflows_bp.route('/workflows/attack/execute', methods=['POST'])
def execute_attack_workflow():
    """Execute LangGraph attack workflow"""
    
    if not LANGGRAPH_AVAILABLE:
        return jsonify({
            'success': False,
            'error': 'LangGraph agents not available',
            'message': 'Install: pip install langgraph==0.2.45'
        }), 503
    
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['scenario', 'target_agents']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'success': False,
                    'error': f'Missing required field: {field}'
                }), 400
        
        scenario = data['scenario']
        target_agents = data['target_agents']
        user_id = data.get('user_id', 'api-user')
        organization_id = data.get('organization_id', 'org-123')
        
        # Execute workflow asynchronously
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(
                langgraph_attack_agent.execute_attack_workflow(
                    scenario, target_agents, user_id, organization_id
                )
            )
        finally:
            loop.close()
        
        return jsonify({
            'success': True,
            'workflow_type': 'langgraph_attack',
            'result': result,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Attack workflow execution failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'workflow_type': 'langgraph_attack'
        }), 500

@langgraph_workflows_bp.route('/workflows/attack/resume', methods=['POST'])
def resume_attack_workflow():
    """Resume paused attack workflow"""
    
    if not LANGGRAPH_AVAILABLE:
        return jsonify({
            'success': False,
            'error': 'LangGraph agents not available'
        }), 503
    
    try:
        data = request.get_json()
        
        if 'thread_id' not in data:
            return jsonify({
                'success': False,
                'error': 'Missing required field: thread_id'
            }), 400
        
        thread_id = data['thread_id']
        human_input = data.get('human_input')
        
        # Resume workflow
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(
                langgraph_attack_agent.resume_attack_workflow(thread_id, human_input)
            )
        finally:
            loop.close()
        
        return jsonify({
            'success': True,
            'workflow_type': 'langgraph_attack_resume',
            'result': result,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Attack workflow resume failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'workflow_type': 'langgraph_attack_resume'
        }), 500

@langgraph_workflows_bp.route('/workflows/detection/execute', methods=['POST'])
def execute_detection_workflow():
    """Execute LangGraph detection workflow"""
    
    if not LANGGRAPH_AVAILABLE:
        return jsonify({
            'success': False,
            'error': 'LangGraph agents not available',
            'message': 'Install: pip install langgraph==0.2.45'
        }), 503
    
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['agent_data', 'agent_id']
        for field in required_fields:
            if field not in data:
                return jsonify({
                    'success': False,
                    'error': f'Missing required field: {field}'
                }), 400
        
        agent_data = data['agent_data']
        agent_id = data['agent_id']
        organization_id = data.get('organization_id', 'org-123')
        
        # Execute workflow asynchronously
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(
                langgraph_detection_agent.execute_detection_workflow(
                    agent_data, agent_id, organization_id
                )
            )
        finally:
            loop.close()
        
        return jsonify({
            'success': True,
            'workflow_type': 'langgraph_detection',
            'result': result,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Detection workflow execution failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'workflow_type': 'langgraph_detection'
        }), 500

@langgraph_workflows_bp.route('/workflows/detection/resume', methods=['POST'])
def resume_detection_workflow():
    """Resume paused detection workflow"""
    
    if not LANGGRAPH_AVAILABLE:
        return jsonify({
            'success': False,
            'error': 'LangGraph agents not available'
        }), 503
    
    try:
        data = request.get_json()
        
        if 'thread_id' not in data:
            return jsonify({
                'success': False,
                'error': 'Missing required field: thread_id'
            }), 400
        
        thread_id = data['thread_id']
        human_input = data.get('human_input')
        
        # Resume workflow
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(
                langgraph_detection_agent.resume_detection_workflow(thread_id, human_input)
            )
        finally:
            loop.close()
        
        return jsonify({
            'success': True,
            'workflow_type': 'langgraph_detection_resume',
            'result': result,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Detection workflow resume failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'workflow_type': 'langgraph_detection_resume'
        }), 500

@langgraph_workflows_bp.route('/workflows/status', methods=['GET'])
def get_workflows_status():
    """Get LangGraph workflows status"""
    
    try:
        status = {
            'langgraph_available': LANGGRAPH_AVAILABLE,
            'timestamp': datetime.now().isoformat()
        }
        
        if LANGGRAPH_AVAILABLE:
            # Add more detailed status
            status.update({
                'attack_agent': {
                    'available': True,
                    'workflow_type': 'stateful_graph',
                    'features': [
                        'multi_step_execution',
                        'human_approval_gates',
                        'checkpoint_recovery',
                        'adaptive_routing'
                    ]
                },
                'detection_agent': {
                    'available': True,
                    'workflow_type': 'stateful_graph',
                    'features': [
                        'ml_and_ai_analysis',
                        'threat_correlation',
                        'human_review_gates',
                        'auto_response'
                    ]
                }
            })
        else:
            status.update({
                'error': 'LangGraph not available',
                'install_command': 'pip install langgraph==0.2.45 langgraph-checkpoint==2.0.2 langgraph-checkpoint-sqlite==2.0.1'
            })
        
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"Status check failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@langgraph_workflows_bp.route('/workflows/health', methods=['GET'])
def health_check():
    """Health check for LangGraph workflows"""
    
    try:
        health_status = {
            'status': 'healthy',
            'langgraph_available': LANGGRAPH_AVAILABLE,
            'timestamp': datetime.now().isoformat(),
            'checks': {}
        }
        
        if LANGGRAPH_AVAILABLE:
            # Test basic imports
            try:
                from langgraph.graph import StateGraph
                health_status['checks']['langgraph_core'] = 'healthy'
            except Exception as e:
                health_status['checks']['langgraph_core'] = f'unhealthy: {e}'
                health_status['status'] = 'degraded'
            
            try:
                from langgraph.checkpoint.sqlite import SqliteSaver
                health_status['checks']['sqlite_checkpointer'] = 'healthy'
            except Exception as e:
                health_status['checks']['sqlite_checkpointer'] = f'unhealthy: {e}'
                health_status['status'] = 'degraded'
            
            try:
                from langchain_community.chat_models import ChatOllama
                health_status['checks']['chat_ollama'] = 'healthy'
            except Exception as e:
                health_status['checks']['chat_ollama'] = f'unhealthy: {e}'
                health_status['status'] = 'degraded'
        
        else:
            health_status['status'] = 'unhealthy'
            health_status['checks']['langgraph'] = 'not_installed'
        
        status_code = 200 if health_status['status'] == 'healthy' else 503
        
        return jsonify(health_status), status_code
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@langgraph_workflows_bp.route('/workflows/examples', methods=['GET'])
def get_workflow_examples():
    """Get example workflow requests"""
    
    examples = {
        'attack_workflow_example': {
            'endpoint': '/api/workflows/attack/execute',
            'method': 'POST',
            'payload': {
                'scenario': {
                    'name': 'Advanced Persistent Threat Simulation',
                    'objective': 'credential_harvesting',
                    'type': 'apt',
                    'description': 'Multi-phase APT attack with AI adaptation'
                },
                'target_agents': ['agent-windows-001', 'agent-linux-002'],
                'user_id': 'security-analyst',
                'organization_id': 'org-123'
            }
        },
        'attack_resume_example': {
            'endpoint': '/api/workflows/attack/resume',
            'method': 'POST',
            'payload': {
                'thread_id': 'attack-security-analyst-1727164800',
                'human_input': 'approve - proceed with attack execution'
            }
        },
        'detection_workflow_example': {
            'endpoint': '/api/workflows/detection/execute',
            'method': 'POST',
            'payload': {
                'agent_data': {
                    'processes': [
                        {
                            'name': 'powershell.exe',
                            'cmdline': 'powershell.exe -encodedcommand dwhoami',
                            'cpu_percent': 25.5,
                            'memory_percent': 8.2,
                            'username': 'SYSTEM'
                        }
                    ],
                    'files': [
                        {
                            'path': 'C:\\temp\\suspicious.exe',
                            'hash': 'd41d8cd98f00b204e9800998ecf8427e',
                            'size': 2048,
                            'action': 'created'
                        }
                    ]
                },
                'agent_id': 'agent-test-001',
                'organization_id': 'org-123'
            }
        },
        'detection_resume_example': {
            'endpoint': '/api/workflows/detection/resume',
            'method': 'POST',
            'payload': {
                'thread_id': 'detection-agent-test-001-1727164800',
                'human_input': 'escalate - confirmed threat, initiate incident response'
            }
        }
    }
    
    return jsonify({
        'success': True,
        'examples': examples,
        'langgraph_features': [
            'Stateful multi-step workflows',
            'Human-in-the-loop approval gates',
            'Automatic checkpoint recovery',
            'Persistent conversation history',
            'Graph-based execution flow',
            'Conditional routing and loops'
        ],
        'timestamp': datetime.now().isoformat()
    })

# Error handlers
@langgraph_workflows_bp.errorhandler(404)
def not_found(error):
    return jsonify({
        'success': False,
        'error': 'Endpoint not found',
        'available_endpoints': [
            '/workflows/attack/execute',
            '/workflows/attack/resume',
            '/workflows/detection/execute',
            '/workflows/detection/resume',
            '/workflows/status',
            '/workflows/health',
            '/workflows/examples'
        ]
    }), 404

@langgraph_workflows_bp.errorhandler(500)
def internal_error(error):
    return jsonify({
        'success': False,
        'error': 'Internal server error',
        'message': 'Check server logs for details'
    }), 500
