"""
Adaptive Attack APIs - Production SOC Platform
Provides direct API access to adaptive attack orchestration
No hardcoded scenarios - everything is dynamic and network-aware
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timezone
import sqlite3
import json
import uuid
import asyncio
import sys
from pathlib import Path
from functools import wraps

# Import adaptive attack orchestrator
sys.path.append(str(Path(__file__).parent.parent.parent / "agents" / "attack_agent"))
from adaptive_attack_orchestrator import adaptive_orchestrator

adaptive_attacks_bp = Blueprint('adaptive_attacks', __name__)

def require_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({
                'success': False,
                'error': 'Missing or invalid Authorization header',
                'error_code': 'UNAUTHORIZED'
            }), 401
        return f(*args, **kwargs)
    return decorated_function

@adaptive_attacks_bp.route('/attack/generate-scenario', methods=['POST'])
@require_auth
def generate_attack_scenario():
    """
    POST /api/attack/generate-scenario
    Generate dynamic attack scenario based on current network topology
    """
    try:
        data = request.get_json() or {}
        
        # Get parameters
        prompt = data.get('prompt', 'Generate a realistic attack scenario for this network')
        attack_type = data.get('attack_type', 'apt')
        complexity = data.get('complexity', 'intermediate')
        force_refresh = data.get('force_refresh_network', False)
        
        # Run async scenario generation
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            # Get network context
            network_context = loop.run_until_complete(
                adaptive_orchestrator.get_network_context(force_refresh=force_refresh)
            )
            
            if network_context.total_agents == 0:
                return jsonify({
                    'success': False,
                    'error': 'No active agents found in network. Deploy client agents first.',
                    'error_code': 'NO_TARGETS',
                    'suggestion': 'Deploy codegrey-agent on target endpoints'
                }), 400
            
            # Generate scenario
            scenario = loop.run_until_complete(
                adaptive_orchestrator.generate_dynamic_scenario(prompt, network_context)
            )
            
        finally:
            loop.close()
        
        # Return scenario details
        return jsonify({
            'success': True,
            'scenario': {
                'id': scenario.id,
                'name': scenario.name,
                'description': scenario.description,
                'attack_type': scenario.attack_type,
                'complexity': scenario.complexity,
                'estimated_duration': scenario.estimated_duration,
                'target_elements': scenario.target_elements,
                'attack_path': scenario.attack_path,
                'mitre_techniques': scenario.mitre_techniques,
                'success_criteria': scenario.success_criteria,
                'risk_level': scenario.risk_level,
                'prerequisites': scenario.prerequisites,
                'confidence_score': scenario.confidence_score,
                'generated_at': scenario.generated_at
            },
            'network_context': {
                'total_agents': network_context.total_agents,
                'domain_controllers': len(network_context.domain_controllers),
                'endpoints': len(network_context.endpoints),
                'dmz_servers': len(network_context.dmz_servers),
                'security_zones': network_context.security_zones,
                'high_value_targets': len(network_context.high_value_targets)
            },
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Scenario generation failed: {str(e)}',
            'error_code': 'GENERATION_ERROR'
        }), 500

@adaptive_attacks_bp.route('/attack/execute', methods=['POST'])
@require_auth
def execute_attack_scenario():
    """
    POST /api/attack/execute
    Execute dynamic attack scenario
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'Request body is required',
                'error_code': 'MISSING_DATA'
            }), 400
        
        # Get parameters
        prompt = data.get('prompt')
        scenario_id = data.get('scenario_id')
        target_agents = data.get('target_agents', [])
        
        if not prompt and not scenario_id:
            return jsonify({
                'success': False,
                'error': 'Either "prompt" or "scenario_id" is required',
                'error_code': 'INVALID_PARAMETERS'
            }), 400
        
        # Run async execution
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            if prompt:
                # Generate and execute new scenario
                network_context = loop.run_until_complete(
                    adaptive_orchestrator.get_network_context()
                )
                
                if network_context.total_agents == 0:
                    return jsonify({
                        'success': False,
                        'error': 'No active agents found in network',
                        'error_code': 'NO_TARGETS'
                    }), 400
                
                # Generate scenario
                scenario = loop.run_until_complete(
                    adaptive_orchestrator.generate_dynamic_scenario(prompt, network_context)
                )
                
                # Execute scenario
                execution = loop.run_until_complete(
                    adaptive_orchestrator.execute_dynamic_scenario(scenario, target_agents)
                )
                
            else:
                # Execute existing scenario by ID
                # This would require storing scenarios, for now return error
                return jsonify({
                    'success': False,
                    'error': 'Execution by scenario_id not yet implemented. Use "prompt" instead.',
                    'error_code': 'NOT_IMPLEMENTED'
                }), 501
                
        finally:
            loop.close()
        
        # Return execution details
        return jsonify({
            'success': True,
            'execution': {
                'execution_id': execution.execution_id,
                'scenario_name': execution.scenario.name,
                'status': execution.status,
                'target_agents': execution.target_agents,
                'estimated_duration': execution.scenario.estimated_duration,
                'attack_path': execution.scenario.attack_path,
                'started_at': execution.started_at
            },
            'scenario': {
                'id': execution.scenario.id,
                'name': execution.scenario.name,
                'attack_type': execution.scenario.attack_type,
                'complexity': execution.scenario.complexity,
                'mitre_techniques': execution.scenario.mitre_techniques
            },
            'message': f'Attack scenario "{execution.scenario.name}" launched successfully',
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Attack execution failed: {str(e)}',
            'error_code': 'EXECUTION_ERROR'
        }), 500

@adaptive_attacks_bp.route('/attack/status/<execution_id>', methods=['GET'])
@require_auth
def get_execution_status(execution_id):
    """
    GET /api/attack/status/{execution_id}
    Get status of attack execution
    """
    try:
        status = adaptive_orchestrator.get_execution_status(execution_id)
        
        if not status:
            return jsonify({
                'success': False,
                'error': f'Execution {execution_id} not found',
                'error_code': 'NOT_FOUND'
            }), 404
        
        return jsonify({
            'success': True,
            'execution_status': status,
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Status query failed: {str(e)}',
            'error_code': 'QUERY_ERROR'
        }), 500

@adaptive_attacks_bp.route('/attack/active', methods=['GET'])
@require_auth
def list_active_executions():
    """
    GET /api/attack/active
    List all active attack executions
    """
    try:
        active_executions = adaptive_orchestrator.list_active_executions()
        
        return jsonify({
            'success': True,
            'active_executions': active_executions,
            'count': len(active_executions),
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Active executions query failed: {str(e)}',
            'error_code': 'QUERY_ERROR'
        }), 500

@adaptive_attacks_bp.route('/attack/stop/<execution_id>', methods=['POST'])
@require_auth
def stop_execution(execution_id):
    """
    POST /api/attack/stop/{execution_id}
    Stop running attack execution
    """
    try:
        # Run async stop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            success = loop.run_until_complete(
                adaptive_orchestrator.stop_execution(execution_id)
            )
        finally:
            loop.close()
        
        if success:
            return jsonify({
                'success': True,
                'message': f'Execution {execution_id} stopped successfully',
                'execution_id': execution_id,
                'timestamp': datetime.now(timezone.utc).isoformat()
            })
        else:
            return jsonify({
                'success': False,
                'error': f'Could not stop execution {execution_id}. It may not exist or already be completed.',
                'error_code': 'STOP_FAILED'
            }), 400
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Stop execution failed: {str(e)}',
            'error_code': 'STOP_ERROR'
        }), 500

@adaptive_attacks_bp.route('/network/context', methods=['GET'])
@require_auth
def get_network_context():
    """
    GET /api/network/context
    Get current network context for attack planning
    """
    try:
        force_refresh = request.args.get('force_refresh', 'false').lower() == 'true'
        
        # Run async network scan
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            network_context = loop.run_until_complete(
                adaptive_orchestrator.get_network_context(force_refresh=force_refresh)
            )
        finally:
            loop.close()
        
        return jsonify({
            'success': True,
            'network_context': {
                'total_agents': network_context.total_agents,
                'domain_controllers': len(network_context.domain_controllers),
                'endpoints': len(network_context.endpoints),
                'dmz_servers': len(network_context.dmz_servers),
                'firewalls': len(network_context.firewalls),
                'soc_systems': len(network_context.soc_systems),
                'cloud_resources': len(network_context.cloud_resources),
                'security_zones': network_context.security_zones,
                'high_value_targets': len(network_context.high_value_targets),
                'attack_paths': len(network_context.attack_paths)
            },
            'high_value_targets': [
                {
                    'id': hvt.get('id'),
                    'hostname': hvt.get('hostname'),
                    'network_element_type': hvt.get('network_element_type'),
                    'security_zone': hvt.get('security_zone'),
                    'ip_address': hvt.get('ip_address')
                }
                for hvt in network_context.high_value_targets[:10]  # Limit to 10
            ],
            'attack_paths': [
                {
                    'path_id': i,
                    'agents': path,
                    'length': len(path)
                }
                for i, path in enumerate(network_context.attack_paths[:5])  # Limit to 5
            ],
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Network context query failed: {str(e)}',
            'error_code': 'CONTEXT_ERROR'
        }), 500

@adaptive_attacks_bp.route('/attack/techniques/<technique_id>', methods=['POST'])
@require_auth
def generate_technique_commands(technique_id):
    """
    POST /api/attack/techniques/{technique_id}
    Generate commands for specific MITRE ATT&CK technique
    """
    try:
        data = request.get_json() or {}
        platform = data.get('platform', 'any')
        
        # This would integrate with your dynamic attack generator
        # For now, return a placeholder response
        
        return jsonify({
            'success': True,
            'technique_id': technique_id,
            'platform': platform,
            'commands': [
                {
                    'command': f'Simulated command for {technique_id} on {platform}',
                    'command_type': 'powershell' if platform == 'windows' else 'bash',
                    'risk_level': 'medium',
                    'source': 'cybersec_ai',
                    'confidence': 0.85
                }
            ],
            'message': 'Command generation feature coming soon - integrate with dynamic_attack_generator.py',
            'timestamp': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Command generation failed: {str(e)}',
            'error_code': 'GENERATION_ERROR'
        }), 500
