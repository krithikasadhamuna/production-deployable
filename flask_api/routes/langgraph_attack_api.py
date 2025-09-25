"""
Flask API for LangGraph-based Attack Agent
RESTful endpoints for the complete attack workflow
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timezone
import json
import asyncio
import logging
import uuid

# Import LangGraph workflow
try:
    from agents.langgraph.workflows.attack_workflow import attack_workflow, AttackWorkflow
    from agents.langgraph.tools.llm_manager import llm_manager
    from agents.langgraph.prompts.attack_prompts import attack_prompts
    LANGGRAPH_AVAILABLE = True
except ImportError as e:
    logging.warning(f"LangGraph attack workflow not available: {e}")
    LANGGRAPH_AVAILABLE = False

logger = logging.getLogger(__name__)
langgraph_attack_bp = Blueprint('langgraph_attack', __name__)

# Store active workflows
active_workflows = {}

@langgraph_attack_bp.route('/langgraph/attack/start', methods=['POST'])
def start_attack_workflow():
    """
    POST /api/langgraph/attack/start
    Start a new LangGraph attack workflow
    
    Request body:
    {
        "user_request": "Execute DNS tunneling attack on critical systems",
        "scenario_type": "stealth" | "ransomware" | "exfiltration",
        "constraints": {
            "time_limit": "4 hours",
            "risk_tolerance": "medium",
            "avoid_detection": true
        },
        "llm_provider": "ollama" | "openai" | "anthropic" | "local",
        "auto_approve": false
    }
    """
    try:
        if not LANGGRAPH_AVAILABLE:
            return jsonify({
                'success': False,
                'error': 'LangGraph not available. Install with: pip install langgraph'
            }), 503
        
        data = request.get_json()
        
        # Validate input
        if not data or 'user_request' not in data:
            return jsonify({
                'success': False,
                'error': 'Missing required field: user_request'
            }), 400
        
        user_request = data['user_request']
        scenario_type = data.get('scenario_type', 'adaptive')
        constraints = data.get('constraints', {})
        llm_provider = data.get('llm_provider', 'ollama')
        auto_approve = data.get('auto_approve', False)
        
        # Create workflow ID
        workflow_id = f"wf_{uuid.uuid4().hex[:12]}"
        
        # Run workflow asynchronously
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            # Create new workflow instance
            workflow_instance = AttackWorkflow()
            
            # If auto-approve, set approval in initial state
            if auto_approve:
                # This would be passed to the run method
                constraints['auto_approve'] = True
            
            # Start workflow
            result = loop.run_until_complete(
                workflow_instance.run(
                    user_request=user_request,
                    scenario_type=scenario_type,
                    constraints=constraints,
                    llm_provider=llm_provider
                )
            )
            
            # Store workflow instance
            active_workflows[workflow_id] = {
                'instance': workflow_instance,
                'state': result,
                'created_at': datetime.now(timezone.utc).isoformat(),
                'status': 'running' if not result.get('errors') else 'error'
            }
            
        finally:
            loop.close()
        
        # Prepare response
        response_data = {
            'success': True,
            'workflow_id': workflow_id,
            'status': active_workflows[workflow_id]['status'],
            'current_phase': str(result.get('current_phase', 'unknown')),
            'messages': result.get('messages', []),
            'errors': result.get('errors', []),
            'requires_approval': result.get('requires_approval', False)
        }
        
        # Include attack plan if generated
        if result.get('attack_plan'):
            response_data['attack_plan'] = {
                'id': result['attack_plan'].get('id'),
                'name': result['attack_plan'].get('name'),
                'phases': len(result['attack_plan'].get('phases', [])),
                'targets': len(result['attack_plan'].get('targets', [])),
                'techniques': result['attack_plan'].get('techniques', [])
            }
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Error starting workflow: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@langgraph_attack_bp.route('/langgraph/attack/<workflow_id>/status', methods=['GET'])
def get_workflow_status(workflow_id):
    """
    GET /api/langgraph/attack/{workflow_id}/status
    Get current status of attack workflow
    """
    try:
        if workflow_id not in active_workflows:
            return jsonify({
                'success': False,
                'error': 'Workflow not found'
            }), 404
        
        workflow = active_workflows[workflow_id]
        state = workflow['state']
        
        return jsonify({
            'success': True,
            'workflow_id': workflow_id,
            'status': workflow['status'],
            'created_at': workflow['created_at'],
            'current_phase': str(state.get('current_phase', 'unknown')),
            'messages': state.get('messages', []),
            'errors': state.get('errors', []),
            'requires_approval': state.get('requires_approval', False),
            'approved': state.get('approved', False),
            'network_discovered': len(state.get('online_agents', [])),
            'vulnerabilities_found': state.get('vulnerabilities', {}).get('total_vulnerabilities', 0),
            'scenarios_generated': len(state.get('attack_scenarios', [])),
            'commands_sent': len(state.get('commands_sent', [])),
            'results_received': len(state.get('results_received', []))
        })
        
    except Exception as e:
        logger.error(f"Error getting workflow status: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@langgraph_attack_bp.route('/langgraph/attack/<workflow_id>/approve', methods=['POST'])
def approve_workflow(workflow_id):
    """
    POST /api/langgraph/attack/{workflow_id}/approve
    Approve attack plan for execution
    """
    try:
        if not LANGGRAPH_AVAILABLE:
            return jsonify({
                'success': False,
                'error': 'LangGraph not available'
            }), 503
        
        if workflow_id not in active_workflows:
            return jsonify({
                'success': False,
                'error': 'Workflow not found'
            }), 404
        
        workflow = active_workflows[workflow_id]
        
        # Update approval status
        workflow['state']['approved'] = True
        workflow['state']['current_phase'] = 'GOLDEN_IMAGE_CREATION'
        
        # Continue workflow execution
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            # Resume workflow with approval
            result = loop.run_until_complete(
                workflow['instance'].approve_plan(workflow_id)
            )
            
            # Update stored state
            workflow['state'] = result
            workflow['status'] = 'approved'
            
        finally:
            loop.close()
        
        return jsonify({
            'success': True,
            'workflow_id': workflow_id,
            'status': 'approved',
            'message': 'Attack plan approved and execution started',
            'current_phase': str(workflow['state'].get('current_phase', 'unknown'))
        })
        
    except Exception as e:
        logger.error(f"Error approving workflow: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@langgraph_attack_bp.route('/langgraph/attack/<workflow_id>/abort', methods=['POST'])
def abort_workflow(workflow_id):
    """
    POST /api/langgraph/attack/{workflow_id}/abort
    Abort attack workflow and trigger restoration
    """
    try:
        if workflow_id not in active_workflows:
            return jsonify({
                'success': False,
                'error': 'Workflow not found'
            }), 404
        
        workflow = active_workflows[workflow_id]
        
        # Set abort flag
        workflow['state']['abort'] = True
        workflow['state']['current_phase'] = 'RESTORATION'
        workflow['status'] = 'aborted'
        
        return jsonify({
            'success': True,
            'workflow_id': workflow_id,
            'status': 'aborted',
            'message': 'Workflow aborted, restoration initiated'
        })
        
    except Exception as e:
        logger.error(f"Error aborting workflow: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@langgraph_attack_bp.route('/langgraph/llm/providers', methods=['GET'])
def get_llm_providers():
    """
    GET /api/langgraph/llm/providers
    Get available LLM providers
    """
    try:
        providers = llm_manager.get_available_providers()
        current = llm_manager.current_provider.value if llm_manager.current_provider else 'none'
        
        return jsonify({
            'success': True,
            'providers': providers,
            'current_provider': current,
            'fallback_order': [p.value for p in llm_manager.fallback_order]
        })
        
    except Exception as e:
        logger.error(f"Error getting LLM providers: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@langgraph_attack_bp.route('/langgraph/llm/switch', methods=['POST'])
def switch_llm_provider():
    """
    POST /api/langgraph/llm/switch
    Switch to a different LLM provider
    
    Request body:
    {
        "provider": "ollama" | "openai" | "anthropic" | "google" | "local"
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'provider' not in data:
            return jsonify({
                'success': False,
                'error': 'Missing required field: provider'
            }), 400
        
        provider = data['provider']
        
        # Import LLMProvider enum
        from agents.langgraph.tools.llm_manager import LLMProvider
        
        try:
            provider_enum = LLMProvider(provider)
            success = llm_manager.switch_provider(provider_enum)
            
            if success:
                return jsonify({
                    'success': True,
                    'message': f'Switched to {provider}',
                    'current_provider': provider
                })
            else:
                return jsonify({
                    'success': False,
                    'error': f'Provider {provider} not available'
                }), 400
                
        except ValueError:
            return jsonify({
                'success': False,
                'error': f'Invalid provider: {provider}'
            }), 400
        
    except Exception as e:
        logger.error(f"Error switching LLM provider: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@langgraph_attack_bp.route('/langgraph/prompts/customize', methods=['POST'])
def customize_prompt():
    """
    POST /api/langgraph/prompts/customize
    Customize a prompt template
    
    Request body:
    {
        "prompt_type": "network_analysis" | "attack_planning" | etc.,
        "custom_template": "Your custom prompt with {variables}"
    }
    """
    try:
        data = request.get_json()
        
        if not data or 'prompt_type' not in data or 'custom_template' not in data:
            return jsonify({
                'success': False,
                'error': 'Missing required fields: prompt_type, custom_template'
            }), 400
        
        prompt_type = data['prompt_type']
        custom_template = data['custom_template']
        
        # Set custom prompt
        attack_prompts.set_custom_prompt(prompt_type, custom_template)
        
        return jsonify({
            'success': True,
            'message': f'Custom prompt set for {prompt_type}',
            'prompt_type': prompt_type
        })
        
    except Exception as e:
        logger.error(f"Error customizing prompt: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@langgraph_attack_bp.route('/langgraph/prompts/reset/<prompt_type>', methods=['POST'])
def reset_prompt(prompt_type):
    """
    POST /api/langgraph/prompts/reset/{prompt_type}
    Reset prompt to default
    """
    try:
        attack_prompts.reset_prompt(prompt_type)
        
        return jsonify({
            'success': True,
            'message': f'Prompt {prompt_type} reset to default'
        })
        
    except Exception as e:
        logger.error(f"Error resetting prompt: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@langgraph_attack_bp.route('/langgraph/prompts/types', methods=['GET'])
def get_prompt_types():
    """
    GET /api/langgraph/prompts/types
    Get available prompt types
    """
    try:
        prompt_types = list(attack_prompts.prompts.keys())
        custom_prompts = list(attack_prompts.custom_prompts.keys())
        
        return jsonify({
            'success': True,
            'prompt_types': prompt_types,
            'customized': custom_prompts
        })
        
    except Exception as e:
        logger.error(f"Error getting prompt types: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@langgraph_attack_bp.route('/langgraph/attack/<workflow_id>/details', methods=['GET'])
def get_workflow_details(workflow_id):
    """
    GET /api/langgraph/attack/{workflow_id}/details
    Get complete workflow details including LLM responses
    """
    try:
        if workflow_id not in active_workflows:
            return jsonify({
                'success': False,
                'error': 'Workflow not found'
            }), 404
        
        workflow = active_workflows[workflow_id]
        state = workflow['state']
        
        details = {
            'success': True,
            'workflow_id': workflow_id,
            'user_request': state.get('user_request'),
            'scenario_type': state.get('scenario_type'),
            'constraints': state.get('constraints'),
            'network_topology': {
                'total_agents': len(state.get('online_agents', []) + state.get('offline_agents', [])),
                'online': len(state.get('online_agents', [])),
                'offline': len(state.get('offline_agents', [])),
                'critical_assets': len(state.get('critical_assets', []))
            },
            'vulnerabilities': state.get('vulnerabilities', {}),
            'threat_assessment': state.get('threat_assessment', {}),
            'attack_scenarios': state.get('attack_scenarios', []),
            'selected_scenario': state.get('selected_scenario', {}),
            'attack_plan': state.get('attack_plan', {}),
            'target_priority': state.get('target_priority', []),
            'techniques_selected': state.get('techniques_selected', []),
            'golden_images': list(state.get('golden_images', {}).keys()),
            'execution_log': state.get('execution_log', []),
            'llm_responses': state.get('llm_responses', [])
        }
        
        return jsonify(details)
        
    except Exception as e:
        logger.error(f"Error getting workflow details: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@langgraph_attack_bp.route('/langgraph/workflows/list', methods=['GET'])
def list_workflows():
    """
    GET /api/langgraph/workflows/list
    List all active workflows
    """
    try:
        workflows = []
        for wf_id, wf_data in active_workflows.items():
            workflows.append({
                'id': wf_id,
                'status': wf_data['status'],
                'created_at': wf_data['created_at'],
                'current_phase': str(wf_data['state'].get('current_phase', 'unknown')),
                'user_request': wf_data['state'].get('user_request', '')[:100]
            })
        
        return jsonify({
            'success': True,
            'workflows': workflows,
            'total': len(workflows)
        })
        
    except Exception as e:
        logger.error(f"Error listing workflows: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
