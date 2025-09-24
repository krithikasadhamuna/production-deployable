"""
AI Attack API Routes
Endpoints for interacting with the LangGraph-powered AI Attack Agent
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime
import json
import uuid
import asyncio
import sqlite3
from functools import wraps
import logging
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
from agents.attack_agent.ai_attacker_brain import AIAttackerBrain

logger = logging.getLogger(__name__)
ai_attack_bp = Blueprint('ai_attack', __name__)

# Initialize AI Attacker Brain
attacker_brain = None

def get_attacker_brain():
    """Get or initialize the AI Attacker Brain"""
    global attacker_brain
    if attacker_brain is None:
        attacker_brain = AIAttackerBrain(db_path=current_app.config['DATABASE'])
    return attacker_brain

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
        
        token = auth_header.split(' ')[1]
        VALID_API_KEYS = {
            "soc-prod-fOpXLgHLmN66qvPgU5ZXDCj1YVQ9quiwWcNT6ECvPBs": "admin",
            "soc-frontend-2024": "frontend"
        }
        
        if token not in VALID_API_KEYS:
            return jsonify({
                'success': False,
                'error': 'Invalid API token',
                'error_code': 'UNAUTHORIZED'
            }), 401
            
        return f(*args, **kwargs)
    return decorated_function

def get_db_connection():
    """Get database connection"""
    conn = sqlite3.connect(current_app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

@ai_attack_bp.route('/ai-attack/start', methods=['POST'])
@require_auth
def start_ai_attack():
    """
    POST /api/ai-attack/start
    Start a new AI-driven attack workflow
    """
    try:
        data = request.get_json() or {}
        
        # Get attack objective
        objective = data.get('objective', 'Comprehensive network security assessment')
        
        # Create workflow ID
        workflow_id = str(uuid.uuid4())
        
        # Store workflow in database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO attack_workflows 
            (id, objective, status, created_at)
            VALUES (?, ?, ?, ?)
        """, (workflow_id, objective, 'initializing', datetime.now().isoformat()))
        conn.commit()
        conn.close()
        
        # Start async workflow
        async def run_workflow():
            brain = get_attacker_brain()
            config = {"configurable": {"thread_id": workflow_id}}
            await brain.run_attack_workflow(objective, config)
        
        # Run in background (in production, use Celery or similar)
        asyncio.create_task(run_workflow())
        
        logger.info(f"Started AI attack workflow: {workflow_id}")
        
        return jsonify({
            "success": True,
            "workflow_id": workflow_id,
            "status": "started",
            "message": "AI attack workflow initiated. Network discovery in progress..."
        })
        
    except Exception as e:
        logger.error(f"Error starting AI attack: {e}")
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "WORKFLOW_ERROR"
        }), 500

@ai_attack_bp.route('/ai-attack/status/<workflow_id>', methods=['GET'])
@require_auth
def get_attack_status(workflow_id):
    """
    GET /api/ai-attack/status/{workflow_id}
    Get current status of attack workflow
    """
    try:
        # Get workflow state
        async def get_state():
            brain = get_attacker_brain()
            config = {"configurable": {"thread_id": workflow_id}}
            state = await brain.graph.aget_state(config)
            return state.values
        
        state = asyncio.run(get_state())
        
        # Format response
        response = {
            "success": True,
            "workflow_id": workflow_id,
            "status": state.get("execution_status", "unknown"),
            "current_phase": state.get("current_phase", 0),
            "network_topology": state.get("network_topology", {}),
            "available_endpoints": len(state.get("available_endpoints", [])),
            "attack_scenarios": state.get("attack_scenarios", []),
            "selected_scenario": state.get("selected_scenario", {}),
            "messages": [msg.content for msg in state.get("messages", [])]
        }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Error getting attack status: {e}")
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "STATUS_ERROR"
        }), 500

@ai_attack_bp.route('/ai-attack/scenarios/<workflow_id>', methods=['GET'])
@require_auth
def get_attack_scenarios(workflow_id):
    """
    GET /api/ai-attack/scenarios/{workflow_id}
    Get generated attack scenarios for review
    """
    try:
        async def get_scenarios():
            brain = get_attacker_brain()
            config = {"configurable": {"thread_id": workflow_id}}
            state = await brain.graph.aget_state(config)
            return state.values.get("attack_scenarios", [])
        
        scenarios = asyncio.run(get_scenarios())
        
        return jsonify({
            "success": True,
            "workflow_id": workflow_id,
            "scenarios": scenarios,
            "total": len(scenarios),
            "message": "Please review and select a scenario for execution"
        })
        
    except Exception as e:
        logger.error(f"Error getting scenarios: {e}")
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "SCENARIO_ERROR"
        }), 500

@ai_attack_bp.route('/ai-attack/approve/<workflow_id>', methods=['POST'])
@require_auth
def approve_attack_scenario(workflow_id):
    """
    POST /api/ai-attack/approve/{workflow_id}
    Approve and execute selected attack scenario
    """
    try:
        data = request.get_json()
        
        if not data or 'scenario_id' not in data:
            return jsonify({
                "success": False,
                "error": "Missing scenario_id",
                "error_code": "INVALID_REQUEST"
            }), 400
        
        scenario_id = data['scenario_id']
        
        # Approve scenario
        async def approve():
            brain = get_attacker_brain()
            selected = await brain.approve_scenario(workflow_id, scenario_id)
            return selected
        
        selected = asyncio.run(approve())
        
        # Update database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE attack_workflows 
            SET status = 'approved', 
                selected_scenario = ?,
                approved_at = ?
            WHERE id = ?
        """, (json.dumps(selected), datetime.now().isoformat(), workflow_id))
        conn.commit()
        conn.close()
        
        logger.info(f"Approved scenario {scenario_id} for workflow {workflow_id}")
        
        return jsonify({
            "success": True,
            "workflow_id": workflow_id,
            "scenario": selected,
            "status": "approved",
            "message": "Attack scenario approved. Execution starting..."
        })
        
    except Exception as e:
        logger.error(f"Error approving scenario: {e}")
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "APPROVAL_ERROR"
        }), 500

@ai_attack_bp.route('/ai-attack/modify/<workflow_id>', methods=['POST'])
@require_auth
def modify_attack_scenario(workflow_id):
    """
    POST /api/ai-attack/modify/{workflow_id}
    Modify attack scenario parameters
    """
    try:
        data = request.get_json()
        
        if not data or 'modifications' not in data:
            return jsonify({
                "success": False,
                "error": "Missing modifications",
                "error_code": "INVALID_REQUEST"
            }), 400
        
        modifications = data['modifications']
        
        # Apply modifications
        async def modify():
            brain = get_attacker_brain()
            result = await brain.modify_scenario(workflow_id, modifications)
            return result
        
        result = asyncio.run(modify())
        
        logger.info(f"Modified scenario for workflow {workflow_id}")
        
        return jsonify({
            "success": True,
            "workflow_id": workflow_id,
            "modifications": modifications,
            "status": "modified",
            "message": "Scenario modified. Please review updated plan."
        })
        
    except Exception as e:
        logger.error(f"Error modifying scenario: {e}")
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "MODIFICATION_ERROR"
        }), 500

@ai_attack_bp.route('/ai-attack/cancel/<workflow_id>', methods=['POST'])
@require_auth
def cancel_attack_workflow(workflow_id):
    """
    POST /api/ai-attack/cancel/{workflow_id}
    Cancel ongoing attack workflow
    """
    try:
        # Update database
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE attack_workflows 
            SET status = 'cancelled',
                cancelled_at = ?
            WHERE id = ?
        """, (datetime.now().isoformat(), workflow_id))
        conn.commit()
        conn.close()
        
        logger.info(f"Cancelled workflow {workflow_id}")
        
        return jsonify({
            "success": True,
            "workflow_id": workflow_id,
            "status": "cancelled",
            "message": "Attack workflow cancelled"
        })
        
    except Exception as e:
        logger.error(f"Error cancelling workflow: {e}")
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "CANCELLATION_ERROR"
        }), 500

@ai_attack_bp.route('/ai-attack/results/<workflow_id>', methods=['GET'])
@require_auth
def get_attack_results(workflow_id):
    """
    GET /api/ai-attack/results/{workflow_id}
    Get execution results of completed attack
    """
    try:
        async def get_results():
            brain = get_attacker_brain()
            config = {"configurable": {"thread_id": workflow_id}}
            state = await brain.graph.aget_state(config)
            return state.values.get("execution_results", [])
        
        results = asyncio.run(get_results())
        
        # Get from database as well
        conn = get_db_connection()
        cursor = conn.execute("""
            SELECT * FROM attack_timeline 
            WHERE scenario_id LIKE ?
            ORDER BY started_at DESC
        """, (f"%{workflow_id}%",))
        db_results = cursor.fetchall()
        conn.close()
        
        return jsonify({
            "success": True,
            "workflow_id": workflow_id,
            "execution_results": results,
            "timeline_entries": len(db_results),
            "status": "completed",
            "message": "Attack execution complete"
        })
        
    except Exception as e:
        logger.error(f"Error getting results: {e}")
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "RESULTS_ERROR"
        }), 500

@ai_attack_bp.route('/ai-attack/history', methods=['GET'])
@require_auth
def get_attack_history():
    """
    GET /api/ai-attack/history
    Get history of all AI attack workflows
    """
    try:
        conn = get_db_connection()
        cursor = conn.execute("""
            SELECT id, objective, status, created_at, approved_at, completed_at
            FROM attack_workflows
            ORDER BY created_at DESC
            LIMIT 50
        """)
        workflows = cursor.fetchall()
        conn.close()
        
        history = []
        for wf in workflows:
            history.append({
                "workflow_id": wf['id'],
                "objective": wf['objective'],
                "status": wf['status'],
                "created_at": wf['created_at'],
                "approved_at": wf['approved_at'],
                "completed_at": wf['completed_at']
            })
        
        return jsonify({
            "success": True,
            "workflows": history,
            "total": len(history)
        })
        
    except Exception as e:
        logger.error(f"Error getting history: {e}")
        return jsonify({
            "success": False,
            "error": str(e),
            "error_code": "HISTORY_ERROR"
        }), 500
