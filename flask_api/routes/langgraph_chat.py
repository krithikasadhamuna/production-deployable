#!/usr/bin/env python3
"""
LangGraph-powered Chat API Routes
Stateful, multi-step SOC conversations with human-in-the-loop
"""

import asyncio
from flask import Blueprint, request, jsonify
from datetime import datetime
import logging

# Import the LangGraph workflow
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent.parent))
from agents.ai_reasoning_agent.langgraph_soc_workflow import langgraph_soc_workflow

logger = logging.getLogger(__name__)

langgraph_bp = Blueprint('langgraph', __name__)

@langgraph_bp.route('/v2/chat', methods=['POST'])
def langgraph_chat():
    """
    LangGraph-powered stateful chat with SOC capabilities
    
    Supports:
    - Multi-step attack workflows
    - Human-in-the-loop approvals
    - Persistent conversation state
    - Checkpoint-based resumption
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'No JSON data provided'
            }), 400
        
        user_query = data.get('query') or data.get('message')
        user_id = data.get('user_id', 'analyst-1')
        organization_id = data.get('organization_id', 'org-123')
        
        if not user_query:
            return jsonify({
                'success': False,
                'error': 'Query/message is required'
            }), 400
        
        logger.info(f"Processing LangGraph chat: {user_query[:100]}...")
        
        # Process through LangGraph workflow
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(
                langgraph_soc_workflow.process_soc_command(
                    user_query=user_query,
                    user_id=user_id,
                    organization_id=organization_id
                )
            )
            
            response_data = {
                'success': result['success'],
                'response': result['response'],
                'timestamp': datetime.now().isoformat(),
                'workflow_type': 'langgraph_stateful',
                'thread_id': result.get('thread_id'),
                'execution_status': result.get('execution_status'),
                'checkpoints_count': result.get('checkpoints_count', 0),
                'workflow_state': result.get('workflow_state')
            }
            
            if not result['success']:
                response_data['error'] = result.get('error')
                return jsonify(response_data), 500
            
            return jsonify(response_data), 200
            
        finally:
            loop.close()
        
    except Exception as e:
        logger.error(f"LangGraph chat error: {e}")
        return jsonify({
            'success': False,
            'error': f'Internal server error: {str(e)}',
            'timestamp': datetime.now().isoformat()
        }), 500

@langgraph_bp.route('/v2/chat/resume', methods=['POST'])
def resume_workflow():
    """
    Resume a paused LangGraph workflow
    
    Used for:
    - Human approval responses
    - Continuing interrupted workflows
    - Providing additional input
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'No JSON data provided'
            }), 400
        
        thread_id = data.get('thread_id')
        human_input = data.get('input') or data.get('response')
        
        if not thread_id:
            return jsonify({
                'success': False,
                'error': 'thread_id is required to resume workflow'
            }), 400
        
        logger.info(f"Resuming LangGraph workflow: {thread_id}")
        
        # Resume workflow
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(
                langgraph_soc_workflow.resume_workflow(
                    thread_id=thread_id,
                    human_input=human_input
                )
            )
            
            response_data = {
                'success': result['success'],
                'response': result['response'],
                'timestamp': datetime.now().isoformat(),
                'thread_id': thread_id,
                'execution_status': result.get('execution_status'),
                'workflow_state': result.get('workflow_state')
            }
            
            if not result['success']:
                response_data['error'] = result.get('error')
                return jsonify(response_data), 500
            
            return jsonify(response_data), 200
            
        finally:
            loop.close()
        
    except Exception as e:
        logger.error(f"Workflow resume error: {e}")
        return jsonify({
            'success': False,
            'error': f'Internal server error: {str(e)}',
            'timestamp': datetime.now().isoformat()
        }), 500

@langgraph_bp.route('/v2/workflows', methods=['GET'])
def list_workflows():
    """List active/paused workflows for monitoring"""
    try:
        # In a real implementation, you'd query the SQLite checkpointer
        # For now, return a simple response
        
        return jsonify({
            'success': True,
            'workflows': [],
            'message': 'Workflow listing feature - integrate with checkpointer database',
            'timestamp': datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Workflow listing error: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@langgraph_bp.route('/v2/workflows/<thread_id>/status', methods=['GET'])
def get_workflow_status(thread_id: str):
    """Get status of a specific workflow"""
    try:
        # In a real implementation, query the checkpointer for workflow state
        
        return jsonify({
            'success': True,
            'thread_id': thread_id,
            'status': 'Status checking feature - integrate with checkpointer database',
            'timestamp': datetime.now().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Workflow status error: {e}")
        return jsonify({
            'success': False,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500
