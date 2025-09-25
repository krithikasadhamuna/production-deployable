"""
Flask API for LangGraph-based AI Detection System
RESTful endpoints for continuous threat detection
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime, timezone
import json
import asyncio
import threading
import logging
import uuid

# Import LangGraph detection workflow
try:
    from agents.langgraph.workflows.detection_workflow import detection_workflow, DetectionWorkflow
    from agents.langgraph.tools.llm_manager import llm_manager
    from agents.langgraph.prompts.detection_prompts import detection_prompts
    LANGGRAPH_AVAILABLE = True
except ImportError as e:
    logging.warning(f"LangGraph detection workflow not available: {e}")
    LANGGRAPH_AVAILABLE = False

logger = logging.getLogger(__name__)
langgraph_detection_bp = Blueprint('langgraph_detection', __name__)

# Store active detection sessions
active_detections = {}
continuous_detection_thread = None

@langgraph_detection_bp.route('/langgraph/detection/start', methods=['POST'])
def start_detection():
    """
    POST /api/langgraph/detection/start
    Start a detection analysis session
    
    Request body:
    {
        "batch_size": 100,
        "time_window": 5,  // minutes
        "continuous_mode": false,
        "llm_provider": "ollama",
        "severity_filter": "high",  // optional
        "agent_filter": "agent_id"  // optional
    }
    """
    try:
        if not LANGGRAPH_AVAILABLE:
            return jsonify({
                'success': False,
                'error': 'LangGraph not available. Install with: pip install langgraph'
            }), 503
        
        data = request.get_json() or {}
        
        batch_size = data.get('batch_size', 100)
        time_window = data.get('time_window', 5)
        continuous_mode = data.get('continuous_mode', False)
        llm_provider = data.get('llm_provider', 'ollama')
        
        # Create detection ID
        detection_id = f"det_{uuid.uuid4().hex[:12]}"
        
        # Run detection workflow
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            # Create new workflow instance
            workflow_instance = DetectionWorkflow()
            
            # Run detection
            result = loop.run_until_complete(
                workflow_instance.run(
                    batch_size=batch_size,
                    time_window=time_window,
                    continuous_mode=continuous_mode,
                    llm_provider=llm_provider
                )
            )
            
            # Store detection session
            active_detections[detection_id] = {
                'instance': workflow_instance,
                'state': result,
                'created_at': datetime.now(timezone.utc).isoformat(),
                'status': 'completed' if not continuous_mode else 'running',
                'continuous': continuous_mode
            }
            
        finally:
            if not continuous_mode:
                loop.close()
        
        # Prepare response
        response_data = {
            'success': True,
            'detection_id': detection_id,
            'status': active_detections[detection_id]['status'],
            'logs_processed': len(result.get('raw_logs', [])),
            'threats_detected': result.get('threats_detected', 0),
            'ml_anomalies': len(result.get('ml_anomalies', [])),
            'ml_malware': len(result.get('ml_malware', [])),
            'final_verdict': result.get('final_verdict', 'unknown'),
            'verdict_confidence': result.get('verdict_confidence', 0),
            'alerts_generated': len(result.get('alerts_generated', [])),
            'processing_time': result.get('processing_time', 0),
            'messages': result.get('messages', []),
            'errors': result.get('errors', [])
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Error starting detection: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@langgraph_detection_bp.route('/langgraph/detection/continuous/start', methods=['POST'])
def start_continuous_detection():
    """
    POST /api/langgraph/detection/continuous/start
    Start continuous background detection
    """
    global continuous_detection_thread
    
    try:
        if not LANGGRAPH_AVAILABLE:
            return jsonify({
                'success': False,
                'error': 'LangGraph not available'
            }), 503
        
        # Check if already running
        if continuous_detection_thread and continuous_detection_thread.is_alive():
            return jsonify({
                'success': False,
                'error': 'Continuous detection already running'
            }), 400
        
        data = request.get_json() or {}
        
        # Start continuous detection in background thread
        def run_continuous():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                workflow = DetectionWorkflow()
                loop.run_until_complete(
                    workflow.run_continuous(
                        batch_size=data.get('batch_size', 100),
                        time_window=data.get('time_window', 5),
                        llm_provider=data.get('llm_provider', 'ollama')
                    )
                )
            except Exception as e:
                logger.error(f"Continuous detection error: {e}")
            finally:
                loop.close()
        
        continuous_detection_thread = threading.Thread(
            target=run_continuous,
            daemon=True
        )
        continuous_detection_thread.start()
        
        return jsonify({
            'success': True,
            'message': 'Continuous detection started',
            'status': 'running'
        })
        
    except Exception as e:
        logger.error(f"Error starting continuous detection: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@langgraph_detection_bp.route('/langgraph/detection/continuous/stop', methods=['POST'])
def stop_continuous_detection():
    """
    POST /api/langgraph/detection/continuous/stop
    Stop continuous background detection
    """
    try:
        # Stop all running detection workflows
        for detection_id, detection in active_detections.items():
            if detection.get('continuous'):
                detection['instance'].stop()
        
        return jsonify({
            'success': True,
            'message': 'Continuous detection stopped'
        })
        
    except Exception as e:
        logger.error(f"Error stopping continuous detection: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@langgraph_detection_bp.route('/langgraph/detection/<detection_id>/status', methods=['GET'])
def get_detection_status(detection_id):
    """
    GET /api/langgraph/detection/{detection_id}/status
    Get status of detection session
    """
    try:
        if detection_id not in active_detections:
            return jsonify({
                'success': False,
                'error': 'Detection session not found'
            }), 404
        
        detection = active_detections[detection_id]
        state = detection['state']
        
        return jsonify({
            'success': True,
            'detection_id': detection_id,
            'status': detection['status'],
            'created_at': detection['created_at'],
            'continuous': detection['continuous'],
            'current_phase': str(state.get('current_phase', 'unknown')),
            'iteration_count': state.get('iteration_count', 0),
            'logs_processed': len(state.get('raw_logs', [])),
            'threats_detected': state.get('threats_detected', 0),
            'false_positives': state.get('false_positives', 0),
            'ml_detections': {
                'anomalies': len(state.get('ml_anomalies', [])),
                'malware': len(state.get('ml_malware', []))
            },
            'verdict': {
                'final_verdict': str(state.get('final_verdict', 'unknown')),
                'confidence': state.get('verdict_confidence', 0)
            },
            'alerts': len(state.get('alerts_generated', [])),
            'processing_time': state.get('processing_time', 0)
        })
        
    except Exception as e:
        logger.error(f"Error getting detection status: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@langgraph_detection_bp.route('/langgraph/detection/<detection_id>/results', methods=['GET'])
def get_detection_results(detection_id):
    """
    GET /api/langgraph/detection/{detection_id}/results
    Get detailed detection results
    """
    try:
        if detection_id not in active_detections:
            return jsonify({
                'success': False,
                'error': 'Detection session not found'
            }), 404
        
        detection = active_detections[detection_id]
        state = detection['state']
        
        results = {
            'success': True,
            'detection_id': detection_id,
            'ml_analysis': {
                'results': state.get('ml_results', {}),
                'anomalies': state.get('ml_anomalies', []),
                'malware': state.get('ml_malware', []),
                'confidence_scores': state.get('ml_confidence_scores', [])
            },
            'llm_analysis': {
                'results': state.get('llm_results', []),
                'threats': state.get('llm_threats', [])
            },
            'threat_intelligence': {
                'results': state.get('threat_intel_results', {}),
                'known_iocs': state.get('known_iocs', [])
            },
            'correlations': state.get('correlations', []),
            'patterns': state.get('patterns', []),
            'reasoning': state.get('reasoning_analysis', {}),
            'alerts': state.get('alerts_generated', []),
            'notifications': state.get('notifications_sent', [])
        }
        
        return jsonify(results)
        
    except Exception as e:
        logger.error(f"Error getting detection results: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@langgraph_detection_bp.route('/langgraph/detection/alerts', methods=['GET'])
def get_all_alerts():
    """
    GET /api/langgraph/detection/alerts
    Get all generated alerts across all detection sessions
    """
    try:
        all_alerts = []
        
        for detection_id, detection in active_detections.items():
            alerts = detection['state'].get('alerts_generated', [])
            for alert in alerts:
                alert['detection_id'] = detection_id
                all_alerts.append(alert)
        
        # Sort by timestamp (newest first)
        all_alerts.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        return jsonify({
            'success': True,
            'total_alerts': len(all_alerts),
            'alerts': all_alerts[:100]  # Limit to 100 most recent
        })
        
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@langgraph_detection_bp.route('/langgraph/detection/statistics', methods=['GET'])
def get_detection_statistics():
    """
    GET /api/langgraph/detection/statistics
    Get overall detection statistics
    """
    try:
        total_detections = len(active_detections)
        total_threats = sum(d['state'].get('threats_detected', 0) for d in active_detections.values())
        total_false_positives = sum(d['state'].get('false_positives', 0) for d in active_detections.values())
        total_logs = sum(len(d['state'].get('raw_logs', [])) for d in active_detections.values())
        total_alerts = sum(len(d['state'].get('alerts_generated', [])) for d in active_detections.values())
        
        # Calculate average processing time
        processing_times = [d['state'].get('processing_time', 0) for d in active_detections.values()]
        avg_processing_time = sum(processing_times) / len(processing_times) if processing_times else 0
        
        # Count by verdict
        verdict_counts = {}
        for detection in active_detections.values():
            verdict = str(detection['state'].get('final_verdict', 'unknown'))
            verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
        
        return jsonify({
            'success': True,
            'statistics': {
                'total_detection_sessions': total_detections,
                'total_threats_detected': total_threats,
                'total_false_positives': total_false_positives,
                'total_logs_processed': total_logs,
                'total_alerts_generated': total_alerts,
                'average_processing_time': avg_processing_time,
                'verdict_distribution': verdict_counts,
                'detection_accuracy': (total_threats / (total_threats + total_false_positives) * 100) 
                                     if (total_threats + total_false_positives) > 0 else 0
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@langgraph_detection_bp.route('/langgraph/detection/ml-models/info', methods=['GET'])
def get_ml_models_info():
    """
    GET /api/langgraph/detection/ml-models/info
    Get information about loaded ML models
    """
    try:
        from agents.langgraph.tools.ml_detection_tools import MLModelManager
        
        ml_manager = MLModelManager()
        model_info = ml_manager.get_model_info()
        
        return jsonify({
            'success': True,
            'models': model_info
        })
        
    except Exception as e:
        logger.error(f"Error getting ML models info: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@langgraph_detection_bp.route('/langgraph/detection/prompts/customize', methods=['POST'])
def customize_detection_prompt():
    """
    POST /api/langgraph/detection/prompts/customize
    Customize a detection prompt template
    
    Request body:
    {
        "prompt_type": "log_analysis" | "threat_detection" | etc.,
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
        detection_prompts.set_custom_prompt(prompt_type, custom_template)
        
        return jsonify({
            'success': True,
            'message': f'Custom detection prompt set for {prompt_type}',
            'prompt_type': prompt_type
        })
        
    except Exception as e:
        logger.error(f"Error customizing prompt: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@langgraph_detection_bp.route('/langgraph/detection/prompts/types', methods=['GET'])
def get_detection_prompt_types():
    """
    GET /api/langgraph/detection/prompts/types
    Get available detection prompt types
    """
    try:
        prompt_types = list(detection_prompts.prompts.keys())
        custom_prompts = list(detection_prompts.custom_prompts.keys())
        
        return jsonify({
            'success': True,
            'prompt_types': prompt_types,
            'customized': custom_prompts,
            'total': len(prompt_types)
        })
        
    except Exception as e:
        logger.error(f"Error getting prompt types: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@langgraph_detection_bp.route('/langgraph/detection/test', methods=['POST'])
def test_detection():
    """
    POST /api/langgraph/detection/test
    Test detection with sample logs
    """
    try:
        if not LANGGRAPH_AVAILABLE:
            return jsonify({
                'success': False,
                'error': 'LangGraph not available'
            }), 503
        
        # Create sample suspicious logs for testing
        import sqlite3
        conn = sqlite3.connect(current_app.config.get('DATABASE', 'soc_database.db'))
        cursor = conn.cursor()
        
        # Insert test logs
        test_logs = [
            {
                'id': f'test_{uuid.uuid4().hex[:8]}',
                'agent_id': 'test_agent_001',
                'type': 'suspicious_process',
                'severity': 'high',
                'data': json.dumps({
                    'process': 'powershell.exe -enc SGVsbG8gV29ybGQ=',
                    'user': 'admin'
                }),
                'description': 'PowerShell with encoded command detected'
            },
            {
                'id': f'test_{uuid.uuid4().hex[:8]}',
                'agent_id': 'test_agent_001',
                'type': 'network_connection',
                'severity': 'critical',
                'data': json.dumps({
                    'destination': 'evil.com',
                    'port': 443
                }),
                'description': 'Connection to known malicious domain'
            },
            {
                'id': f'test_{uuid.uuid4().hex[:8]}',
                'agent_id': 'test_agent_002',
                'type': 'file_creation',
                'severity': 'medium',
                'data': json.dumps({
                    'file': 'C:\\Windows\\Temp\\malware.exe',
                    'hash': 'd41d8cd98f00b204e9800998ecf8427e'
                }),
                'description': 'Suspicious file created in temp directory'
            }
        ]
        
        for log in test_logs:
            cursor.execute("""
                INSERT INTO detections 
                (id, agent_id, type, severity, data, description, status, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
            """, (
                log['id'], log['agent_id'], log['type'], log['severity'],
                log['data'], log['description'], datetime.now(timezone.utc).isoformat()
            ))
        
        conn.commit()
        conn.close()
        
        # Run detection on test logs
        workflow = DetectionWorkflow()
        
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(
                workflow.run(
                    batch_size=10,
                    time_window=1,
                    continuous_mode=False,
                    llm_provider='ollama'
                )
            )
        finally:
            loop.close()
        
        return jsonify({
            'success': True,
            'message': 'Test detection completed',
            'test_logs_inserted': len(test_logs),
            'detection_results': {
                'logs_processed': len(result.get('raw_logs', [])),
                'threats_detected': result.get('threats_detected', 0),
                'final_verdict': str(result.get('final_verdict', 'unknown')),
                'verdict_confidence': result.get('verdict_confidence', 0),
                'alerts_generated': len(result.get('alerts_generated', []))
            }
        })
        
    except Exception as e:
        logger.error(f"Error testing detection: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@langgraph_detection_bp.route('/langgraph/detection/sessions', methods=['GET'])
def list_detection_sessions():
    """
    GET /api/langgraph/detection/sessions
    List all detection sessions
    """
    try:
        sessions = []
        for det_id, det_data in active_detections.items():
            sessions.append({
                'id': det_id,
                'status': det_data['status'],
                'created_at': det_data['created_at'],
                'continuous': det_data['continuous'],
                'threats_detected': det_data['state'].get('threats_detected', 0),
                'logs_processed': len(det_data['state'].get('raw_logs', [])),
                'current_phase': str(det_data['state'].get('current_phase', 'unknown'))
            })
        
        # Sort by created_at (newest first)
        sessions.sort(key=lambda x: x['created_at'], reverse=True)
        
        return jsonify({
            'success': True,
            'sessions': sessions,
            'total': len(sessions),
            'active': sum(1 for s in sessions if s['status'] == 'running')
        })
        
    except Exception as e:
        logger.error(f"Error listing sessions: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
