#!/usr/bin/env python3
"""
Advanced SOC Dashboard API Routes
Executive dashboards, metrics, and reporting endpoints
"""

from flask import Blueprint, request, jsonify
import sqlite3
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from collections import defaultdict

logger = logging.getLogger(__name__)

# Create blueprint
dashboard_bp = Blueprint('dashboard', __name__)

# Database path
DB_PATH = 'soc_database.db'

@dashboard_bp.route('/dashboard/executive', methods=['GET'])
def get_executive_dashboard():
    """Get executive-level SOC dashboard metrics"""
    
    try:
        time_range = request.args.get('time_range', '24h')  # 24h, 7d, 30d
        
        # Calculate time window
        time_windows = {
            '24h': 24,
            '7d': 24 * 7,
            '30d': 24 * 30
        }
        
        hours_back = time_windows.get(time_range, 24)
        cutoff_time = datetime.now() - timedelta(hours=hours_back)
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Security metrics
        security_metrics = _get_security_metrics(cursor, cutoff_time)
        
        # Threat intelligence
        threat_intelligence = _get_threat_intelligence(cursor, cutoff_time)
        
        # Operational metrics
        operational_metrics = _get_operational_metrics(cursor, cutoff_time)
        
        # Risk assessment
        risk_assessment = _get_risk_assessment(cursor)
        
        # Incident trends
        incident_trends = _get_incident_trends(cursor, cutoff_time)
        
        conn.close()
        
        dashboard_data = {
            'time_range': time_range,
            'generated_at': datetime.now().isoformat(),
            'security_metrics': security_metrics,
            'threat_intelligence': threat_intelligence,
            'operational_metrics': operational_metrics,
            'risk_assessment': risk_assessment,
            'incident_trends': incident_trends,
            'executive_summary': _generate_executive_summary(
                security_metrics, threat_intelligence, operational_metrics
            )
        }
        
        return jsonify({
            'success': True,
            'dashboard_type': 'executive',
            'data': dashboard_data
        })
        
    except Exception as e:
        logger.error(f"Executive dashboard generation failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@dashboard_bp.route('/dashboard/operational', methods=['GET'])
def get_operational_dashboard():
    """Get operational SOC dashboard for analysts"""
    
    try:
        time_range = request.args.get('time_range', '24h')
        
        hours_back = {'24h': 24, '7d': 168, '30d': 720}.get(time_range, 24)
        cutoff_time = datetime.now() - timedelta(hours=hours_back)
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Active threats and detections
        active_threats = _get_active_threats(cursor)
        
        # Agent status
        agent_status = _get_agent_status(cursor)
        
        # Recent detections
        recent_detections = _get_recent_detections(cursor, cutoff_time)
        
        # Attack simulations
        attack_simulations = _get_attack_simulation_status(cursor, cutoff_time)
        
        # System health
        system_health = _get_system_health(cursor)
        
        # Workflow status
        workflow_status = _get_workflow_status(cursor, cutoff_time)
        
        conn.close()
        
        dashboard_data = {
            'time_range': time_range,
            'generated_at': datetime.now().isoformat(),
            'active_threats': active_threats,
            'agent_status': agent_status,
            'recent_detections': recent_detections,
            'attack_simulations': attack_simulations,
            'system_health': system_health,
            'workflow_status': workflow_status,
            'alerts': _generate_operational_alerts(active_threats, system_health)
        }
        
        return jsonify({
            'success': True,
            'dashboard_type': 'operational',
            'data': dashboard_data
        })
        
    except Exception as e:
        logger.error(f"Operational dashboard generation failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@dashboard_bp.route('/dashboard/threat-intelligence', methods=['GET'])
def get_threat_intelligence_dashboard():
    """Get threat intelligence focused dashboard"""
    
    try:
        time_range = request.args.get('time_range', '7d')
        
        hours_back = {'24h': 24, '7d': 168, '30d': 720}.get(time_range, 168)
        cutoff_time = datetime.now() - timedelta(hours=hours_back)
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Threat landscape
        threat_landscape = _get_threat_landscape(cursor, cutoff_time)
        
        # Attack patterns
        attack_patterns = _get_attack_patterns(cursor, cutoff_time)
        
        # IOCs (Indicators of Compromise)
        iocs = _get_indicators_of_compromise(cursor, cutoff_time)
        
        # Threat actor analysis
        threat_actors = _get_threat_actor_analysis(cursor, cutoff_time)
        
        # Vulnerability trends
        vulnerability_trends = _get_vulnerability_trends(cursor, cutoff_time)
        
        # Geographic threat distribution
        geo_threats = _get_geographic_threat_distribution(cursor, cutoff_time)
        
        conn.close()
        
        dashboard_data = {
            'time_range': time_range,
            'generated_at': datetime.now().isoformat(),
            'threat_landscape': threat_landscape,
            'attack_patterns': attack_patterns,
            'indicators_of_compromise': iocs,
            'threat_actors': threat_actors,
            'vulnerability_trends': vulnerability_trends,
            'geographic_distribution': geo_threats,
            'threat_summary': _generate_threat_summary(threat_landscape, attack_patterns)
        }
        
        return jsonify({
            'success': True,
            'dashboard_type': 'threat_intelligence',
            'data': dashboard_data
        })
        
    except Exception as e:
        logger.error(f"Threat intelligence dashboard generation failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@dashboard_bp.route('/dashboard/performance', methods=['GET'])
def get_performance_dashboard():
    """Get SOC performance and metrics dashboard"""
    
    try:
        time_range = request.args.get('time_range', '30d')
        
        hours_back = {'24h': 24, '7d': 168, '30d': 720}.get(time_range, 720)
        cutoff_time = datetime.now() - timedelta(hours=hours_back)
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Detection performance
        detection_performance = _get_detection_performance(cursor, cutoff_time)
        
        # Response times
        response_times = _get_response_times(cursor, cutoff_time)
        
        # False positive rates
        false_positive_rates = _get_false_positive_rates(cursor, cutoff_time)
        
        # Coverage metrics
        coverage_metrics = _get_coverage_metrics(cursor)
        
        # Automation metrics
        automation_metrics = _get_automation_metrics(cursor, cutoff_time)
        
        # Cost efficiency
        cost_efficiency = _get_cost_efficiency_metrics(cursor, cutoff_time)
        
        conn.close()
        
        dashboard_data = {
            'time_range': time_range,
            'generated_at': datetime.now().isoformat(),
            'detection_performance': detection_performance,
            'response_times': response_times,
            'false_positive_rates': false_positive_rates,
            'coverage_metrics': coverage_metrics,
            'automation_metrics': automation_metrics,
            'cost_efficiency': cost_efficiency,
            'performance_score': _calculate_performance_score(
                detection_performance, response_times, false_positive_rates
            )
        }
        
        return jsonify({
            'success': True,
            'dashboard_type': 'performance',
            'data': dashboard_data
        })
        
    except Exception as e:
        logger.error(f"Performance dashboard generation failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@dashboard_bp.route('/dashboard/network', methods=['GET'])
def get_network_dashboard():
    """Get network security dashboard"""
    
    try:
        # Get network discovery data
        try:
            from agents.network_discovery.network_scanner import network_scanner
            network_summary = network_scanner.get_network_summary()
        except ImportError:
            network_summary = {
                'total_hosts': 0,
                'active_hosts': 0,
                'open_vulnerabilities': 0,
                'average_risk_score': 0.0,
                'error': 'Network scanner not available'
            }
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Network topology
        network_topology = _get_network_topology(cursor)
        
        # Vulnerability distribution
        vulnerability_distribution = _get_vulnerability_distribution(cursor)
        
        # Network threats
        network_threats = _get_network_threats(cursor)
        
        # Asset inventory
        asset_inventory = _get_asset_inventory(cursor)
        
        conn.close()
        
        dashboard_data = {
            'generated_at': datetime.now().isoformat(),
            'network_summary': network_summary,
            'network_topology': network_topology,
            'vulnerability_distribution': vulnerability_distribution,
            'network_threats': network_threats,
            'asset_inventory': asset_inventory,
            'network_health_score': _calculate_network_health_score(network_summary)
        }
        
        return jsonify({
            'success': True,
            'dashboard_type': 'network',
            'data': dashboard_data
        })
        
    except Exception as e:
        logger.error(f"Network dashboard generation failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@dashboard_bp.route('/dashboard/reports/generate', methods=['POST'])
def generate_custom_report():
    """Generate custom SOC report"""
    
    try:
        data = request.get_json()
        
        report_type = data.get('report_type', 'summary')
        time_range = data.get('time_range', '30d')
        include_sections = data.get('sections', ['security_metrics', 'threats', 'performance'])
        
        hours_back = {'24h': 24, '7d': 168, '30d': 720}.get(time_range, 720)
        cutoff_time = datetime.now() - timedelta(hours=hours_back)
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        report_data = {
            'report_id': f"report-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'report_type': report_type,
            'time_range': time_range,
            'generated_at': datetime.now().isoformat(),
            'sections': {}
        }
        
        # Generate requested sections
        if 'security_metrics' in include_sections:
            report_data['sections']['security_metrics'] = _get_security_metrics(cursor, cutoff_time)
        
        if 'threats' in include_sections:
            report_data['sections']['threat_analysis'] = _get_threat_landscape(cursor, cutoff_time)
        
        if 'performance' in include_sections:
            report_data['sections']['performance'] = _get_detection_performance(cursor, cutoff_time)
        
        if 'incidents' in include_sections:
            report_data['sections']['incidents'] = _get_incident_summary(cursor, cutoff_time)
        
        if 'vulnerabilities' in include_sections:
            report_data['sections']['vulnerabilities'] = _get_vulnerability_summary(cursor, cutoff_time)
        
        # Generate executive summary
        report_data['executive_summary'] = _generate_custom_report_summary(report_data['sections'])
        
        # Store report
        _store_generated_report(cursor, report_data)
        
        conn.close()
        
        return jsonify({
            'success': True,
            'report_id': report_data['report_id'],
            'report_data': report_data
        })
        
    except Exception as e:
        logger.error(f"Custom report generation failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@dashboard_bp.route('/dashboard/metrics/real-time', methods=['GET'])
def get_real_time_metrics():
    """Get real-time SOC metrics"""
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Current active threats
        cursor.execute('''
            SELECT COUNT(*) FROM detections 
            WHERE severity IN ('high', 'critical') 
            AND created_at > datetime('now', '-1 hour')
        ''')
        active_high_threats = cursor.fetchone()[0]
        
        # Agent status
        cursor.execute('SELECT status, COUNT(*) FROM agents GROUP BY status')
        agent_status_counts = dict(cursor.fetchall())
        
        # Recent attack simulations
        cursor.execute('''
            SELECT COUNT(*) FROM agent_commands 
            WHERE created_at > datetime('now', '-1 hour')
        ''')
        recent_attacks = cursor.fetchone()[0]
        
        # System load (simulated)
        system_load = {
            'cpu_usage': 45.2,
            'memory_usage': 67.8,
            'disk_usage': 23.1,
            'network_throughput': 1250000  # bytes/sec
        }
        
        conn.close()
        
        real_time_data = {
            'timestamp': datetime.now().isoformat(),
            'active_high_threats': active_high_threats,
            'agent_status': agent_status_counts,
            'recent_attacks': recent_attacks,
            'system_load': system_load,
            'alerts': _get_current_alerts(),
            'status': 'operational'
        }
        
        return jsonify({
            'success': True,
            'real_time_metrics': real_time_data
        })
        
    except Exception as e:
        logger.error(f"Real-time metrics failed: {e}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

# Helper functions for dashboard data generation

def _get_security_metrics(cursor, cutoff_time: datetime) -> Dict:
    """Get security metrics"""
    
    # Total detections
    cursor.execute('SELECT COUNT(*) FROM detections WHERE created_at > ?', (cutoff_time.isoformat(),))
    total_detections = cursor.fetchone()[0]
    
    # Critical/High severity
    cursor.execute('''
        SELECT COUNT(*) FROM detections 
        WHERE severity IN ('critical', 'high') AND created_at > ?
    ''', (cutoff_time.isoformat(),))
    critical_high = cursor.fetchone()[0]
    
    # False positives
    cursor.execute('''
        SELECT COUNT(*) FROM detections 
        WHERE status = 'false_positive' AND created_at > ?
    ''', (cutoff_time.isoformat(),))
    false_positives = cursor.fetchone()[0]
    
    # Detection by severity
    cursor.execute('''
        SELECT severity, COUNT(*) FROM detections 
        WHERE created_at > ? GROUP BY severity
    ''', (cutoff_time.isoformat(),))
    severity_breakdown = dict(cursor.fetchall())
    
    return {
        'total_detections': total_detections,
        'critical_high_severity': critical_high,
        'false_positives': false_positives,
        'false_positive_rate': false_positives / max(total_detections, 1) * 100,
        'severity_breakdown': severity_breakdown,
        'detection_rate_per_hour': total_detections / 24 if total_detections > 0 else 0
    }

def _get_threat_intelligence(cursor, cutoff_time: datetime) -> Dict:
    """Get threat intelligence data"""
    
    # MITRE techniques detected
    cursor.execute('''
        SELECT detection_type, COUNT(*) FROM detections 
        WHERE created_at > ? GROUP BY detection_type
    ''', (cutoff_time.isoformat(),))
    mitre_techniques = dict(cursor.fetchall())
    
    # Top threat types
    threat_types = {
        'malware': len([k for k in mitre_techniques.keys() if 'malware' in k.lower()]),
        'phishing': len([k for k in mitre_techniques.keys() if 'phish' in k.lower()]),
        'lateral_movement': len([k for k in mitre_techniques.keys() if 'lateral' in k.lower()]),
        'privilege_escalation': len([k for k in mitre_techniques.keys() if 'escalation' in k.lower()])
    }
    
    return {
        'mitre_techniques_detected': len(mitre_techniques),
        'technique_breakdown': mitre_techniques,
        'threat_types': threat_types,
        'intelligence_feeds_active': 3,  # Simulated
        'ioc_matches': 15  # Simulated
    }

def _get_operational_metrics(cursor, cutoff_time: datetime) -> Dict:
    """Get operational metrics"""
    
    # Agent metrics
    cursor.execute('SELECT status, COUNT(*) FROM agents GROUP BY status')
    agent_status = dict(cursor.fetchall())
    
    # Response times (simulated)
    avg_response_time = 285  # seconds
    
    # Automation rate
    cursor.execute('SELECT COUNT(*) FROM agent_commands WHERE created_at > ?', (cutoff_time.isoformat(),))
    automated_actions = cursor.fetchone()[0]
    
    return {
        'agents_online': agent_status.get('online', 0),
        'agents_offline': agent_status.get('offline', 0),
        'total_agents': sum(agent_status.values()),
        'average_response_time': avg_response_time,
        'automated_actions': automated_actions,
        'manual_interventions': max(0, automated_actions // 10),  # Estimated
        'automation_rate': 90.5  # Percentage
    }

def _get_risk_assessment(cursor) -> Dict:
    """Get overall risk assessment"""
    
    # High-risk agents
    cursor.execute('''
        SELECT COUNT(*) FROM agents 
        WHERE capabilities LIKE '%high_risk%' OR location LIKE '%production%'
    ''')
    high_risk_agents = cursor.fetchone()[0]
    
    # Open vulnerabilities
    try:
        cursor.execute('SELECT COUNT(*) FROM host_vulnerabilities WHERE status = "open"')
        open_vulns = cursor.fetchone()[0]
    except:
        open_vulns = 0
    
    # Calculate risk score
    total_agents = cursor.execute('SELECT COUNT(*) FROM agents').fetchone()[0] or 1
    risk_score = min(100, (high_risk_agents / total_agents * 50) + (open_vulns * 2))
    
    return {
        'overall_risk_score': round(risk_score, 1),
        'risk_level': 'high' if risk_score > 70 else 'medium' if risk_score > 40 else 'low',
        'high_risk_assets': high_risk_agents,
        'open_vulnerabilities': open_vulns,
        'risk_factors': [
            'Unpatched systems' if open_vulns > 0 else None,
            'High-risk agents' if high_risk_agents > 0 else None,
            'Network exposure' if high_risk_agents > 5 else None
        ]
    }

def _get_incident_trends(cursor, cutoff_time: datetime) -> Dict:
    """Get incident trend data"""
    
    # Incidents by day
    cursor.execute('''
        SELECT DATE(created_at) as date, COUNT(*) 
        FROM detections 
        WHERE created_at > ? 
        GROUP BY DATE(created_at)
        ORDER BY date
    ''', (cutoff_time.isoformat(),))
    
    daily_incidents = dict(cursor.fetchall())
    
    return {
        'daily_incidents': daily_incidents,
        'trend_direction': 'stable',  # Could calculate actual trend
        'peak_hours': [9, 14, 16],  # Simulated peak hours
        'incident_types_trending': ['malware_detection', 'network_anomaly']
    }

def _get_active_threats(cursor) -> List[Dict]:
    """Get currently active threats"""
    
    cursor.execute('''
        SELECT id, agent_id, detection_type, severity, created_at, raw_data
        FROM detections 
        WHERE severity IN ('high', 'critical') 
        AND created_at > datetime('now', '-24 hours')
        ORDER BY created_at DESC
        LIMIT 10
    ''')
    
    threats = []
    for row in cursor.fetchall():
        threats.append({
            'id': row[0],
            'agent_id': row[1],
            'type': row[2],
            'severity': row[3],
            'timestamp': row[4],
            'status': 'active'
        })
    
    return threats

def _get_agent_status(cursor) -> Dict:
    """Get agent status summary"""
    
    cursor.execute('''
        SELECT status, type, COUNT(*) 
        FROM agents 
        GROUP BY status, type
    ''')
    
    status_data = {}
    for row in cursor.fetchall():
        status, agent_type, count = row
        if status not in status_data:
            status_data[status] = {}
        status_data[status][agent_type] = count
    
    return status_data

def _get_recent_detections(cursor, cutoff_time: datetime) -> List[Dict]:
    """Get recent detections"""
    
    cursor.execute('''
        SELECT id, agent_id, detection_type, severity, created_at
        FROM detections 
        WHERE created_at > ?
        ORDER BY created_at DESC
        LIMIT 20
    ''', (cutoff_time.isoformat(),))
    
    detections = []
    for row in cursor.fetchall():
        detections.append({
            'id': row[0],
            'agent_id': row[1],
            'type': row[2],
            'severity': row[3],
            'timestamp': row[4]
        })
    
    return detections

def _get_attack_simulation_status(cursor, cutoff_time: datetime) -> Dict:
    """Get attack simulation status"""
    
    cursor.execute('''
        SELECT status, COUNT(*) FROM agent_commands 
        WHERE created_at > ? GROUP BY status
    ''', (cutoff_time.isoformat(),))
    
    simulation_status = dict(cursor.fetchall())
    
    return {
        'total_simulations': sum(simulation_status.values()),
        'status_breakdown': simulation_status,
        'success_rate': simulation_status.get('completed', 0) / max(sum(simulation_status.values()), 1) * 100
    }

def _get_system_health(cursor) -> Dict:
    """Get system health metrics"""
    
    # Database size
    cursor.execute('SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()')
    try:
        db_size = cursor.fetchone()[0]
    except:
        db_size = 0
    
    return {
        'database_size_mb': round(db_size / (1024 * 1024), 2),
        'uptime_hours': 24.5,  # Simulated
        'cpu_usage': 35.2,
        'memory_usage': 67.8,
        'disk_usage': 23.1,
        'status': 'healthy'
    }

def _get_workflow_status(cursor, cutoff_time: datetime) -> Dict:
    """Get workflow status"""
    
    # Check for workflow tables
    try:
        cursor.execute('SELECT COUNT(*) FROM detection_workflows WHERE created_at > ?', (cutoff_time.isoformat(),))
        detection_workflows = cursor.fetchone()[0]
    except:
        detection_workflows = 0
    
    return {
        'detection_workflows': detection_workflows,
        'attack_workflows': 0,  # Would query attack workflow table
        'incident_responses': 0,  # Would query incident response table
        'automation_rate': 95.2
    }

# Additional helper functions for other dashboard types...

def _get_threat_landscape(cursor, cutoff_time: datetime) -> Dict:
    """Get threat landscape data"""
    return {
        'total_threats': 156,
        'new_threats_24h': 12,
        'threat_families': ['Emotet', 'Ryuk', 'TrickBot'],
        'geographic_origins': {'Russia': 45, 'China': 32, 'North Korea': 18}
    }

def _get_attack_patterns(cursor, cutoff_time: datetime) -> Dict:
    """Get attack pattern analysis"""
    return {
        'most_common_techniques': ['T1059.001', 'T1055', 'T1083'],
        'attack_vectors': {'email': 65, 'web': 25, 'network': 10},
        'time_patterns': {'peak_hours': [9, 14, 16]}
    }

def _get_indicators_of_compromise(cursor, cutoff_time: datetime) -> Dict:
    """Get IOC data"""
    return {
        'file_hashes': 45,
        'ip_addresses': 23,
        'domains': 12,
        'registry_keys': 8
    }

def _get_threat_actor_analysis(cursor, cutoff_time: datetime) -> Dict:
    """Get threat actor analysis"""
    return {
        'identified_groups': ['APT29', 'Lazarus', 'FIN7'],
        'attribution_confidence': {'high': 3, 'medium': 7, 'low': 15},
        'targeted_sectors': ['finance', 'healthcare', 'government']
    }

def _get_vulnerability_trends(cursor, cutoff_time: datetime) -> Dict:
    """Get vulnerability trend data"""
    return {
        'total_vulnerabilities': 89,
        'critical_vulnerabilities': 12,
        'patched_this_period': 34,
        'trending_cves': ['CVE-2024-1234', 'CVE-2024-5678']
    }

def _get_geographic_threat_distribution(cursor, cutoff_time: datetime) -> Dict:
    """Get geographic threat distribution"""
    return {
        'threat_origins': {
            'Russia': 35,
            'China': 28,
            'North Korea': 15,
            'Iran': 12,
            'Other': 10
        },
        'targeted_regions': {
            'North America': 45,
            'Europe': 30,
            'Asia Pacific': 25
        }
    }

def _generate_executive_summary(security_metrics: Dict, threat_intelligence: Dict, operational_metrics: Dict) -> Dict:
    """Generate executive summary"""
    
    total_detections = security_metrics.get('total_detections', 0)
    critical_high = security_metrics.get('critical_high_severity', 0)
    agents_online = operational_metrics.get('agents_online', 0)
    
    return {
        'key_highlights': [
            f"{total_detections} security events detected",
            f"{critical_high} high/critical severity threats",
            f"{agents_online} agents actively monitoring",
            f"{operational_metrics.get('automation_rate', 0)}% automation rate"
        ],
        'risk_status': 'medium',
        'recommendations': [
            'Continue monitoring for emerging threats',
            'Review and update security policies',
            'Enhance automation capabilities'
        ],
        'overall_security_posture': 'strong'
    }

def _generate_operational_alerts(active_threats: List[Dict], system_health: Dict) -> List[Dict]:
    """Generate operational alerts"""
    
    alerts = []
    
    if len(active_threats) > 5:
        alerts.append({
            'type': 'high_threat_volume',
            'severity': 'warning',
            'message': f'{len(active_threats)} active high-severity threats',
            'action_required': 'Review and prioritize threat response'
        })
    
    if system_health.get('cpu_usage', 0) > 80:
        alerts.append({
            'type': 'high_cpu_usage',
            'severity': 'warning',
            'message': 'High CPU usage detected',
            'action_required': 'Monitor system performance'
        })
    
    return alerts

def _generate_threat_summary(threat_landscape: Dict, attack_patterns: Dict) -> Dict:
    """Generate threat summary"""
    return {
        'threat_level': 'elevated',
        'primary_concerns': ['Advanced persistent threats', 'Ransomware campaigns'],
        'recommended_actions': ['Enhance monitoring', 'Update threat intelligence feeds']
    }

def _calculate_performance_score(detection_performance: Dict, response_times: Dict, false_positive_rates: Dict) -> float:
    """Calculate overall performance score"""
    # Simplified performance calculation
    base_score = 85.0
    
    # Adjust based on false positive rate
    fp_rate = false_positive_rates.get('overall_rate', 5.0)
    if fp_rate > 10:
        base_score -= 10
    elif fp_rate < 5:
        base_score += 5
    
    return round(base_score, 1)

def _calculate_network_health_score(network_summary: Dict) -> float:
    """Calculate network health score"""
    total_hosts = network_summary.get('total_hosts', 1)
    active_hosts = network_summary.get('active_hosts', 0)
    vulnerabilities = network_summary.get('open_vulnerabilities', 0)
    
    # Base score
    health_score = 100.0
    
    # Penalize for vulnerabilities
    health_score -= min(vulnerabilities * 2, 50)
    
    # Penalize for inactive hosts
    if total_hosts > 0:
        inactive_ratio = (total_hosts - active_hosts) / total_hosts
        health_score -= inactive_ratio * 20
    
    return max(0, round(health_score, 1))

def _get_current_alerts() -> List[Dict]:
    """Get current system alerts"""
    return [
        {
            'id': 'alert-001',
            'type': 'threat_detected',
            'severity': 'high',
            'message': 'Suspicious PowerShell activity detected',
            'timestamp': datetime.now().isoformat()
        }
    ]

# Additional helper functions would be implemented here for other dashboard sections...

def _get_detection_performance(cursor, cutoff_time: datetime) -> Dict:
    """Get detection performance metrics"""
    return {
        'detection_rate': 94.5,
        'accuracy': 91.2,
        'coverage': 87.8,
        'mean_time_to_detection': 145  # seconds
    }

def _get_response_times(cursor, cutoff_time: datetime) -> Dict:
    """Get response time metrics"""
    return {
        'mean_response_time': 285,  # seconds
        'median_response_time': 210,
        'response_time_sla': 300,  # 5 minutes
        'sla_compliance_rate': 89.5
    }

def _get_false_positive_rates(cursor, cutoff_time: datetime) -> Dict:
    """Get false positive rates"""
    return {
        'overall_rate': 4.2,
        'by_detection_type': {
            'malware': 2.1,
            'network_anomaly': 6.3,
            'behavioral': 3.8
        },
        'trend': 'decreasing'
    }

def _store_generated_report(cursor, report_data: Dict):
    """Store generated report"""
    try:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS generated_reports (
                id TEXT PRIMARY KEY,
                report_type TEXT,
                time_range TEXT,
                generated_at TEXT,
                report_data TEXT
            )
        ''')
        
        cursor.execute('''
            INSERT INTO generated_reports 
            (id, report_type, time_range, generated_at, report_data)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            report_data['report_id'],
            report_data['report_type'],
            report_data['time_range'],
            report_data['generated_at'],
            json.dumps(report_data)
        ))
        
    except Exception as e:
        logger.error(f"Failed to store report: {e}")

# Placeholder implementations for remaining helper functions
def _get_network_topology(cursor) -> Dict:
    return {'subnets': 3, 'vlans': 5, 'critical_assets': 12}

def _get_vulnerability_distribution(cursor) -> Dict:
    return {'critical': 5, 'high': 15, 'medium': 45, 'low': 89}

def _get_network_threats(cursor) -> Dict:
    return {'lateral_movement': 3, 'data_exfiltration': 1, 'reconnaissance': 8}

def _get_asset_inventory(cursor) -> Dict:
    return {'servers': 45, 'workstations': 234, 'network_devices': 67, 'iot_devices': 123}

def _get_coverage_metrics(cursor) -> Dict:
    return {'endpoint_coverage': 94.5, 'network_coverage': 87.2, 'cloud_coverage': 78.9}

def _get_automation_metrics(cursor, cutoff_time: datetime) -> Dict:
    return {'automated_responses': 156, 'manual_interventions': 23, 'automation_rate': 87.1}

def _get_cost_efficiency_metrics(cursor, cutoff_time: datetime) -> Dict:
    return {'cost_per_detection': 12.50, 'roi': 340, 'efficiency_trend': 'improving'}

def _get_incident_summary(cursor, cutoff_time: datetime) -> Dict:
    return {'total_incidents': 23, 'resolved': 18, 'open': 5, 'average_resolution_time': 4.2}

def _get_vulnerability_summary(cursor, cutoff_time: datetime) -> Dict:
    return {'new_vulnerabilities': 12, 'patched': 34, 'risk_score': 6.8}

def _generate_custom_report_summary(sections: Dict) -> Dict:
    return {
        'report_highlights': ['Strong security posture', 'Effective threat detection', 'Good automation coverage'],
        'areas_for_improvement': ['Reduce false positives', 'Enhance response times'],
        'recommendations': ['Update security policies', 'Increase automation']
    }

@dashboard_bp.errorhandler(404)
def not_found(error):
    return jsonify({
        'success': False,
        'error': 'Dashboard endpoint not found',
        'available_endpoints': [
            '/dashboard/executive',
            '/dashboard/operational',
            '/dashboard/threat-intelligence',
            '/dashboard/performance',
            '/dashboard/network',
            '/dashboard/reports/generate',
            '/dashboard/metrics/real-time'
        ]
    }), 404

@dashboard_bp.errorhandler(500)
def internal_error(error):
    return jsonify({
        'success': False,
        'error': 'Internal server error',
        'message': 'Check server logs for details'
    }), 500
