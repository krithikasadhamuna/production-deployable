#!/usr/bin/env python3
"""
Network Element Detector - Identifies network infrastructure roles
Automatically classifies agents based on their network function and location
"""

import json
import socket
import subprocess
import re
import logging
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import ipaddress
import platform
import requests
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

@dataclass
class NetworkElement:
    """Detected network element with role and characteristics"""
    element_type: str  # 'firewall', 'dmz', 'datacenter', 'endpoint', etc.
    network_role: str  # 'security', 'infrastructure', 'user', 'external'
    subnet: str
    security_zone: str  # 'external', 'dmz', 'internal', 'secure'
    confidence: float  # 0.0 to 1.0
    characteristics: Dict[str, Any]
    services: List[str]

class NetworkElementDetector:
    """Detects and classifies network infrastructure elements"""
    
    def __init__(self):
        self.detection_rules = self._load_detection_rules()
        self.network_segments = {}
        self.discovered_infrastructure = {}
        
    def _load_detection_rules(self) -> Dict:
        """Load rules for detecting different network elements"""
        return {
            "firewall": {
                "ports": [22, 443, 8080, 8443, 4443],  # Management ports
                "services": ["iptables", "pf", "checkpoint", "fortigate", "palo_alto"],
                "hostnames": ["fw", "firewall", "gateway", "border", "edge"],
                "characteristics": ["packet_filtering", "nat", "vpn"],
                "confidence_boost": 0.8
            },
            "dmz": {
                "subnets": ["10.0.0.0/24", "172.16.0.0/24", "192.168.0.0/24"],
                "ports": [80, 443, 25, 53, 21],  # Public services
                "services": ["nginx", "apache", "iis", "postfix", "bind"],
                "hostnames": ["web", "mail", "dns", "public", "dmz"],
                "characteristics": ["public_facing", "limited_internal_access"],
                "confidence_boost": 0.7
            },
            "datacenter": {
                "ports": [3389, 22, 5985, 5986, 1433, 3306, 5432],  # Server management
                "services": ["hyperv", "vmware", "docker", "kubernetes", "mssql", "mysql"],
                "hostnames": ["dc", "srv", "server", "vm", "host", "cluster"],
                "characteristics": ["virtualization", "database", "high_availability"],
                "confidence_boost": 0.9
            },
            "domain_controller": {
                "ports": [389, 636, 88, 53, 135, 445],  # AD ports
                "services": ["active_directory", "ldap", "kerberos", "dns"],
                "hostnames": ["dc", "ad", "domain", "controller"],
                "characteristics": ["authentication", "directory_services", "group_policy"],
                "confidence_boost": 0.95
            },
            "endpoint": {
                "ports": [135, 445, 3389],  # Windows workstation ports
                "services": ["workstation", "desktop", "laptop"],
                "hostnames": ["pc", "ws", "workstation", "laptop", "desktop"],
                "characteristics": ["user_device", "office_applications", "endpoint_protection"],
                "confidence_boost": 0.6
            },
            "soc": {
                "ports": [8080, 8443, 9200, 5601, 8086],  # SIEM/monitoring ports
                "services": ["elasticsearch", "kibana", "splunk", "graylog", "ossec"],
                "hostnames": ["soc", "siem", "log", "monitor", "security"],
                "characteristics": ["log_analysis", "threat_detection", "incident_response"],
                "confidence_boost": 0.85
            },
            "cloud": {
                "ip_ranges": [
                    "52.0.0.0/8",    # AWS
                    "13.0.0.0/8",    # AWS
                    "20.0.0.0/8",    # Azure
                    "104.0.0.0/8",   # Azure
                    "8.8.8.0/24",    # Google
                    "35.0.0.0/8"     # Google Cloud
                ],
                "services": ["aws", "azure", "gcp", "cloud"],
                "characteristics": ["cloud_service", "external_dependency", "api_access"],
                "confidence_boost": 0.9
            }
        }
    
    async def detect_network_element(self, agent_data: Dict) -> NetworkElement:
        """Detect what type of network element an agent represents"""
        try:
            # Extract agent information
            hostname = agent_data.get('hostname', '').lower()
            ip_address = agent_data.get('ip_address', '')
            open_ports = agent_data.get('open_ports', [])
            services = agent_data.get('services', [])
            os_info = agent_data.get('os_info', {})
            capabilities = agent_data.get('capabilities', [])
            
            # Run detection algorithms
            detection_results = []
            
            # 1. Hostname-based detection
            hostname_result = self._detect_by_hostname(hostname)
            if hostname_result:
                detection_results.append(hostname_result)
            
            # 2. Port-based detection
            port_result = self._detect_by_ports(open_ports)
            if port_result:
                detection_results.append(port_result)
            
            # 3. Service-based detection
            service_result = self._detect_by_services(services)
            if service_result:
                detection_results.append(service_result)
            
            # 4. IP-based detection
            ip_result = self._detect_by_ip_location(ip_address)
            if ip_result:
                detection_results.append(ip_result)
            
            # 5. OS-based detection
            os_result = self._detect_by_os_characteristics(os_info)
            if os_result:
                detection_results.append(os_result)
            
            # 6. Capability-based detection
            capability_result = self._detect_by_capabilities(capabilities)
            if capability_result:
                detection_results.append(capability_result)
            
            # Consolidate results and determine best match
            final_element = self._consolidate_detection_results(
                detection_results, agent_data
            )
            
            logger.info(f"Detected {hostname} as {final_element.element_type} "
                       f"(confidence: {final_element.confidence:.2f})")
            
            return final_element
            
        except Exception as e:
            logger.error(f"Error detecting network element: {e}")
            # Return default endpoint classification
            return NetworkElement(
                element_type="endpoint",
                network_role="user",
                subnet=self._determine_subnet(agent_data.get('ip_address', '')),
                security_zone="internal",
                confidence=0.3,
                characteristics={"default_classification": True},
                services=[]
            )
    
    def _detect_by_hostname(self, hostname: str) -> Optional[Tuple[str, float]]:
        """Detect element type based on hostname patterns"""
        for element_type, rules in self.detection_rules.items():
            for pattern in rules.get('hostnames', []):
                if pattern in hostname:
                    return (element_type, rules['confidence_boost'])
        return None
    
    def _detect_by_ports(self, open_ports: List[int]) -> Optional[Tuple[str, float]]:
        """Detect element type based on open ports"""
        best_match = None
        best_score = 0
        
        for element_type, rules in self.detection_rules.items():
            rule_ports = set(rules.get('ports', []))
            agent_ports = set(open_ports)
            
            if rule_ports & agent_ports:  # Intersection
                match_ratio = len(rule_ports & agent_ports) / len(rule_ports)
                score = match_ratio * rules.get('confidence_boost', 0.5)
                
                if score > best_score:
                    best_score = score
                    best_match = (element_type, score)
        
        return best_match
    
    def _detect_by_services(self, services: List[str]) -> Optional[Tuple[str, float]]:
        """Detect element type based on running services"""
        services_lower = [s.lower() for s in services]
        
        for element_type, rules in self.detection_rules.items():
            for service_pattern in rules.get('services', []):
                if any(service_pattern in service for service in services_lower):
                    return (element_type, rules['confidence_boost'])
        return None
    
    def _detect_by_ip_location(self, ip_address: str) -> Optional[Tuple[str, float]]:
        """Detect element type based on IP address location"""
        if not ip_address:
            return None
            
        try:
            ip = ipaddress.ip_address(ip_address)
            
            # Check cloud IP ranges
            for element_type, rules in self.detection_rules.items():
                for ip_range in rules.get('ip_ranges', []):
                    if ip in ipaddress.ip_network(ip_range):
                        return (element_type, rules['confidence_boost'])
            
            # Check private vs public
            if ip.is_private:
                # Determine subnet type
                if str(ip).startswith('10.0.'):
                    return ('dmz', 0.4)
                elif str(ip).startswith('172.16.'):
                    return ('datacenter', 0.4)
                elif str(ip).startswith('192.168.'):
                    return ('endpoint', 0.3)
            else:
                return ('external', 0.7)
                
        except Exception as e:
            logger.warning(f"Error parsing IP address {ip_address}: {e}")
            
        return None
    
    def _detect_by_os_characteristics(self, os_info: Dict) -> Optional[Tuple[str, float]]:
        """Detect element type based on OS characteristics"""
        os_type = os_info.get('type', '').lower()
        os_version = os_info.get('version', '').lower()
        
        # Windows Server detection
        if 'server' in os_version:
            if 'domain' in os_version or 'active directory' in str(os_info):
                return ('domain_controller', 0.8)
            else:
                return ('datacenter', 0.7)
        
        # Linux server detection
        if os_type == 'linux':
            if any(keyword in os_version for keyword in ['server', 'centos', 'rhel']):
                return ('datacenter', 0.6)
        
        # Workstation detection
        if any(keyword in os_version for keyword in ['10', '11', 'desktop', 'workstation']):
            return ('endpoint', 0.5)
        
        return None
    
    def _detect_by_capabilities(self, capabilities: List[str]) -> Optional[Tuple[str, float]]:
        """Detect element type based on agent capabilities"""
        capabilities_lower = [c.lower() for c in capabilities]
        
        # SOC/Security tools
        if any('detection' in cap or 'threat' in cap for cap in capabilities_lower):
            return ('soc', 0.8)
        
        # Attack simulation
        if any('attack' in cap or 'penetration' in cap for cap in capabilities_lower):
            return ('soc', 0.7)
        
        # Endpoint characteristics
        if any('endpoint' in cap or 'workstation' in cap for cap in capabilities_lower):
            return ('endpoint', 0.6)
        
        return None
    
    def _consolidate_detection_results(self, results: List[Tuple[str, float]], 
                                     agent_data: Dict) -> NetworkElement:
        """Consolidate multiple detection results into final classification"""
        if not results:
            # Default classification
            return NetworkElement(
                element_type="endpoint",
                network_role="user",
                subnet=self._determine_subnet(agent_data.get('ip_address', '')),
                security_zone="internal",
                confidence=0.2,
                characteristics={"no_detection_match": True},
                services=[]
            )
        
        # Weight and combine results
        element_scores = {}
        for element_type, confidence in results:
            if element_type not in element_scores:
                element_scores[element_type] = []
            element_scores[element_type].append(confidence)
        
        # Calculate weighted average for each element type
        final_scores = {}
        for element_type, scores in element_scores.items():
            final_scores[element_type] = sum(scores) / len(scores)
        
        # Get best match
        best_element = max(final_scores.items(), key=lambda x: x[1])
        element_type, confidence = best_element
        
        # Build network element
        network_element = NetworkElement(
            element_type=element_type,
            network_role=self._determine_network_role(element_type),
            subnet=self._determine_subnet(agent_data.get('ip_address', '')),
            security_zone=self._determine_security_zone(element_type, agent_data),
            confidence=min(confidence, 1.0),
            characteristics=self._extract_characteristics(element_type, agent_data),
            services=self._extract_services(agent_data)
        )
        
        return network_element
    
    def _determine_network_role(self, element_type: str) -> str:
        """Determine high-level network role"""
        role_mapping = {
            "firewall": "security",
            "dmz": "external_facing",
            "datacenter": "infrastructure",
            "domain_controller": "infrastructure",
            "endpoint": "user",
            "soc": "security",
            "cloud": "external"
        }
        return role_mapping.get(element_type, "unknown")
    
    def _determine_subnet(self, ip_address: str) -> str:
        """Determine subnet from IP address"""
        if not ip_address:
            return "unknown"
        
        try:
            ip = ipaddress.ip_address(ip_address)
            if ip.is_private:
                octets = str(ip).split('.')
                return f"{'.'.join(octets[:3])}.0/24"
            else:
                return "external"
        except:
            return "unknown"
    
    def _determine_security_zone(self, element_type: str, agent_data: Dict) -> str:
        """Determine security zone"""
        zone_mapping = {
            "firewall": "perimeter",
            "dmz": "dmz",
            "datacenter": "secure",
            "domain_controller": "secure",
            "endpoint": "internal",
            "soc": "secure",
            "cloud": "external"
        }
        return zone_mapping.get(element_type, "internal")
    
    def _extract_characteristics(self, element_type: str, agent_data: Dict) -> Dict:
        """Extract relevant characteristics"""
        base_chars = self.detection_rules.get(element_type, {}).get('characteristics', [])
        
        characteristics = {
            "element_type": element_type,
            "detection_method": "automated",
            "timestamp": agent_data.get('last_heartbeat', ''),
            "base_characteristics": base_chars
        }
        
        # Add agent-specific characteristics
        if agent_data.get('os_info'):
            characteristics['os_details'] = agent_data['os_info']
        
        if agent_data.get('capabilities'):
            characteristics['agent_capabilities'] = agent_data['capabilities']
        
        return characteristics
    
    def _extract_services(self, agent_data: Dict) -> List[str]:
        """Extract detected services"""
        services = []
        
        # From agent services
        if agent_data.get('services'):
            services.extend(agent_data['services'])
        
        # From capabilities
        if agent_data.get('capabilities'):
            services.extend(agent_data['capabilities'])
        
        return list(set(services))  # Remove duplicates
    
    def get_network_topology_summary(self, detected_elements: List[NetworkElement]) -> Dict:
        """Generate network topology summary"""
        topology = {
            "total_elements": len(detected_elements),
            "by_type": {},
            "by_zone": {},
            "by_role": {},
            "security_zones": set(),
            "subnets": set(),
            "confidence_distribution": {
                "high": 0,      # > 0.8
                "medium": 0,    # 0.5 - 0.8
                "low": 0        # < 0.5
            }
        }
        
        for element in detected_elements:
            # By type
            if element.element_type not in topology["by_type"]:
                topology["by_type"][element.element_type] = 0
            topology["by_type"][element.element_type] += 1
            
            # By zone
            if element.security_zone not in topology["by_zone"]:
                topology["by_zone"][element.security_zone] = 0
            topology["by_zone"][element.security_zone] += 1
            
            # By role
            if element.network_role not in topology["by_role"]:
                topology["by_role"][element.network_role] = 0
            topology["by_role"][element.network_role] += 1
            
            # Collect unique zones and subnets
            topology["security_zones"].add(element.security_zone)
            topology["subnets"].add(element.subnet)
            
            # Confidence distribution
            if element.confidence > 0.8:
                topology["confidence_distribution"]["high"] += 1
            elif element.confidence > 0.5:
                topology["confidence_distribution"]["medium"] += 1
            else:
                topology["confidence_distribution"]["low"] += 1
        
        # Convert sets to lists for JSON serialization
        topology["security_zones"] = list(topology["security_zones"])
        topology["subnets"] = list(topology["subnets"])
        
        return topology

# Global instance
network_element_detector = NetworkElementDetector()

