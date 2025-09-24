#!/usr/bin/env python3
"""
Test Web Search Capabilities for AI Agents
Demonstrates how your cybersec-ai can search the web like ChatGPT
"""

import sys
import os
sys.path.append(os.path.dirname(__file__))

from agents.ai_reasoning_agent.reasoning_engine import ReasoningEngine

def test_web_search_capabilities():
    """Test the web search and threat intelligence capabilities"""
    
    print("🚀 Testing AI Agent Web Search Capabilities...")
    print("=" * 60)
    
    # Initialize the reasoning engine with web search
    reasoning_engine = ReasoningEngine()
    
    # Test 1: Web search for threat intelligence
    print("\n🌐 Test 1: Searching web for threat intelligence...")
    query = "CVE-2023-44487 HTTP/2 Rapid Reset attack"
    results = reasoning_engine.search_web_for_threat_intel(query)
    print(f"Query: {query}")
    print(f"Results: {results[:500]}...")
    
    # Test 2: CVE lookup
    print("\n🔍 Test 2: Looking up CVE details...")
    cve_data = reasoning_engine.lookup_cve_details("CVE-2023-44487")
    print(f"CVE Data: {cve_data}")
    
    # Test 3: IP reputation check
    print("\n🛡️ Test 3: Checking IP reputation...")
    ip_reputation = reasoning_engine.check_ip_reputation("8.8.8.8")
    print(f"IP Reputation: {ip_reputation}")
    
    # Test 4: Domain analysis
    print("\n🕵️ Test 4: Analyzing domain reputation...")
    domain_analysis = reasoning_engine.analyze_domain_reputation("suspicious-phishing-site.tk")
    print(f"Domain Analysis: {domain_analysis}")
    
    # Test 5: AI-powered incident analysis with web search
    print("\n🧠 Test 5: AI incident analysis with web enrichment...")
    incident_data = {
        "incident_id": "INC-2024-001",
        "description": "Suspicious PowerShell execution detected",
        "indicators": {
            "command": "powershell.exe -enc JABhAD0AJwBoAHQAdABwADoALwAvAG0AYQBsAGkAYwBpAG8AdQBzAC4AZQB4AGEAbQBwAGwAZQAuAGMAbwBtAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcA",
            "source_ip": "192.168.1.100",
            "destination": "malicious.example.com"
        },
        "mitre_techniques": ["T1059.001", "T1105"]
    }
    
    analysis = reasoning_engine.analyze_incident(incident_data)
    print(f"AI Analysis: {analysis}")
    
    print("\n✅ Web search capabilities test completed!")
    print("🎯 Your AI agents can now:")
    print("   • Search the web for threat intelligence")
    print("   • Look up CVE vulnerabilities")
    print("   • Check IP/domain reputation")
    print("   • Enrich incident analysis with web data")
    print("   • Access real-time threat information")

if __name__ == "__main__":
    test_web_search_capabilities()
