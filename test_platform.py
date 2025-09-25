#!/usr/bin/env python3
"""
Test the SOC Platform - Step by step verification
"""

import requests
import json
import time
import sys

def test_endpoint(name, url, method="GET", data=None):
    """Test a single endpoint"""
    try:
        print(f"\nTesting {name}:")
        print(f"  URL: {url}")
        
        if method == "GET":
            response = requests.get(url, timeout=10)
        else:
            response = requests.post(url, json=data, timeout=10)
        
        if response.status_code == 200:
            print(f"  Status: SUCCESS ({response.status_code})")
            result = response.json()
            
            # Print key information
            if 'status' in result:
                print(f"  Platform Status: {result['status']}")
            if 'platform' in result:
                print(f"  Platform: {result['platform']}")
            if 'agents' in result:
                print(f"  Agents: {len(result['agents']) if isinstance(result['agents'], list) else result['agents']}")
            if 'success' in result:
                print(f"  Operation: {'SUCCESS' if result['success'] else 'FAILED'}")
            if 'workflow_id' in result:
                print(f"  Workflow ID: {result['workflow_id']}")
            if 'message' in result:
                print(f"  Message: {result['message']}")
            
            return True, result
        else:
            print(f"  Status: FAILED ({response.status_code})")
            print(f"  Error: {response.text}")
            return False, None
            
    except requests.exceptions.ConnectionError:
        print(f"  Status: CONNECTION FAILED - Server not running")
        return False, None
    except Exception as e:
        print(f"  Status: ERROR - {str(e)}")
        return False, None

def main():
    base_url = "http://localhost:8080/api/backend"
    
    print("="*60)
    print(" TESTING SOC PLATFORM")
    print("="*60)
    
    # 1. Test health
    success, result = test_endpoint("Health Check", f"{base_url}/health")
    if not success:
        print("\nServer is not running. Start with:")
        print("  python3 COMPLETE_SOC_PLATFORM.py")
        print("  or")
        print("  python3 start_complete_platform.py")
        return
    
    # 2. Test root
    test_endpoint("Root API", f"{base_url}/")
    
    # 3. Test agents
    test_endpoint("Agents List", f"{base_url}/agents")
    
    # 4. Test network topology
    test_endpoint("Network Topology", f"{base_url}/network-topology")
    
    # 5. Test attack agent
    test_endpoint("PhantomStrike AI - Attack Start", 
                 f"{base_url}/langgraph/attack/start", 
                 "POST", 
                 {"user_request": "Execute APT simulation on critical infrastructure"})
    
    # 6. Test detection
    test_endpoint("GuardianAlpha AI - Detection Status", 
                 f"{base_url}/langgraph/detection/status")
    
    # 7. Test AI chat
    test_endpoint("AI Reasoning Chat", 
                 f"{base_url}/v1/chat", 
                 "POST", 
                 {"message": "Analyze current network threats"})
    
    # 8. Test dashboard
    test_endpoint("Executive Dashboard", f"{base_url}/dashboard/executive")
    
    # 9. Test multitenancy
    test_endpoint("Tenant Health (CodeGrey)", f"{base_url}/t/codegrey/health")
    
    print("\n" + "="*60)
    print(" TESTING COMPLETE")
    print("="*60)
    print("\nIf all tests passed, your SOC platform is fully operational!")
    print("If some failed, check the server logs:")
    print("  tail -f complete_platform.log")
    print("  or")
    print("  tail -f platform.log")

if __name__ == "__main__":
    main()
