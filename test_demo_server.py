#!/usr/bin/env python3
"""
Test script for the CodeGrey SOC Demo Server
"""

import requests
import json
import time

# Server configuration
SERVER_URL = "http://localhost:8443"
API_KEY = "ak_default_key_change_in_production"
HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

def test_endpoint(endpoint, method="GET", data=None):
    """Test a specific endpoint"""
    url = f"{SERVER_URL}{endpoint}"
    
    try:
        if method == "GET":
            response = requests.get(url, headers=HEADERS, timeout=5)
        elif method == "POST":
            response = requests.post(url, headers=HEADERS, json=data, timeout=5)
        
        print(f"\n{'='*60}")
        print(f"🔍 Testing: {method} {endpoint}")
        print(f"Status Code: {response.status_code}")
        
        if response.status_code == 200:
            print("✅ SUCCESS")
            result = response.json()
            print(f"Response: {json.dumps(result, indent=2)}")
        else:
            print("❌ FAILED")
            print(f"Error: {response.text}")
        
        return response.status_code == 200
        
    except requests.exceptions.ConnectionError:
        print(f"\n❌ CONNECTION ERROR: Server not running on {SERVER_URL}")
        return False
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        return False

def main():
    """Run demo tests"""
    print("🚀 CodeGrey SOC Demo Server Test")
    print(f"Server: {SERVER_URL}")
    print(f"API Key: {API_KEY}")
    
    # Test endpoints
    endpoints = [
        ("/", "GET"),
        ("/api/system/status", "GET"),
        ("/api/agents", "GET"),
        ("/api/attack_scenarios", "GET"),
        ("/api/detections/live", "GET"),
        ("/api/network/topology", "GET"),
        ("/api/network/topology?hierarchy=true", "GET"),
        ("/api/v1/chat", "POST", {"message": "What is the current threat level?"})
    ]
    
    successful_tests = 0
    total_tests = len(endpoints)
    
    for endpoint_data in endpoints:
        endpoint = endpoint_data[0]
        method = endpoint_data[1]
        data = endpoint_data[2] if len(endpoint_data) > 2 else None
        
        if test_endpoint(endpoint, method, data):
            successful_tests += 1
        
        time.sleep(0.5)  # Brief pause between tests
    
    print(f"\n{'='*60}")
    print(f"📊 Test Results: {successful_tests}/{total_tests} tests passed")
    
    if successful_tests == total_tests:
        print("🎉 ALL TESTS PASSED! Your SOC backend is working perfectly!")
    elif successful_tests > 0:
        print("⚠️  Some tests passed. Server is partially functional.")
    else:
        print("🚨 No tests passed. Check if server is running.")

if __name__ == "__main__":
    main()


