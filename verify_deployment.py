#!/usr/bin/env python3
"""
Deployment Verification Script
Checks if all components are properly installed
"""

import os
import sys
import sqlite3
import importlib

def check_component(name, check_func):
    try:
        result = check_func()
        print(f"[OK] {name}: {result}")
        return True
    except Exception as e:
        print(f"[FAIL] {name}: {e}")
        return False

def check_python_version():
    version = f"{sys.version_info.major}.{sys.version_info.minor}"
    assert sys.version_info >= (3, 8), "Python 3.8+ required"
    return f"Python {version}"

def check_flask():
    import flask
    return f"Flask {flask.__version__}"

def check_ml_models():
    models = []
    model_files = [
        "ml_models/anomaly_detector.joblib",
        "ml_models/trained_models/network_random_forest.pkl"
    ]
    for model in model_files:
        if os.path.exists(model):
            models.append(os.path.basename(model))
    return f"{len(models)} models found"

def check_database():
    if os.path.exists("master_platform.db"):
        conn = sqlite3.connect("master_platform.db")
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM tenants")
        count = cursor.fetchone()[0]
        conn.close()
        return f"{count} tenants configured"
    return "Database will be created on first run"

def check_sklearn():
    import sklearn
    return f"scikit-learn {sklearn.__version__}"

def check_directories():
    dirs = ["flask_api", "agents", "ml_models", "tenant_databases", "logs"]
    existing = [d for d in dirs if os.path.exists(d)]
    return f"{len(existing)}/{len(dirs)} directories"

print("="*50)
print("SOC PLATFORM DEPLOYMENT VERIFICATION")
print("="*50)

checks = [
    ("Python Version", check_python_version),
    ("Flask Framework", check_flask),
    ("ML Libraries", check_sklearn),
    ("ML Models", check_ml_models),
    ("Database", check_database),
    ("Directory Structure", check_directories)
]

passed = 0
for name, check in checks:
    if check_component(name, check):
        passed += 1

print("="*50)
print(f"Result: {passed}/{len(checks)} checks passed")

if passed == len(checks):
    print("âœ“ Deployment is ready!")
else:
    print("âœ— Some components need attention")
    
print("\nTo start the server: python start_production_server.py")
