#!/usr/bin/env python3
"""
Simple health check script for Railway deployment
This ensures the Flask app is responding before Railway considers it healthy
"""

import requests
import time
import sys

def check_health(base_url, max_attempts=30, delay=2):
    """Check if the Flask app is responding to health checks"""
    print(f"Checking health at: {base_url}")
    
    for attempt in range(1, max_attempts + 1):
        try:
            # Try the root endpoint
            response = requests.get(f"{base_url}/", timeout=5)
            if response.status_code == 200:
                print(f"✅ Health check passed on attempt {attempt}")
                return True
                
            # Try the API health endpoint
            response = requests.get(f"{base_url}/api/health", timeout=5)
            if response.status_code == 200:
                print(f"✅ API health check passed on attempt {attempt}")
                return True
                
        except requests.exceptions.RequestException as e:
            print(f"Attempt {attempt}/{max_attempts}: {e}")
            
        if attempt < max_attempts:
            time.sleep(delay)
    
    print(f"❌ Health check failed after {max_attempts} attempts")
    return False

if __name__ == "__main__":
    # Get the URL from command line or use default
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:5001"
    
    if check_health(base_url):
        print("🎉 Application is healthy!")
        sys.exit(0)
    else:
        print("💥 Application health check failed!")
        sys.exit(1)
