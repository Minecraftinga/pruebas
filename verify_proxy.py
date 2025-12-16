import threading
import time
import os
import json
import socket
import urllib.request
import urllib.error
from proxy_server import start_proxy_thread

# Configuration for test
PROXY_HOST = '127.0.0.1'
PROXY_PORT = 8888
PROXY_URL = f"http://{PROXY_HOST}:{PROXY_PORT}"

def run_tests():
    print("Starting Proxy Server for testing...")
    # Start proxy in a thread
    t = threading.Thread(target=start_proxy_thread)
    t.daemon = True
    t.start()
    
    # Give it a second to start
    time.sleep(2)
    
    # Setup proxy handler
    proxy = urllib.request.ProxyHandler({'http': PROXY_URL, 'https': PROXY_URL})
    opener = urllib.request.build_opener(proxy)
    urllib.request.install_opener(opener)

    try:
        # Test 1: Allowed Request
        print("\n[Test 1] Testing Allowed Request (http://example.org)...")
        try:
            with urllib.request.urlopen("http://example.org", timeout=5) as response:
                print(f"Status Code: {response.getcode()}")
                if response.getcode() == 200:
                    print("PASS: Allowed request successful.")
                else:
                    print(f"FAIL: Allowed request returned unexpected status: {response.getcode()}")
        except Exception as e:
            print(f"FAIL: Allowed request failed with error: {e}")

        # Test 2: Blocked Request
        print("\n[Test 2] Testing Blocked Request (http://blocked-site.com)...")
        try:
            with urllib.request.urlopen("http://blocked-site.com", timeout=5) as response:
                 print(f"FAIL: Blocked request returned status {response.getcode()} instead of raising error.")
        except urllib.error.HTTPError as e:
            print(f"Status Code: {e.code}")
            if e.code == 403:
                print("PASS: Blocked request correctly returned 403.")
            else:
                 print(f"FAIL: Blocked request returned {e.code} instead of 403.")
        except Exception as e:
            print(f"FAIL: Blocked request failed with unexpected error: {e}")

        # Test 3: Check Logs
        print("\n[Test 3] Verifying Logs...")
        # Give a moment for log flush
        time.sleep(1)
        
        # Find latest log file
        log_dir = "logs"
        if not os.path.exists(log_dir):
            print("FAIL: Log directory not found.")
            return

        # Get latest hour folder
        subdirs = [os.path.join(log_dir, d) for d in os.listdir(log_dir) if os.path.isdir(os.path.join(log_dir, d))]
        if not subdirs:
             print("FAIL: No log subdirectories found.")
             return
             
        latest_subdir = max(subdirs, key=os.path.getmtime)
        
        # Get latest log file in that folder
        files = [os.path.join(latest_subdir, f) for f in os.listdir(latest_subdir) if f.endswith('.txt')]
        if not files:
            print("FAIL: No log files found in latest folder.")
            return

        latest_log = max(files, key=os.path.getmtime)
        print(f"Reading log file: {latest_log}")
        
        with open(latest_log, 'r') as f:
            lines = f.readlines()
            
        if not lines:
            print("FAIL: Log file is empty.")
            return
            
        # Parse last few lines to check for our activities
        found_allowed = False
        found_blocked = False
        
        for line in lines[-5:]: # Check last 5 lines
            try:
                entry = json.loads(line)
                # Check for structure
                if "action_reason" in entry or "reason" in entry: # reason for blocked
                    pass
                if "method" not in entry:
                    print("FAIL: Log entry missing 'method'")
                
                if entry.get("host") == "example.org" and entry.get("action") == "ALLOWED":
                    found_allowed = True
                    print(f"PASS: Found Log for Allowed Request: {entry}")
                    
                if "blocked-site.com" in entry.get("host", "") and entry.get("action") == "BLOCKED":
                    found_blocked = True
                    print(f"PASS: Found Log for Blocked Request: {entry}")
                    if entry.get("reason"):
                        print(f"PASS: Blocked reason present: {entry['reason']}")
                    else:
                        print("FAIL: Blocked reason missing")
                        
            except json.JSONDecodeError:
                print(f"FAIL: Line is not valid JSON: {line}")

        if found_allowed and found_blocked:
            print("\nSUCCESS: All Log verification checks passed.")
        else:
             print("\nWARNING: Not all expected log entries were found.")

    finally:
        print("\nStopping Server...")
        os._exit(0)

if __name__ == "__main__":
    run_tests()
