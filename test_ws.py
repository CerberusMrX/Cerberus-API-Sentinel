import asyncio
import websockets
import json
import requests
import sys

# Configuration
BASE_URL = "http://localhost:8000"
WS_URL = "ws://localhost:8000"

async def test_scan_websocket():
    print(f"[*] Creating project...")
    try:
        # 1. Create Project
        project_data = {
            "name": "WebSocket Test Project",
            "target_url": "http://test.com",
            "description": "Test for WS"
        }
        response = requests.post(f"{BASE_URL}/api/projects/projects/", json=project_data)
        if response.status_code != 201:
            print(f"[!] Failed to create project: {response.text}")
            return
        
        project = response.json()
        project_id = project['id']
        print(f"[*] Project created: {project_id}")

        # 2. Start Scan
        print(f"[*] Starting scan...")
        response = requests.post(f"{BASE_URL}/api/projects/projects/{project_id}/start_scan/")
        if response.status_code != 201:
            print(f"[!] Failed to start scan: {response.text}")
            return
        
        scan = response.json()
        scan_id = scan['id']
        print(f"[*] Scan started: {scan_id}")

        # 3. Connect to WebSocket
        ws_endpoint = f"{WS_URL}/ws/scans/{scan_id}/"
        print(f"[*] Connecting to WebSocket: {ws_endpoint}")
        
        async with websockets.connect(ws_endpoint) as websocket:
            print("[*] Connected! Waiting for messages...")
            
            while True:
                try:
                    message = await asyncio.wait_for(websocket.recv(), timeout=20.0)
                    data = json.loads(message)
                    print(f"[>] Received: {data}")
                    
                    if data.get('action') == 'Completed' or data.get('action') == 'Failed':
                        print("[*] Scan finished.")
                        break
                        
                except asyncio.TimeoutError:
                    print("[!] Timeout waiting for message")
                    break
                except Exception as e:
                    print(f"[!] Error: {e}")
                    break

    except Exception as e:
        print(f"[!] An error occurred: {e}")

if __name__ == "__main__":
    asyncio.run(test_scan_websocket())
