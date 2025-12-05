# CRITICAL: Server Restart Required

## Problem
Your scan finished in 2 seconds because the server is running the OLD code.

Current server: `manage.py runserver` (doesn't auto-reload scanner files)
Need: `daphne` (will load new 200+ payload scanners)

## Solution

### Step 1: Kill Old Server
```bash
pkill -f "manage.py runserver"
pkill -f daphne
```

### Step 2: Start with Daphne
```bash
cd /home/cerberusmrxi/Desktop/new\ project/cerberus-sentinel/web/backend
bash start_server.sh
```

### Step 3: Verify New Code Loaded
The startup should show:
```
Running database migrations...
Starting Daphne server on 0.0.0.0:8000...
```

### Step 4: Run Scan Again
- Refresh browser (Ctrl+Shift+R)
- Start new scan
- Should now take **5-10 minutes** (not 2 seconds)
- Watch payloads scroll in console

## Why This Happened
- `manage.py runserver` caches Python imports
- Scanner payload changes require server restart
- Daphne required for WebSocket real-time updates

## Quick Commands
```bash
# One-liner to restart
pkill -f "manage.py" && cd /home/cerberusmrxi/Desktop/new\ project/cerberus-sentinel/web/backend && bash start_server.sh
```
