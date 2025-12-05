# Cerberus Sentinel - Server Startup Guide

## Running the Backend with WebSocket Support

The backend requires **Daphne** to support WebSockets for real-time scan updates.

### Quick Start

**Option 1: Using the startup script (Recommended)**
```bash
cd web/backend
bash start_server.sh
```

**Option 2: Manual startup**
```bash
cd web/backend
source ../../venv/bin/activate
python manage.py migrate
daphne -b 0.0.0.0 -p 8000 config.asgi:application
```

### Important Notes

❌ **DO NOT** use `python manage.py runserver` - it doesn't support WebSockets!

✅ **DO** use `daphne` for development with WebSocket support

### Verifying WebSocket Support

After starting the server, you should see:
```
Starting Daphne server on 0.0.0.0:8000...
2025-12-06 03:15:00 INFO     Starting server at tcp:port=8000:interface=0.0.0.0
2025-12-06 03:15:00 INFO     HTTP/2 support enabled
2025-12-06 03:15:00 INFO     Configuring endpoint tcp:port=8000:interface=0.0.0.0
```

### Testing WebSockets

1. Start the backend with Daphne (see above)
2. Start the frontend:
   ```bash
   cd web/frontend
   npm run dev
   ```
3. Open browser to http://localhost:5173
4. Create a project and start a scan
5. Check browser console for: `[ScanProgress] WebSocket Connected`

### Troubleshooting

**Error: `manage.py: command not found`**
- Make sure you're in the `web/backend` directory
- Activate virtual environment first

**Error: `daphne: command not found`**
- Install daphne: `pip install daphne channels channels-redis`

**Error: WebSocket connection fails**
- Ensure server is running with Daphne, not `manage.py runserver`
- Check server logs for errors
- Verify port 8000 is not blocked by firewall
