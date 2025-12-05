#!/bin/bash
# Startup script for Cerberus Sentinel Backend with WebSocket support

echo "Starting Cerberus Sentinel Backend with Daphne..."

# Get the directory of this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Activate virtual environment
source "$DIR/../../venv/bin/activate"

# Navigate to backend directory
cd "$DIR"

# Run migrations
echo "Running database migrations..."
python manage.py migrate

# Start Daphne server with WebSocket support
echo "Starting Daphne server on 0.0.0.0:8000..."
daphne -b 0.0.0.0 -p 8000 config.asgi:application
