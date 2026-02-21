#!/bin/bash

# ScamShield Start Script

echo "Starting ScamShield..."

# Check environment
ENV=${1:-development}

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Please run setup first."
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Set environment variables
export FLASK_APP=main.py

if [ "$ENV" = "production" ]; then
    export FLASK_ENV=production
else
    export FLASK_ENV=development
fi

# Initialize database if needed
if [ ! -f "database/scamshield.db" ]; then
    echo "Initializing database..."
    python -c "import sys; sys.path.insert(0, '.'); from backend.database.db import init_db; init_db()"
fi

# Start application based on environment
if [ "$ENV" = "production" ]; then
    echo "Starting ScamShield in PRODUCTION mode..."
    echo "Using gunicorn on http://0.0.0.0:8000"
    gunicorn backend.main:app --bind 0.0.0.0:8000 --workers 4 --timeout 120
else
    echo "Starting Flask server in DEVELOPMENT mode..."
    python backend/main.py
fi
