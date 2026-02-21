#!/bin/bash

# ScamShield Worker Script

echo "Starting ScamShield background workers..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Virtual environment not found. Please run setup first."
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Set environment variables
export FLASK_APP=main.py
export FLASK_ENV=development

# Check for worker type argument
WORKER_TYPE=${1:-all}

case $WORKER_TYPE in
    email)
        echo "Starting email worker..."
        python -c "
            from backend.workers.email_worker import start_email_worker
            start_email_worker()
        "
        ;;
    detection)
        echo "Starting detection worker..."
        python -c "
            from backend.workers.detection_worker import start_detection_worker
            start_detection_worker()
        "
        ;;
    alert)
        echo "Starting alert worker..."
        python -c "
            from backend.workers.alert_worker import start_alert_worker
            start_alert_worker()
        "
        ;;
    all)
        echo "Starting all workers..."
        python -c "
            from backend.workers.email_worker import start_email_worker
            from backend.workers.detection_worker import start_detection_worker
            from backend.workers.alert_worker import start_alert_worker
            
            start_email_worker()
            start_detection_worker()
            start_alert_worker()
            
            import time
            while True:
                time.sleep(1)
        "
        ;;
    *)
        echo "Usage: $0 [email|detection|alert|all]"
        exit 1
        ;;
esac
