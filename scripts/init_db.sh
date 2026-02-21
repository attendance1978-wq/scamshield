#!/bin/bash

# ScamShield Database Initialization Script

echo "Initializing ScamShield database..."

# Create database directory if not exists
mkdir -p database

# Check if virtual environment exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Set Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)"

# Initialize database
python -c "
import sys
sys.path.insert(0, '.')
from backend.database.db import init_db, reset_db
from backend.database.models import User, BlacklistEntry
from backend.auth.password_hash import hash_password

# Initialize tables
print('Creating database tables...')
init_db()

# Create default admin user
from backend.database.db import get_session
from backend.database.models import UserRole

with get_session() as session:
    # Check if admin exists
    admin = session.query(User).filter_by(email='admin@scamshield.com').first()
    
    if not admin:
        print('Creating default admin user...')
        admin = User(
            email='admin@scamshield.com',
            username='admin',
            password_hash=hash_password('admin123'),
            role=UserRole.ADMIN,
            is_active=True,
            is_verified=True
        )
        session.add(admin)
        session.commit()
        print('Admin user created: admin@scamshield.com / admin123')
    else:
        print('Admin user already exists')

    # Add some default blacklist entries
    print('Adding default blacklist entries...')
    
    default_blacklist = [
        ('domain', 'fake-bank.com', 'PHISHING', 'Default blacklist'),
        ('domain', 'paypal-verify.net', 'PHISHING', 'Default blacklist'),
        ('domain', 'amazon-order-cancel.com', 'PHISHING', 'Default blacklist'),
        ('domain', 'apple-id-verify.net', 'PHISHING', 'Default blacklist'),
        ('domain', 'netflix-payment-update.com', 'PHISHING', 'Default blacklist'),
        ('keyword', 'urgent action required', 'PHISHING', 'Default keywords'),
        ('keyword', 'verify your account now', 'PHISHING', 'Default keywords'),
        ('keyword', 'account suspended', 'PHISHING', 'Default keywords'),
        ('keyword', 'click here to verify', 'PHISHING', 'Default keywords'),
    ]
    
    for entry_type, value, category, source in default_blacklist:
        existing = session.query(BlacklistEntry).filter_by(
            entry_type=entry_type,
            value=value
        ).first()
        
        if not existing:
            blacklist_entry = BlacklistEntry(
                entry_type=entry_type,
                value=value,
                category=category,
                source=source,
                confidence=1.0
            )
            session.add(blacklist_entry)
    
    session.commit()
    print('Blacklist entries added')

print('Database initialization complete!')
"
