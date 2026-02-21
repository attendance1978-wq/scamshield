# ScamShield 🛡️

ScamShield is a comprehensive email scam detection and prevention system that uses advanced AI and machine learning to identify phishing attempts, fraudulent emails, and malicious links.

## Features

- **AI-Powered Detection**: Advanced machine learning models analyze emails for suspicious patterns
- **Real-Time Scanning**: Instant analysis with detailed risk scores and threat categorization
- **URL Analysis**: Deep inspection of links to identify malicious websites
- **Email Monitoring**: Automatic scanning of incoming emails
- **Threat Intelligence**: Continuous updates from global threat databases
- **Multi-Channel Alerts**: Email, WebSocket, and in-app notifications
- **User Dashboard**: Comprehensive dashboard for managing scans and alerts
- **RESTful API**: Full API for programmatic access

## Tech Stack

### Backend
- **Python 3.11+**: Primary programming language
- **Flask**: Web framework
- **SQLAlchemy**: ORM for database operations
- **SQLite**: Default database (easily swappable to PostgreSQL)
- **Redis**: Caching and message broker
- **Celery**: Background task processing
- **JWT**: Authentication tokens

### Frontend
- **HTML5/CSS3**: Modern responsive UI
- **Vanilla JavaScript**: No heavy framework dependencies
- **WebSocket**: Real-time updates

## Project Structure

```
scamshield/
├── backend/
│   ├── main.py                 # Application entry point
│   ├── config.py               # Configuration
│   ├── constants.py            # Global constants
│   ├── api/                    # REST API routes
│   │   ├── routes.py
│   │   ├── auth_routes.py
│   │   ├── email_routes.py
│   │   └── admin_routes.py
│   ├── auth/                   # Authentication
│   ├── detection/              # Scam detection engine
│   ├── email/                  # Email monitoring
│   ├── intel/                  # Threat intelligence
│   ├── decision/               # Decision engine
│   ├── alert/                  # Notification system
│   ├── realtime/               # WebSocket server
│   ├── database/               # Database models
│   ├── cache/                  # Caching layer
│   ├── workers/                # Background workers
│   └── utils/                  # Utilities
├── frontend/
│   ├── index.html              # Landing page
│   ├── dashboard.html          # User dashboard
│   ├── login.html              # Login page
│   ├── register.html           # Registration page
│   ├── css/styles.css          # Styles
│   └── js/                     # JavaScript files
├── tests/                      # Unit tests
├── docker/                     # Docker configuration
├── scripts/                    # Shell scripts
├── database/                   # Database files
└── logs/                       # Application logs
```

## Installation

### Prerequisites

- Python 3.11 or higher
- Redis (optional, for caching and message broker)
- Git

### Setup

1. **Clone the repository**
   
```
bash
   git clone https://github.com/attendance1978-wq/scamshield.git
   cd scamshield
   
```

2. **Create virtual environment**
   
```
bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   
```

3. **Install dependencies**
   
```
bash
   pip install -r requirements.txt
   
```

4. **Configure environment variables**
   
```
bash
   cp .env.example .env
   # Edit .env with your settings
   
```

5. **Initialize database**
   
```
bash
   bash scripts/init_db.sh
   
```

6. **Start the application**
   
```
bash
   bash scripts/start.sh
   
```

The application will be available at `http://localhost:5000`

## Docker Deployment

### Using Docker Compose

```
bash
cd docker
docker-compose up -d
```

### Manual Docker Build

```
bash
docker build -t scamshield .
docker run -d -p 5000:5000 scamshield
```

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout
- `GET /api/auth/me` - Get current user

### Scanning
- `POST /api/scan` - Scan content for scams
- `GET /api/scan/<scan_id>` - Get scan result
- `GET /api/scans` - Get scan history

### Statistics
- `GET /api/stats` - Get scan statistics

### Email (requires authentication)
- `GET /api/email` - Get scanned emails
- `POST /api/email/connect` - Connect email account
- `POST /api/email/sync` - Sync emails

### Admin (requires admin role)
- `GET /api/admin/users` - Get all users
- `GET /api/admin/stats` - Get system statistics
- `GET /api/admin/blacklist` - Get blacklist entries

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| FLASK_APP | Flask application module | main.py |
| FLASK_ENV | Environment | development |
| DATABASE_URL | Database connection string | sqlite:///database/scamshield.db |
| JWT_SECRET_KEY | JWT signing key | (generated) |
| REDIS_URL | Redis connection URL | redis://localhost:6379/0 |
| EMAIL_IMAP_SERVER | IMAP server for email | imap.gmail.com |
| VIRUSTOTAL_API_KEY | VirusTotal API key | (empty) |

## Usage

### Scanning Emails

```
python
import requests

# Scan email content
response = requests.post('/api/scan', json={
    'content': 'Your suspicious email content here',
    'type': 'email'
}, headers={
    'Authorization': 'Bearer YOUR_TOKEN'
})

result = response.json()
print(f"Is Scam: {result['is_scam']}")
print(f"Risk Score: {result['risk_score']}")
```

### Using the Dashboard

1. Register a new account at `/register.html`
2. Login at `/login.html`
3. Use the dashboard to scan emails/URLs
4. View scan history and statistics

## Development

### Running Tests

```
bash
pytest tests/ -v
```

### Code Style

The project follows PEP 8 style guidelines. Use flake8 to check:

```
bash
flake8 backend/
```

## Architecture

### Detection Pipeline

1. **Input Processing**: Email/URL/text is parsed and normalized
2. **Rule-Based Detection**: Keywords, patterns, and blacklists are checked
3. **ML Classification**: AI model predicts scam probability
4. **URL Analysis**: Links are checked for malicious patterns
5. **Domain Reputation**: Domain age and reputation are verified
6. **Similarity Check**: Content is compared to known scam patterns
7. **Risk Scoring**: All results are combined into a final risk score
8. **Verdict**: Based on threshold, content is flagged as scam or safe

### Background Workers

- **Email Worker**: Monitors connected email accounts for new messages
- **Detection Worker**: Processes scan requests in background
- **Alert Worker**: Sends notifications for detected threats

## Security Considerations

- Always change default secret keys in production
- Use HTTPS in production
- Implement rate limiting
- Keep dependencies updated
- Review and update blacklist regularly

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## License

MIT License

## Support

For issues and feature requests, please open an issue on GitHub.

## Acknowledgments

- VirusTotal API for threat intelligence
- Various open-source ML libraries
