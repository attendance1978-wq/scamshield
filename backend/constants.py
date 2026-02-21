"""
ScamShield Constants Module
Global constants used throughout the application
"""

# Scam Detection Categories
SCAM_CATEGORIES = {
    'PHISHING': 'Phishing',
    'FRAUD': 'Fraud',
    'MALWARE': 'Malware',
    'SPAM': 'Spam',
    'EXTORTION': 'Extortion',
    'IMPERSINATION': 'Impersonation',
    'FAKE_STORE': 'Fake Store',
    'CRYPTO_SCAM': 'Crypto Scam',
    'ROMANCE_SCAM': 'Romance Scam',
    'TECH_SUPPORT_SCAM': 'Tech Support Scam',
    'GOVERNMENT_IMPERSONATION': 'Government Impersonation',
    'LEGITIMATE': 'Legitimate'
}

# Risk Levels
RISK_LEVELS = {
    'LOW': 0,
    'MEDIUM': 1,
    'HIGH': 2,
    'CRITICAL': 3
}

RISK_LEVEL_NAMES = {
    0: 'Low',
    1: 'Medium',
    2: 'High',
    3: 'Critical'
}

# Email Alert Priorities
ALERT_PRIORITIES = {
    'LOW': 0,
    'MEDIUM': 1,
    'HIGH': 2,
    'URGENT': 3
}

# Common Phishing Keywords
PHISHING_KEYWORDS = [
    'urgent action required',
    'verify your account',
    'suspended',
    'locked',
    'unauthorized access',
    'confirm your identity',
    'update payment',
    'expired',
    'click here to verify',
    'immediate attention',
    'account verification',
    'security alert',
    'unusual activity',
    'password expiration',
    'bank account',
    'credit card',
    'social security',
    'irs',
    'tax refund',
    'lottery winner',
    'inheritance',
    'prince',
    'nigerian prince',
    'bitcoin',
    'investment opportunity',
    'make money fast',
    'work from home',
    'double your money',
    'guaranteed return',
    'risk free',
    'limited time offer',
    'act now',
    'don\'t miss out',
    'free gift',
    'free prize',
    'winner',
    'congratulations',
    'you have been selected',
    'claim your prize'
]

# Suspicious URL Patterns
SUSPICIOUS_URL_PATTERNS = [
    r'login\.php',
    r'signin\.php',
    r'verify\.php',
    r'secure\.php',
    r'account-update',
    r'banking-login',
    r'paypal-verify',
    r'amazon-order',
    r'netflix-payment',
    r'apple-id-verify'
]

# Common Fake Domain Patterns
FAKE_DOMAIN_PATTERNS = [
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address as domain
    r'[a-z]{10,}\.com',  # Long random domain
    r'(.+)@(.+)\.(.+){2,10}',  # Email as domain
    r'.*-(login|signin|secure|verify|account|update).*',
    r'.*\d{4,}.*'  # Domain with many numbers
]

# Typosquatting Common Brands
TYPOSQUATTING_TARGETS = [
    'google', 'facebook', 'amazon', 'apple', 'microsoft',
    'paypal', 'netflix', 'twitter', 'instagram', 'linkedin',
    'bankofamerica', 'chase', 'wellsfargo', 'citi', 'usbank',
    'irs', 'socialsecurity', 'medicare', 'fedex', 'ups', 'dhl'
]

# Maximum Analysis Lengths
MAX_EMAIL_SUBJECT_LENGTH = 200
MAX_EMAIL_BODY_LENGTH = 50000
MAX_URL_LENGTH = 2048
MAX_DOMAIN_LENGTH = 253

# Analysis Thresholds
URL_ANALYSIS_THRESHOLD = 0.7
DOMAIN_REPUTATION_THRESHOLD = 0.6
ML_CONFIDENCE_THRESHOLD = 0.7
SIMILARITY_THRESHOLD = 0.85

# API Rate Limits
API_RATE_LIMIT_PER_MINUTE = 60
API_RATE_LIMIT_PER_HOUR = 1000

# Cache TTL (seconds)
CACHE_TTL_SHORT = 60  # 1 minute
CACHE_TTL_MEDIUM = 300  # 5 minutes
CACHE_TTL_LONG = 3600  # 1 hour
CACHE_TTL_DAY = 86400  # 24 hours

# Database Constants
MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 20

# WebSocket Events
WS_EVENT_SCAN_COMPLETE = 'scan_complete'
WS_EVENT_NEW_ALERT = 'new_alert'
WS_EVENT_STATUS_UPDATE = 'status_update'
WS_EVENT_THREAT_DETECTED = 'threat_detected'

# Email Processing
EMAIL_FETCH_INTERVAL = 60  # seconds
EMAIL_BATCH_SIZE = 50
EMAIL_PROCESSING_TIMEOUT = 30  # seconds

# Background Worker Intervals
DETECTION_WORKER_INTERVAL = 5  # seconds
ALERT_WORKER_INTERVAL = 10  # seconds

# Blacklist Categories
BLACKLIST_CATEGORIES = {
    'DOMAIN': 'domain',
    'IP': 'ip',
    'URL': 'url',
    'EMAIL': 'email',
    'KEYWORD': 'keyword'
}

# HTTP Methods
HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']

# Response Messages
MESSAGES = {
    'USER_REGISTERED': 'User registered successfully',
    'USER_LOGGED_IN': 'Login successful',
    'USER_LOGGED_OUT': 'Logout successful',
    'EMAIL_SCANNED': 'Email scanned successfully',
    'SCAM_DETECTED': 'Potential scam detected',
    'NO_THREAT_FOUND': 'No threat detected',
    'ANALYSIS_COMPLETE': 'Analysis complete',
    'ALERT_SENT': 'Alert sent successfully',
    'UNAUTHORIZED': 'Unauthorized access',
    'INVALID_CREDENTIALS': 'Invalid credentials',
    'USER_NOT_FOUND': 'User not found',
    'EMAIL_NOT_FOUND': 'Email not found',
    'VALIDATION_ERROR': 'Validation error',
    'INTERNAL_ERROR': 'Internal server error'
}
