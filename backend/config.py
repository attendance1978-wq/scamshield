"""
ScamShield Configuration Module
Handles environment variables and application settings
"""
import os
from dotenv import load_dotenv
from dataclasses import dataclass
from typing import Optional

load_dotenv()


@dataclass
class Config:
    """Application Configuration"""
    
    # Flask Settings
    FLASK_APP: str = os.getenv('FLASK_APP', 'main.py')
    FLASK_ENV: str = os.getenv('FLASK_ENV', 'development')
    FLASK_DEBUG: bool = os.getenv('FLASK_DEBUG', '1') == '1'
    SECRET_KEY: str = os.getenv('SECRET_KEY', 'dev-secret-key')
    
    # Database Settings
    DATABASE_URL: str = os.getenv('DATABASE_URL', 'sqlite:///database/scamshield.db')
    SQLALCHEMY_DATABASE_URI: str = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///database/scamshield.db')
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False
    
    # JWT Settings
    JWT_SECRET_KEY: str = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key')
    JWT_ACCESS_TOKEN_EXPIRES: int = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', '3600'))
    JWT_REFRESH_TOKEN_EXPIRES: int = int(os.getenv('JWT_REFRESH_TOKEN_EXPIRES', '86400'))
    
    # Email Settings
    EMAIL_IMAP_SERVER: str = os.getenv('EMAIL_IMAP_SERVER', 'imap.gmail.com')
    EMAIL_IMAP_PORT: int = int(os.getenv('EMAIL_IMAP_PORT', '993'))
    EMAIL_SMTP_SERVER: str = os.getenv('EMAIL_SMTP_SERVER', 'smtp.gmail.com')
    EMAIL_SMTP_PORT: int = int(os.getenv('EMAIL_SMTP_PORT', '587'))
    EMAIL_ACCOUNT: str = os.getenv('EMAIL_ACCOUNT', '')
    EMAIL_PASSWORD: str = os.getenv('EMAIL_PASSWORD', '')
    EMAIL_USE_SSL: bool = os.getenv('EMAIL_USE_SSL', 'True') == 'True'
    EMAIL_USE_TLS: bool = os.getenv('EMAIL_USE_TLS', 'True') == 'True'
    
    # Redis Settings
    REDIS_URL: str = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    REDIS_CACHE_TTL: int = int(os.getenv('REDIS_CACHE_TTL', '300'))
    
    # Celery Settings
    CELERY_BROKER_URL: str = os.getenv('CELERY_BROKER_URL', 'redis://localhost:6379/1')
    CELERY_RESULT_BACKEND: str = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost:6379/2')
    
    # API Keys
    VIRUSTOTAL_API_KEY: str = os.getenv('VIRUSTOTAL_API_KEY', '')
    ABUSEIPDB_API_KEY: str = os.getenv('ABUSEIPDB_API_KEY', '')
    ALPHA_VANTAGE_API_KEY: str = os.getenv('ALPHA_VANTAGE_API_KEY', '')
    
    # ML Model Settings
    ML_MODEL_PATH: str = os.getenv('ML_MODEL_PATH', 'models/scam_classifier.pkl')
    ML_CONFIDENCE_THRESHOLD: float = float(os.getenv('ML_CONFIDENCE_THRESHOLD', '0.7'))
    
    # Alert Settings
    ALERT_EMAIL_ENABLED: bool = os.getenv('ALERT_EMAIL_ENABLED', 'True') == 'True'
    ALERT_EMAIL_FROM: str = os.getenv('ALERT_EMAIL_FROM', 'noreply@scamshield.com')
    ALERT_EMAIL_TO: str = os.getenv('ALERT_EMAIL_TO', 'admin@scamshield.com')
    ALERT_WEBHOOK_URL: str = os.getenv('ALERT_WEBHOOK_URL', '')
    
    # WebSocket Settings
    WEBSOCKET_PING_TIMEOUT: int = int(os.getenv('WEBSOCKET_PING_TIMEOUT', '60'))
    WEBSOCKET_PING_INTERVAL: int = int(os.getenv('WEBSOCKET_PING_INTERVAL', '25'))
    
    # Logging Settings
    LOG_LEVEL: str = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE: str = os.getenv('LOG_FILE', 'logs/scamshield.log')
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv('RATE_LIMIT_PER_MINUTE', '60'))
    RATE_LIMIT_STORAGE: str = os.getenv('RATE_LIMIT_STORAGE', 'redis://localhost:6379/3')
    
    # Admin Settings
    ADMIN_EMAIL: str = os.getenv('ADMIN_EMAIL', 'admin@scamshield.com')
    ADMIN_PASSWORD: str = os.getenv('ADMIN_PASSWORD', 'admin123')


class DevelopmentConfig(Config):
    """Development Configuration"""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Production Configuration"""
    DEBUG = False
    TESTING = False


class TestingConfig(Config):
    """Testing Configuration"""
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    JWT_ACCESS_TOKEN_EXPIRES = 5


def get_config(env: Optional[str] = None) -> Config:
    """Get configuration based on environment"""
    env = env or os.getenv('FLASK_ENV', 'development')
    
    configs = {
        'development': DevelopmentConfig,
        'production': ProductionConfig,
        'testing': TestingConfig
    }
    
    return configs.get(env, DevelopmentConfig)()


# Create config instance
config = get_config()
