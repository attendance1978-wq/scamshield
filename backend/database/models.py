"""
ScamShield Database Models
SQLAlchemy ORM models for the application
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, Float, ForeignKey, Enum, JSON
from sqlalchemy.orm import relationship
import enum

from backend.database.db import Base


class UserRole(enum.Enum):
    """User role enumeration"""
    USER = "user"
    ADMIN = "admin"
    MODERATOR = "moderator"


class ScanStatus(enum.Enum):
    """Scan status enumeration"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class RiskLevel(enum.Enum):
    """Risk level enumeration"""
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3


class User(Base):
    """User model"""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.USER)
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    scans = relationship("ScanResult", back_populates="user")
    alerts = relationship("Alert", back_populates="user")


class Email(Base):
    """Email model for storing scanned emails"""
    __tablename__ = 'emails'
    
    id = Column(Integer, primary_key=True, index=True)
    message_id = Column(String(500), unique=True, index=True)
    subject = Column(String(500))
    sender = Column(String(255), index=True)
    sender_email = Column(String(255), index=True)
    recipient = Column(String(255))
    body_text = Column(Text)
    body_html = Column(Text)
    received_at = Column(DateTime, index=True)
    processed_at = Column(DateTime, nullable=True)
    is_read = Column(Boolean, default=False)
    is_spam = Column(Boolean, default=False)
    has_attachments = Column(Boolean, default=False)
    headers = Column(JSON, nullable=True)
    email_metadata = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan_results = relationship("ScanResult", back_populates="email")


class ScanResult(Base):
    """Scan result model"""
    __tablename__ = 'scan_results'
    
    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(String(100), unique=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    email_id = Column(Integer, ForeignKey('emails.id'), nullable=True)
    scan_type = Column(String(50))  # 'email', 'url', 'domain', 'text'
    content = Column(Text)  # The content that was scanned
    url = Column(String(2048), nullable=True)
    domain = Column(String(255), nullable=True)
    
    # Detection results
    is_scam = Column(Boolean, default=False)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(Enum(RiskLevel), default=RiskLevel.LOW)
    category = Column(String(100), nullable=True)
    confidence = Column(Float, default=0.0)
    
    # Detailed results
    detection_methods = Column(JSON, nullable=True)  # Which methods detected the scam
    details = Column(JSON, nullable=True)  # Detailed analysis results
    recommendations = Column(Text, nullable=True)
    
    # Status
    status = Column(Enum(ScanStatus), default=ScanStatus.PENDING)
    error_message = Column(Text, nullable=True)
    
    # Timestamps
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="scans")
    email = relationship("Email", back_populates="scan_results")
    alerts = relationship("Alert", back_populates="scan_result")


class Alert(Base):
    """Alert model"""
    __tablename__ = 'alerts'
    
    id = Column(Integer, primary_key=True, index=True)
    alert_type = Column(String(50))  # 'email', 'webhook', 'sms', etc.
    priority = Column(Integer, default=1)  # 0=Low, 1=Medium, 2=High, 3=Urgent
    title = Column(String(255))
    message = Column(Text)
    
    # Related entities
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    scan_result_id = Column(Integer, ForeignKey('scan_results.id'), nullable=True)
    
    # Delivery status
    is_sent = Column(Boolean, default=False)
    sent_at = Column(DateTime, nullable=True)
    delivery_status = Column(String(50), nullable=True)
    error_message = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="alerts")
    scan_result = relationship("ScanResult", back_populates="alerts")


class BlacklistEntry(Base):
    """Blacklist entry model"""
    __tablename__ = 'blacklist'
    
    id = Column(Integer, primary_key=True, index=True)
    entry_type = Column(String(20))  # 'domain', 'ip', 'url', 'email', 'keyword'
    value = Column(String(2048), index=True)
    category = Column(String(100))  # The type of threat
    source = Column(String(255))  # Where this entry came from
    confidence = Column(Float, default=1.0)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ReputationRecord(Base):
    """Domain/IP reputation record"""
    __tablename__ = 'reputation_records'
    
    id = Column(Integer, primary_key=True, index=True)
    entity_type = Column(String(20))  # 'domain' or 'ip'
    entity_value = Column(String(255), index=True)
    
    # Reputation scores (0-100)
    trust_score = Column(Float, default=50.0)
    safety_score = Column(Float, default=50.0)
    threat_score = Column(Float, default=0.0)
    
    # Detailed metrics
    is_malicious = Column(Boolean, default=False)
    is_suspicious = Column(Boolean, default=False)
    is_new_domain = Column(Boolean, default=False)
    is_parked = Column(Boolean, default=False)
    
    # Additional info
    registrar = Column(String(255), nullable=True)
    registration_date = Column(DateTime, nullable=True)
    expiration_date = Column(DateTime, nullable=True)
    country = Column(String(10), nullable=True)
    asn = Column(String(20), nullable=True)
    isp = Column(String(255), nullable=True)
    
    # Source data
    sources = Column(JSON, nullable=True)
    
    # Timestamps
    last_checked = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)


class APIKey(Base):
    """API Key model for programmatic access"""
    __tablename__ = 'api_keys'
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    key_hash = Column(String(255), unique=True, index=True)
    name = Column(String(100))
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, default=True)
    last_used = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    """Audit log for tracking user actions"""
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=True)
    action = Column(String(100))
    resource_type = Column(String(50))
    resource_id = Column(String(100), nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
