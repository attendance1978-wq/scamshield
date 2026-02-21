"""
ScamShield Database Schema
SQLAlchemy table definitions and schema utilities
"""
from sqlalchemy import Table, Column, Integer, String, Text, DateTime, Boolean, Float, ForeignKey, Enum, JSON, Index
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import JSONB

from backend.database.db import Base
from backend.database.models import UserRole, ScanStatus, RiskLevel


# User Role Enum for SQLAlchemy
user_role_enum = Enum(UserRole, name='user_role')
scan_status_enum = Enum(ScanStatus, name='scan_status')
risk_level_enum = Enum(RiskLevel, name='risk_level')


# Table creation functions
def create_user_table(metadata):
    """Create users table"""
    return Table(
        'users',
        metadata,
        Column('id', Integer, primary_key=True, index=True),
        Column('email', String(255), unique=True, index=True, nullable=False),
        Column('username', String(100), unique=True, index=True, nullable=False),
        Column('password_hash', String(255), nullable=False),
        Column('role', user_role_enum, default=UserRole.USER),
        Column('is_active', Boolean, default=True),
        Column('is_verified', Boolean, default=False),
        Column('created_at', DateTime, default='CURRENT_TIMESTAMP'),
        Column('updated_at', DateTime, default='CURRENT_TIMESTAMP', onupdate='CURRENT_TIMESTAMP'),
        Column('last_login', DateTime, nullable=True),
        extend_existing=True
    )


def create_email_table(metadata):
    """Create emails table"""
    return Table(
        'emails',
        metadata,
        Column('id', Integer, primary_key=True, index=True),
        Column('message_id', String(500), unique=True, index=True),
        Column('subject', String(500)),
        Column('sender', String(255), index=True),
        Column('sender_email', String(255), index=True),
        Column('recipient', String(255)),
        Column('body_text', Text),
        Column('body_html', Text),
        Column('received_at', DateTime, index=True),
        Column('processed_at', DateTime, nullable=True),
        Column('is_read', Boolean, default=False),
        Column('is_spam', Boolean, default=False),
        Column('has_attachments', Boolean, default=False),
        Column('headers', JSON, nullable=True),
        Column('metadata', JSON, nullable=True),
        Column('created_at', DateTime, default='CURRENT_TIMESTAMP'),
        extend_existing=True
    )


def create_scan_result_table(metadata):
    """Create scan_results table"""
    return Table(
        'scan_results',
        metadata,
        Column('id', Integer, primary_key=True, index=True),
        Column('scan_id', String(100), unique=True, index=True),
        Column('user_id', Integer, ForeignKey('users.id'), nullable=True),
        Column('email_id', Integer, ForeignKey('emails.id'), nullable=True),
        Column('scan_type', String(50)),
        Column('content', Text),
        Column('url', String(2048), nullable=True),
        Column('domain', String(255), nullable=True),
        Column('is_scam', Boolean, default=False),
        Column('risk_score', Float, default=0.0),
        Column('risk_level', risk_level_enum, default=RiskLevel.LOW),
        Column('category', String(100), nullable=True),
        Column('confidence', Float, default=0.0),
        Column('detection_methods', JSON, nullable=True),
        Column('details', JSON, nullable=True),
        Column('recommendations', Text, nullable=True),
        Column('status', scan_status_enum, default=ScanStatus.PENDING),
        Column('error_message', Text, nullable=True),
        Column('started_at', DateTime, default='CURRENT_TIMESTAMP'),
        Column('completed_at', DateTime, nullable=True),
        Column('created_at', DateTime, default='CURRENT_TIMESTAMP'),
        extend_existing=True
    )


def create_alert_table(metadata):
    """Create alerts table"""
    return Table(
        'alerts',
        metadata,
        Column('id', Integer, primary_key=True, index=True),
        Column('alert_type', String(50)),
        Column('priority', Integer, default=1),
        Column('title', String(255)),
        Column('message', Text),
        Column('user_id', Integer, ForeignKey('users.id'), nullable=True),
        Column('scan_result_id', Integer, ForeignKey('scan_results.id'), nullable=True),
        Column('is_sent', Boolean, default=False),
        Column('sent_at', DateTime, nullable=True),
        Column('delivery_status', String(50), nullable=True),
        Column('error_message', Text, nullable=True),
        Column('created_at', DateTime, default='CURRENT_TIMESTAMP'),
        extend_existing=True
    )


def create_blacklist_table(metadata):
    """Create blacklist table"""
    return Table(
        'blacklist',
        metadata,
        Column('id', Integer, primary_key=True, index=True),
        Column('entry_type', String(20)),
        Column('value', String(2048), index=True),
        Column('category', String(100)),
        Column('source', String(255)),
        Column('confidence', Float, default=1.0),
        Column('description', Text, nullable=True),
        Column('is_active', Boolean, default=True),
        Column('expires_at', DateTime, nullable=True),
        Column('created_at', DateTime, default='CURRENT_TIMESTAMP'),
        Column('updated_at', DateTime, default='CURRENT_TIMESTAMP', onupdate='CURRENT_TIMESTAMP'),
        extend_existing=True
    )


def create_reputation_table(metadata):
    """Create reputation_records table"""
    return Table(
        'reputation_records',
        metadata,
        Column('id', Integer, primary_key=True, index=True),
        Column('entity_type', String(20)),
        Column('entity_value', String(255), index=True),
        Column('trust_score', Float, default=50.0),
        Column('safety_score', Float, default=50.0),
        Column('threat_score', Float, default=0.0),
        Column('is_malicious', Boolean, default=False),
        Column('is_suspicious', Boolean, default=False),
        Column('is_new_domain', Boolean, default=False),
        Column('is_parked', Boolean, default=False),
        Column('registrar', String(255), nullable=True),
        Column('registration_date', DateTime, nullable=True),
        Column('expiration_date', DateTime, nullable=True),
        Column('country', String(10), nullable=True),
        Column('asn', String(20), nullable=True),
        Column('isp', String(255), nullable=True),
        Column('sources', JSON, nullable=True),
        Column('last_checked', DateTime, default='CURRENT_TIMESTAMP'),
        Column('created_at', DateTime, default='CURRENT_TIMESTAMP'),
        extend_existing=True
    )


def create_api_key_table(metadata):
    """Create api_keys table"""
    return Table(
        'api_keys',
        metadata,
        Column('id', Integer, primary_key=True, index=True),
        Column('user_id', Integer, ForeignKey('users.id')),
        Column('key_hash', String(255), unique=True, index=True),
        Column('name', String(100)),
        Column('description', Text, nullable=True),
        Column('is_active', Boolean, default=True),
        Column('last_used', DateTime, nullable=True),
        Column('expires_at', DateTime, nullable=True),
        Column('created_at', DateTime, default='CURRENT_TIMESTAMP'),
        extend_existing=True
    )


def create_audit_log_table(metadata):
    """Create audit_logs table"""
    return Table(
        'audit_logs',
        metadata,
        Column('id', Integer, primary_key=True, index=True),
        Column('user_id', Integer, ForeignKey('users.id'), nullable=True),
        Column('action', String(100)),
        Column('resource_type', String(50)),
        Column('resource_id', String(100), nullable=True),
        Column('ip_address', String(45), nullable=True),
        Column('user_agent', String(500), nullable=True),
        Column('details', JSON, nullable=True),
        Column('created_at', DateTime, default='CURRENT_TIMESTAMP'),
        extend_existing=True
    )


# Index definitions for performance
INDEXES = [
    # User indexes
    Index('idx_user_email', 'email'),
    Index('idx_user_username', 'username'),
    Index('idx_user_role', 'role'),
    
    # Email indexes
    Index('idx_email_sender', 'sender'),
    Index('idx_email_sender_email', 'sender_email'),
    Index('idx_email_received', 'received_at'),
    
    # Scan result indexes
    Index('idx_scan_user', 'user_id'),
    Index('idx_scan_email', 'email_id'),
    Index('idx_scan_status', 'status'),
    Index('idx_scan_risk_level', 'risk_level'),
    Index('idx_scan_is_scam', 'is_scam'),
    Index('idx_scan_created', 'created_at'),
    
    # Alert indexes
    Index('idx_alert_user', 'user_id'),
    Index('idx_alert_scan', 'scan_result_id'),
    Index('idx_alert_priority', 'priority'),
    Index('idx_alert_created', 'created_at'),
    
    # Blacklist indexes
    Index('idx_blacklist_type', 'entry_type'),
    Index('idx_blacklist_value', 'value'),
    Index('idx_blacklist_category', 'category'),
    Index('idx_blacklist_active', 'is_active'),
    
    # Reputation indexes
    Index('idx_reputation_type_value', 'entity_type', 'entity_value'),
]


# Database version/migration tracking
DB_VERSION = 1


def get_schema_info():
    """Get database schema information"""
    return {
        'version': DB_VERSION,
        'tables': [
            'users',
            'emails',
            'scan_results',
            'alerts',
            'blacklist',
            'reputation_records',
            'api_keys',
            'audit_logs'
        ],
        'indexes': len(INDEXES)
    }
