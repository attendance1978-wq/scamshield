"""
ScamShield Admin Routes
Administrative endpoints for system management
"""
from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta

from backend.auth.jwt_handler import token_required, admin_required
from backend.database.db import get_session
from backend.database.models import User, ScanResult, Alert, BlacklistEntry, UserRole, RiskLevel
from backend.constants import BLACKLIST_CATEGORIES
from backend.config import config

admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/users', methods=['GET'])
@admin_required
def list_users(current_user):
    """List all users"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    role = request.args.get('role')
    is_active = request.args.get('is_active')
    
    with get_session() as session:
        query = session.query(User)
        
        if role:
            query = query.filter_by(role=UserRole(role))
        if is_active is not None:
            query = query.filter_by(is_active=is_active.lower() == 'true')
        
        total = query.count()
        users = query.offset((page - 1) * per_page).limit(per_page).all()
        
        return jsonify({
            'users': [{
                'id': u.id,
                'email': u.email,
                'username': u.username,
                'role': u.role.value,
                'is_active': u.is_active,
                'is_verified': u.is_verified,
                'created_at': u.created_at.isoformat() if u.created_at else None,
                'last_login': u.last_login.isoformat() if u.last_login else None
            } for u in users],
            'total': total,
            'page': page,
            'per_page': per_page
        })


@admin_bp.route('/users/<int:user_id>', methods=['GET'])
@admin_required
def get_user(current_user, user_id):
    """Get user details"""
    with get_session() as session:
        user = session.query(User).filter_by(id=user_id).first()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'id': user.id,
            'email': user.email,
            'username': user.username,
            'role': user.role.value,
            'is_active': user.is_active,
            'is_verified': user.is_verified,
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'last_login': user.last_login.isoformat() if user.last_login else None
        })


@admin_bp.route('/users/<int:user_id>', methods=['PUT'])
@admin_required
def update_user(current_user, user_id):
    """Update user"""
    data = request.get_json()
    
    with get_session() as session:
        user = session.query(User).filter_by(id=user_id).first()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if 'role' in data:
            try:
                user.role = UserRole(data['role'])
            except ValueError:
                return jsonify({'error': 'Invalid role'}), 400
        
        if 'is_active' in data:
            user.is_active = data['is_active']
        
        if 'is_verified' in data:
            user.is_verified = data['is_verified']
        
        session.commit()
        
        return jsonify({
            'message': 'User updated successfully',
            'user': {
                'id': user.id,
                'email': user.email,
                'username': user.username,
                'role': user.role.value,
                'is_active': user.is_active
            }
        })


@admin_bp.route('/users/<int:user_id>', methods=['DELETE'])
@admin_required
def delete_user(current_user, user_id):
    """Delete user"""
    if current_user.id == user_id:
        return jsonify({'error': 'Cannot delete yourself'}), 400
    
    with get_session() as session:
        user = session.query(User).filter_by(id=user_id).first()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        session.delete(user)
        session.commit()
    
    return jsonify({'message': 'User deleted successfully'})


@admin_bp.route('/blacklist', methods=['GET'])
@admin_required
def list_blacklist(current_user):
    """List blacklist entries"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    entry_type = request.args.get('type')
    category = request.args.get('category')
    is_active = request.args.get('is_active')
    
    with get_session() as session:
        query = session.query(BlacklistEntry)
        
        if entry_type:
            query = query.filter_by(entry_type=entry_type)
        if category:
            query = query.filter_by(category=category)
        if is_active is not None:
            query = query.filter_by(is_active=is_active.lower() == 'true')
        
        total = query.count()
        entries = query.order_by(BlacklistEntry.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
        
        return jsonify({
            'entries': [{
                'id': e.id,
                'entry_type': e.entry_type,
                'value': e.value,
                'category': e.category,
                'source': e.source,
                'confidence': e.confidence,
                'is_active': e.is_active,
                'created_at': e.created_at.isoformat() if e.created_at else None
            } for e in entries],
            'total': total,
            'page': page,
            'per_page': per_page
        })


@admin_bp.route('/blacklist', methods=['POST'])
@admin_required
def add_blacklist(current_user):
    """Add blacklist entry"""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    entry_type = data.get('type')
    value = data.get('value')
    category = data.get('category')
    
    if not entry_type or not value or not category:
        return jsonify({'error': 'Type, value, and category are required'}), 400
    
    if entry_type not in BLACKLIST_CATEGORIES.values():
        return jsonify({'error': 'Invalid entry type'}), 400
    
    with get_session() as session:
        # Check if entry exists
        existing = session.query(BlacklistEntry).filter_by(
            entry_type=entry_type,
            value=value
        ).first()
        
        if existing:
            return jsonify({'error': 'Entry already exists'}), 409
        
        entry = BlacklistEntry(
            entry_type=entry_type,
            value=value,
            category=category,
            source=data.get('source', 'manual'),
            confidence=data.get('confidence', 1.0),
            description=data.get('description'),
            is_active=True,
            created_at=datetime.utcnow()
        )
        
        session.add(entry)
        session.commit()
        
        return jsonify({
            'message': 'Blacklist entry added successfully',
            'entry': {
                'id': entry.id,
                'entry_type': entry.entry_type,
                'value': entry.value,
                'category': entry.category
            }
        }), 201


@admin_bp.route('/blacklist/<int:entry_id>', methods=['DELETE'])
@admin_required
def delete_blacklist(current_user, entry_id):
    """Delete blacklist entry"""
    with get_session() as session:
        entry = session.query(BlacklistEntry).filter_by(id=entry_id).first()
        
        if not entry:
            return jsonify({'error': 'Entry not found'}), 404
        
        session.delete(entry)
        session.commit()
    
    return jsonify({'message': 'Blacklist entry deleted successfully'})


@admin_bp.route('/alerts', methods=['GET'])
@admin_required
def list_alerts(current_user):
    """List alerts"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    priority = request.args.get('priority', type=int)
    is_sent = request.args.get('is_sent')
    
    with get_session() as session:
        query = session.query(Alert)
        
        if priority is not None:
            query = query.filter_by(priority=priority)
        if is_sent is not None:
            query = query.filter_by(is_sent=is_sent.lower() == 'true')
        
        total = query.count()
        alerts = query.order_by(Alert.created_at.desc()).offset((page - 1) * per_page).limit(per_page).all()
        
        return jsonify({
            'alerts': [{
                'id': a.id,
                'alert_type': a.alert_type,
                'priority': a.priority,
                'title': a.title,
                'message': a.message,
                'is_sent': a.is_sent,
                'delivery_status': a.delivery_status,
                'created_at': a.created_at.isoformat() if a.created_at else None
            } for a in alerts],
            'total': total,
            'page': page,
            'per_page': per_page
        })


@admin_bp.route('/stats', methods=['GET'])
@admin_required
def get_system_stats(current_user):
    """Get system statistics"""
    with get_session() as session:
        # User stats
        total_users = session.query(User).count()
        active_users = session.query(User).filter_by(is_active=True).count()
        
        # Scan stats
        total_scans = session.query(ScanResult).count()
        scams_detected = session.query(ScanResult).filter_by(is_scam=True).count()
        
        # Risk distribution
        low_risk = session.query(ScanResult).filter_by(risk_level=RiskLevel.LOW).count()
        medium_risk = session.query(ScanResult).filter_by(risk_level=RiskLevel.MEDIUM).count()
        high_risk = session.query(ScanResult).filter_by(risk_level=RiskLevel.HIGH).count()
        critical_risk = session.query(ScanResult).filter_by(risk_level=RiskLevel.CRITICAL).count()
        
        # Alert stats
        total_alerts = session.query(Alert).count()
        sent_alerts = session.query(Alert).filter_by(is_sent=True).count()
        
        # Blacklist stats
        blacklist_entries = session.query(BlacklistEntry).filter_by(is_active=True).count()
        
        # Recent activity (last 24 hours)
        day_ago = datetime.utcnow() - timedelta(days=1)
        recent_scans = session.query(ScanResult).filter(ScanResult.created_at >= day_ago).count()
        recent_alerts = session.query(Alert).filter(Alert.created_at >= day_ago).count()
        
        return jsonify({
            'users': {
                'total': total_users,
                'active': active_users
            },
            'scans': {
                'total': total_scans,
                'scams_detected': scams_detected,
                'detection_rate': round(scams_detected / total_scans * 100, 2) if total_scans > 0 else 0,
                'risk_distribution': {
                    'low': low_risk,
                    'medium': medium_risk,
                    'high': high_risk,
                    'critical': critical_risk
                }
            },
            'alerts': {
                'total': total_alerts,
                'sent': sent_alerts
            },
            'blacklist': {
                'entries': blacklist_entries
            },
            'recent_activity': {
                'scans_24h': recent_scans,
                'alerts_24h': recent_alerts
            }
        })


@admin_bp.route('/config', methods=['GET'])
@admin_required
def get_config(current_user):
    """Get sanitized configuration (no secrets)"""
    return jsonify({
        'flask_env': config.FLASK_ENV,
        'database_url': '***hidden***' if config.DATABASE_URL else None,
        'email_imap_server': config.EMAIL_IMAP_SERVER,
        'email_smtp_server': config.EMAIL_SMTP_SERVER,
        'redis_connected': True,  # Would check actual connection
        'log_level': config.LOG_LEVEL
    })
