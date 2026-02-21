"""
ScamShield Authentication Routes
User registration, login, and authentication endpoints
"""
from flask import Blueprint, request, jsonify
from datetime import datetime, timedelta

from backend.auth.jwt_handler import create_access_token, create_refresh_token, token_required
from backend.auth.password_hash import hash_password, verify_password
from backend.database.db import get_session
from backend.database.models import User, UserRole
from backend.constants import MESSAGES
from backend.config import config

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/register', methods=['POST'])
def register():
    """Register a new user"""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    # Validate required fields
    required_fields = ['email', 'username', 'password']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'{field} is required'}), 400
    
    email = data.get('email', '').lower().strip()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    # Validate email format
    if '@' not in email or '.' not in email:
        return jsonify({'error': 'Invalid email format'}), 400
    
    # Validate password strength
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    
    # Check if user already exists
    with get_session() as session:
        existing_user = session.query(User).filter(
            (User.email == email) | (User.username == username)
        ).first()
        
        if existing_user:
            return jsonify({'error': 'User already exists'}), 409
        
        # Create new user
        password_hash = hash_password(password)
        user = User(
            email=email,
            username=username,
            password_hash=password_hash,
            role=UserRole.USER,
            is_active=True,
            created_at=datetime.utcnow()
        )
        
        session.add(user)
        session.commit()
        
        # Generate tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        return jsonify({
            'message': MESSAGES['USER_REGISTERED'],
            'user': {
                'id': user.id,
                'email': user.email,
                'username': user.username,
                'role': user.role.value
            },
            'access_token': access_token,
            'refresh_token': refresh_token
        }), 201


@auth_bp.route('/login', methods=['POST'])
def login():
    """User login"""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    email = data.get('email', '').lower().strip()
    password = data.get('password', '')
    
    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400
    
    # Find user
    with get_session() as session:
        user = session.query(User).filter_by(email=email).first()
        
        if not user or not verify_password(password, user.password_hash):
            return jsonify({'error': MESSAGES['INVALID_CREDENTIALS']}), 401
        
        if not user.is_active:
            return jsonify({'error': 'Account is disabled'}), 403
        
        # Update last login
        user.last_login = datetime.utcnow()
        session.commit()
        
        # Generate tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        return jsonify({
            'message': MESSAGES['USER_LOGGED_IN'],
            'user': {
                'id': user.id,
                'email': user.email,
                'username': user.username,
                'role': user.role.value
            },
            'access_token': access_token,
            'refresh_token': refresh_token
        })


@auth_bp.route('/refresh', methods=['POST'])
@token_required
def refresh(current_user):
    """Refresh access token"""
    access_token = create_access_token(identity=current_user.id)
    
    return jsonify({
        'access_token': access_token
    })


@auth_bp.route('/logout', methods=['POST'])
@token_required
def logout(current_user):
    """User logout"""
    # In a production system, you might want to blacklist the token
    return jsonify({
        'message': MESSAGES['USER_LOGGED_OUT']
    })


@auth_bp.route('/me', methods=['GET'])
@token_required
def get_current_user(current_user):
    """Get current user information"""
    return jsonify({
        'id': current_user.id,
        'email': current_user.email,
        'username': current_user.username,
        'role': current_user.role.value,
        'is_active': current_user.is_active,
        'is_verified': current_user.is_verified,
        'created_at': current_user.created_at.isoformat() if current_user.created_at else None,
        'last_login': current_user.last_login.isoformat() if current_user.last_login else None
    })


@auth_bp.route('/change-password', methods=['POST'])
@token_required
def change_password(current_user):
    """Change user password"""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if not current_password or not new_password:
        return jsonify({'error': 'Current and new password are required'}), 400
    
    # Verify current password
    if not verify_password(current_password, current_user.password_hash):
        return jsonify({'error': 'Current password is incorrect'}), 401
    
    # Validate new password strength
    if len(new_password) < 8:
        return jsonify({'error': 'New password must be at least 8 characters'}), 400
    
    # Update password
    with get_session() as session:
        user = session.query(User).filter_by(id=current_user.id).first()
        if user:
            user.password_hash = hash_password(new_password)
            session.commit()
    
    return jsonify({
        'message': 'Password changed successfully'
    })


@auth_bp.route('/admin/create-user', methods=['POST'])
@token_required
def admin_create_user(current_user):
    """Admin: Create a new user"""
    if current_user.role.value not in ['admin', 'moderator']:
        return jsonify({'error': 'Admin access required'}), 403
    
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    email = data.get('email', '').lower().strip()
    username = data.get('username', '').strip()
    password = data.get('password', 'changeme123')
    role = data.get('role', 'user')
    
    # Validate role
    try:
        user_role = UserRole(role)
    except ValueError:
        return jsonify({'error': 'Invalid role'}), 400
    
    with get_session() as session:
        # Check if user exists
        existing = session.query(User).filter(
            (User.email == email) | (User.username == username)
        ).first()
        
        if existing:
            return jsonify({'error': 'User already exists'}), 409
        
        # Create user
        user = User(
            email=email,
            username=username,
            password_hash=hash_password(password),
            role=user_role,
            is_active=True,
            is_verified=True,
            created_at=datetime.utcnow()
        )
        
        session.add(user)
        session.commit()
        
        return jsonify({
            'message': 'User created successfully',
            'user': {
                'id': user.id,
                'email': user.email,
                'username': user.username,
                'role': user.role.value
            }
        }), 201
