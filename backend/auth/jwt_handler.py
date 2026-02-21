"""
ScamShield JWT Handler Module
Handles JWT token creation, validation, and refresh
"""
from functools import wraps
from datetime import datetime, timedelta
from typing import Optional

import jwt
from flask import request, jsonify, g

from backend.config import config
from backend.database.db import get_session
from backend.database.models import User


def create_access_token(identity: int, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token
    
    Args:
        identity: User ID
        expires_delta: Optional custom expiration time
        
    Returns:
        JWT token string
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(seconds=config.JWT_ACCESS_TOKEN_EXPIRES)
    
    payload = {
        'exp': expire,
        'iat': datetime.utcnow(),
        'sub': identity,
        'type': 'access'
    }
    
    return jwt.encode(payload, config.JWT_SECRET_KEY, algorithm='HS256')


def create_refresh_token(identity: int, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT refresh token
    
    Args:
        identity: User ID
        expires_delta: Optional custom expiration time
        
    Returns:
        JWT token string
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(seconds=config.JWT_REFRESH_TOKEN_EXPIRES)
    
    payload = {
        'exp': expire,
        'iat': datetime.utcnow(),
        'sub': identity,
        'type': 'refresh'
    }
    
    return jwt.encode(payload, config.JWT_SECRET_KEY, algorithm='HS256')


def decode_token(token: str) -> Optional[dict]:
    """
    Decode and validate a JWT token
    
    Args:
        token: JWT token string
        
    Returns:
        Decoded payload or None if invalid
    """
    try:
        payload = jwt.decode(token, config.JWT_SECRET_KEY, algorithms=['HS256'])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None


def get_token_from_header() -> Optional[str]:
    """
    Extract token from Authorization header
    
    Returns:
        Token string or None
    """
    auth_header = request.headers.get('Authorization')
    
    if not auth_header:
        return None
    
    parts = auth_header.split()
    
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return None
    
    return parts[1]


def token_required(f):
    """
    Decorator to require valid JWT token
    
    Usage:
        @token_required
        def protected_route(current_user):
            ...
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_from_header()
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        payload = decode_token(token)
        
        if not payload:
            return jsonify({'error': 'Token is invalid or expired'}), 401
        
        # Get user from database
        user_id = payload.get('sub')
        token_type = payload.get('type')
        
        if token_type != 'access':
            return jsonify({'error': 'Invalid token type'}), 401
        
        with get_session() as session:
            user = session.query(User).filter_by(id=user_id).first()
            
            if not user:
                return jsonify({'error': 'User not found'}), 401
            
            if not user.is_active:
                return jsonify({'error': 'User account is disabled'}), 403
            
            # Set current user in Flask's g object
            g.current_user = user
            
            return f(user, *args, **kwargs)
    
    return decorated


def admin_required(f):
    """
    Decorator to require admin role
    
    Usage:
        @admin_required
        def admin_route(current_user):
            ...
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_from_header()
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        payload = decode_token(token)
        
        if not payload:
            return jsonify({'error': 'Token is invalid or expired'}), 401
        
        user_id = payload.get('sub')
        
        with get_session() as session:
            user = session.query(User).filter_by(id=user_id).first()
            
            if not user:
                return jsonify({'error': 'User not found'}), 401
            
            if not user.is_active:
                return jsonify({'error': 'User account is disabled'}), 403
            
            if user.role.value not in ['admin', 'moderator']:
                return jsonify({'error': 'Admin access required'}), 403
            
            g.current_user = user
            
            return f(user, *args, **kwargs)
    
    return decorated


def generate_api_key(user_id: int) -> str:
    """
    Generate an API key for programmatic access
    
    Args:
        user_id: User ID
        
    Returns:
        API key string
    """
    payload = {
        'exp': datetime.utcnow() + timedelta(days=365),  # 1 year validity
        'iat': datetime.utcnow(),
        'sub': user_id,
        'type': 'api_key'
    }
    
    return jwt.encode(payload, config.JWT_SECRET_KEY, algorithm='HS256')
