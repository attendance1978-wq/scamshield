"""
ScamShield User Login Module
Handles user authentication and login
"""
from datetime import datetime
from typing import Tuple, Optional

from backend.database.db import get_session
from backend.database.models import User
from backend.auth.password_hash import verify_password
from backend.auth.jwt_handler import create_access_token, create_refresh_token


class AuthenticationError(Exception):
    """Custom exception for authentication errors"""
    pass


def authenticate_user(email: str, password: str) -> Tuple[Optional[User], Optional[str]]:
    """
    Authenticate a user with email and password
    
    Args:
        email: User's email address
        password: User's password
        
    Returns:
        Tuple of (User object or None, error message or None)
    """
    with get_session() as session:
        # Find user by email
        user = session.query(User).filter_by(email=email.lower()).first()
        
        if not user:
            return None, "Invalid email or password"
        
        # Verify password
        if not verify_password(password, user.password_hash):
            return None, "Invalid email or password"
        
        # Check if user is active
        if not user.is_active:
            return None, "Account is disabled. Please contact support."
        
        return user, None


def login_user(email: str, password: str) -> Tuple[Optional[dict], Optional[str]]:
    """
    Login a user and generate tokens
    
    Args:
        email: User's email address
        password: User's password
        
    Returns:
        Tuple of (response dict or None, error message or None)
    """
    user, error = authenticate_user(email, password)
    
    if error:
        return None, error
    
    # Update last login
    with get_session() as session:
        user_obj = session.query(User).filter_by(id=user.id).first()
        if user_obj:
            user_obj.last_login = datetime.utcnow()
            session.commit()
    
    # Generate tokens
    access_token = create_access_token(user.id)
    refresh_token = create_refresh_token(user.id)
    
    return {
        'user': {
            'id': user.id,
            'email': user.email,
            'username': user.username,
            'role': user.role.value
        },
        'access_token': access_token,
        'refresh_token': refresh_token
    }, None


def logout_user(user_id: int) -> bool:
    """
    Logout a user (invalidate tokens)
    
    Note: In a production system, you would add the token to a
    blacklist in Redis or database.
    
    Args:
        user_id: User ID
        
    Returns:
        True if successful
    """
    # In a full implementation, you would:
    # 1. Add the access token to a blacklist
    # 2. Optionally invalidate refresh tokens
    # For now, we'll just return success
    return True


def check_account_status(user_id: int) -> Tuple[bool, Optional[str]]:
    """
    Check if a user's account is in good standing
    
    Args:
        user_id: User ID to check
        
    Returns:
        Tuple of (is_good_standing, reason_if_not)
    """
    with get_session() as session:
        user = session.query(User).filter_by(id=user_id).first()
        
        if not user:
            return False, "User not found"
        
        if not user.is_active:
            return False, "Account is disabled"
        
        return True, None


def record_failed_login(email: str) -> None:
    """
    Record a failed login attempt
    
    In a production system, this could be used to:
    - Track failed attempts
    - Temporarily lock account after N attempts
    - Send security alerts
    
    Args:
        email: Email that failed to login
    """
    # In a full implementation, you would:
    # 1. Track failed attempts in database or Redis
    # 2. Implement account lockout after N attempts
    # 3. Send security alert to user
    pass


def record_successful_login(user_id: int, ip_address: str = None, user_agent: str = None) -> None:
    """
    Record a successful login
    
    Args:
        user_id: User ID
        ip_address: Client IP address
        user_agent: Client user agent
    """
    # In a full implementation, you would:
    # 1. Update last_login timestamp
    # 2. Log the login event for audit purposes
    # 3. Send login notification email (optional)
    pass


def get_login_history(user_id: int, limit: int = 10) -> list:
    """
    Get user's login history
    
    Args:
        user_id: User ID
        limit: Maximum number of records to return
        
    Returns:
        List of login records
    """
    # In a full implementation, this would query login history
    # from an audit log or similar table
    return []


def refresh_session(user_id: int) -> Tuple[Optional[dict], Optional[str]]:
    """
    Refresh a user's session
    
    Args:
        user_id: User ID
        
    Returns:
        Tuple of (new tokens or None, error message or None)
    """
    with get_session() as session:
        user = session.query(User).filter_by(id=user_id).first()
        
        if not user:
            return None, "User not found"
        
        if not user.is_active:
            return None, "Account is disabled"
        
        # Generate new tokens
        access_token = create_access_token(user.id)
        refresh_token = create_refresh_token(user.id)
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token
        }, None
