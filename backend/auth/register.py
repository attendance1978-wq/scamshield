"""
ScamShield User Registration Module
Handles user registration and validation
"""
import re
from datetime import datetime
from typing import Tuple, Optional

from backend.database.db import get_session
from backend.database.models import User, UserRole
from backend.auth.password_hash import hash_password


class RegistrationError(Exception):
    """Custom exception for registration errors"""
    pass


def validate_email(email: str) -> Tuple[bool, Optional[str]]:
    """
    Validate email format
    
    Args:
        email: Email address to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not email:
        return False, "Email is required"
    
    # Email regex pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if not re.match(pattern, email):
        return False, "Invalid email format"
    
    return True, None


def validate_username(username: str) -> Tuple[bool, Optional[str]]:
    """
    Validate username
    
    Args:
        username: Username to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not username:
        return False, "Username is required"
    
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    
    if len(username) > 50:
        return False, "Username must be at most 50 characters"
    
    # Username can only contain alphanumeric, underscore, and hyphen
    if not re.match(r'^[a-zA-Z0-9_-]+$', username):
        return False, "Username can only contain letters, numbers, underscores, and hyphens"
    
    return True, None


def validate_password(password: str) -> Tuple[bool, Optional[str]]:
    """
    Validate password strength
    
    Args:
        password: Password to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not password:
        return False, "Password is required"
    
    if len(password) < 8:
        return False, "Password must be at least 8 characters"
    
    if len(password) > 128:
        return False, "Password must be at most 128 characters"
    
    # Check for at least one letter
    if not re.search(r'[a-zA-Z]', password):
        return False, "Password must contain at least one letter"
    
    # Check for at least one number
    if not re.search(r'\d', password):
        return False, "Password must contain at least one number"
    
    # Check for at least one special character (optional but recommended)
    # Not enforcing this for flexibility
    
    return True, None


def check_user_exists(email: str, username: str) -> Tuple[bool, Optional[str]]:
    """
    Check if user already exists
    
    Args:
        email: Email to check
        username: Username to check
        
    Returns:
        Tuple of (exists, error_message)
    """
    with get_session() as session:
        # Check for existing email
        existing_email = session.query(User).filter_by(email=email.lower()).first()
        if existing_email:
            return True, "Email is already registered"
        
        # Check for existing username
        existing_username = session.query(User).filter_by(username=username).first()
        if existing_username:
            return True, "Username is already taken"
    
    return False, None


def register_user(email: str, username: str, password: str, role: str = 'user') -> User:
    """
    Register a new user
    
    Args:
        email: User's email address
        username: Desired username
        password: User's password
        role: User role (default: user)
        
    Returns:
        Created User object
        
    Raises:
        RegistrationError: If validation fails or user exists
    """
    # Validate email
    is_valid, error = validate_email(email)
    if not is_valid:
        raise RegistrationError(error)
    
    # Validate username
    is_valid, error = validate_username(username)
    if not is_valid:
        raise RegistrationError(error)
    
    # Validate password
    is_valid, error = validate_password(password)
    if not is_valid:
        raise RegistrationError(error)
    
    # Check if user exists
    exists, error = check_user_exists(email, username)
    if exists:
        raise RegistrationError(error)
    
    # Validate role
    try:
        user_role = UserRole(role)
    except ValueError:
        user_role = UserRole.USER
    
    # Create user
    with get_session() as session:
        user = User(
            email=email.lower(),
            username=username,
            password_hash=hash_password(password),
            role=user_role,
            is_active=True,
            is_verified=False,
            created_at=datetime.utcnow()
        )
        
        session.add(user)
        session.commit()
        
        # Refresh to get the ID
        session.refresh(user)
        
        return user


def verify_user_registration(user_id: int) -> bool:
    """
    Verify a user's registration (mark as verified)
    
    Args:
        user_id: User ID to verify
        
    Returns:
        True if successful
    """
    with get_session() as session:
        user = session.query(User).filter_by(id=user_id).first()
        
        if not user:
            return False
        
        user.is_verified = True
        session.commit()
        
        return True


def resend_verification_email(email: str) -> Tuple[bool, Optional[str]]:
    """
    Resend verification email
    
    Args:
        email: User's email address
        
    Returns:
        Tuple of (success, message)
    """
    with get_session() as session:
        user = session.query(User).filter_by(email=email.lower()).first()
        
        if not user:
            return False, "User not found"
        
        if user.is_verified:
            return False, "User is already verified"
        
        # In a real application, this would send an email
        # For now, we'll just return success
        return True, "Verification email sent"
