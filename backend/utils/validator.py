"""
ScamShield Validator
Input validation utilities
"""
import re
from typing import Optional, Dict, Any, List
from datetime import datetime


class Validator:
    """Input validation class"""
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """
        Validate email address
        
        Args:
            email: Email address
            
        Returns:
            True if valid
        """
        if not email:
            return False
        
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """
        Validate URL
        
        Args:
            url: URL string
            
        Returns:
            True if valid
        """
        if not url:
            return False
        
        pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        return bool(re.match(pattern, url, re.IGNORECASE))
    
    @staticmethod
    def validate_username(username: str) -> Dict[str, Any]:
        """
        Validate username
        
        Args:
            username: Username
            
        Returns:
            Validation result with 'valid' and optional 'error'
        """
        if not username:
            return {'valid': False, 'error': 'Username is required'}
        
        if len(username) < 3:
            return {'valid': False, 'error': 'Username must be at least 3 characters'}
        
        if len(username) > 50:
            return {'valid': False, 'error': 'Username must be less than 50 characters'}
        
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            return {'valid': False, 'error': 'Username can only contain letters, numbers, hyphens and underscores'}
        
        return {'valid': True}
    
    @staticmethod
    def validate_password(password: str) -> Dict[str, Any]:
        """
        Validate password
        
        Args:
            password: Password
            
        Returns:
            Validation result with 'valid' and optional 'error'
        """
        if not password:
            return {'valid': False, 'error': 'Password is required'}
        
        if len(password) < 8:
            return {'valid': False, 'error': 'Password must be at least 8 characters'}
        
        if len(password) > 128:
            return {'valid': False, 'error': 'Password is too long'}
        
        # Check for complexity
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        
        complexity_score = sum([has_upper, has_lower, has_digit, has_special])
        
        if complexity_score < 2:
            return {'valid': False, 'error': 'Password must contain at least 2 of: uppercase, lowercase, numbers, special characters'}
        
        return {'valid': True}
    
    @staticmethod
    def validate_scan_type(scan_type: str) -> bool:
        """
        Validate scan type
        
        Args:
            scan_type: Scan type
            
        Returns:
            True if valid
        """
        valid_types = ['text', 'url', 'email', 'domain']
        return scan_type in valid_types
    
    @staticmethod
    def validate_risk_level(level: int) -> bool:
        """
        Validate risk level
        
        Args:
            level: Risk level
            
        Returns:
            True if valid
        """
        return 0 <= level <= 3
    
    @staticmethod
    def sanitize_html(html: str) -> str:
        """
        Sanitize HTML content
        
        Args:
            html: HTML string
            
        Returns:
            Sanitized HTML
        """
        # Remove script tags
        html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.IGNORECASE | re.DOTALL)
        
        # Remove on* attributes
        html = re.sub(r'\s*on\w+\s*=\s*["\'][^"\']*["\']', '', html, flags=re.IGNORECASE)
        
        return html
    
    @staticmethod
    def validate_api_key(api_key: str) -> bool:
        """
        Validate API key format
        
        Args:
            api_key: API key
            
        Returns:
            True if valid
        """
        if not api_key:
            return False
        
        # API keys should be at least 32 characters
        if len(api_key) < 32:
            return False
        
        # Should only contain alphanumeric and dashes/underscores
        return bool(re.match(r'^[a-zA-Z0-9_-]+$', api_key))


# Global validator instance
validator = Validator()
