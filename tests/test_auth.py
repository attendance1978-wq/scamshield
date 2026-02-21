"""
ScamShield Authentication Tests
Unit tests for authentication system
"""
import pytest
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.auth.password_hash import hash_password, verify_password
from backend.auth.jwt_handler import create_token, decode_token
from backend.utils.validator import validator


class TestPasswordHash:
    """Test password hashing"""
    
    def test_hash_password(self):
        """Test password hashing"""
        password = "testpassword123"
        hashed = hash_password(password)
        
        assert hashed is not None
        assert hashed != password
        assert len(hashed) > 0
    
    def test_verify_password(self):
        """Test password verification"""
        password = "testpassword123"
        hashed = hash_password(password)
        
        assert verify_password(password, hashed) == True
        assert verify_password("wrongpassword", hashed) == False


class TestJWTHandler:
    """Test JWT handler"""
    
    def test_create_token(self):
        """Test token creation"""
        user_id = 1
        token = create_token(user_id)
        
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0
    
    def test_decode_token(self):
        """Test token decoding"""
        user_id = 1
        token = create_token(user_id)
        
        decoded = decode_token(token)
        
        assert decoded is not None
        assert decoded['user_id'] == user_id
    
    def test_invalid_token(self):
        """Test invalid token"""
        decoded = decode_token("invalid-token")
        
        assert decoded is None


class TestValidator:
    """Test validator"""
    
    def test_validate_username(self):
        """Test username validation"""
        # Valid usernames
        assert validator.validate_username('john')['valid'] == True
        assert validator.validate_username('john_doe')['valid'] == True
        assert validator.validate_username('John123')['valid'] == True
        
        # Invalid usernames
        assert validator.validate_username('ab')['valid'] == False
        assert validator.validate_username('')['valid'] == False
        assert validator.validate_username('a' * 51)['valid'] == False
    
    def test_validate_password(self):
        """Test password validation"""
        # Valid passwords
        assert validator.validate_password('password123')['valid'] == True
        assert validator.validate_password('Password123!')['valid'] == True
        
        # Invalid passwords
        assert validator.validate_password('short')['valid'] == False
        assert validator.validate_password('')['valid'] == False
    
    def test_validate_email(self):
        """Test email validation"""
        assert validator.validate_email('test@example.com') == True
        assert validator.validate_email('user@domain.co.uk') == True
        assert validator.validate_email('invalid-email') == False
        assert validator.validate_email('') == False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
