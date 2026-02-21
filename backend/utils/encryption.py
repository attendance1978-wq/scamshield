"""
ScamShield Encryption
Encryption and decryption utilities
"""
import base64
import hashlib
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from typing import Optional


class Encryption:
    """Encryption utilities"""
    
    def __init__(self, key: bytes = None):
        """
        Initialize encryption
        
        Args:
            key: Encryption key (generated if not provided)
        """
        if key is None:
            key = self.generate_key()
        
        self.cipher = Fernet(key)
    
    @staticmethod
    def generate_key() -> bytes:
        """Generate a new encryption key"""
        return Fernet.generate_key()
    
    @staticmethod
    def derive_key(password: str, salt: bytes = None) -> bytes:
        """
        Derive key from password
        
        Args:
            password: Password
            salt: Salt (generated if not provided)
            
        Returns:
            Derived key
        """
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def encrypt(self, data: str) -> str:
        """
        Encrypt data
        
        Args:
            data: Data to encrypt
            
        Returns:
            Encrypted data (base64 encoded)
        """
        encrypted = self.cipher.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt(self, encrypted_data: str) -> Optional[str]:
        """
        Decrypt data
        
        Args:
            encrypted_data: Encrypted data
            
        Returns:
            Decrypted data or None
        """
        try:
            decoded = base64.urlsafe_b64decode(encrypted_data.encode())
            decrypted = self.cipher.decrypt(decoded)
            return decrypted.decode()
        except Exception:
            return None
    
    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash password
        
        Args:
            password: Password to hash
            
        Returns:
            Hashed password
        """
        return hashlib.sha256(password.encode()).hexdigest()
    
    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """
        Verify password against hash
        
        Args:
            password: Password to verify
            hashed: Hashed password
            
        Returns:
            True if matches
        """
        return Encryption.hash_password(password) == hashed
    
    @staticmethod
    def generate_token(length: int = 32) -> str:
        """Generate random token"""
        return os.urandom(length).hex()


# Global encryption instance
encryption = Encryption()
