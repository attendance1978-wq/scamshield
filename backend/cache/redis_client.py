"""
ScamShield Redis Client
Redis cache client
"""
import redis
from typing import Optional, Any
import json

from backend.config import config


class RedisClient:
    """Redis cache client"""
    
    def __init__(self):
        """Initialize Redis client"""
        self.redis_url = config.REDIS_URL
        self.client = None
        self.connected = False
    
    def connect(self):
        """Connect to Redis"""
        try:
            self.client = redis.from_url(
                self.redis_url,
                decode_responses=True
            )
            # Test connection
            self.client.ping()
            self.connected = True
        except Exception as e:
            print(f"Redis connection error: {e}")
            self.connected = False
    
    def disconnect(self):
        """Disconnect from Redis"""
        if self.client:
            self.client.close()
            self.connected = False
    
    def is_connected(self) -> bool:
        """Check if connected"""
        if not self.connected or not self.client:
            return False
        
        try:
            self.client.ping()
            return True
        except Exception:
            return False
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None
        """
        if not self.is_connected():
            return None
        
        try:
            value = self.client.get(key)
            if value:
                return json.loads(value)
        except Exception as e:
            print(f"Redis get error: {e}")
        
        return None
    
    def set(self, key: str, value: Any, ttl: int = None) -> bool:
        """
        Set value in cache
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds
            
        Returns:
            True if successful
        """
        if not self.is_connected():
            return False
        
        try:
            serialized = json.dumps(value)
            if ttl:
                self.client.setex(key, ttl, serialized)
            else:
                self.client.set(key, serialized)
            return True
        except Exception as e:
            print(f"Redis set error: {e}")
            return False
    
    def delete(self, key: str) -> bool:
        """
        Delete key from cache
        
        Args:
            key: Cache key
            
        Returns:
            True if successful
        """
        if not self.is_connected():
            return False
        
        try:
            self.client.delete(key)
            return True
        except Exception:
            return False
    
    def exists(self, key: str) -> bool:
        """
        Check if key exists
        
        Args:
            key: Cache key
            
        Returns:
            True if exists
        """
        if not self.is_connected():
            return False
        
        try:
            return bool(self.client.exists(key))
        except Exception:
            return False
    
    def expire(self, key: str, ttl: int) -> bool:
        """
        Set expiration on key
        
        Args:
            key: Cache key
            ttl: Time to live in seconds
            
        Returns:
            True if successful
        """
        if not self.is_connected():
            return False
        
        try:
            return bool(self.client.expire(key, ttl))
        except Exception:
            return False
    
    def incr(self, key: str, amount: int = 1) -> Optional[int]:
        """
        Increment counter
        
        Args:
            key: Cache key
            amount: Amount to increment
            
        Returns:
            New value or None
        """
        if not self.is_connected():
            return None
        
        try:
            return self.client.incr(key, amount)
        except Exception:
            return None
    
    def get_keys(self, pattern: str = '*') -> list:
        """
        Get keys matching pattern
        
        Args:
            pattern: Key pattern
            
        Returns:
            List of keys
        """
        if not self.is_connected():
            return []
        
        try:
            return list(self.client.scan_iter(match=pattern))
        except Exception:
            return []


# Global Redis client
redis_client = RedisClient()
