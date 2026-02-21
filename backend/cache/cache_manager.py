"""
ScamShield Cache Manager
High-level cache management
"""
from typing import Optional, Any
import hashlib
import json

from backend.cache.redis_client import redis_client
from backend.config import config
from backend.constants import CACHE_TTL_SHORT, CACHE_TTL_MEDIUM, CACHE_TTL_LONG


class CacheManager:
    """High-level cache management"""
    
    def __init__(self):
        """Initialize cache manager"""
        self.ttl_short = CACHE_TTL_SHORT
        self.ttl_medium = CACHE_TTL_MEDIUM
        self.ttl_long = CACHE_TTL_LONG
        self.default_ttl = config.REDIS_CACHE_TTL
    
    def get(self, key: str) -> Optional[Any]:
        """
        Get value from cache
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None
        """
        return redis_client.get(key)
    
    def set(self, key: str, value: Any, ttl: int = None):
        """
        Set value in cache
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds
        """
        if ttl is None:
            ttl = self.default_ttl
        
        redis_client.set(key, value, ttl)
    
    def delete(self, key: str):
        """Delete key from cache"""
        redis_client.delete(key)
    
    def generate_key(self, *args, **kwargs) -> str:
        """
        Generate cache key from arguments
        
        Args:
            *args: Positional arguments
            **kwargs: Keyword arguments
            
        Returns:
            Cache key
        """
        # Create a hash from arguments
        key_data = {
            'args': args,
            'kwargs': kwargs
        }
        
        key_string = json.dumps(key_data, sort_keys=True)
        key_hash = hashlib.md5(key_string.encode()).hexdigest()
        
        return f"scamshield:{key_hash}"
    
    def cache_result(self, key: str, ttl: int = None):
        """
        Decorator to cache function results
        
        Args:
            key: Cache key prefix
            ttl: Time to live in seconds
        """
        def decorator(func):
            def wrapper(*args, **kwargs):
                # Generate cache key
                cache_key = f"{key}:{self.generate_key(*args, **kwargs)}"
                
                # Try to get from cache
                cached = self.get(cache_key)
                if cached is not None:
                    return cached
                
                # Execute function
                result = func(*args, **kwargs)
                
                # Cache result
                self.set(cache_key, result, ttl)
                
                return result
            return wrapper
        return decorator
    
    def invalidate_pattern(self, pattern: str):
        """
        Invalidate all keys matching pattern
        
        Args:
            pattern: Key pattern
        """
        keys = redis_client.get_keys(pattern)
        for key in keys:
            redis_client.delete(key)
    
    def cache_scan_result(self, scan_id: str, result: dict, ttl: int = None):
        """Cache scan result"""
        if ttl is None:
            ttl = self.ttl_long
        
        key = f"scan:{scan_id}"
        self.set(key, result, ttl)
    
    def get_scan_result(self, scan_id: str) -> Optional[dict]:
        """Get cached scan result"""
        key = f"scan:{scan_id}"
        return self.get(key)
    
    def cache_detection_result(self, content_hash: str, result: dict, ttl: int = None):
        """Cache detection result"""
        if ttl is None:
            ttl = self.ttl_medium
        
        key = f"detection:{content_hash}"
        self.set(key, result, ttl)
    
    def get_detection_result(self, content_hash: str) -> Optional[dict]:
        """Get cached detection result"""
        key = f"detection:{content_hash}"
        return self.get(key)


# Global cache manager
cache_manager = CacheManager()
