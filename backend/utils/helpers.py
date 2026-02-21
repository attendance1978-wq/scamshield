"""
ScamShield Helper Functions
Utility helper functions
"""
import re
import hashlib
import uuid
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs


def generate_id(prefix: str = '') -> str:
    """
    Generate unique ID
    
    Args:
        prefix: ID prefix
        
    Returns:
        Unique ID
    """
    unique_id = uuid.uuid4().hex[:12].upper()
    return f"{prefix}-{unique_id}" if prefix else unique_id


def generate_scan_id() -> str:
    """Generate unique scan ID"""
    return generate_id('SCAN')


def hash_content(content: str) -> str:
    """
    Generate hash of content
    
    Args:
        content: Content to hash
        
    Returns:
        MD5 hash
    """
    return hashlib.md5(content.encode()).hexdigest()


def extract_domain(url: str) -> Optional[str]:
    """
    Extract domain from URL
    
    Args:
        url: URL string
        
    Returns:
        Domain or None
    """
    try:
        parsed = urlparse(url)
        return parsed.netloc if parsed.netloc else None
    except Exception:
        return None


def extract_urls(text: str) -> List[str]:
    """
    Extract URLs from text
    
    Args:
        text: Text to search
        
    Returns:
        List of URLs
    """
    url_pattern = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    )
    return url_pattern.findall(text)


def extract_emails(text: str) -> List[str]:
    """
    Extract emails from text
    
    Args:
        text: Text to search
        
    Returns:
        List of emails
    """
    email_pattern = re.compile(
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    )
    return email_pattern.findall(text)


def sanitize_string(text: str, max_length: int = None) -> str:
    """
    Sanitize string
    
    Args:
        text: Text to sanitize
        max_length: Maximum length
        
    Returns:
        Sanitized string
    """
    # Remove null bytes
    text = text.replace('\x00', '')
    
    # Strip whitespace
    text = text.strip()
    
    # Truncate if needed
    if max_length and len(text) > max_length:
        text = text[:max_length]
    
    return text


def parse_user_agent(user_agent: str) -> Dict[str, str]:
    """
    Parse user agent string
    
    Args:
        user_agent: User agent string
        
    Returns:
        Parsed information
    """
    return {
        'raw': user_agent,
        'browser': 'Unknown',
        'os': 'Unknown',
        'device': 'Unknown'
    }


def format_timestamp(dt: datetime = None) -> str:
    """
    Format timestamp
    
    Args:
        dt: Datetime object
        
    Returns:
        ISO format string
    """
    if dt is None:
        dt = datetime.utcnow()
    return dt.isoformat()


def parse_timestamp(timestamp_str: str) -> Optional[datetime]:
    """
    Parse timestamp string
    
    Args:
        timestamp_str: Timestamp string
        
    Returns:
        Datetime object or None
    """
    try:
        return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
    except Exception:
        return None


def get_time_ago(dt: datetime) -> str:
    """
    Get human-readable time ago
    
    Args:
        dt: Datetime
        
    Returns:
        Time ago string
    """
    now = datetime.utcnow()
    diff = now - dt
    
    if diff.days > 365:
        return f"{diff.days // 365} year(s) ago"
    elif diff.days > 30:
        return f"{diff.days // 30} month(s) ago"
    elif diff.days > 0:
        return f"{diff.days} day(s) ago"
    elif diff.seconds > 3600:
        return f"{diff.seconds // 3600} hour(s) ago"
    elif diff.seconds > 60:
        return f"{diff.seconds // 60} minute(s) ago"
    else:
        return "just now"


def truncate_text(text: str, length: int = 100, suffix: str = '...') -> str:
    """
    Truncate text
    
    Args:
        text: Text to truncate
        length: Maximum length
        suffix: Suffix to add
        
    Returns:
        Truncated text
    """
    if len(text) <= length:
        return text
    return text[:length - len(suffix)] + suffix


def safe_divide(a: float, b: float, default: float = 0.0) -> float:
    """
    Safe division
    
    Args:
        a: Numerator
        b: Denominator
        default: Default value if division by zero
        
    Returns:
        Result or default
    """
    try:
        return a / b if b != 0 else default
    except (TypeError, ZeroDivisionError):
        return default


def percentage(part: float, total: float, decimals: int = 2) -> float:
    """
    Calculate percentage
    
    Args:
        part: Part value
        total: Total value
        decimals: Decimal places
        
    Returns:
        Percentage
    """
    return round(safe_divide(part, total) * 100, decimals)


def is_valid_url(url: str) -> bool:
    """
    Check if URL is valid
    
    Args:
        url: URL string
        
    Returns:
        True if valid
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def normalize_url(url: str) -> str:
    """
    Normalize URL
    
    Args:
        url: URL string
        
    Returns:
        Normalized URL
    """
    url = url.strip()
    
    # Add scheme if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    return url


def get_domain_age(domain: str) -> Optional[int]:
    """
    Get domain age in days (placeholder)
    
    Args:
        domain: Domain name
        
    Returns:
        Age in days or None
    """
    # This would use whois lookup in production
    return None


def format_bytes(bytes_size: int) -> str:
    """
    Format bytes to human readable
    
    Args:
        bytes_size: Size in bytes
        
    Returns:
        Formatted string
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_size < 1024.0:
            return f"{bytes_size:.2f} {unit}"
        bytes_size /= 1024.0
    return f"{bytes_size:.2f} PB"


def flatten_dict(d: Dict, parent_key: str = '', sep: str = '.') -> Dict:
    """
    Flatten nested dictionary
    
    Args:
        d: Dictionary to flatten
        parent_key: Parent key
        sep: Separator
        
    Returns:
        Flattened dictionary
    """
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)
