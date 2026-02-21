"""
ScamShield WHOIS Lookup
Domain WHOIS information retrieval
"""
import whois
from typing import Dict, Any, Optional
from datetime import datetime
import re


class WhoisLookup:
    """WHOIS domain lookup"""
    
    def __init__(self):
        """Initialize WHOIS lookup"""
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour
    
    def lookup(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Perform WHOIS lookup
        
        Args:
            domain: Domain to lookup
            
        Returns:
            WHOIS information dictionary
        """
        # Check cache
        if domain in self.cache:
            cached = self.cache[domain]
            if (datetime.utcnow() - cached['timestamp']).seconds < self.cache_ttl:
                return cached['data']
        
        try:
            # Perform WHOIS lookup
            w = whois.whois(domain)
            
            result = {
                'domain_name': w.domain_name,
                'registrar': w.registrar,
                'whois_server': w.whois_server,
                'creation_date': self._parse_date(w.creation_date),
                'expiration_date': self._parse_date(w.expiration_date),
                'updated_date': self._parse_date(w.updated_date),
                'name_servers': w.name_servers,
                'status': w.status,
                'emails': w.emails,
                'country': w.country,
                'state': w.state,
                'city': w.city,
                'org': w.org,
                'owner': w.name
            }
            
            # Calculate domain age
            if result['creation_date']:
                age = (datetime.utcnow() - result['creation_date']).days
                result['domain_age_days'] = age
                result['is_new_domain'] = age < 90  # Less than 90 days
            
            # Cache result
            self.cache[domain] = {
                'data': result,
                'timestamp': datetime.utcnow()
            }
            
            return result
            
        except Exception as e:
            print(f"WHOIS lookup error: {e}")
            return None
    
    def _parse_date(self, date_value) -> Optional[datetime]:
        """Parse WHOIS date"""
        if not date_value:
            return None
        
        # Handle list of dates
        if isinstance(date_value, list):
            date_value = date_value[0]
        
        # Already datetime
        if isinstance(date_value, datetime):
            return date_value
        
        # String date
        if isinstance(date_value, str):
            formats = [
                '%Y-%m-%d %H:%M:%S',
                '%Y-%m-%d',
                '%d-%b-%Y'
            ]
            
            for fmt in formats:
                try:
                    return datetime.strptime(date_value.strip(), fmt)
                except ValueError:
                    continue
        
        return None
    
    def is_new_domain(self, domain: str, threshold_days: int = 90) -> bool:
        """
        Check if domain is newly registered
        
        Args:
            domain: Domain to check
            threshold_days: Days threshold for new domain
            
        Returns:
            True if domain is new
        """
        info = self.lookup(domain)
        
        if info and 'domain_age_days' in info:
            return info['domain_age_days'] < threshold_days
        
        return False
    
    def get_domain_info(self, domain: str) -> Dict[str, Any]:
        """
        Get simplified domain info
        
        Args:
            domain: Domain to check
            
        Returns:
            Domain info dictionary
        """
        info = self.lookup(domain)
        
        if not info:
            return {
                'domain': domain,
                'found': False
            }
        
        return {
            'domain': domain,
            'found': True,
            'registrar': info.get('registrar'),
            'creation_date': info.get('creation_date').isoformat() if info.get('creation_date') else None,
            'expiration_date': info.get('expiration_date').isoformat() if info.get('expiration_date') else None,
            'age_days': info.get('domain_age_days'),
            'is_new': info.get('is_new_domain', False),
            'country': info.get('country'),
            'org': info.get('org')
        }
