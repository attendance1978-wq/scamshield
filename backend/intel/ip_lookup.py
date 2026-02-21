"""
ScamShield IP Lookup
IP address information and geolocation
"""
import requests
from typing import Dict, Any, Optional
import re


class IPLookup:
    """IP address lookup and geolocation"""
    
    def __init__(self):
        """Initialize IP lookup"""
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour
    
    def lookup(self, ip: str) -> Optional[Dict[str, Any]]:
        """
        Perform IP lookup
        
        Args:
            ip: IP address to lookup
            
        Returns:
            IP information dictionary
        """
        # Validate IP
        if not self._is_valid_ip(ip):
            return None
        
        # Check cache
        if ip in self.cache:
            cached = self.cache[ip]
            age = (datetime.utcnow() - cached['timestamp']).seconds
            if age < self.cache_ttl:
                return cached['data']
        
        try:
            # Use ip-api.com (free tier)
            response = requests.get(
                f'http://ip-api.com/json/{ip}',
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                
                result = {
                    'ip': ip,
                    'country': data.get('country'),
                    'country_code': data.get('countryCode'),
                    'region': data.get('region'),
                    'region_name': data.get('regionName'),
                    'city': data.get('city'),
                    'zip': data.get('zip'),
                    'latitude': data.get('lat'),
                    'longitude': data.get('lon'),
                    'timezone': data.get('timezone'),
                    'isp': data.get('isp'),
                    'org': data.get('org'),
                    'asn': data.get('as'),
                    'status': data.get('status')
                }
                
                # Cache result
                self.cache[ip] = {
                    'data': result,
                    'timestamp': datetime.utcnow()
                }
                
                return result
            
        except Exception as e:
            print(f"IP lookup error: {e}")
        
        return None
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address"""
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        
        if not re.match(ipv4_pattern, ip):
            return False
        
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    
    def get_ip_info(self, ip: str) -> Dict[str, Any]:
        """
        Get simplified IP info
        
        Args:
            ip: IP address
            
        Returns:
            IP info dictionary
        """
        info = self.lookup(ip)
        
        if not info:
            return {
                'ip': ip,
                'found': False
            }
        
        return {
            'ip': ip,
            'found': True,
            'country': info.get('country'),
            'country_code': info.get('country_code'),
            'city': info.get('city'),
            'isp': info.get('isp'),
            'org': info.get('org'),
            'asn': info.get('asn'),
            'latitude': info.get('latitude'),
            'longitude': info.get('longitude')
        }
    
    def is_proxy(self, ip: str) -> bool:
        """
        Check if IP is a proxy/vpn
        
        Args:
            ip: IP address
            
        Returns:
            True if proxy/vpn detected
        """
        # In production, integrate with:
        # - Proxy detection APIs
        # - VPN detection services
        
        info = self.lookup(ip)
        
        if not info:
            return False
        
        # Simple heuristics
        isp_lower = (info.get('isp') or '').lower()
        org_lower = (info.get('org') or '').lower()
        
        proxy_keywords = ['proxy', 'vpn', 'hosting', 'datacenter', 'cloud']
        
        return any(keyword in isp_lower or keyword in org_lower 
                   for keyword in proxy_keywords)


from datetime import datetime
