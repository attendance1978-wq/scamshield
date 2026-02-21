"""
ScamShield URL Analyzer
URL-based scam detection
"""
import re
import requests
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs
import tldextract

from backend.config import config
from backend.constants import SUSPICIOUS_URL_PATTERNS


class URLAnalyzer:
    """URL analysis for scam detection"""
    
    def __init__(self):
        """Initialize URL analyzer"""
        self.suspicious_patterns = SUSPICIOUS_URL_PATTERNS
        self.shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
            'is.gd', 'buff.ly', 'adf.ly', 'j.mp', 'tr.im',
            'short.to', 'u.to', 'q.gs', 'po.st', 'tiny.cc'
        ]
        self.suspicious_tlds = [
            '.xyz', '.top', '.work', '.click', '.link', '.pw',
            '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.monster'
        ]
    
    def analyze_content(self, content: str) -> Dict[str, Any]:
        """
        Analyze content for URLs and check each one
        
        Args:
            content: Text content containing URLs
            
        Returns:
            Analysis result dictionary
        """
        result = {
            'has_urls': False,
            'urls_found': [],
            'suspicious_urls': [],
            'risk_score': 0.0
        }
        
        # Extract URLs
        urls = self._extract_urls(content)
        
        if not urls:
            return result
        
        result['has_urls'] = True
        result['urls_found'] = urls
        
        # Analyze each URL
        for url in urls:
            url_analysis = self.analyze_url(url)
            
            if url_analysis.get('is_suspicious'):
                result['suspicious_urls'].append({
                    'url': url,
                    'reasons': url_analysis.get('reasons', [])
                })
        
        # Calculate overall risk score
        if result['suspicious_urls']:
            result['risk_score'] = min(
                len(result['suspicious_urls']) / len(urls) * 0.5 + 0.5,
                1.0
            )
        
        return result
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze a single URL
        
        Args:
            url: URL to analyze
            
        Returns:
            Analysis result dictionary
        """
        result = {
            'url': url,
            'is_suspicious': False,
            'risk_score': 0.0,
            'reasons': [],
            'details': {}
        }
        
        if not url:
            return result
        
        # Parse URL
        parsed = urlparse(url)
        
        # Extract domain info
        extracted = tldextract.extract(url)
        
        # Check for suspicious patterns
        self._check_patterns(url, result)
        
        # Check for IP address as domain
        self._check_ip_domain(parsed, result)
        
        # Check for suspicious TLD
        self._check_suspicious_tld(extracted, result)
        
        # Check for URL shortener
        self._check_shortener(extracted, result)
        
        # Check for suspicious subdomain
        self._check_subdomain(extracted, result)
        
        # Check for suspicious path
        self._check_suspicious_path(parsed, result)
        
        # Check for suspicious parameters
        self._check_parameters(parsed, result)
        
        # Check for homograph attacks
        self._check_homograph(url, result)
        
        # Determine overall suspicion
        if result['reasons']:
            result['is_suspicious'] = True
            result['risk_score'] = min(len(result['reasons']) * 0.15, 1.0)
        
        result['details'] = {
            'domain': extracted.domain,
            'suffix': extracted.suffix,
            'subdomain': extracted.subdomain,
            'registered_domain': extracted.registered_domain,
            'is_https': parsed.scheme == 'https',
            'has_port': bool(parsed.port)
        }
        
        return result
    
    def _extract_urls(self, content: str) -> List[str]:
        """Extract URLs from content"""
        url_pattern = re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+',
            re.IGNORECASE
        )
        return url_pattern.findall(content)
    
    def _check_patterns(self, url: str, result: Dict[str, Any]):
        """Check for suspicious URL patterns"""
        for pattern in self.suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                result['reasons'].append(f'Matches suspicious pattern: {pattern}')
    
    def _check_ip_domain(self, parsed, result: Dict[str, Any]):
        """Check if domain is an IP address"""
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
        
        if parsed.netloc and ip_pattern.match(parsed.netloc.split(':')[0]):
            result['reasons'].append('Domain is an IP address')
    
    def _check_suspicious_tld(self, extracted, result: Dict[str, Any]):
        """Check for suspicious TLD"""
        if extracted.suffix.lower() in self.suspicious_tlds:
            result['reasons'].append(f'Suspicious TLD: {extracted.suffix}')
    
    def _check_shortener(self, extracted, result: Dict[str, Any]):
        """Check for URL shortener"""
        domain = extracted.registered_domain.lower()
        
        for shortener in self.shorteners:
            if shortener in domain:
                result['reasons'].append(f'URL shortener detected: {shortener}')
                break
    
    def _check_subdomain(self, extracted, result: Dict[str, Any]):
        """Check for suspicious subdomains"""
        suspicious_subdomains = ['login', 'signin', 'secure', 'verify', 'account', 'update']
        
        if extracted.subdomain:
            subdomain_lower = extracted.subdomain.lower()
            
            for sus in suspicious_subdomains:
                if sus in subdomain_lower:
                    result['reasons'].append(f'Suspicious subdomain: {extracted.subdomain}')
                    break
    
    def _check_suspicious_path(self, parsed, result: Dict[str, Any]):
        """Check for suspicious path patterns"""
        suspicious_paths = ['login', 'signin', 'verify', 'account', 'update', 'secure']
        path_lower = parsed.path.lower()
        
        for sus in suspicious_paths:
            if sus in path_lower:
                result['reasons'].append(f'Suspicious path: {parsed.path}')
                break
    
    def _check_parameters(self, parsed, result: Dict[str, Any]):
        """Check URL parameters for suspicious values"""
        suspicious_params = ['redirect', 'url', 'link', 'goto', 'next', 'return']
        
        params = parse_qs(parsed.query)
        
        for param in suspicious_params:
            if param in params:
                result['reasons'].append(f'Suspicious redirect parameter: {param}')
    
    def _check_homograph(self, url: str, result: Dict[str, Any]):
        """Check for homograph attacks (lookalike characters)"""
        # Check for Cyrillic lookalikes
        # This is a simplified check - full implementation would check for
        # mixed scripts or confusable characters
        try:
            # Check if URL contains non-ASCII characters
            if any(ord(c) > 127 for c in url):
                # Could be a homograph attack
                result['reasons'].append('Contains non-ASCII characters (possible homograph attack)')
        except Exception:
            pass
    
    def check_url_safety(self, url: str) -> Dict[str, Any]:
        """
        Check URL safety using external services
        
        Args:
            url: URL to check
            
        Returns:
            Safety check result
        """
        result = {
            'is_safe': True,
            'details': {}
        }
        
        # In production, you would integrate with services like:
        # - Google Safe Browsing
        # - VirusTotal
        # - PhishTank
        # - OpenPhish
        
        # For now, use local analysis
        analysis = self.analyze_url(url)
        
        result['is_safe'] = not analysis.get('is_suspicious')
        result['details'] = analysis
        
        return result
