"""
ScamShield Rule Engine
Keyword and pattern-based detection
"""
import re
from typing import Dict, Any, List
from backend.constants import PHISHING_KEYWORDS, SUSPICIOUS_URL_PATTERNS, SCAM_CATEGORIES


class RuleEngine:
    """Rule-based scam detection engine"""
    
    def __init__(self):
        """Initialize rules"""
        self.phishing_keywords = PHISHING_KEYWORDS
        self.suspicious_patterns = SUSPICIOUS_URL_PATTERNS
        
        # Compile regex patterns
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns for efficiency"""
        self.url_pattern = re.compile(
            r'https?://[^\s<>"{}|\\^`\[\]]+',
            re.IGNORECASE
        )
        self.email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )
        self.ip_pattern = re.compile(
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        )
        self.phone_pattern = re.compile(
            r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b'
        )
        self.currency_pattern = re.compile(
            r'\$[\d,]+\.?\d*|\bUSD\b|\bBTC\b|\bBitcoin\b',
            re.IGNORECASE
        )
    
    def analyze(self, content: str) -> Dict[str, Any]:
        """
        Analyze content using rule-based detection
        
        Args:
            content: Text content to analyze
            
        Returns:
            Detection result dictionary
        """
        result = {
            'detected': False,
            'risk_score': 0.0,
            'category': None,
            'matched_keywords': [],
            'matched_patterns': [],
            'details': {}
        }
        
        if not content:
            return result
        
        # Convert to lowercase for keyword matching
        content_lower = content.lower()
        
        # Check for phishing keywords
        keyword_matches = self._check_keywords(content_lower)
        result['matched_keywords'] = keyword_matches
        
        # Check for suspicious URL patterns
        url_pattern_matches = self._check_url_patterns(content)
        result['matched_patterns'].extend(url_pattern_matches)
        
        # Check for suspicious elements
        suspicious_elements = self._check_suspicious_elements(content)
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(
            keyword_matches,
            url_pattern_matches,
            suspicious_elements
        )
        
        result['risk_score'] = risk_score
        
        # Determine if scam detected
        threshold = 0.4
        result['detected'] = risk_score >= threshold
        
        # Determine category
        if result['detected']:
            result['category'] = self._determine_category(
                keyword_matches,
                suspicious_elements
            )
        
        result['details'] = {
            'suspicious_elements': suspicious_elements,
            'content_length': len(content)
        }
        
        return result
    
    def _check_keywords(self, content: str) -> List[str]:
        """Check for phishing keywords"""
        matched = []
        
        for keyword in self.phishing_keywords:
            if keyword.lower() in content:
                matched.append(keyword)
        
        return matched
    
    def _check_url_patterns(self, content: str) -> List[str]:
        """Check for suspicious URL patterns"""
        matched = []
        
        urls = self.url_pattern.findall(content)
        
        for url in urls:
            for pattern in self.suspicious_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    matched.append(url)
                    break
        
        return matched
    
    def _check_suspicious_elements(self, content: str) -> Dict[str, Any]:
        """Check for other suspicious elements"""
        elements = {}
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.xyz', '.top', '.work', '.click', '.link', '.pw', '.tk', '.ml', '.ga', '.cf', '.gq']
        elements['suspicious_tlds'] = []
        
        urls = self.url_pattern.findall(content)
        for url in urls:
            for tld in suspicious_tlds:
                if tld in url.lower():
                    elements['suspicious_tlds'].append(url)
                    break
        
        # Check for IP addresses in URLs
        ip_addresses = self.ip_pattern.findall(content)
        elements['ip_addresses'] = ip_addresses
        
        # Check for excessive punctuation
        elements['excessive_punctuation'] = '!!' in content or '??' in content or '!!' in content
        
        # Check for urgency language
        urgency_words = ['immediately', 'urgent', 'act now', 'limited time', 'expires today', '24 hours']
        elements['urgency_language'] = any(word in content.lower() for word in urgency_words)
        
        # Check for money/currency mentions
        elements['money_mentioned'] = bool(self.currency_pattern.search(content))
        
        # Check for threats
        threat_words = ['suspend', 'terminate', 'close', 'lock', 'ban', 'legal action', 'arrest']
        elements['threat_language'] = any(word in content.lower() for word in threat_words)
        
        # Check for too-good-to-be-true offers
        too_good_words = ['free', 'winner', 'won', 'prize', 'congratulations', 'selected']
        elements['too_good'] = any(word in content.lower() for word in too_good_words)
        
        return elements
    
    def _calculate_risk_score(
        self,
        keyword_matches: List[str],
        url_pattern_matches: List[str],
        suspicious_elements: Dict[str, Any]
    ) -> float:
        """Calculate risk score based on findings"""
        score = 0.0
        
        # Keyword scoring (max 0.3)
        keyword_score = min(len(keyword_matches) * 0.05, 0.3)
        score += keyword_score
        
        # URL pattern scoring (max 0.3)
        url_score = min(len(url_pattern_matches) * 0.1, 0.3)
        score += url_score
        
        # Suspicious elements scoring
        if suspicious_elements.get('suspicious_tlds'):
            score += 0.2
        
        if suspicious_elements.get('ip_addresses'):
            score += 0.15
        
        if suspicious_elements.get('urgency_language'):
            score += 0.1
        
        if suspicious_elements.get('threat_language'):
            score += 0.15
        
        if suspicious_elements.get('too_good'):
            score += 0.1
        
        if suspicious_elements.get('money_mentioned'):
            score += 0.05
        
        if suspicious_elements.get('excessive_punctuation'):
            score += 0.05
        
        return min(score, 1.0)
    
    def _determine_category(
        self,
        keyword_matches: List[str],
        suspicious_elements: Dict[str, Any]
    ) -> str:
        """Determine the scam category"""
        # Determine category based on keywords and elements
        financial_keywords = ['bank', 'account', 'payment', 'credit', 'card', 'transfer', 'money']
        tech_keywords = ['password', 'reset', 'verify', 'security', 'login', 'account']
        prize_keywords = ['winner', 'prize', 'won', 'selected', 'congratulations']
        
        content_lower = ' '.join(keyword_matches).lower()
        
        if any(kw in content_lower for kw in financial_keywords):
            return SCAM_CATEGORIES.get('FRAUD', 'Fraud')
        
        if any(kw in content_lower for kw in prize_keywords):
            return SCAM_CATEGORIES.get('SPAM', 'Spam')
        
        if suspicious_elements.get('threat_language'):
            return SCAM_CATEGORIES.get('EXTORTION', 'Extortion')
        
        return SCAM_CATEGORIES.get('PHISHING', 'Phishing')
    
    def add_custom_rule(self, keyword: str, weight: float = 0.1):
        """Add a custom detection keyword"""
        if keyword.lower() not in [k.lower() for k in self.phishing_keywords]:
            self.phishing_keywords.append(keyword)
    
    def remove_custom_rule(self, keyword: str):
        """Remove a custom detection keyword"""
        self.phishing_keywords = [
            k for k in self.phishing_keywords
            if k.lower() != keyword.lower()
        ]
