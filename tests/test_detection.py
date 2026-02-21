"""
ScamShield Detection Tests
Unit tests for the detection system
"""
import pytest
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.detection.scam_detector import ScamDetector
from backend.detection.rule_engine import RuleEngine
from backend.detection.url_analyzer import URLAnalyzer
from backend.detection.domain_checker import DomainChecker


class TestScamDetector:
    """Test ScamDetector class"""
    
    def setup_method(self):
        """Setup test"""
        self.detector = ScamDetector()
    
    def test_detect_phishing_email(self):
        """Test detection of phishing email"""
        content = """
        Subject: URGENT: Verify Your Account Immediately
        
        Dear Valued Customer,
        
        Your account has been suspended due to suspicious activity.
        Please click here to verify your identity:
        http://fake-bank-secure.com/login
        
        Failure to verify within 24 hours will result in account closure.
        
        Sincerely,
        Security Team
        """
        
        result = self.detector.detect(content, 'email')
        
        assert result is not None
        assert result['is_scam'] == True
        assert result['risk_score'] > 0.5
        assert result['category'] in ['PHISHING', 'FRAUD']
    
    def test_detect_legitimate_email(self):
        """Test detection of legitimate email"""
        content = """
        Subject: Meeting Reminder
        
        Hi team,
        
        Just a reminder that we have a meeting tomorrow at 2pm.
        
        Best regards
        """
        
        result = self.detector.detect(content, 'email')
        
        assert result is not None
        assert result['is_scam'] == False
        assert result['risk_score'] < 0.3
    
    def test_detect_url(self):
        """Test URL detection"""
        content = "http://fake-paypal-login.com/verify"
        
        result = self.detector.detect(content, 'url')
        
        assert result is not None
        assert result['is_scam'] == True
    
    def test_detect_safe_url(self):
        """Test safe URL detection"""
        content = "https://www.google.com"
        
        result = self.detector.detect(content, 'url')
        
        assert result is not None


class TestRuleEngine:
    """Test RuleEngine class"""
    
    def setup_method(self):
        """Setup test"""
        self.engine = RuleEngine()
    
    def test_keyword_detection(self):
        """Test keyword detection"""
        content = "Urgent! Verify your account now or lose access"
        
        result = self.engine.analyze(content)
        
        assert result['has_suspicious_keywords'] == True
        assert result['keyword_count'] > 0
    
    def test_no_keywords(self):
        """Test clean content"""
        content = "Hello, let's meet for lunch tomorrow"
        
        result = self.engine.analyze(content)
        
        assert result['has_suspicious_keywords'] == False


class TestURLAnalyzer:
    """Test URLAnalyzer class"""
    
    def setup_method(self):
        """Setup test"""
        self.analyzer = URLAnalyzer()
    
    def test_suspicious_url(self):
        """Test suspicious URL detection"""
        url = "http://paypal-verify-login.com/account"
        
        result = self.analyzer.analyze(url)
        
        assert result['is_suspicious'] == True
    
    def test_safe_url(self):
        """Test safe URL detection"""
        url = "https://www.google.com/search?q=test"
        
        result = self.analyzer.analyze(url)
        
        assert result['is_suspicious'] == False


class TestDomainChecker:
    """Test DomainChecker class"""
    
    def setup_method(self):
        """Setup test"""
        self.checker = DomainChecker()
    
    def test_check_domain(self):
        """Test domain checking"""
        domain = "google.com"
        
        result = self.checker.check(domain)
        
        assert result is not None
        assert 'domain' in result


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
