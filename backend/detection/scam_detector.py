"""
ScamShield Main Detection Engine
Orchestrates all detection methods for comprehensive scam analysis
"""
from typing import Dict, Any, List
from backend.constants import SCAM_CATEGORIES, RISK_LEVELS

from backend.detection.rule_engine import RuleEngine
from backend.detection.ml_classifier import MLClassifier
from backend.detection.url_analyzer import URLAnalyzer
from backend.detection.domain_checker import DomainChecker
from backend.detection.similarity_checker import SimilarityChecker


class ScamDetector:
    """Main scam detection orchestrator"""
    
    def __init__(self):
        """Initialize all detection components"""
        self.rule_engine = RuleEngine()
        self.ml_classifier = MLClassifier()
        self.url_analyzer = URLAnalyzer()
        self.domain_checker = DomainChecker()
        self.similarity_checker = SimilarityChecker()
        
        # Detection method weights
        self.weights = {
            'rule_based': 0.30,
            'ml': 0.25,
            'url_analysis': 0.20,
            'domain_reputation': 0.15,
            'similarity': 0.10
        }
    
    def detect(self, content: str, content_type: str = 'text') -> Dict[str, Any]:
        """
        Main detection method
        
        Args:
            content: Content to analyze
            content_type: Type of content ('text', 'url', 'email', 'domain')
            
        Returns:
            Detection result dictionary
        """
        results = {
            'is_scam': False,
            'risk_score': 0.0,
            'risk_level': 0,
            'category': None,
            'confidence': 0.0,
            'methods': [],
            'details': {}
        }
        
        # Run all detection methods
        method_results = []
        
        # 1. Rule-based detection
        rule_result = self.rule_engine.analyze(content)
        if rule_result['detected']:
            method_results.append(('rule_based', rule_result))
        
        # 2. ML-based detection
        ml_result = self.ml_classifier.classify(content)
        if ml_result['detected']:
            method_results.append(('ml', ml_result))
        
        # 3. URL analysis (if content contains URLs)
        if content_type in ['url', 'email', 'text']:
            url_result = self.url_analyzer.analyze_content(content)
            if url_result.get('has_urls'):
                method_results.append(('url_analysis', url_result))
        
        # 4. Domain reputation (if domains found)
        domain_result = self.domain_checker.check_domains_in_content(content)
        if domain_result.get('domains_found'):
            method_results.append(('domain_reputation', domain_result))
        
        # 5. Similarity detection
        similarity_result = self.similarity_checker.check_similarity(content)
        if similarity_result.get('is_suspicious'):
            method_results.append(('similarity', similarity_result))
        
        # Calculate weighted risk score
        risk_score = self._calculate_risk_score(method_results)
        results['risk_score'] = risk_score
        
        # Determine risk level
        results['risk_level'] = self._get_risk_level(risk_score)
        
        # Determine if scam based on threshold
        threshold = 0.5
        if risk_score >= threshold:
            results['is_scam'] = True
        
        # Determine category
        if results['is_scam']:
            results['category'] = self._determine_category(method_results)
        
        # Calculate confidence
        results['confidence'] = self._calculate_confidence(method_results, results['is_scam'])
        
        # Store detection methods used
        results['methods'] = [m[0] for m in method_results]
        
        # Store detailed results
        results['details'] = {
            'method_results': {m[0]: m[1] for m in method_results},
            'content_type': content_type,
            'content_length': len(content)
        }
        
        return results
    
    def _calculate_risk_score(self, method_results: List[tuple]) -> float:
        """Calculate weighted risk score from all methods"""
        if not method_results:
            return 0.0
        
        total_score = 0.0
        total_weight = 0.0
        
        for method_name, result in method_results:
            weight = self.weights.get(method_name, 0.1)
            score = result.get('risk_score', 0.0)
            
            total_score += score * weight
            total_weight += weight
        
        if total_weight > 0:
            return min(total_score / total_weight, 1.0)
        return 0.0
    
    def _get_risk_level(self, risk_score: float) -> int:
        """Convert risk score to risk level (0-3)"""
        if risk_score >= 0.75:
            return 3  # Critical
        elif risk_score >= 0.5:
            return 2  # High
        elif risk_score >= 0.25:
            return 1  # Medium
        else:
            return 0  # Low
    
    def _determine_category(self, method_results: List[tuple]) -> str:
        """Determine the scam category"""
        categories = []
        
        for method_name, result in method_results:
            if 'category' in result and result['category']:
                categories.append(result['category'])
        
        # Return most common category or default
        if categories:
            return max(set(categories), key=categories.count)
        
        return SCAM_CATEGORIES.get('PHISHING', 'Phishing')
    
    def _calculate_confidence(self, method_results: List[tuple], is_scam: bool) -> float:
        """Calculate confidence score"""
        if not method_results:
            return 0.0
        
        if is_scam:
            # Higher confidence when multiple methods agree
            return min(0.5 + (len(method_results) * 0.1), 1.0)
        else:
            return 0.5
    
    def analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze a specific URL"""
        return self.url_analyzer.analyze_url(url)
    
    def check_domain(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation"""
        return self.domain_checker.check_domain(domain)
