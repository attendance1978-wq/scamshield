"""
ScamShield Verdict Engine
Determines final verdict based on detection results
"""
from typing import Dict, Any, List, Optional
from backend.constants import SCAM_CATEGORIES, RISK_LEVELS


class VerdictEngine:
    """Final verdict determination engine"""
    
    def __init__(self):
        """Initialize verdict engine"""
        # Thresholds
        self.detection_threshold = 0.5
        self.high_confidence_threshold = 0.75
        self.min_methods_required = 2
    
    def determine_verdict(self, detection_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Determine final verdict from detection results
        
        Args:
            detection_results: Combined results from all detection methods
            
        Returns:
            Verdict dictionary
        """
        verdict = {
            'is_scam': False,
            'verdict': 'clean',
            'confidence': 0.0,
            'category': None,
            'risk_level': 0,
            'recommendations': [],
            'details': {}
        }
        
        # Get risk score
        risk_score = detection_results.get('risk_score', 0.0)
        risk_level = detection_results.get('risk_level', 0)
        
        # Determine verdict
        if risk_score >= self.high_confidence_threshold:
            verdict['is_scam'] = True
            verdict['verdict'] = 'malicious'
            verdict['confidence'] = risk_score
        elif risk_score >= self.detection_threshold:
            # Medium confidence - need more evidence
            methods = detection_results.get('methods', [])
            if len(methods) >= self.min_methods_required:
                verdict['is_scam'] = True
                verdict['verdict'] = 'suspicious'
                verdict['confidence'] = risk_score
            else:
                verdict['verdict'] = 'uncertain'
                verdict['confidence'] = risk_score
        else:
            verdict['verdict'] = 'clean'
            verdict['confidence'] = 1.0 - risk_score
        
        # Set risk level
        verdict['risk_level'] = risk_level
        
        # Determine category
        category = detection_results.get('category')
        if category:
            verdict['category'] = category
        else:
            verdict['category'] = self._infer_category(detection_results)
        
        # Generate recommendations
        verdict['recommendations'] = self._generate_recommendations(
            verdict['is_scam'],
            verdict['category'],
            risk_level
        )
        
        # Store details
        verdict['details'] = {
            'risk_score': risk_score,
            'methods_detected': detection_results.get('methods', []),
            'detection_count': len(detection_results.get('methods', []))
        }
        
        return verdict
    
    def _infer_category(self, detection_results: Dict[str, Any]) -> Optional[str]:
        """Infer scam category from detection results"""
        methods = detection_results.get('method_results', {})
        
        # Check each method for category
        for method_name, result in methods.items():
            if isinstance(result, dict) and result.get('category'):
                return result['category']
        
        # Default to phishing
        return SCAM_CATEGORIES.get('PHISHING', 'Phishing')
    
    def _generate_recommendations(self, is_scam: bool, category: Optional[str], 
                                 risk_level: int) -> List[str]:
        """Generate recommendations based on verdict"""
        recommendations = []
        
        if is_scam:
            recommendations.append("Do not click any links in this email")
            recommendations.append("Do not download any attachments")
            recommendations.append("Do not reply to the sender")
            
            if risk_level >= 2:
                recommendations.append("Consider reporting this email as phishing")
                recommendations.append("Block the sender's address")
            
            if category:
                if category in ['Phishing', 'Fraud']:
                    recommendations.append("Do not provide any personal or financial information")
                elif category == 'Malware':
                    recommendations.append("Run a virus scan on your device")
                elif category in ['Extortion', 'Threats']:
                    recommendations.append("Do not respond to threats - report to authorities")
        else:
            recommendations.append("Exercise normal caution with any links or attachments")
        
        return recommendations
    
    def explain_verdict(self, verdict: Dict[str, Any]) -> str:
        """
        Generate human-readable explanation of verdict
        
        Args:
            verdict: Verdict dictionary
            
        Returns:
            Explanation string
        """
        if verdict['verdict'] == 'clean':
            return (
                f"This content appears to be safe. "
                f"Confidence: {verdict['confidence']:.1%}"
            )
        
        elif verdict['verdict'] == 'uncertain':
            return (
                f"This content has some suspicious elements but lacks "
                f"definitive evidence of being a scam. "
                f"Risk score: {verdict['details'].get('risk_score', 0):.1%}"
            )
        
        elif verdict['verdict'] == 'suspicious':
            return (
                f"This content shows signs of being a potential scam. "
                f"Category: {verdict['category']}. "
                f"Risk level: {verdict['risk_level']}/3"
            )
        
        else:  # malicious
            return (
                f"This content is likely a scam! "
                f"Category: {verdict['category']}. "
                f"Confidence: {verdict['confidence']:.1%}. "
                f"Risk level: {verdict['risk_level']}/3"
            )


# Global verdict engine instance
verdict_engine = VerdictEngine()
