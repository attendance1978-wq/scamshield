"""
ScamShield Risk Scorer
Calculates risk scores based on multiple detection methods
"""
from typing import Dict, Any, List
from backend.constants import RISK_LEVELS


class RiskScorer:
    """Risk scoring engine"""
    
    def __init__(self):
        """Initialize risk scorer"""
        # Weights for different detection methods
        self.method_weights = {
            'rule_based': 0.25,
            'ml': 0.25,
            'url_analysis': 0.20,
            'domain_reputation': 0.15,
            'similarity': 0.10,
            'blacklist': 0.05
        }
    
    def calculate_risk_score(self, detection_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate overall risk score from all detection methods
        
        Args:
            detection_results: Dictionary of detection results from different methods
            
        Returns:
            Risk score dictionary
        """
        total_score = 0.0
        total_weight = 0.0
        method_scores = {}
        
        for method_name, result in detection_results.items():
            if not result:
                continue
            
            # Get method weight
            weight = self.method_weights.get(method_name, 0.1)
            
            # Get risk score from method
            if isinstance(result, dict):
                score = result.get('risk_score', 0.0)
            else:
                score = 0.0
            
            method_scores[method_name] = {
                'score': score,
                'weight': weight,
                'weighted_score': score * weight
            }
            
            total_score += score * weight
            total_weight += weight
        
        # Normalize score
        if total_weight > 0:
            normalized_score = total_score / total_weight
        else:
            normalized_score = 0.0
        
        # Determine risk level
        risk_level = self._get_risk_level(normalized_score)
        
        return {
            'risk_score': normalized_score,
            'risk_level': risk_level,
            'risk_level_name': self._get_risk_level_name(risk_level),
            'method_scores': method_scores,
            'is_scam': normalized_score >= 0.5
        }
    
    def _get_risk_level(self, score: float) -> int:
        """Convert score to risk level (0-3)"""
        if score >= 0.75:
            return 3  # Critical
        elif score >= 0.5:
            return 2  # High
        elif score >= 0.25:
            return 1  # Medium
        else:
            return 0  # Low
    
    def _get_risk_level_name(self, level: int) -> str:
        """Get risk level name"""
        names = {
            0: 'Low',
            1: 'Medium',
            2: 'High',
            3: 'Critical'
        }
        return names.get(level, 'Unknown')
    
    def calculate_risk_from_components(self, components: Dict[str, float]) -> Dict[str, Any]:
        """
        Calculate risk from individual components
        
        Args:
            components: Dictionary of component scores
            
        Returns:
            Risk calculation result
        """
        # Calculate weighted sum
        weighted_sum = 0.0
        total_weight = 0.0
        
        for component, score in components.items():
            weight = self.method_weights.get(component, 0.1)
            weighted_sum += score * weight
            total_weight += weight
        
        # Normalize
        if total_weight > 0:
            normalized = weighted_sum / total_weight
        else:
            normalized = 0.0
        
        # Get risk level
        risk_level = self._get_risk_level(normalized)
        
        return {
            'risk_score': normalized,
            'risk_level': risk_level,
            'risk_level_name': self._get_risk_level_name(risk_level),
            'is_scam': normalized >= 0.5,
            'components': components
        }
    
    def adjust_score(self, base_score: float, adjustments: List[Dict[str, Any]]) -> float:
        """
        Adjust risk score based on additional factors
        
        Args:
            base_score: Base risk score
            adjustments: List of adjustment dictionaries
            
        Returns:
            Adjusted score
        """
        adjusted = base_score
        
        for adjustment in adjustments:
            factor = adjustment.get('factor', 0.0)
            weight = adjustment.get('weight', 1.0)
            
            # Apply weighted adjustment
            adjustment_value = factor * weight * 0.1
            adjusted = min(adjusted + adjustment_value, 1.0)
        
        return adjusted


# Global risk scorer instance
risk_scorer = RiskScorer()
