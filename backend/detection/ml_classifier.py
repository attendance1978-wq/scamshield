"""
ScamShield ML Classifier
Machine learning-based scam detection
"""
import re
import pickle
from typing import Dict, Any, Optional
import os

from backend.config import config
from backend.constants import SCAM_CATEGORIES


class MLClassifier:
    """Machine learning-based scam classifier"""
    
    def __init__(self):
        """Initialize the ML classifier"""
        self.model = None
        self.vectorizer = None
        self.threshold = config.ML_CONFIDENCE_THRESHOLD
        self._load_model()
    
    def _load_model(self):
        """Load the trained ML model"""
        model_path = config.ML_MODEL_PATH
        
        # Try to load existing model
        if os.path.exists(model_path):
            try:
                with open(model_path, 'rb') as f:
                    model_data = pickle.load(f)
                    self.model = model_data.get('model')
                    self.vectorizer = model_data.get('vectorizer')
            except Exception:
                # If model loading fails, use fallback
                self.model = None
                self.vectorizer = None
    
    def classify(self, content: str) -> Dict[str, Any]:
        """
        Classify content using ML model
        
        Args:
            content: Text content to classify
            
        Returns:
            Classification result dictionary
        """
        result = {
            'detected': False,
            'risk_score': 0.0,
            'category': None,
            'confidence': 0.0,
            'model_used': 'fallback'
        }
        
        if not content:
            return result
        
        # If model is loaded, use it
        if self.model is not None and self.vectorizer is not None:
            return self._classify_with_model(content)
        
        # Fallback: heuristic-based classification
        return self._classify_fallback(content)
    
    def _classify_with_model(self, content: str) -> Dict[str, Any]:
        """Classify using trained model"""
        try:
            # Transform content
            X = self.vectorizer.transform([content])
            
            # Get prediction
            prediction = self.model.predict(X)[0]
            probabilities = self.model.predict_proba(X)[0]
            
            # Get confidence (probability of predicted class)
            confidence = max(probabilities)
            
            # Determine if detected
            detected = prediction == 1 or confidence >= self.threshold
            
            result = {
                'detected': detected,
                'risk_score': confidence if detected else 1 - confidence,
                'category': SCAM_CATEGORIES.get('PHISHING', 'Phishing') if detected else None,
                'confidence': confidence,
                'model_used': 'trained_model'
            }
            
            return result
        
        except Exception:
            # Fallback on error
            return self._classify_fallback(content)
    
    def _classify_fallback(self, content: str) -> Dict[str, Any]:
        """Fallback heuristic-based classification"""
        # Simple heuristic features
        features = self._extract_features(content)
        
        # Calculate risk score based on features
        risk_score = 0.0
        
        # URL count
        if features['url_count'] > 0:
            risk_score += min(features['url_count'] * 0.1, 0.3)
        
        # Suspicious characters
        if features['suspicious_chars']:
            risk_score += 0.2
        
        # All caps words
        if features['all_caps_ratio'] > 0.3:
            risk_score += 0.15
        
        # Numbers in domain-like patterns
        if features['has_number_domains']:
            risk_score += 0.2
        
        # Shortened URLs
        if features['shortened_urls']:
            risk_score += 0.15
        
        # Special keywords
        if features['scam_keywords_count'] > 0:
            risk_score += min(features['scam_keywords_count'] * 0.1, 0.3)
        
        # Check if detected
        detected = risk_score >= self.threshold
        
        return {
            'detected': detected,
            'risk_score': min(risk_score, 1.0),
            'category': SCAM_CATEGORIES.get('PHISHING', 'Phishing') if detected else None,
            'confidence': min(risk_score + 0.3, 1.0) if detected else 0.5,
            'model_used': 'fallback'
        }
    
    def _extract_features(self, content: str) -> Dict[str, Any]:
        """Extract features from content for fallback classification"""
        # URL detection
        url_pattern = re.compile(r'https?://[^\s]+')
        urls = url_pattern.findall(content)
        
        # Suspicious characters
        suspicious_chars = sum(1 for c in content if c in '<>{}|\\^`[]')
        
        # All caps words
        words = content.split()
        all_caps_words = [w for w in words if w.isupper() and len(w) > 2]
        all_caps_ratio = len(all_caps_words) / max(len(words), 1)
        
        # Numbers in domain-like patterns
        number_domain_pattern = re.compile(r'[a-z]+\d+[a-z]+\.[a-z]+', re.IGNORECASE)
        has_number_domains = bool(number_domain_pattern.search(content))
        
        # Shortened URLs
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd']
        shortened_urls = any(s in url.lower() for url in urls for s in shorteners)
        
        # Scam keywords
        scam_keywords = [
            'verify', 'account', 'suspended', 'urgent', 'immediate',
            'password', 'login', 'bank', 'credit', 'card', 'payment',
            'winner', 'prize', 'congratulations', 'selected', 'free',
            'gift', 'bitcoin', 'invest', 'double', 'guaranteed'
        ]
        content_lower = content.lower()
        scam_keywords_count = sum(1 for kw in scam_keywords if kw in content_lower)
        
        return {
            'url_count': len(urls),
            'suspicious_chars': suspicious_chars,
            'all_caps_ratio': all_caps_ratio,
            'has_number_domains': has_number_domains,
            'shortened_urls': shortened_urls,
            'scam_keywords_count': scam_keywords_count
        }
    
    def train(self, training_data: list, labels: list) -> bool:
        """
        Train the model (placeholder for actual training)
        
        In production, this would use labeled data to train a model
        using scikit-learn or similar libraries.
        
        Args:
            training_data: List of text samples
            labels: List of labels (0 = legitimate, 1 = scam)
            
        Returns:
            True if training successful
        """
        # Placeholder: In production, implement actual model training
        # This would involve:
        # 1. Text preprocessing
        # 2. Feature extraction (TF-IDF, etc.)
        # 3. Model training (Random Forest, SVM, etc.)
        # 4. Evaluation
        # 5. Save model
        return False
    
    def save_model(self, path: str) -> bool:
        """
        Save the trained model
        
        Args:
            path: Path to save the model
            
        Returns:
            True if successful
        """
        if self.model is None:
            return False
        
        try:
            model_data = {
                'model': self.model,
                'vectorizer': self.vectorizer
            }
            
            os.makedirs(os.path.dirname(path), exist_ok=True)
            
            with open(path, 'wb') as f:
                pickle.dump(model_data, f)
            
            return True
        except Exception:
            return False
