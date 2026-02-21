"""
ScamShield Similarity Checker
Detects fake domains using similarity analysis
"""
import re
from typing import Dict, Any, List, Set
from difflib import SequenceMatcher
import tldextract

from backend.constants import TYPOSQUATTING_TARGETS


class SimilarityChecker:
    """Similarity-based detection for typosquatting and brand impersonation"""
    
    def __init__(self):
        """Initialize similarity checker"""
        self.target_brands = TYPOSQUATTING_TARGETS
        self.similarity_threshold = 0.85
        
        # Common misspellings mapping
        self.common_misspellings = {
            'google': ['googel', 'gogle', 'gooogle', 'goggle', 'googl', 'go0gle'],
            'facebook': ['facebok', 'faceboook', 'facebk', 'facebbook', 'faceook'],
            'amazon': ['amazn', 'amazonn', 'amazom', 'amaz0n', 'amazonn'],
            'apple': ['appel', 'aplle', 'aple', 'appple', 'appl'],
            'paypal': ['paypal', 'paypall', 'paypai', 'paypa1', 'paypall'],
            'microsoft': ['microsft', 'microsfot', 'mircosoft', 'microsooft', 'microsft'],
            'netflix': ['netlfix', 'netflix', 'netfilx', 'netffix', 'nettflix'],
            'twitter': ['twiter', 'twittter', 'twiter', 'twittr', 'twittter'],
            'instagram': ['instagran', 'instgram', 'insragram', 'insatgram', '1nstagram']
        }
    
    def check_similarity(self, content: str) -> Dict[str, Any]:
        """
        Check content for similar/impersonating domains
        
        Args:
            content: Text content containing domains
            
        Returns:
            Analysis result dictionary
        """
        result = {
            'is_suspicious': False,
            'similar_domains': [],
            'risk_score': 0.0
        }
        
        # Extract domains from content
        domains = self._extract_domains(content)
        
        if not domains:
            return result
        
        # Check each domain against legitimate brands
        for domain in domains:
            similarity_result = self.check_domain_similarity(domain)
            
            if similarity_result.get('is_suspicious'):
                result['similar_domains'].append(similarity_result)
        
        # Calculate risk score
        if result['similar_domains']:
            result['is_suspicious'] = True
            result['risk_score'] = min(
                len(result['similar_domains']) * 0.3 + 0.4,
                1.0
            )
        
        return result
    
    def check_domain_similarity(self, domain: str) -> Dict[str, Any]:
        """
        Check a domain for similarity to legitimate brands
        
        Args:
            domain: Domain to check
            
        Returns:
            Check result dictionary
        """
        result = {
            'domain': domain,
            'is_suspicious': False,
            'matched_brand': None,
            'similarity_score': 0.0,
            'method': None,
            'reasons': []
        }
        
        if not domain:
            return result
        
        # Extract domain parts
        extracted = tldextract.extract(domain)
        domain_lower = extracted.domain.lower()
        
        # Check against known brands
        for brand in self.target_brands:
            # Direct similarity check
            similarity = self._calculate_similarity(domain_lower, brand)
            
            if similarity >= self.similarity_threshold:
                result['is_suspicious'] = True
                result['matched_brand'] = brand
                result['similarity_score'] = similarity
                result['method'] = 'similarity_check'
                result['reasons'].append(f'Domain is {int(similarity*100)}% similar to {brand}')
                return result
            
            # Check common misspellings
            if brand in self.common_misspellings:
                for misspelling in self.common_misspellings[brand]:
                    if domain_lower == misspelling:
                        result['is_suspicious'] = True
                        result['matched_brand'] = brand
                        result['similarity_score'] = 0.95
                        result['method'] = 'misspelling'
                        result['reasons'].append(f'Domain appears to be misspelling of {brand}')
                        return result
            
            # Check for added characters
            if self._has_added_characters(domain_lower, brand):
                result['is_suspicious'] = True
                result['matched_brand'] = brand
                result['similarity_score'] = 0.8
                result['method'] = 'added_characters'
                result['reasons'].append(f'Domain adds characters to {brand}')
                return result
            
            # Check for hyphenation
            if self._has_hyphenation(domain_lower, brand):
                result['is_suspicious'] = True
                result['matched_brand'] = brand
                result['similarity_score'] = 0.9
                result['method'] = 'hyphenation'
                result['reasons'].append(f'Domain hyphens {brand}')
                return result
        
        return result
    
    def _extract_domains(self, content: str) -> List[str]:
        """Extract domains from content"""
        domain_pattern = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        )
        return domain_pattern.findall(content)
    
    def _calculate_similarity(self, str1: str, str2: str) -> float:
        """Calculate similarity ratio between two strings"""
        return SequenceMatcher(None, str1, str2).ratio()
    
    def _has_added_characters(self, domain: str, brand: str) -> bool:
        """Check if domain adds characters to brand"""
        # Check if brand is contained in domain with extra characters
        if brand in domain:
            extra = domain.replace(brand, '')
            # Allow some extra characters (like 'login' in 'googlelogin')
            if len(extra) > 0 and len(extra) <= 6:
                return True
        
        return False
    
    def _has_hyphenation(self, domain: str, brand: str) -> bool:
        """Check if domain hyphenates brand name"""
        # Check for hyphenated versions
        hyphenated = f"{brand}-{brand}"  # e.g., google-google.com
        if brand in domain and '-' in domain:
            return True
        
        return False
    
    def check_url_similarity(self, url: str, legitimate_url: str) -> Dict[str, Any]:
        """
        Check similarity between a URL and a legitimate URL
        
        Args:
            url: URL to check
            legitimate_url: Legitimate URL to compare against
            
        Returns:
            Similarity result dictionary
        """
        result = {
            'is_similar': False,
            'similarity_score': 0.0,
            'differences': []
        }
        
        # Extract domains from URLs
        extracted1 = tldextract.extract(url)
        extracted2 = tldextract.extract(legitimate_url)
        
        domain1 = extracted1.domain
        domain2 = extracted2.domain
        
        # Calculate similarity
        similarity = self._calculate_similarity(domain1, domain2)
        result['similarity_score'] = similarity
        
        if similarity >= self.similarity_threshold:
            result['is_similar'] = True
            result['differences'].append(f'Domain is {int(similarity*100)}% similar')
        
        # Check TLD difference
        if extracted1.suffix != extracted2.suffix:
            result['differences'].append(f'Different TLD: {extracted1.suffix} vs {extracted2.suffix}')
        
        return result
    
    def generate_alternatives(self, domain: str) -> List[str]:
        """
        Generate potential typosquatting alternatives
        
        Args:
            domain: Domain to generate alternatives for
            
        Returns:
            List of potential fake domains
        """
        alternatives = []
        extracted = tldextract.extract(domain)
        base = extracted.domain
        
        # Common character substitutions
        substitutions = {
            'o': '0', '0': 'o', 'l': '1', '1': 'l',
            'i': 'j', 'e': '3', 'a': '4'
        }
        
        # Generate single-character variants
        for i, char in enumerate(base):
            if char in substitutions:
                variant = base[:i] + substitutions[char] + base[i+1:]
                alternatives.append(f"{variant}.{extracted.suffix}")
        
        # Generate missing character variants
        for i in range(len(base)):
            variant = base[:i] + base[i+1:]
            if variant:
                alternatives.append(f"{variant}.{extracted.suffix}")
        
        # Generate double character variants
        for i, char in enumerate(base):
            variant = base[:i] + char + char + base[i+1:]
            alternatives.append(f"{variant}.{extracted.suffix}")
        
        return alternatives[:10]  # Return top 10
