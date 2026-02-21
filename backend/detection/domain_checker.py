"""
ScamShield Domain Checker
Domain reputation and analysis
"""
import re
from typing import Dict, Any, List, Optional
from datetime import datetime
import tldextract

from backend.database.db import get_session
from backend.database.models import ReputationRecord


class DomainChecker:
    """Domain reputation checker"""
    
    def __init__(self):
        """Initialize domain checker"""
        self.suspicious_tlds = [
            '.xyz', '.top', '.work', '.click', '.link', '.pw',
            '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.monster',
            '.date', '.racing', '.science', '.party', '.cricket',
            '.win', '.download', '.bid', '.stream', '.trade'
        ]
    
    def check_domains_in_content(self, content: str) -> Dict[str, Any]:
        """
        Check domains found in content
        
        Args:
            content: Text content containing domains
            
        Returns:
            Analysis result dictionary
        """
        result = {
            'domains_found': [],
            'suspicious_domains': [],
            'risk_score': 0.0
        }
        
        # Extract domains
        domains = self._extract_domains(content)
        
        if not domains:
            return result
        
        result['domains_found'] = domains
        
        # Check each domain
        for domain in domains:
            domain_check = self.check_domain(domain)
            
            if domain_check.get('is_suspicious') or domain_check.get('is_malicious'):
                result['suspicious_domains'].append({
                    'domain': domain,
                    'reasons': domain_check.get('reasons', [])
                })
        
        # Calculate risk score
        if result['suspicious_domains']:
            result['risk_score'] = min(
                len(result['suspicious_domains']) / len(domains) * 0.5 + 0.5,
                1.0
            )
        
        return result
    
    def check_domain(self, domain: str) -> Dict[str, Any]:
        """
        Check domain reputation
        
        Args:
            domain: Domain to check
            
        Returns:
            Check result dictionary
        """
        result = {
            'domain': domain,
            'is_suspicious': False,
            'is_malicious': False,
            'risk_score': 0.0,
            'reasons': [],
            'details': {}
        }
        
        if not domain:
            return result
        
        # Extract domain parts
        extracted = tldextract.extract(domain)
        
        # Basic checks
        self._check_domain_age(extracted, result)
        self._check_suspicious_tld(extracted, result)
        self._check_domain_length(extracted, result)
        self._check_numbers_in_domain(extracted, result)
        self._check_typosquatting(extracted, result)
        self._check_parked_domain(extracted, result)
        
        # Check against local blacklist
        self._check_blacklist(domain, result)
        
        # Check database for known reputation
        self._check_reputation_database(domain, result)
        
        # Determine overall assessment
        if result['reasons']:
            result['is_suspicious'] = True
            result['risk_score'] = min(len(result['reasons']) * 0.15, 1.0)
            
            if any('malicious' in r.lower() or 'blacklist' in r.lower() for r in result['reasons']):
                result['is_malicious'] = True
        
        result['details'] = {
            'domain': extracted.domain,
            'suffix': extracted.suffix,
            'subdomain': extracted.subdomain,
            'registered_domain': extracted.registered_domain
        }
        
        return result
    
    def _extract_domains(self, content: str) -> List[str]:
        """Extract domains from content"""
        # Match domain patterns
        domain_pattern = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        )
        
        domains = domain_pattern.findall(content)
        
        # Filter out common false positives
        excluded = ['google.com', 'facebook.com', 'amazon.com', 'microsoft.com', 
                    'apple.com', 'github.com', 'stackoverflow.com', 'reddit.com']
        
        return [d for d in domains if d.lower() not in excluded]
    
    def _check_domain_age(self, extracted, result: Dict[str, Any]):
        """Check if domain is newly registered"""
        # In production, this would use WHOIS data
        # For now, we'll check for suspicious characteristics
        pass
    
    def _check_suspicious_tld(self, extracted, result: Dict[str, Any]):
        """Check for suspicious TLD"""
        if extracted.suffix.lower() in self.suspicious_tlds:
            result['reasons'].append(f'Suspicious TLD: {extracted.suffix}')
    
    def _check_domain_length(self, extracted, result: Dict[str, Any]):
        """Check domain length"""
        if len(extracted.domain) > 20:
            result['reasons'].append('Unusually long domain name')
    
    def _check_numbers_in_domain(self, extracted, result: Dict[str, Any]):
        """Check for numbers in domain"""
        if any(c.isdigit() for c in extracted.domain):
            if len([c for c in extracted.domain if c.isdigit()]) > 2:
                result['reasons'].append('Domain contains excessive numbers')
    
    def _check_typosquatting(self, extracted, result: Dict[str, Any]):
        """Check for typosquatting"""
        legitimate_brands = [
            'google', 'facebook', 'amazon', 'apple', 'microsoft',
            'paypal', 'netflix', 'twitter', 'instagram', 'linkedin',
            'bankofamerica', 'chase', 'wellsfargo', 'citi', 'usbank'
        ]
        
        domain_lower = extracted.domain.lower()
        
        for brand in legitimate_brands:
            # Check for common typos
            if self._is_similar(domain_lower, brand):
                result['reasons'].append(f'Possible typosquatting of {brand}')
                break
    
    def _is_similar(self, domain: str, brand: str) -> bool:
        """Check if domain is similar to brand (typosquatting detection)"""
        if domain == brand:
            return False
        
        # Check for character substitution
        common_typos = {
            'o': '0', '0': 'o', 'l': '1', '1': 'l',
            'i': '1', '1': 'i', 'e': '3', '3': 'e',
            'a': '4', '4': 'a', 's': '5', '5': 's'
        }
        
        # Check with single character difference
        for i, char in enumerate(domain):
            modified = domain[:i] + common_typos.get(char, char) + domain[i+1:]
            if modified == brand:
                return True
        
        # Check for missing characters
        for i in range(len(domain)):
            modified = domain[:i] + domain[i+1:]
            if modified == brand:
                return True
        
        return False
    
    def _check_parked_domain(self, extracted, result: Dict[str, Any]):
        """Check for parked domains"""
        # In production, this would check for parked domain indicators
        pass
    
    def _check_blacklist(self, domain: str, result: Dict[str, Any]):
        """Check against local blacklist"""
        with get_session() as session:
            blacklist_entry = session.query(ReputationRecord).filter_by(
                entity_type='domain',
                entity_value=domain.lower()
            ).first()
            
            if blacklist_entry and blacklist_entry.is_malicious:
                result['reasons'].append('Domain is in blacklist')
                result['is_malicious'] = True
    
    def _check_reputation_database(self, domain: str, result: Dict[str, Any]):
        """Check reputation from database"""
        with get_session() as session:
            record = session.query(ReputationRecord).filter_by(
                entity_type='domain',
                entity_value=domain.lower()
            ).first()
            
            if record:
                result['details']['reputation'] = {
                    'trust_score': record.trust_score,
                    'safety_score': record.safety_score,
                    'threat_score': record.threat_score,
                    'is_malicious': record.is_malicious,
                    'is_suspicious': record.is_suspicious,
                    'last_checked': record.last_checked.isoformat() if record.last_checked else None
                }
                
                if record.is_malicious:
                    result['is_malicious'] = True
                    result['reasons'].append('Known malicious domain')
                
                if record.is_suspicious:
                    result['is_suspicious'] = True
    
    def save_reputation(self, domain: str, reputation_data: Dict[str, Any]):
        """Save domain reputation to database"""
        with get_session() as session:
            # Check if exists
            record = session.query(ReputationRecord).filter_by(
                entity_type='domain',
                entity_value=domain.lower()
            ).first()
            
            if record:
                # Update existing
                record.trust_score = reputation_data.get('trust_score', 50.0)
                record.safety_score = reputation_data.get('safety_score', 50.0)
                record.threat_score = reputation_data.get('threat_score', 0.0)
                record.is_malicious = reputation_data.get('is_malicious', False)
                record.is_suspicious = reputation_data.get('is_suspicious', False)
                record.last_checked = datetime.utcnow()
            else:
                # Create new
                record = ReputationRecord(
                    entity_type='domain',
                    entity_value=domain.lower(),
                    trust_score=reputation_data.get('trust_score', 50.0),
                    safety_score=reputation_data.get('safety_score', 50.0),
                    threat_score=reputation_data.get('threat_score', 0.0),
                    is_malicious=reputation_data.get('is_malicious', False),
                    is_suspicious=reputation_data.get('is_suspicious', False),
                    last_checked=datetime.utcnow()
                )
                session.add(record)
            
            session.commit()
