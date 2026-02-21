"""
ScamShield Reputation Checker
Checks reputation of domains and IPs using external services
"""
import requests
from typing import Dict, Any, Optional
from datetime import datetime

from backend.config import config
from backend.database.db import get_session
from backend.database.models import ReputationRecord


class ReputationChecker:
    """Reputation checking service"""
    
    def __init__(self):
        """Initialize reputation checker"""
        self.virustotal_key = config.VIRUSTOTAL_API_KEY
        self.abuseipdb_key = config.ABUSEIPDB_API_KEY
    
    def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """
        Check domain reputation
        
        Args:
            domain: Domain to check
            
        Returns:
            Reputation result dictionary
        """
        result = {
            'domain': domain,
            'is_malicious': False,
            'is_suspicious': False,
            'trust_score': 50.0,
            'threat_score': 0.0,
            'sources': []
        }
        
        # Check local database first
        local_result = self._check_local_database(domain)
        if local_result:
            return {**result, **local_result}
        
        # In production, integrate with external APIs:
        # - VirusTotal
        # - Google Safe Browsing
        # - PhishTank
        # - OpenPhish
        
        # For now, return basic analysis
        result['sources'].append('local_analysis')
        
        return result
    
    def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """
        Check IP reputation
        
        Args:
            ip: IP address to check
            
        Returns:
            Reputation result dictionary
        """
        result = {
            'ip': ip,
            'is_malicious': False,
            'is_suspicious': False,
            'trust_score': 50.0,
            'threat_score': 0.0,
            'country': None,
            'asn': None,
            'isp': None,
            'sources': []
        }
        
        # Check local database
        local_result = self._check_local_database(ip)
        if local_result:
            return {**result, **local_result}
        
        # In production, integrate with:
        # - AbuseIPDB
        # - Shodan
        # - IPVoid
        
        result['sources'].append('local_analysis')
        
        return result
    
    def _check_local_database(self, entity: str) -> Optional[Dict[str, Any]]:
        """Check local reputation database"""
        with get_session() as session:
            record = session.query(ReputationRecord).filter_by(
                entity_value=entity.lower()
            ).first()
            
            if record:
                return {
                    'trust_score': record.trust_score,
                    'safety_score': record.safety_score,
                    'threat_score': record.threat_score,
                    'is_malicious': record.is_malicious,
                    'is_suspicious': record.is_suspicious,
                    'last_checked': record.last_checked.isoformat() if record.last_checked else None
                }
        
        return None
    
    def save_reputation(self, entity_type: str, entity_value: str, 
                       reputation_data: Dict[str, Any]):
        """Save reputation to database"""
        with get_session() as session:
            record = session.query(ReputationRecord).filter_by(
                entity_type=entity_type,
                entity_value=entity_value.lower()
            ).first()
            
            if record:
                record.trust_score = reputation_data.get('trust_score', 50.0)
                record.safety_score = reputation_data.get('safety_score', 50.0)
                record.threat_score = reputation_data.get('threat_score', 0.0)
                record.is_malicious = reputation_data.get('is_malicious', False)
                record.is_suspicious = reputation_data.get('is_suspicious', False)
                record.last_checked = datetime.utcnow()
            else:
                record = ReputationRecord(
                    entity_type=entity_type,
                    entity_value=entity_value.lower(),
                    trust_score=reputation_data.get('trust_score', 50.0),
                    safety_score=reputation_data.get('safety_score', 50.0),
                    threat_score=reputation_data.get('threat_score', 0.0),
                    is_malicious=reputation_data.get('is_malicious', False),
                    is_suspicious=reputation_data.get('is_suspicious', False),
                    country=reputation_data.get('country'),
                    asn=reputation_data.get('asn'),
                    isp=reputation_data.get('isp'),
                    last_checked=datetime.utcnow()
                )
                session.add(record)
            
            session.commit()
