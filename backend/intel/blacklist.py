"""
ScamShield Blacklist Module
Manages blacklists for domains, IPs, URLs, emails, and keywords
"""
from typing import List, Dict, Any, Optional
from datetime import datetime

from backend.database.db import get_session
from backend.database.models import BlacklistEntry
from backend.constants import BLACKLIST_CATEGORIES


class BlacklistManager:
    """Blacklist management"""
    
    def __init__(self):
        """Initialize blacklist manager"""
        self.categories = BLACKLIST_CATEGORIES
    
    def add_entry(self, entry_type: str, value: str, category: str, 
                  source: str = 'manual', confidence: float = 1.0,
                  description: str = None) -> Optional[BlacklistEntry]:
        """
        Add entry to blacklist
        
        Args:
            entry_type: Type of entry (domain, ip, url, email, keyword)
            value: Value to blacklist
            category: Threat category
            source: Source of the entry
            confidence: Confidence level (0-1)
            description: Optional description
            
        Returns:
            Created BlacklistEntry or None
        """
        if entry_type not in self.categories.values():
            return None
        
        with get_session() as session:
            # Check if exists
            existing = session.query(BlacklistEntry).filter_by(
                entry_type=entry_type,
                value=value.lower()
            ).first()
            
            if existing:
                # Update existing
                existing.category = category
                existing.source = source
                existing.confidence = confidence
                existing.description = description
                existing.is_active = True
                existing.updated_at = datetime.utcnow()
                session.commit()
                return existing
            
            # Create new
            entry = BlacklistEntry(
                entry_type=entry_type,
                value=value.lower(),
                category=category,
                source=source,
                confidence=confidence,
                description=description,
                is_active=True,
                created_at=datetime.utcnow()
            )
            session.add(entry)
            session.commit()
            return entry
    
    def remove_entry(self, entry_type: str, value: str) -> bool:
        """
        Remove entry from blacklist
        
        Args:
            entry_type: Type of entry
            value: Value to remove
            
        Returns:
            True if removed
        """
        with get_session() as session:
            entry = session.query(BlacklistEntry).filter_by(
                entry_type=entry_type,
                value=value.lower()
            ).first()
            
            if entry:
                entry.is_active = False
                session.commit()
                return True
            
            return False
    
    def check(self, entry_type: str, value: str) -> Optional[BlacklistEntry]:
        """
        Check if value is blacklisted
        
        Args:
            entry_type: Type of entry
            value: Value to check
            
        Returns:
            BlacklistEntry if found, None otherwise
        """
        with get_session() as session:
            return session.query(BlacklistEntry).filter_by(
                entry_type=entry_type,
                value=value.lower(),
                is_active=True
            ).first()
    
    def get_all(self, entry_type: str = None, category: str = None,
                limit: int = 100) -> List[BlacklistEntry]:
        """
        Get blacklist entries
        
        Args:
            entry_type: Filter by type
            category: Filter by category
            limit: Maximum results
            
        Returns:
            List of BlacklistEntry
        """
        with get_session() as session:
            query = session.query(BlacklistEntry).filter_by(is_active=True)
            
            if entry_type:
                query = query.filter_by(entry_type=entry_type)
            if category:
                query = query.filter_by(category=category)
            
            return query.limit(limit).all()
    
    def get_domains(self, limit: int = 100) -> List[str]:
        """Get blacklisted domains"""
        with get_session() as session:
            entries = session.query(BlacklistEntry).filter_by(
                entry_type='domain',
                is_active=True
            ).limit(limit).all()
            return [e.value for e in entries]
    
    def get_ips(self, limit: int = 100) -> List[str]:
        """Get blacklisted IPs"""
        with get_session() as session:
            entries = session.query(BlacklistEntry).filter_by(
                entry_type='ip',
                is_active=True
            ).limit(limit).all()
            return [e.value for e in entries]
    
    def get_keywords(self, limit: int = 100) -> List[str]:
        """Get blacklisted keywords"""
        with get_session() as session:
            entries = session.query(BlacklistEntry).filter_by(
                entry_type='keyword',
                is_active=True
            ).limit(limit).all()
            return [e.value for e in entries]
    
    def import_list(self, entries: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Import multiple entries
        
        Args:
            entries: List of entry dictionaries
            
        Returns:
            Import statistics
        """
        stats = {'added': 0, 'updated': 0, 'skipped': 0}
        
        for entry_data in entries:
            try:
                result = self.add_entry(
                    entry_type=entry_data.get('type'),
                    value=entry_data.get('value'),
                    category=entry_data.get('category', 'unknown'),
                    source=entry_data.get('source', 'import'),
                    confidence=entry_data.get('confidence', 1.0),
                    description=entry_data.get('description')
                )
                
                if result:
                    stats['added'] += 1
            except Exception:
                stats['skipped'] += 1
        
        return stats


# Global blacklist manager
blacklist_manager = BlacklistManager()
