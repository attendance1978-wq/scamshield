"""
ScamShield Email Monitor
Real-time email monitoring loop
"""
import time
import threading
from typing import Callable, Optional, Dict, Any
from datetime import datetime, timedelta

from backend.email.email_fetcher import EmailFetcher
from backend.detection.scam_detector import ScamDetector
from backend.database.db import get_session
from backend.database.models import Email, ScanResult, ScanStatus, RiskLevel
from backend.config import config


class EmailMonitor:
    """Real-time email monitoring"""
    
    def __init__(self):
        """Initialize email monitor"""
        self.fetcher = EmailFetcher()
        self.detector = ScamDetector()
        self.running = False
        self.thread = None
        self.interval = config.EMAIL_FETCH_INTERVAL
        self.callbacks = []
        self.last_check = None
    
    def start(self):
        """Start monitoring"""
        if self.running:
            return
        
        self.running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
    
    def is_running(self) -> bool:
        """Check if monitoring"""
        return self.running
    
    def add_callback(self, callback: Callable[[Dict[str, Any]], None]):
        """
        Add callback for new email detection
        
        Args:
            callback: Function to call with email data
        """
        self.callbacks.append(callback)
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                # Fetch new emails
                new_emails = self._fetch_new_emails()
                
                # Process each new email
                for email_data in new_emails:
                    self._process_email(email_data)
                
                # Update last check time
                self.last_check = datetime.utcnow()
                
            except Exception as e:
                print(f"Monitor error: {e}")
            
            # Sleep until next check
            time.sleep(self.interval)
    
    def _fetch_new_emails(self) -> list:
        """Fetch new emails since last check"""
        if self.last_check is None:
            # First run - fetch recent emails
            return self.fetcher.fetch_emails(limit=5)
        
        # Fetch emails since last check
        return self.fetcher.fetch_new_emails(self.last_check)
    
    def _process_email(self, email_data: Dict[str, Any]):
        """Process a single email"""
        message_id = email_data.get('message_id')
        
        # Check if already processed
        with get_session() as session:
            existing = session.query(Email).filter_by(message_id=message_id).first()
            if existing:
                return
            
            # Save email
            email = Email(
                message_id=message_id,
                subject=email_data.get('subject', ''),
                sender=email_data.get('from', ''),
                sender_email=email_data.get('from_email', ''),
                recipient=email_data.get('to', ''),
                body_text=email_data.get('body_text', ''),
                body_html=email_data.get('body_html', ''),
                received_at=email_data.get('date') or datetime.utcnow(),
                has_attachments=email_data.get('has_attachments', False),
                created_at=datetime.utcnow()
            )
            session.add(email)
            session.commit()
            
            # Scan for scams
            content = f"Subject: {email.subject}\n\n{email.body_text}"
            result = self.detector.detect(content, 'email')
            
            # Create scan result
            scan_result = ScanResult(
                scan_id=f"EMAIL-MONITOR-{message_id[:12]}",
                email_id=email.id,
                scan_type='email',
                content=content[:50000],
                is_scam=result.get('is_scam', False),
                risk_score=result.get('risk_score', 0.0),
                risk_level=RiskLevel(result.get('risk_level', 0)),
                category=result.get('category'),
                confidence=result.get('confidence', 0.0),
                detection_methods=result.get('methods', []),
                details=result.get('details', {}),
                status=ScanStatus.COMPLETED,
                completed_at=datetime.utcnow()
            )
            session.add(scan_result)
            
            # Update email
            email.is_spam = result.get('is_scam', False)
            email.processed_at = datetime.utcnow()
            
            session.commit()
            
            # Call callbacks
            for callback in self.callbacks:
                try:
                    callback({
                        'email': email_data,
                        'scan_result': result
                    })
                except Exception as e:
                    print(f"Callback error: {e}")
    
    def force_scan(self, message_id: str) -> Optional[Dict[str, Any]]:
        """
        Force scan a specific email
        
        Args:
            message_id: Message ID to scan
            
        Returns:
            Scan result
        """
        email_data = self.fetcher.get_email_by_id(message_id)
        
        if not email_data:
            return None
        
        self._process_email(email_data)
        
        # Return scan result
        with get_session() as session:
            scan = session.query(ScanResult).filter_by(
                scan_id=f"EMAIL-MONITOR-{message_id[:12]}"
            ).first()
            
            if scan:
                return {
                    'is_scam': scan.is_scam,
                    'risk_score': scan.risk_score,
                    'risk_level': scan.risk_level.value if scan.risk_level else 0,
                    'category': scan.category,
                    'confidence': scan.confidence
                }
        
        return None
    
    def get_status(self) -> Dict[str, Any]:
        """Get monitor status"""
        return {
            'running': self.running,
            'last_check': self.last_check.isoformat() if self.last_check else None,
            'interval': self.interval,
            'connection_status': self.fetcher.get_connection_status()
        }
