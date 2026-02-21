"""
ScamShield Email Worker
Background worker for email processing
"""
import time
import threading
from typing import Optional
from datetime import datetime

from backend.email.email_fetcher import EmailFetcher
from backend.email.email_queue import EmailQueue, EmailTask
from backend.database.db import get_session
from backend.database.models import Email, ScanResult, ScanStatus, RiskLevel
from backend.detection.scam_detector import ScamDetector


class EmailWorker:
    """Background worker for email processing"""
    
    def __init__(self):
        """Initialize email worker"""
        self.fetcher = EmailFetcher()
        self.queue = EmailQueue()
        self.detector = ScamDetector()
        self.running = False
        self.thread = None
        self.interval = 30  # Check every 30 seconds
    
    def start(self):
        """Start email worker"""
        if self.running:
            return
        
        self.running = True
        
        # Start queue workers
        self.queue.start()
        
        # Start main worker thread
        self.thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.thread.start()
        
        print("Email worker started")
    
    def stop(self):
        """Stop email worker"""
        self.running = False
        
        if self.thread:
            self.thread.join(timeout=5)
        
        self.queue.stop()
        
        print("Email worker stopped")
    
    def is_running(self) -> bool:
        """Check if worker is running"""
        return self.running
    
    def _worker_loop(self):
        """Main worker loop"""
        while self.running:
            try:
                # Fetch new emails
                self._fetch_and_queue_emails()
                
            except Exception as e:
                print(f"Email worker error: {e}")
            
            # Sleep until next iteration
            time.sleep(self.interval)
    
    def _fetch_and_queue_emails(self):
        """Fetch emails and add to processing queue"""
        try:
            # Fetch recent emails
            emails = self.fetcher.fetch_emails(limit=10)
            
            for email_data in emails:
                message_id = email_data.get('message_id')
                
                # Check if already processed
                with get_session() as session:
                    existing = session.query(Email).filter_by(
                        message_id=message_id
                    ).first()
                    
                    if existing and existing.processed_at:
                        continue
                    
                    # Create email task
                    task = EmailTask(
                        email_id=existing.id if existing else 0,
                        message_id=message_id,
                        subject=email_data.get('subject', ''),
                        sender=email_data.get('from', ''),
                        body_text=email_data.get('body_text', ''),
                        body_html=email_data.get('body_html', ''),
                        priority=1
                    )
                    
                    # Add to queue
                    self.queue.add_task(task)
                    
        except Exception as e:
            print(f"Error fetching emails: {e}")
    
    def process_email(self, task: EmailTask) -> dict:
        """
        Process a single email task
        
        Args:
            task: Email task
            
        Returns:
            Processing result
        """
        # Combine content
        content = f"Subject: {task.subject}\n\n{task.body_text}"
        
        # Detect scams
        result = self.detector.detect(content, 'email')
        
        # Save result
        with get_session() as session:
            # Create or update email record
            email = session.query(Email).filter_by(
                message_id=task.message_id
            ).first()
            
            if not email:
                email = Email(
                    message_id=task.message_id,
                    subject=task.subject,
                    sender=task.sender,
                    body_text=task.body_text,
                    body_html=task.body_html,
                    created_at=datetime.utcnow()
                )
                session.add(email)
                session.commit()
                session.refresh(email)
            
            # Create scan result
            scan_result = ScanResult(
                scan_id=f"WORKER-{task.message_id[:12]}",
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
        
        return result
    
    def get_status(self) -> dict:
        """Get worker status"""
        return {
            'running': self.running,
            'queue_stats': self.queue.get_stats()
        }


# Global email worker
email_worker = EmailWorker()


def start_email_worker():
    """Start the email worker"""
    email_worker.start()


def stop_email_worker():
    """Stop the email worker"""
    email_worker.stop()
