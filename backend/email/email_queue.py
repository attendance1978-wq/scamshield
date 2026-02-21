"""
ScamShield Email Queue
Queue-based email processing system
"""
import queue
import threading
import time
from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass
from datetime import datetime

from backend.detection.scam_detector import ScamDetector
from backend.database.db import get_session
from backend.database.models import Email, ScanResult, ScanStatus, RiskLevel


@dataclass
class EmailTask:
    """Email processing task"""
    email_id: int
    message_id: str
    subject: str
    sender: str
    body_text: str
    body_html: str
    priority: int = 0


class EmailQueue:
    """Email processing queue"""
    
    def __init__(self, max_workers: int = 3, max_size: int = 1000):
        """Initialize email queue"""
        self.queue = queue.PriorityQueue(maxsize=max_size)
        self.max_workers = max_workers
        self.workers = []
        self.running = False
        self.detector = ScamDetector()
        self.processed_count = 0
        self.failed_count = 0
    
    def start(self):
        """Start queue workers"""
        if self.running:
            return
        
        self.running = True
        
        # Start worker threads
        for i in range(self.max_workers):
            worker = threading.Thread(
                target=self._worker,
                args=(i,),
                daemon=True
            )
            worker.start()
            self.workers.append(worker)
    
    def stop(self):
        """Stop queue workers"""
        self.running = False
        
        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=5)
        
        self.workers.clear()
    
    def add_task(self, email_task: EmailTask) -> bool:
        """
        Add task to queue
        
        Args:
            email_task: Email task to add
            
        Returns:
            True if added successfully
        """
        try:
            # Priority queue: lower number = higher priority
            # We invert priority so higher priority tasks are processed first
            priority = 10 - email_task.priority
            self.queue.put((priority, email_task))
            return True
        except queue.Full:
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get queue statistics"""
        return {
            'queue_size': self.queue.qsize(),
            'max_workers': self.max_workers,
            'running': self.running,
            'processed_count': self.processed_count,
            'failed_count': self.failed_count
        }
    
    def _worker(self, worker_id: int):
        """Worker thread function"""
        print(f"Email queue worker {worker_id} started")
        
        while self.running:
            try:
                # Get task from queue with timeout
                priority, task = self.queue.get(timeout=1)
                
                # Process email
                self._process_email(task)
                
                # Mark task as done
                self.queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Worker {worker_id} error: {e}")
                self.failed_count += 1
        
        print(f"Email queue worker {worker_id} stopped")
    
    def _process_email(self, task: EmailTask):
        """Process a single email task"""
        try:
            # Combine content for analysis
            content = f"Subject: {task.subject}\n\n{task.body_text}"
            
            # Perform detection
            result = self.detector.detect(content, 'email')
            
            # Save scan result
            with get_session() as session:
                # Create scan result
                scan_result = ScanResult(
                    scan_id=f"QUEUE-{task.message_id[:12]}-{int(time.time())}",
                    email_id=task.email_id,
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
                
                # Update email record
                email = session.query(Email).filter_by(id=task.email_id).first()
                if email:
                    email.is_spam = result.get('is_scam', False)
                    email.processed_at = datetime.utcnow()
                
                session.commit()
            
            self.processed_count += 1
            
        except Exception as e:
            print(f"Error processing email {task.email_id}: {e}")
            self.failed_count += 1


# Global email queue instance
email_queue = EmailQueue()


def get_email_queue() -> EmailQueue:
    """Get global email queue instance"""
    return email_queue
