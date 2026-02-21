"""
ScamShield Alert Worker
Background worker for alert processing
"""
import time
import threading
from typing import Optional, List
from datetime import datetime
from queue import Queue, Empty

from backend.database.db import get_session
from backend.database.models import Alert, ScanResult
from backend.alert.notifier import notifier
from backend.alert.email_alert import email_alert
from backend.alert.log_alert import log_alert


class AlertWorker:
    """Background worker for alert processing"""
    
    def __init__(self):
        """Initialize alert worker"""
        self.task_queue = Queue()
        self.running = False
        self.workers = []
        self.num_workers = 2
    
    def start(self):
        """Start alert worker"""
        if self.running:
            return
        
        self.running = True
        
        # Start worker threads
        for i in range(self.num_workers):
            worker = threading.Thread(
                target=self._worker_loop,
                args=(i,),
                daemon=True
            )
            worker.start()
            self.workers.append(worker)
        
        print(f"Alert worker started with {self.num_workers} workers")
    
    def stop(self):
        """Stop alert worker"""
        self.running = False
        
        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=5)
        
        self.workers.clear()
        
        print("Alert worker stopped")
    
    def is_running(self) -> bool:
        """Check if worker is running"""
        return self.running
    
    def submit_alert(self, title: str, message: str, priority: int = 1,
                     user_id: int = None, scan_result_id: int = None):
        """
        Submit alert task
        
        Args:
            title: Alert title
            message: Alert message
            priority: Alert priority
            user_id: User ID
            scan_result_id: Scan result ID
        """
        self.task_queue.put({
            'title': title,
            'message': message,
            'priority': priority,
            'user_id': user_id,
            'scan_result_id': scan_result_id
        })
    
    def _worker_loop(self, worker_id: int):
        """Worker thread loop"""
        print(f"Alert worker {worker_id} started")
        
        while self.running:
            try:
                # Get task from queue
                task = self.task_queue.get(timeout=1)
                
                # Process alert
                self._process_alert(task)
                
                # Mark task as done
                self.task_queue.task_done()
                
            except Empty:
                continue
            except Exception as e:
                print(f"Alert worker {worker_id} error: {e}")
        
        print(f"Alert worker {worker_id} stopped")
    
    def _process_alert(self, task: dict):
        """Process alert task"""
        title = task.get('title')
        message = task.get('message')
        priority = task.get('priority', 1)
        user_id = task.get('user_id')
        scan_result_id = task.get('scan_result_id')
        
        # Create alert in database
        with get_session() as session:
            alert = Alert(
                alert_type='system',
                priority=priority,
                title=title,
                message=message,
                user_id=user_id,
                scan_result_id=scan_result_id,
                created_at=datetime.utcnow()
            )
            session.add(alert)
            session.commit()
            alert_id = alert.id
        
        # Send notifications
        # 1. Log alert
        log_alert.alert(
            'warning' if priority >= 2 else 'info',
            f"{title}: {message}"
        )
        
        # 2. In-app notification
        if user_id:
            notifier.notify(
                title=title,
                message=message,
                priority=priority,
                user_id=user_id,
                scan_result_id=scan_result_id
            )
        
        # 3. Email notification for high priority
        if priority >= 2:
            # Get user email if available
            with get_session() as session:
                from backend.database.models import User
                user = session.query(User).filter_by(id=user_id).first()
                if user and user.email:
                    email_alert.send_alert(
                        user.email,
                        f"⚠️ ScamShield Alert: {title}",
                        message
                    )
        
        # Update alert as sent
        with get_session() as session:
            alert = session.query(Alert).filter_by(id=alert_id).first()
            if alert:
                alert.is_sent = True
                alert.sent_at = datetime.utcnow()
                alert.delivery_status = 'sent'
                session.commit()
    
    def process_pending_alerts(self, limit: int = 50):
        """Process pending alerts from database"""
        with get_session() as session:
            pending_alerts = session.query(Alert).filter_by(
                is_sent=False
            ).filter(
                Alert.created_at >= datetime.utcnow()  # Only recent alerts
            ).limit(limit).all()
            
            for alert in pending_alerts:
                self.submit_alert(
                    title=alert.title,
                    message=alert.message,
                    priority=alert.priority,
                    user_id=alert.user_id,
                    scan_result_id=alert.scan_result_id
                )
    
    def get_queue_size(self) -> int:
        """Get current queue size"""
        return self.task_queue.qsize()
    
    def get_status(self) -> dict:
        """Get worker status"""
        return {
            'running': self.running,
            'queue_size': self.get_queue_size(),
            'num_workers': self.num_workers
        }


# Global alert worker
alert_worker = AlertWorker()


def start_alert_worker():
    """Start the alert worker"""
    alert_worker.start()


def stop_alert_worker():
    """Stop the alert worker"""
    alert_worker.stop()
