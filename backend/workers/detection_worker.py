"""
ScamShield Detection Worker
Background worker for scam detection
"""
import time
import threading
from typing import Optional, List
from datetime import datetime, timedelta
from queue import Queue, Empty

from backend.database.db import get_session
from backend.database.models import ScanResult, ScanStatus
from backend.detection.scam_detector import ScamDetector


class DetectionWorker:
    """Background worker for detection processing"""
    
    def __init__(self):
        """Initialize detection worker"""
        self.detector = ScamDetector()
        self.task_queue = Queue()
        self.running = False
        self.workers = []
        self.num_workers = 3
    
    def start(self):
        """Start detection worker"""
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
        
        print(f"Detection worker started with {self.num_workers} workers")
    
    def stop(self):
        """Stop detection worker"""
        self.running = False
        
        # Wait for workers to finish
        for worker in self.workers:
            worker.join(timeout=5)
        
        self.workers.clear()
        
        print("Detection worker stopped")
    
    def is_running(self) -> bool:
        """Check if worker is running"""
        return self.running
    
    def submit_task(self, scan_id: str, content: str, scan_type: str):
        """
        Submit detection task
        
        Args:
            scan_id: Scan ID
            content: Content to analyze
            scan_type: Type of content
        """
        self.task_queue.put({
            'scan_id': scan_id,
            'content': content,
            'scan_type': scan_type
        })
    
    def _worker_loop(self, worker_id: int):
        """Worker thread loop"""
        print(f"Detection worker {worker_id} started")
        
        while self.running:
            try:
                # Get task from queue
                task = self.task_queue.get(timeout=1)
                
                # Process detection
                self._process_detection(task)
                
                # Mark task as done
                self.task_queue.task_done()
                
            except Empty:
                continue
            except Exception as e:
                print(f"Detection worker {worker_id} error: {e}")
        
        print(f"Detection worker {worker_id} stopped")
    
    def _process_detection(self, task: dict):
        """Process detection task"""
        scan_id = task.get('scan_id')
        content = task.get('content')
        scan_type = task.get('scan_type')
        
        # Update status to in progress
        with get_session() as session:
            scan = session.query(ScanResult).filter_by(scan_id=scan_id).first()
            
            if scan:
                scan.status = ScanStatus.IN_PROGRESS
                session.commit()
        
        # Perform detection
        try:
            result = self.detector.detect(content, scan_type)
            
            # Update scan result
            with get_session() as session:
                scan = session.query(ScanResult).filter_by(scan_id=scan_id).first()
                
                if scan:
                    scan.is_scam = result.get('is_scam', False)
                    scan.risk_score = result.get('risk_score', 0.0)
                    scan.risk_level = result.get('risk_level', 0)
                    scan.category = result.get('category')
                    scan.confidence = result.get('confidence', 0.0)
                    scan.detection_methods = result.get('methods', [])
                    scan.details = result.get('details', {})
                    scan.status = ScanStatus.COMPLETED
                    scan.completed_at = datetime.utcnow()
                    session.commit()
                    
        except Exception as e:
            # Update status to failed
            with get_session() as session:
                scan = session.query(ScanResult).filter_by(scan_id=scan_id).first()
                
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = str(e)
                    session.commit()
    
    def process_pending_scans(self, limit: int = 50):
        """Process pending scans from database"""
        with get_session() as session:
            pending_scans = session.query(ScanResult).filter_by(
                status=ScanStatus.PENDING
            ).limit(limit).all()
            
            for scan in pending_scans:
                if scan.content:
                    self.submit_task(scan.scan_id, scan.content, scan.scan_type)
    
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


# Global detection worker
detection_worker = DetectionWorker()


def start_detection_worker():
    """Start the detection worker"""
    detection_worker.start()


def stop_detection_worker():
    """Stop the detection worker"""
    detection_worker.stop()
