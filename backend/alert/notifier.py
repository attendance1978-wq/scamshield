"""
ScamShield Notifier
Main notification system
"""
from typing import Dict, Any, List, Optional
from datetime import datetime

from backend.config import config
from backend.database.db import get_session
from backend.database.models import Alert


class Notifier:
    """Notification system"""
    
    def __init__(self):
        """Initialize notifier"""
        self.enabled = True
        self.handlers = []
    
    def add_handler(self, handler):
        """Add notification handler"""
        self.handlers.append(handler)
    
    def notify(self, title: str, message: str, priority: int = 1, 
               user_id: int = None, scan_result_id: int = None) -> Optional[int]:
        """
        Send notification
        
        Args:
            title: Notification title
            message: Notification message
            priority: Priority level (0-3)
            user_id: User ID to notify
            scan_result_id: Related scan result ID
            
        Returns:
            Alert ID or None
        """
        if not self.enabled:
            return None
        
        # Create alert in database
        with get_session() as session:
            alert = Alert(
                alert_type='notification',
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
        
        # Send to handlers
        for handler in self.handlers:
            try:
                handler({
                    'alert_id': alert_id,
                    'title': title,
                    'message': message,
                    'priority': priority,
                    'timestamp': datetime.utcnow().isoformat()
                })
            except Exception as e:
                print(f"Notification handler error: {e}")
        
        return alert_id
    
    def notify_scam_detected(self, scan_result: Dict[str, Any], user_id: int = None):
        """Notify about detected scam"""
        title = f"🚨 Scam Detected: {scan_result.get('category', 'Unknown')}"
        message = (
            f"A potential scam was detected!\n\n"
            f"Risk Score: {scan_result.get('risk_score', 0):.1%}\n"
            f"Risk Level: {scan_result.get('risk_level', 0)}/3\n"
            f"Confidence: {scan_result.get('confidence', 0):.1%}"
        )
        
        priority = scan_result.get('risk_level', 1)
        
        return self.notify(
            title=title,
            message=message,
            priority=priority,
            user_id=user_id,
            scan_result_id=scan_result.get('id')
        )
    
    def notify_scan_complete(self, scan_id: str, is_scam: bool, user_id: int = None):
        """Notify about completed scan"""
        status = "⚠️ Potential Scam" if is_scam else "✅ Safe"
        
        title = f"Scan Complete: {status}"
        message = f"Scan {scan_id} has completed."
        
        return self.notify(
            title=title,
            message=message,
            priority=1,
            user_id=user_id
        )


# Global notifier instance
notifier = Notifier()
