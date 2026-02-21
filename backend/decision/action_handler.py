"""
ScamShield Action Handler
Handles actions based on detection verdicts
"""
from typing import Dict, Any, Callable, List
from datetime import datetime

from backend.database.db import get_session
from backend.database.models import Alert, ScanResult


class ActionHandler:
    """Handles actions based on detection results"""
    
    def __init__(self):
        """Initialize action handler"""
        self.action_handlers = {}
        self._register_default_handlers()
    
    def _register_default_handlers(self):
        """Register default action handlers"""
        self.register_action('alert', self._create_alert)
        self.register_action('log', self._log_action)
        self.register_action('quarantine', self._quarantine_action)
        self.register_action('notify', self._notify_action)
        self.register_action('block_sender', self._block_sender)
    
    def register_action(self, action_type: str, handler: Callable):
        """
        Register an action handler
        
        Args:
            action_type: Type of action
            handler: Handler function
        """
        self.action_handlers[action_type] = handler
    
    def execute_actions(self, scan_result: Dict[str, Any], actions: List[str]) -> Dict[str, Any]:
        """
        Execute actions based on scan result
        
        Args:
            scan_result: Scan result dictionary
            actions: List of action types to execute
            
        Returns:
            Execution results
        """
        results = {
            'executed': [],
            'failed': [],
            'timestamp': datetime.utcnow().isoformat()
        }
        
        for action in actions:
            if action in self.action_handlers:
                try:
                    handler = self.action_handlers[action]
                    result = handler(scan_result)
                    results['executed'].append({
                        'action': action,
                        'result': result
                    })
                except Exception as e:
                    results['failed'].append({
                        'action': action,
                        'error': str(e)
                    })
            else:
                results['failed'].append({
                    'action': action,
                    'error': 'Unknown action type'
                })
        
        return results
    
    def _create_alert(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Create alert for scan result"""
        with get_session() as session:
            alert = Alert(
                alert_type='system',
                priority=scan_result.get('risk_level', 1),
                title=f"Scam Detected: {scan_result.get('category', 'Unknown')}",
                message=f"Risk Score: {scan_result.get('risk_score', 0):.2f}",
                scan_result_id=scan_result.get('id'),
                created_at=datetime.utcnow()
            )
            session.add(alert)
            session.commit()
            
            return {'alert_id': alert.id}
    
    def _log_action(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Log scan result"""
        # In production, this would log to a proper logging system
        print(f"[ACTION] Scam detected: {scan_result.get('scan_id')}")
        return {'logged': True}
    
    def _quarantine_action(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Quarantine the email"""
        # In production, this would move the email to quarantine
        return {'quarantined': True}
    
    def _notify_action(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Send notification about the detection"""
        # This would trigger real-time notifications
        return {'notified': True}
    
    def _block_sender(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Block the sender"""
        # In production, this would add sender to blacklist
        sender = scan_result.get('sender_email')
        if sender:
            return {'blocked': True, 'sender': sender}
        return {'blocked': False}


# Global action handler
action_handler = ActionHandler()
