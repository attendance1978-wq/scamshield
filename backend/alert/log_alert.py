"""
ScamShield Log Alert
Logging-based notification system
"""
import logging
from typing import Dict, Any
from datetime import datetime


class LogAlert:
    """Logging notification handler"""
    
    def __init__(self):
        """Initialize log alert"""
        self.logger = logging.getLogger('scamshield.alerts')
    
    def alert(self, level: str, message: str, data: Dict[str, Any] = None):
        """
        Log an alert
        
        Args:
            level: Log level (debug, info, warning, error, critical)
            message: Alert message
            data: Additional data
        """
        log_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'message': message,
            'data': data or {}
        }
        
        # Map string level to logging level
        log_level = getattr(logging, level.upper(), logging.INFO)
        
        self.logger.log(log_level, f"{message} | {log_data}")
    
    def scam_detected(self, scan_result: Dict[str, Any]):
        """Log scam detection"""
        self.alert(
            'warning',
            f"Scam detected: {scan_result.get('category', 'Unknown')}",
            {
                'scan_id': scan_result.get('scan_id'),
                'risk_score': scan_result.get('risk_score'),
                'risk_level': scan_result.get('risk_level'),
                'confidence': scan_result.get('confidence'),
                'methods': scan_result.get('methods', [])
            }
        )
    
    def scan_complete(self, scan_id: str, is_scam: bool):
        """Log scan completion"""
        self.alert(
            'info',
            f"Scan complete: {scan_id} - {'SCAM' if is_scam else 'CLEAN'}",
            {
                'scan_id': scan_id,
                'is_scam': is_scam
            }
        )
    
    def error(self, message: str, error: Exception = None):
        """Log error"""
        self.alert(
            'error',
            message,
            {'error': str(error) if error else None}
        )
    
    def info(self, message: str, data: Dict[str, Any] = None):
        """Log info"""
        self.alert('info', message, data)


# Global log alert instance
log_alert = LogAlert()
