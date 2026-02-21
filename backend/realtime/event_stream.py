"""
ScamShield Event Stream
Event streaming for real-time updates
"""
from typing import Dict, Any, Callable, List
from datetime import datetime
from collections import defaultdict
import threading


class EventStream:
    """Event streaming system"""
    
    def __init__(self):
        """Initialize event stream"""
        self.subscribers = defaultdict(list)
        self.event_history = []
        self.max_history = 100
        self.lock = threading.Lock()
    
    def subscribe(self, event_type: str, callback: Callable):
        """
        Subscribe to event type
        
        Args:
            event_type: Type of event to subscribe to
            callback: Callback function
        """
        with self.lock:
            self.subscribers[event_type].append(callback)
    
    def unsubscribe(self, event_type: str, callback: Callable):
        """
        Unsubscribe from event type
        
        Args:
            event_type: Type of event
            callback: Callback to remove
        """
        with self.lock:
            if callback in self.subscribers[event_type]:
                self.subscribers[event_type].remove(callback)
    
    def publish(self, event_type: str, data: Dict[str, Any]):
        """
        Publish event
        
        Args:
            event_type: Type of event
            data: Event data
        """
        event = {
            'type': event_type,
            'data': data,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Store in history
        with self.lock:
            self.event_history.append(event)
            
            # Trim history if needed
            if len(self.event_history) > self.max_history:
                self.event_history = self.event_history[-self.max_history:]
        
        # Notify subscribers
        with self.lock:
            callbacks = self.subscribers.get(event_type, []).copy()
            callbacks.extend(self.subscribers.get('*', []))  # Wildcard subscribers
        
        for callback in callbacks:
            try:
                callback(event)
            except Exception as e:
                print(f"Event callback error: {e}")
    
    def get_history(self, event_type: str = None, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Get event history
        
        Args:
            event_type: Filter by event type (optional)
            limit: Maximum events to return
            
        Returns:
            List of events
        """
        with self.lock:
            if event_type:
                events = [e for e in self.event_history if e['type'] == event_type]
            else:
                events = self.event_history.copy()
        
        return events[-limit:]
    
    def clear_history(self):
        """Clear event history"""
        with self.lock:
            self.event_history.clear()


# Global event stream
event_stream = EventStream()


# Predefined event types
class Events:
    """Event type constants"""
    SCAN_STARTED = 'scan_started'
    SCAN_COMPLETED = 'scan_completed'
    SCAM_DETECTED = 'scam_detected'
    ALERT_CREATED = 'alert_created'
    EMAIL_RECEIVED = 'email_received'
    USER_LOGIN = 'user_login'
    SYSTEM_ERROR = 'system_error'
