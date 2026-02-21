"""
ScamShield Connection Manager
Manages WebSocket connections
"""
from typing import Dict, Set, Optional
from datetime import datetime
import uuid


class ConnectionManager:
    """Manages WebSocket connections"""
    
    def __init__(self):
        """Initialize connection manager"""
        self.connections: Dict[str, Dict] = {}
        self.user_connections: Dict[int, Set[str]] = {}
        self.room_members: Dict[str, Set[str]] = {}
    
    def add_connection(self, connection_id: str, user_id: int = None, 
                      metadata: Dict = None) -> str:
        """
        Add a new connection
        
        Args:
            connection_id: Connection ID
            user_id: User ID (optional)
            metadata: Additional metadata
            
        Returns:
            Connection ID
        """
        if not connection_id:
            connection_id = str(uuid.uuid4())
        
        self.connections[connection_id] = {
            'user_id': user_id,
            'connected_at': datetime.utcnow(),
            'metadata': metadata or {},
            'active': True
        }
        
        # Track user connections
        if user_id:
            if user_id not in self.user_connections:
                self.user_connections[user_id] = set()
            self.user_connections[user_id].add(connection_id)
        
        return connection_id
    
    def remove_connection(self, connection_id: str):
        """Remove a connection"""
        if connection_id in self.connections:
            user_id = self.connections[connection_id].get('user_id')
            
            # Remove from user connections
            if user_id and user_id in self.user_connections:
                self.user_connections[user_id].discard(connection_id)
            
            # Remove connection
            del self.connections[connection_id]
        
        # Remove from rooms
        for room_id in list(self.room_members.keys()):
            self.room_members[room_id].discard(connection_id)
    
    def get_connection(self, connection_id: str) -> Optional[Dict]:
        """Get connection info"""
        return self.connections.get(connection_id)
    
    def get_user_connections(self, user_id: int) -> Set[str]:
        """Get all connections for a user"""
        return self.user_connections.get(user_id, set())
    
    def join_room(self, connection_id: str, room_id: str):
        """Add connection to room"""
        if room_id not in self.room_members:
            self.room_members[room_id] = set()
        
        self.room_members[room_id].add(connection_id)
        
        # Update connection metadata
        if connection_id in self.connections:
            if 'rooms' not in self.connections[connection_id]['metadata']:
                self.connections[connection_id]['metadata']['rooms'] = []
            self.connections[connection_id]['metadata']['rooms'].append(room_id)
    
    def leave_room(self, connection_id: str, room_id: str):
        """Remove connection from room"""
        if room_id in self.room_members:
            self.room_members[room_id].discard(connection_id)
            
            # Update connection metadata
            if connection_id in self.connections:
                rooms = self.connections[connection_id]['metadata'].get('rooms', [])
                if room_id in rooms:
                    rooms.remove(room_id)
    
    def get_room_members(self, room_id: str) -> Set[str]:
        """Get all connections in a room"""
        return self.room_members.get(room_id, set())
    
    def get_connection_count(self) -> int:
        """Get total connection count"""
        return len(self.connections)
    
    def get_active_connections(self) -> Dict[str, Dict]:
        """Get all active connections"""
        return {
            conn_id: conn 
            for conn_id, conn in self.connections.items() 
            if conn.get('active')
        }


# Global connection manager
connection_manager = ConnectionManager()
