"""
ScamShield Email Fetcher
Fetches and manages emails from connected accounts
"""
from typing import Dict, Any, List, Optional
from datetime import datetime

from backend.email.email_connector import EmailConnector
from backend.config import config


class EmailFetcher:
    """Email fetching and management"""
    
    def __init__(self):
        """Initialize email fetcher"""
        self.connector = EmailConnector()
        self.fetch_interval = config.EMAIL_FETCH_INTERVAL
        self.batch_size = config.EMAIL_BATCH_SIZE
    
    def fetch_emails(self, limit: int = 10, folder: str = 'INBOX') -> List[Dict[str, Any]]:
        """
        Fetch recent emails
        
        Args:
            limit: Maximum number of emails to fetch
            folder: Folder to fetch from
            
        Returns:
            List of email dictionaries
        """
        # Connect
        if not self.connector.connect():
            return []
        
        try:
            # Select folder
            if not self.connector.select_folder(folder):
                return []
            
            # Fetch messages
            messages = self.connector.fetch_recent_messages(limit)
            
            return messages
            
        finally:
            # Disconnect
            self.connector.disconnect()
    
    def fetch_new_emails(self, since: datetime, folder: str = 'INBOX') -> List[Dict[str, Any]]:
        """
        Fetch emails received after a specific date
        
        Args:
            since: Fetch emails after this date
            folder: Folder to fetch from
            
        Returns:
            List of email dictionaries
        """
        if not self.connector.connect():
            return []
        
        try:
            if not self.connector.select_folder(folder):
                return []
            
            # Search for emails since date
            date_str = since.strftime('%d-%b-%Y')
            status, data = self.connector.connection.search(None, f'SINCE {date_str}')
            
            if status != 'OK':
                return []
            
            message_ids = data[0].split()
            messages = []
            
            for msg_id in message_ids[-self.batch_size:]:
                msg = self.connector.fetch_message(
                    msg_id.decode() if isinstance(msg_id, bytes) else msg_id
                )
                if msg:
                    messages.append(msg)
            
            return messages
            
        finally:
            self.connector.disconnect()
    
    def get_email_by_id(self, message_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific email by ID
        
        Args:
            message_id: Message ID
            
        Returns:
            Email dictionary or None
        """
        if not self.connector.connect():
            return None
        
        try:
            if not self.connector.select_folder():
                return None
            
            return self.connector.fetch_message(message_id)
            
        finally:
            self.connector.disconnect()
    
    def mark_email_read(self, message_id: str) -> bool:
        """
        Mark email as read
        
        Args:
            message_id: Message ID
            
        Returns:
            True if successful
        """
        if not self.connector.connect():
            return False
        
        try:
            return self.connector.mark_as_read(message_id)
        finally:
            self.connector.disconnect()
    
    def get_unread_count(self, folder: str = 'INBOX') -> int:
        """
        Get count of unread emails
        
        Args:
            folder: Folder to check
            
        Returns:
            Number of unread emails
        """
        if not self.connector.connect():
            return 0
        
        try:
            if not self.connector.select_folder(folder):
                return 0
            
            status, data = self.connector.connection.search(None, 'UNSEEN')
            
            if status == 'OK':
                return len(data[0].split())
            
            return 0
            
        finally:
            self.connector.disconnect()
    
    def get_folder_list(self) -> List[str]:
        """
        Get list of email folders
        
        Returns:
            List of folder names
        """
        if not self.connector.connect():
            return []
        
        try:
            status, data = self.connector.connection.list()
            
            if status != 'OK':
                return []
            
            folders = []
            for line in data:
                if isinstance(line, bytes):
                    line = line.decode()
                # Parse folder name from list response
                parts = line.split('"/"')
                if len(parts) > 1:
                    folder = parts[1].strip().strip('"')
                    folders.append(folder)
            
            return folders
            
        finally:
            self.connector.disconnect()
    
    def test_connection(self) -> bool:
        """
        Test email connection
        
        Returns:
            True if connection successful
        """
        return self.connector.connect()
    
    def get_connection_status(self) -> Dict[str, Any]:
        """
        Get connection status
        
        Returns:
            Status dictionary
        """
        connected = self.connector.connect()
        
        if connected:
            message_count = self.connector.get_message_count()
            self.connector.disconnect()
            
            return {
                'connected': True,
                'server': config.EMAIL_IMAP_SERVER,
                'account': config.EMAIL_ACCOUNT,
                'message_count': message_count
            }
        
        return {
            'connected': False,
            'server': config.EMAIL_IMAP_SERVER,
            'account': config.EMAIL_ACCOUNT,
            'error': 'Failed to connect'
        }
