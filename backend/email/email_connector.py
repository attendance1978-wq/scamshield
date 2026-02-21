"""
ScamShield Email Connector
IMAP/Gmail API connector for email access
"""
import imaplib
import email
from typing import Dict, Any, List, Optional
from datetime import datetime
from email.parser import Parser
from email.policy import default

from backend.config import config


class EmailConnector:
    """Email connection handler"""
    
    def __init__(self):
        """Initialize email connector"""
        self.imap_server = config.EMAIL_IMAP_SERVER
        self.imap_port = config.EMAIL_IMAP_PORT
        self.email_account = config.EMAIL_ACCOUNT
        self.email_password = config.EMAIL_PASSWORD
        self.use_ssl = config.EMAIL_USE_SSL
        
        self.connection = None
        self.connected = False
    
    def connect(self) -> bool:
        """
        Connect to email server
        
        Returns:
            True if connection successful
        """
        try:
            if self.use_ssl:
                self.connection = imaplib.IMAP4_SSL(
                    self.imap_server,
                    self.imap_port
                )
            else:
                self.connection = imaplib.IMAP4(
                    self.imap_server,
                    self.imap_port
                )
            
            # Login
            self.connection.login(self.email_account, self.email_password)
            self.connected = True
            return True
            
        except Exception as e:
            print(f"Email connection error: {e}")
            self.connected = False
            return False
    
    def disconnect(self):
        """Disconnect from email server"""
        if self.connection:
            try:
                self.connection.logout()
            except Exception:
                pass
            finally:
                self.connected = False
                self.connection = None
    
    def is_connected(self) -> bool:
        """Check if connected"""
        return self.connected
    
    def select_folder(self, folder: str = 'INBOX') -> bool:
        """
        Select email folder
        
        Args:
            folder: Folder name
            
        Returns:
            True if successful
        """
        if not self.connected:
            return False
        
        try:
            status, _ = self.connection.select(folder)
            return status == 'OK'
        except Exception:
            return False
    
    def get_message_count(self, folder: str = 'INBOX') -> int:
        """
        Get number of messages in folder
        
        Args:
            folder: Folder name
            
        Returns:
            Number of messages
        """
        if not self.connected:
            return 0
        
        try:
            status, data = self.connection.select(folder)
            if status == 'OK':
                return int(data[0])
        except Exception:
            pass
        
        return 0
    
    def fetch_message(self, message_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch a single message by ID
        
        Args:
            message_id: Message ID
            
        Returns:
            Message data dictionary
        """
        if not self.connected:
            return None
        
        try:
            status, data = self.connection.fetch(message_id, '(RFC822)')
            
            if status != 'OK':
                return None
            
            raw_message = data[0][1]
            message = email.message_from_bytes(raw_message, policy=default)
            
            return self._parse_message(message)
            
        except Exception as e:
            print(f"Error fetching message: {e}")
            return None
    
    def fetch_recent_messages(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Fetch recent messages
        
        Args:
            limit: Maximum number of messages
            
        Returns:
            List of message dictionaries
        """
        if not self.connected:
            return []
        
        messages = []
        
        try:
            # Search for recent messages
            status, data = self.connection.search(None, 'ALL')
            
            if status != 'OK':
                return []
            
            message_ids = data[0].split()
            
            # Get the most recent messages
            recent_ids = message_ids[-limit:] if len(message_ids) > limit else message_ids
            
            for msg_id in recent_ids:
                msg = self.fetch_message(msg_id.decode() if isinstance(msg_id, bytes) else msg_id)
                if msg:
                    messages.append(msg)
            
        except Exception as e:
            print(f"Error fetching messages: {e}")
        
        return messages
    
    def _parse_message(self, message) -> Dict[str, Any]:
        """Parse email message"""
        parsed = {
            'message_id': message.get('Message-ID', ''),
            'subject': message.get('Subject', ''),
            'from': message.get('From', ''),
            'to': message.get('To', ''),
            'date': self._parse_date(message.get('Date', '')),
            'body_text': '',
            'body_html': '',
            'has_attachments': False,
            'headers': {}
        }
        
        # Extract body
        if message.is_multipart():
            for part in message.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get('Content-Disposition', ''))
                
                if content_type == 'text/plain' and 'attachment' not in content_disposition:
                    try:
                        parsed['body_text'] = part.get_content()
                    except Exception:
                        pass
                
                elif content_type == 'text/html' and 'attachment' not in content_disposition:
                    try:
                        parsed['body_html'] = part.get_content()
                    except Exception:
                        pass
                
                if 'attachment' in content_disposition:
                    parsed['has_attachments'] = True
        else:
            content_type = message.get_content_type()
            try:
                content = message.get_content()
                if content_type == 'text/plain':
                    parsed['body_text'] = content
                elif content_type == 'text/html':
                    parsed['body_html'] = content
            except Exception:
                pass
        
        # Extract email address from 'From'
        parsed['from_email'] = self._extract_email(parsed['from'])
        
        # Extract headers
        for header in ['Received', 'DKIM-Signature', 'Return-Path', 'X-Spam-Status']:
            value = message.get(header)
            if value:
                parsed['headers'][header] = value
        
        return parsed
    
    def _parse_date(self, date_str: str) -> Optional[datetime]:
        """Parse email date string"""
        try:
            # Try various date formats
            for fmt in [
                '%a, %d %b %Y %H:%M:%S %z',
                '%d %b %Y %H:%M:%S %z',
                '%a, %d %b %Y %H:%M:%S %Z',
                '%d %b %Y %H:%M:%S %Z'
            ]:
                try:
                    return datetime.strptime(date_str.strip(), fmt)
                except ValueError:
                    continue
        except Exception:
            pass
        
        return None
    
    def _extract_email(self, from_str: str) -> str:
        """Extract email address from From header"""
        import re
        match = re.search(r'<(.+?)>', from_str)
        if match:
            return match.group(1)
        
        match = re.search(r'[\w\.-]+@[\w\.-]+', from_str)
        if match:
            return match.group(0)
        
        return from_str
    
    def mark_as_read(self, message_id: str) -> bool:
        """Mark message as read"""
        if not self.connected:
            return False
        
        try:
            self.connection.store(message_id, '+FLAGS', '\\Seen')
            return True
        except Exception:
            return False
    
    def mark_as_spam(self, message_id: str) -> bool:
        """Mark message as spam"""
        if not self.connected:
            return False
        
        try:
            self.connection.store(message_id, '+FLAGS', '\\Spam')
            return True
        except Exception:
            return False
