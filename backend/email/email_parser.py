"""
ScamShield Email Parser
Parses and extracts information from emails
"""
import re
from typing import Dict, Any, Optional, List
from email import message_from_string
from email.policy import default
from datetime import datetime


class EmailParser:
    """Email parsing and extraction"""
    
    def __init__(self):
        """Initialize email parser"""
        self.url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
        self.phone_pattern = re.compile(r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b')
    
    def parse(self, raw_email: str) -> Dict[str, Any]:
        """
        Parse raw email content
        
        Args:
            raw_email: Raw email content
            
        Returns:
            Parsed email dictionary
        """
        try:
            message = message_from_string(raw_email, policy=default)
            return self._parse_message(message)
        except Exception as e:
            return {'error': str(e)}
    
    def parse_bytes(self, raw_email: bytes) -> Dict[str, Any]:
        """
        Parse raw email bytes
        
        Args:
            raw_email: Raw email bytes
            
        Returns:
            Parsed email dictionary
        """
        try:
            message = message_from_bytes(raw_email, policy=default)
            return self._parse_message(message)
        except Exception as e:
            return {'error': str(e)}
    
    def _parse_message(self, message) -> Dict[str, Any]:
        """Parse email message object"""
        parsed = {
            'message_id': message.get('Message-ID', ''),
            'subject': message.get('Subject', ''),
            'from': message.get('From', ''),
            'to': message.get('To', ''),
            'cc': message.get('Cc', ''),
            'bcc': message.get('Bcc', ''),
            'date': message.get('Date', ''),
            'reply_to': message.get('Reply-To', ''),
            'body_text': '',
            'body_html': '',
            'attachments': [],
            'headers': {}
        }
        
        # Extract email addresses
        parsed['from_email'] = self._extract_email(parsed['from'])
        parsed['to_emails'] = self._extract_all_emails(parsed['to'])
        
        # Extract body
        if message.is_multipart():
            for part in message.walk():
                self._process_part(part, parsed)
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
        
        # Extract all headers
        for header in message.keys():
            parsed['headers'][header] = message.get(header)
        
        # Extract URLs from body
        parsed['urls'] = self._extract_urls(parsed['body_text'] + ' ' + parsed['body_html'])
        
        # Extract phone numbers
        parsed['phones'] = self._extract_phones(parsed['body_text'])
        
        return parsed
    
    def _process_part(self, part, parsed: Dict[str, Any]):
        """Process a message part"""
        content_type = part.get_content_type()
        content_disposition = str(part.get('Content-Disposition', ''))
        
        # Skip attachments for body extraction
        if 'attachment' in content_disposition:
            filename = part.get_filename()
            if filename:
                parsed['attachments'].append({
                    'filename': filename,
                    'content_type': part.get_content_type(),
                    'size': len(part.get_payload(decode=True) or b'')
                })
            return
        
        try:
            payload = part.get_content()
        except Exception:
            return
        
        if content_type == 'text/plain':
            parsed['body_text'] = payload
        elif content_type == 'text/html':
            parsed['body_html'] = payload
    
    def _extract_email(self, text: str) -> Optional[str]:
        """Extract first email address from text"""
        match = self.email_pattern.search(text)
        return match.group(0) if match else None
    
    def _extract_all_emails(self, text: str) -> List[str]:
        """Extract all email addresses from text"""
        return self.email_pattern.findall(text)
    
    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text"""
        return self.url_pattern.findall(text)
    
    def _extract_phones(self, text: str) -> List[str]:
        """Extract phone numbers from text"""
        return self.phone_pattern.findall(text)
    
    def extract_links(self, email_content: str) -> List[Dict[str, Any]]:
        """
        Extract links with their context
        
        Args:
            email_content: Email body content
            
        Returns:
            List of link dictionaries with context
        """
        links = []
        
        # Find all URLs with surrounding context
        for match in self.url_pattern.finditer(email_content):
            url = match.group(0)
            
            # Get surrounding context
            start = max(0, match.start() - 50)
            end = min(len(email_content), match.end() + 50)
            context = email_content[start:end]
            
            links.append({
                'url': url,
                'context': context,
                'position': match.start()
            })
        
        return links
    
    def extract_sender_info(self, from_header: str) -> Dict[str, Any]:
        """
        Extract sender information
        
        Args:
            from_header: From header value
            
        Returns:
            Sender info dictionary
        """
        info = {
            'raw': from_header,
            'email': None,
            'name': None
        }
        
        # Extract email
        info['email'] = self._extract_email(from_header)
        
        # Extract name
        name_match = re.search(r'^([^<]+)', from_header)
        if name_match:
            name = name_match.group(1).strip()
            if name:
                info['name'] = name
        
        return info
    
    def sanitize_content(self, content: str) -> str:
        """
        Sanitize email content for analysis
        
        Args:
            content: Raw content
            
        Returns:
            Sanitized content
        """
        # Remove excessive whitespace
        content = re.sub(r'\s+', ' ', content)
        
        # Remove HTML tags (keep text)
        content = re.sub(r'<[^>]+>', '', content)
        
        # Remove URLs (they'll be analyzed separately)
        content = self.url_pattern.sub('[URL]', content)
        
        # Remove email addresses
        content = self.email_pattern.sub('[EMAIL]', content)
        
        # Normalize unicode
        content = content.encode('ascii', 'ignore').decode('ascii')
        
        return content.strip()
