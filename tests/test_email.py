"""
ScamShield Email Tests
Unit tests for the email system
"""
import pytest
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.email.email_parser import EmailParser
from backend.email.email_fetcher import EmailFetcher
from backend.email.email_queue import EmailQueue, EmailTask


class TestEmailParser:
    """Test EmailParser class"""
    
    def setup_method(self):
        """Setup test"""
        self.parser = EmailParser()
    
    def test_parse_simple_email(self):
        """Test parsing simple email"""
        raw_email = """From: sender@example.com
To: recipient@example.com
Subject: Test Email
Date: Mon, 1 Jan 2024 12:00:00 +0000

This is a test email body.
"""
        
        result = self.parser.parse(raw_email)
        
        assert result is not None
        assert 'from' in result
        assert 'subject' in result
        assert 'body' in result
    
    def test_extract_urls(self):
        """Test URL extraction"""
        body = """
        Check out our website at https://example.com
        Also visit http://test.com for more info
        """
        
        urls = self.parser.extract_urls(body)
        
        assert len(urls) == 2
        assert 'https://example.com' in urls
        assert 'http://test.com' in urls
    
    def test_extract_sender_email(self):
        """Test sender email extraction"""
        email = "John Doe <john@example.com>"
        
        sender_email = self.parser.extract_sender_email(email)
        
        assert sender_email == 'john@example.com'


class TestEmailQueue:
    """Test EmailQueue class"""
    
    def setup_method(self):
        """Setup test"""
        self.queue = EmailQueue()
    
    def test_add_task(self):
        """Test adding task to queue"""
        task = EmailTask(
            email_id=1,
            message_id="test-123",
            subject="Test",
            sender="test@example.com",
            body_text="Test body",
            priority=1
        )
        
        self.queue.add_task(task)
        
        assert self.queue.size() > 0
    
    def test_get_task(self):
        """Test getting task from queue"""
        task = EmailTask(
            email_id=1,
            message_id="test-123",
            subject="Test",
            sender="test@example.com",
            body_text="Test body",
            priority=1
        )
        
        self.queue.add_task(task)
        retrieved = self.queue.get_task()
        
        assert retrieved is not None
        assert retrieved.message_id == "test-123"


class TestEmailFetcher:
    """Test EmailFetcher class"""
    
    def setup_method(self):
        """Setup test"""
        self.fetcher = EmailFetcher()
    
    def test_fetcher_initialization(self):
        """Test fetcher initialization"""
        assert self.fetcher is not None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
