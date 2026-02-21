"""
ScamShield Email Alert
Email-based notification system
"""
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, Optional
from datetime import datetime

from backend.config import config


class EmailAlert:
    """Email notification handler"""
    
    def __init__(self):
        """Initialize email alert"""
        self.smtp_server = config.EMAIL_SMTP_SERVER
        self.smtp_port = config.EMAIL_SMTP_PORT
        self.from_email = config.ALERT_EMAIL_FROM
        self.username = config.EMAIL_ACCOUNT
        self.password = config.EMAIL_PASSWORD
        self.enabled = config.ALERT_EMAIL_ENABLED
    
    def send_alert(self, to_email: str, subject: str, body: str, 
                   html: str = None) -> bool:
        """
        Send email alert
        
        Args:
            to_email: Recipient email
            subject: Email subject
            body: Email body (plain text)
            html: Optional HTML body
            
        Returns:
            True if sent successfully
        """
        if not self.enabled:
            return False
        
        if not to_email:
            return False
        
        try:
            # Create message
            msg = MIMEMultipart('alternative')
            msg['From'] = self.from_email
            msg['To'] = to_email
            msg['Subject'] = subject
            msg['Date'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S +0000')
            
            # Attach plain text
            msg.attach(MIMEText(body, 'plain'))
            
            # Attach HTML if provided
            if html:
                msg.attach(MIMEText(html, 'html'))
            
            # Send email
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)
            
            return True
            
        except Exception as e:
            print(f"Email alert error: {e}")
            return False
    
    def send_scam_alert(self, to_email: str, scan_result: Dict[str, Any]) -> bool:
        """
        Send scam detection alert
        
        Args:
            to_email: Recipient email
            scan_result: Scan result dictionary
            
        Returns:
            True if sent successfully
        """
        subject = f"⚠️ ScamShield Alert: Potential Scam Detected"
        
        body = f"""
ScamShield Security Alert

A potential scam has been detected!

Details:
- Risk Score: {scan_result.get('risk_score', 0):.1%}
- Risk Level: {scan_result.get('risk_level', 0)}/3
- Category: {scan_result.get('category', 'Unknown')}
- Confidence: {scan_result.get('confidence', 0):.1%}

Detection Methods:
{', '.join(scan_result.get('methods', []))}

Recommendations:
"""
        
        # Add recommendations
        recommendations = scan_result.get('recommendations', [])
        for rec in recommendations:
            body += f"- {rec}\n"
        
        body += """
---
ScamShield - Your Email Security System
"""
        
        # HTML version
        html = f"""
<html>
<head>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
        .alert {{ background: #fff3cd; border: 1px solid #ffc107; padding: 15px; border-radius: 5px; }}
        .details {{ margin: 15px 0; }}
        .details strong {{ display: inline-block; width: 120px; }}
        .recommendations {{ background: #f8f9fa; padding: 15px; border-radius: 5px; }}
        .footer {{ color: #6c757d; font-size: 12px; margin-top: 20px; }}
    </style>
</head>
<body>
    <div class="alert">
        <h2>⚠️ ScamShield Security Alert</h2>
        <p>A potential scam has been detected!</p>
    </div>
    
    <div class="details">
        <p><strong>Risk Score:</strong> {scan_result.get('risk_score', 0):.1%}</p>
        <p><strong>Risk Level:</strong> {scan_result.get('risk_level', 0)}/3</p>
        <p><strong>Category:</strong> {scan_result.get('category', 'Unknown')}</p>
        <p><strong>Confidence:</strong> {scan_result.get('confidence', 0):.1%}</p>
        <p><strong>Detection:</strong> {', '.join(scan_result.get('methods', []))}</p>
    </div>
    
    <div class="recommendations">
        <h3>Recommendations:</h3>
        <ul>
"""
        
        for rec in recommendations:
            html += f"<li>{rec}</li>"
        
        html += """
        </ul>
    </div>
    
    <div class="footer">
        <p>ScamShield - Your Email Security System</p>
    </div>
</body>
</html>
"""
        
        return self.send_alert(to_email, subject, body, html)
    
    def send_welcome_email(self, to_email: str, username: str) -> bool:
        """
        Send welcome email
        
        Args:
            to_email: Recipient email
            username: Username
            
        Returns:
            True if sent successfully
        """
        subject = "Welcome to ScamShield!"
        
        body = f"""
Welcome to ScamShield, {username}!

Thank you for signing up for ScamShield - your email security solution.

With ScamShield, you can:
- Scan emails for potential scams
- Monitor your inbox for threats
- Get real-time alerts about suspicious emails
- Protect yourself from phishing attacks

To get started, log in to your dashboard and try scanning an email!

Best regards,
The ScamShield Team
"""
        
        return self.send_alert(to_email, subject, body)
    
    def test_connection(self) -> bool:
        """
        Test SMTP connection
        
        Returns:
            True if connection successful
        """
        try:
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
            return True
        except Exception:
            return False


# Global email alert instance
email_alert = EmailAlert()
