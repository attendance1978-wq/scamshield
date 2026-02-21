"""
ScamShield Email Routes
Email scanning and management endpoints
"""
from flask import Blueprint, request, jsonify
from datetime import datetime
import uuid

from backend.auth.jwt_handler import token_required
from backend.database.db import get_session
from backend.database.models import Email, ScanResult, ScanStatus, RiskLevel
from backend.detection.scam_detector import ScamDetector
from backend.email.email_fetcher import EmailFetcher
from backend.constants import MESSAGES

email_bp = Blueprint('email', __name__)


@email_bp.route('/scan', methods=['POST'])
@token_required
def scan_email(current_user):
    """Scan an email for scam detection"""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    subject = data.get('subject', '')
    sender = data.get('sender', '')
    body = data.get('body', '')
    message_id = data.get('message_id')
    
    if not body and not subject:
        return jsonify({'error': 'Email content is required'}), 400
    
    # Generate unique scan ID
    scan_id = f"EMAIL-{uuid.uuid4().hex[:12].upper()}"
    
    # Combine subject and body for analysis
    content = f"Subject: {subject}\n\n{body}"
    
    # Create email record
    with get_session() as session:
        email = Email(
            message_id=message_id or f"scan-{uuid.uuid4().hex}",
            subject=subject[:500] if subject else None,
            sender=sender,
            sender_email=sender,
            body_text=body[:50000],
            received_at=datetime.utcnow(),
            processed_at=datetime.utcnow(),
            created_at=datetime.utcnow()
        )
        session.add(email)
        session.commit()
        
        # Create scan result
        scan_result = ScanResult(
            scan_id=scan_id,
            user_id=current_user.id,
            email_id=email.id,
            scan_type='email',
            content=content[:50000],
            status=ScanStatus.IN_PROGRESS,
            started_at=datetime.utcnow()
        )
        session.add(scan_result)
        session.commit()
    
    # Perform detection
    detector = ScamDetector()
    result = detector.detect(content, 'email')
    
    # Update scan result
    with get_session() as session:
        scan_result = session.query(ScanResult).filter_by(scan_id=scan_id).first()
        if scan_result:
            scan_result.is_scam = result.get('is_scam', False)
            scan_result.risk_score = result.get('risk_score', 0.0)
            scan_result.risk_level = RiskLevel(result.get('risk_level', 0))
            scan_result.category = result.get('category')
            scan_result.confidence = result.get('confidence', 0.0)
            scan_result.detection_methods = result.get('methods', [])
            scan_result.details = result.get('details', {})
            scan_result.status = ScanStatus.COMPLETED
            scan_result.completed_at = datetime.utcnow()
            session.commit()
    
    return jsonify({
        'scan_id': scan_id,
        'email_id': email.id,
        'is_scam': result.get('is_scam', False),
        'risk_score': result.get('risk_score', 0.0),
        'risk_level': result.get('risk_level', 0),
        'category': result.get('category'),
        'confidence': result.get('confidence', 0.0),
        'methods': result.get('methods', []),
        'details': result.get('details', {}),
        'message': MESSAGES['SCAM_DETECTED'] if result.get('is_scam') else MESSAGES['NO_THREAT_FOUND']
    })


@email_bp.route('/fetch', methods=['POST'])
@token_required
def fetch_emails(current_user):
    """Fetch emails from configured email account"""
    data = request.get_json() or {}
    limit = data.get('limit', 10)
    
    try:
        fetcher = EmailFetcher()
        emails = fetcher.fetch_emails(limit=limit)
        
        # Save fetched emails
        with get_session() as session:
            saved_count = 0
            for email_data in emails:
                # Check if email already exists
                existing = session.query(Email).filter_by(
                    message_id=email_data.get('message_id')
                ).first()
                
                if not existing:
                    email = Email(
                        message_id=email_data.get('message_id'),
                        subject=email_data.get('subject', ''),
                        sender=email_data.get('from', ''),
                        sender_email=email_data.get('from_email', ''),
                        recipient=email_data.get('to', ''),
                        body_text=email_data.get('body_text', ''),
                        body_html=email_data.get('body_html', ''),
                        received_at=email_data.get('date', datetime.utcnow()),
                        is_read=False,
                        has_attachments=email_data.get('has_attachments', False),
                        created_at=datetime.utcnow()
                    )
                    session.add(email)
                    saved_count += 1
            
            session.commit()
        
        return jsonify({
            'message': f'Fetched {len(emails)} emails, {saved_count} new',
            'total_fetched': len(emails),
            'new_emails': saved_count,
            'emails': [{
                'message_id': e.get('message_id'),
                'subject': e.get('subject'),
                'from': e.get('from'),
                'date': e.get('date').isoformat() if e.get('date') else None
            } for e in emails[:5]]  # Return first 5
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@email_bp.route('/list', methods=['GET'])
@token_required
def list_emails(current_user):
    """List scanned emails"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    per_page = min(per_page, 100)
    
    with get_session() as session:
        query = session.query(Email).order_by(Email.received_at.desc())
        
        total = query.count()
        emails = query.offset((page - 1) * per_page).limit(per_page).all()
        
        return jsonify({
            'emails': [{
                'id': e.id,
                'message_id': e.message_id,
                'subject': e.subject,
                'sender': e.sender,
                'sender_email': e.sender_email,
                'received_at': e.received_at.isoformat() if e.received_at else None,
                'is_read': e.is_read,
                'is_spam': e.is_spam,
                'has_attachments': e.has_attachments
            } for e in emails],
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': (total + per_page - 1) // per_page
        })


@email_bp.route('/<int:email_id>', methods=['GET'])
@token_required
def get_email(current_user, email_id):
    """Get email details"""
    with get_session() as session:
        email = session.query(Email).filter_by(id=email_id).first()
        
        if not email:
            return jsonify({'error': 'Email not found'}), 404
        
        return jsonify({
            'id': email.id,
            'message_id': email.message_id,
            'subject': email.subject,
            'sender': email.sender,
            'sender_email': email.sender_email,
            'recipient': email.recipient,
            'body_text': email.body_text,
            'body_html': email.body_html,
            'received_at': email.received_at.isoformat() if email.received_at else None,
            'processed_at': email.processed_at.isoformat() if email.processed_at else None,
            'is_read': email.is_read,
            'is_spam': email.is_spam,
            'has_attachments': email.has_attachments,
            'headers': email.headers,
            'metadata': email.email_metadata
        })


@email_bp.route('/<int:email_id>/scan', methods=['POST'])
@token_required
def scan_saved_email(current_user, email_id):
    """Scan a saved email"""
    with get_session() as session:
        email = session.query(Email).filter_by(id=email_id).first()
        
        if not email:
            return jsonify({'error': 'Email not found'}), 404
        
        # Combine subject and body
        content = f"Subject: {email.subject or ''}\n\n{email.body_text or ''}"
        
        # Generate scan ID
        scan_id = f"EMAIL-{uuid.uuid4().hex[:12].upper()}"
        
        # Create scan result
        scan_result = ScanResult(
            scan_id=scan_id,
            user_id=current_user.id,
            email_id=email.id,
            scan_type='email',
            content=content[:50000],
            status=ScanStatus.IN_PROGRESS,
            started_at=datetime.utcnow()
        )
        session.add(scan_result)
        session.commit()
    
    # Perform detection
    detector = ScamDetector()
    result = detector.detect(content, 'email')
    
    # Update scan result and email
    with get_session() as session:
        scan_result = session.query(ScanResult).filter_by(scan_id=scan_id).first()
        if scan_result:
            scan_result.is_scam = result.get('is_scam', False)
            scan_result.risk_score = result.get('risk_score', 0.0)
            scan_result.risk_level = RiskLevel(result.get('risk_level', 0))
            scan_result.category = result.get('category')
            scan_result.confidence = result.get('confidence', 0.0)
            scan_result.detection_methods = result.get('methods', [])
            scan_result.details = result.get('details', {})
            scan_result.status = ScanStatus.COMPLETED
            scan_result.completed_at = datetime.utcnow()
        
        # Update email
        email = session.query(Email).filter_by(id=email_id).first()
        if email:
            email.is_spam = result.get('is_scam', False)
            email.processed_at = datetime.utcnow()
        
        session.commit()
    
    return jsonify({
        'scan_id': scan_id,
        'is_scam': result.get('is_scam', False),
        'risk_score': result.get('risk_score', 0.0),
        'risk_level': result.get('risk_level', 0),
        'category': result.get('category'),
        'confidence': result.get('confidence', 0.0),
        'message': MESSAGES['SCAM_DETECTED'] if result.get('is_scam') else MESSAGES['NO_THREAT_FOUND']
    })


@email_bp.route('/mark-read/<int:email_id>', methods=['POST'])
@token_required
def mark_email_read(current_user, email_id):
    """Mark email as read"""
    with get_session() as session:
        email = session.query(Email).filter_by(id=email_id).first()
        
        if not email:
            return jsonify({'error': 'Email not found'}), 404
        
        email.is_read = True
        session.commit()
    
    return jsonify({'message': 'Email marked as read'})


@email_bp.route('/delete/<int:email_id>', methods=['DELETE'])
@token_required
def delete_email(current_user, email_id):
    """Delete an email"""
    with get_session() as session:
        email = session.query(Email).filter_by(id=email_id).first()
        
        if not email:
            return jsonify({'error': 'Email not found'}), 404
        
        session.delete(email)
        session.commit()
    
    return jsonify({'message': 'Email deleted successfully'})
