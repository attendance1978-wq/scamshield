"""
ScamShield API Routes
Main API routes for the application
"""
from flask import Blueprint, request, jsonify
from datetime import datetime
import uuid

from backend.auth.jwt_handler import token_required
from backend.database.db import get_session
from backend.database.models import ScanResult, ScanStatus, RiskLevel
from backend.detection.scam_detector import ScamDetector
from backend.constants import MESSAGES
from backend.realtime.websocket_server import emit_scan_complete, emit_alert

api_bp = Blueprint('api', __name__)


@api_bp.route('/scan', methods=['POST'])
@token_required
def scan_content(current_user):
    """Scan content for scam detection"""
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    content = data.get('content')
    scan_type = data.get('type', 'text')  # text, url, email, domain
    
    if not content:
        return jsonify({'error': 'No content provided'}), 400
    
    # Generate unique scan ID
    scan_id = f"SCAN-{uuid.uuid4().hex[:12].upper()}"
    
    # Create scan result entry
    with get_session() as session:
        scan_result = ScanResult(
            scan_id=scan_id,
            user_id=current_user.id if current_user else None,
            scan_type=scan_type,
            content=content[:50000],  # Limit content length
            status=ScanStatus.IN_PROGRESS,
            started_at=datetime.utcnow()
        )
        session.add(scan_result)
        session.commit()
    
    # Perform detection
    detector = ScamDetector()
    result = detector.detect(content, scan_type)
    
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
    
    response_data = {
        'scan_id': scan_id,
        'is_scam': result.get('is_scam', False),
        'risk_score': result.get('risk_score', 0.0),
        'risk_level': result.get('risk_level', 0),
        'category': result.get('category'),
        'confidence': result.get('confidence', 0.0),
        'methods': result.get('methods', []),
        'details': result.get('details', {}),
        'message': MESSAGES['SCAM_DETECTED'] if result.get('is_scam') else MESSAGES['NO_THREAT_FOUND']
    }
    
    # Emit real-time scan complete event
    scan_data = {
        'scan_id': scan_id,
        'is_scam': result.get('is_scam', False),
        'risk_score': result.get('risk_score', 0.0),
        'risk_level': result.get('risk_level', 0),
        'category': result.get('category'),
        'confidence': result.get('confidence', 0.0),
        'scan_type': scan_type,
        'user_id': current_user.id if current_user else None
    }
    emit_scan_complete(scan_data)
    
    # Emit alert if scam detected
    if result.get('is_scam'):
        alert_data = {
            'type': 'scam_alert',
            'title': 'Scam Detected!',
            'message': f"A {scan_type} was flagged as potentially malicious",
            'scan_id': scan_id,
            'risk_score': result.get('risk_score', 0.0),
            'category': result.get('category')
        }
        emit_alert(alert_data)
    
    return jsonify(response_data)


@api_bp.route('/scan/<scan_id>', methods=['GET'])
@token_required
def get_scan_result(current_user, scan_id):
    """Get scan result by ID"""
    with get_session() as session:
        scan_result = session.query(ScanResult).filter_by(scan_id=scan_id).first()
        
        if not scan_result:
            return jsonify({'error': 'Scan result not found'}), 404
        
        return jsonify({
            'scan_id': scan_result.scan_id,
            'scan_type': scan_result.scan_type,
            'is_scam': scan_result.is_scam,
            'risk_score': scan_result.risk_score,
            'risk_level': scan_result.risk_level.value if scan_result.risk_level else 0,
            'category': scan_result.category,
            'confidence': scan_result.confidence,
            'detection_methods': scan_result.detection_methods,
            'details': scan_result.details,
            'status': scan_result.status.value if scan_result.status else 'unknown',
            'created_at': scan_result.created_at.isoformat() if scan_result.created_at else None,
            'completed_at': scan_result.completed_at.isoformat() if scan_result.completed_at else None
        })


@api_bp.route('/scans', methods=['GET'])
@token_required
def get_scan_history(current_user):
    """Get scan history for current user"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    per_page = min(per_page, 100)  # Limit max results
    
    with get_session() as session:
        query = session.query(ScanResult)
        
        # Filter by user if not admin
        if current_user.role.value != 'admin':
            query = query.filter_by(user_id=current_user.id)
        
        # Order by most recent
        query = query.order_by(ScanResult.created_at.desc())
        
        # Paginate
        total = query.count()
        scans = query.offset((page - 1) * per_page).limit(per_page).all()
        
        return jsonify({
            'scans': [{
                'scan_id': scan.scan_id,
                'scan_type': scan.scan_type,
                'is_scam': scan.is_scam,
                'risk_score': scan.risk_score,
                'risk_level': scan.risk_level.value if scan.risk_level else 0,
                'category': scan.category,
                'confidence': scan.confidence,
                'status': scan.status.value if scan.status else 'unknown',
                'created_at': scan.created_at.isoformat() if scan.created_at else None
            } for scan in scans],
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': (total + per_page - 1) // per_page
        })


@api_bp.route('/stats', methods=['GET'])
@token_required
def get_stats(current_user):
    """Get scan statistics"""
    with get_session() as session:
        # Total scans
        total_scans = session.query(ScanResult).count()
        
        # Scams detected
        scams_detected = session.query(ScanResult).filter_by(is_scam=True).count()
        
        # By risk level
        low_risk = session.query(ScanResult).filter_by(risk_level=RiskLevel.LOW).count()
        medium_risk = session.query(ScanResult).filter_by(risk_level=RiskLevel.MEDIUM).count()
        high_risk = session.query(ScanResult).filter_by(risk_level=RiskLevel.HIGH).count()
        critical_risk = session.query(ScanResult).filter_by(risk_level=RiskLevel.CRITICAL).count()
        
        # By category
        from sqlalchemy import func
        category_counts = session.query(
            ScanResult.category,
            func.count(ScanResult.id)
        ).group_by(ScanResult.category).all()
        
        return jsonify({
            'total_scans': total_scans,
            'scams_detected': scams_detected,
            'detection_rate': round(scams_detected / total_scans * 100, 2) if total_scans > 0 else 0,
            'risk_distribution': {
                'low': low_risk,
                'medium': medium_risk,
                'high': high_risk,
                'critical': critical_risk
            },
            'category_distribution': {cat: count for cat, count in category_counts if cat}
        })


@api_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat()
    })
