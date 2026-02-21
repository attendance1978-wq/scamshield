"""
ScamShield WebSocket Server
Real-time communication server
"""
from flask import Flask, request
from flask_socketio import SocketIO, emit, join_room, leave_room

from backend.config import config

socketio = SocketIO()


def init_socketio(app: Flask):
    """
    Initialize SocketIO with Flask app
    
    Args:
        app: Flask application
    """
    socketio.init_app(app, 
                     cors_allowed_origins="*",
                     ping_timeout=config.WEBSOCKET_PING_TIMEOUT,
                     ping_interval=config.WEBSOCKET_PING_INTERVAL)


@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    print(f"Client connected: {request.sid}")
    emit('connected', {'status': 'connected', 'sid': request.sid})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print(f"Client disconnected: {request.sid}")


@socketio.on('join')
def handle_join(data):
    """
    Handle room join
    
    Args:
        data: Join data with room name
    """
    room = data.get('room')
    if room:
        join_room(room)
        emit('joined', {'room': room}, room=room)


@socketio.on('leave')
def handle_leave(data):
    """
    Handle room leave
    
    Args:
        data: Leave data with room name
    """
    room = data.get('room')
    if room:
        leave_room(room)
        emit('left', {'room': room}, room=room)


@socketio.on('scan_request')
def handle_scan_request(data):
    """
    Handle scan request via WebSocket
    
    Args:
        data: Scan request data with content and scan_type
    """
    content = data.get('content')
    scan_type = data.get('scan_type', 'text')
    
    emit('scan_started', {'content': content, 'scan_type': scan_type})


def emit_scan_result(scan_result: dict, room: str = None):
    """
    Emit scan result to client(s)
    
    Args:
        scan_result: Scan result dictionary
        room: Room to emit to (optional)
    """
    if room:
        socketio.emit('scan_result', scan_result, room=room)
    else:
        socketio.emit('scan_result', scan_result)


def emit_alert(alert: dict, room: str = None):
    """
    Emit alert to client(s)
    
    Args:
        alert: Alert dictionary
        room: Room to emit to (optional)
    """
    if room:
        socketio.emit('alert', alert, room=room)
        socketio.emit('scam_alert', alert, room=room)
    else:
        socketio.emit('alert', alert)
        socketio.emit('scam_alert', alert)


def emit_status_update(status: dict, room: str = None):
    """
    Emit status update
    
    Args:
        status: Status dictionary
        room: Room to emit to (optional)
    """
    if room:
        socketio.emit('status_update', status, room=room)
    else:
        socketio.emit('status_update', status)


def emit_scan_complete(scan_result: dict, room: str = None):
    """
    Emit scan complete event
    
    Args:
        scan_result: Scan result dictionary
        room: Room to emit to (optional)
    """
    event_data = {
        'type': 'scan_complete',
        'scan_id': scan_result.get('scan_id'),
        'is_scam': scan_result.get('is_scam', False),
        'risk_score': scan_result.get('risk_score', 0),
        'category': scan_result.get('category'),
        'confidence': scan_result.get('confidence', 0)
    }
    
    if room:
        socketio.emit('scan_complete', event_data, room=room)
    else:
        socketio.emit('scan_complete', event_data)
