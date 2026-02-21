"""
ScamShield Main Application Entry Point
"""
import os
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO
from dotenv import load_dotenv

from config import config, get_config
from constants import MESSAGES

# Load environment variables
load_dotenv()

# Initialize Flask extensions
socketio = SocketIO()

def create_app(config_name=None):
    """Application Factory"""
    app = Flask(__name__,
                template_folder='../frontend',
                static_folder='../frontend')
    
    # Load configuration
    if config_name:
        app.config.from_object(get_config(config_name))
    else:
        app.config.from_object(config)
    
    # Enable CORS
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    
    # Initialize SocketIO
    socketio.init_app(app, 
                      cors_allowed_origins="*",
                      ping_timeout=config.WEBSOCKET_PING_TIMEOUT,
                      ping_interval=config.WEBSOCKET_PING_INTERVAL)
    
    # Create necessary directories
    _create_directories()
    
    # Initialize database (create tables if they don't exist)
    _init_database()
    
    # Register blueprints
    _register_blueprints(app)
    
    # Register error handlers
    _register_error_handlers(app)
    
    # Register routes
    _register_routes(app)
    
    return app


def _init_database():
    """Initialize database tables"""
    from backend.database.db import init_db
    try:
        init_db()
        print("Database tables initialized successfully")
    except Exception as e:
        print(f"Warning: Failed to initialize database: {e}")


def _create_directories():
    """Create necessary directories if they don't exist"""
    directories = [
        'database',
        'logs',
        'models',
        'cache',
        'backend/database',
        'backend/utils'
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)


def _register_blueprints(app):
    """Register Flask blueprints"""
    from api.routes import api_bp
    from api.auth_routes import auth_bp
    from api.email_routes import email_bp
    from api.admin_routes import admin_bp
    
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(email_bp, url_prefix='/api/email')
    app.register_blueprint(admin_bp, url_prefix='/api/admin')


def _register_error_handlers(app):
    """Register error handlers"""
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'error': 'Not found', 'message': MESSAGES['EMAIL_NOT_FOUND']}), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({'error': 'Internal server error', 'message': MESSAGES['INTERNAL_ERROR']}), 500
    
    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({'error': 'Forbidden', 'message': MESSAGES['UNAUTHORIZED']}), 403
    
    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({'error': 'Unauthorized', 'message': MESSAGES['UNAUTHORIZED']}), 401


def _register_routes(app):
    """Register main routes"""
    @app.route('/')
    def index():
        return jsonify({
            'name': 'ScamShield API',
            'version': '1.0.0',
            'description': 'Email Scam Detection and Prevention System',
            'status': 'running'
        })
    
    @app.route('/health')
    def health():
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'cache': 'connected'
        })


# Initialize app
app = create_app()


def main():
    """Main entry point"""
    port = int(os.getenv('PORT', 5000))
    host = os.getenv('HOST', '0.0.0.0')
    debug = config.FLASK_DEBUG
    
    print(f"Starting ScamShield on {host}:{port}")
    socketio.run(app, 
                 host=host, 
                 port=port, 
                 debug=debug,
                 allow_unsafe_werkzeug=True)


if __name__ == '__main__':
    main()
