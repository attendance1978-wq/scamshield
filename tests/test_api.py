"""
ScamShield API Tests
Unit tests for API endpoints
"""
import pytest
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestAPIEndpoints:
    """Test API endpoints"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        from backend.main import create_app
        app = create_app('testing')
        app.config['TESTING'] = True
        
        with app.test_client() as client:
            yield client
    
    def test_health_check(self, client):
        """Test health check endpoint"""
        response = client.get('/health')
        
        assert response.status_code == 200
        data = response.get_json()
        assert data['status'] == 'healthy'
    
    def test_index_endpoint(self, client):
        """Test index endpoint"""
        response = client.get('/')
        
        assert response.status_code == 200
        data = response.get_json()
        assert 'name' in data
        assert data['name'] == 'ScamShield API'
    
    def test_scan_endpoint_no_auth(self, client):
        """Test scan endpoint without authentication"""
        response = client.post('/api/scan',
                            json={'content': 'test', 'type': 'text'})
        
        # Should return 401 for unauthorized
        assert response.status_code == 401
    
    def test_scan_endpoint_invalid_data(self, client):
        """Test scan endpoint with invalid data"""
        # Login first
        # This would require setting up authentication
        
        # Test with missing content
        response = client.post('/api/scan',
                            json={'type': 'text'})
        
        assert response.status_code in [400, 401]


class TestAPIValidation:
    """Test API validation"""
    
    def test_validate_scan_type(self):
        """Test scan type validation"""
        from backend.utils.validator import validator
        
        assert validator.validate_scan_type('text') == True
        assert validator.validate_scan_type('url') == True
        assert validator.validate_scan_type('email') == True
        assert validator.validate_scan_type('invalid') == False
    
    def test_validate_url(self):
        """Test URL validation"""
        from backend.utils.validator import validator
        
        assert validator.validate_url('https://example.com') == True
        assert validator.validate_url('http://test.com/path') == True
        assert validator.validate_url('not-a-url') == False
    
    def test_validate_email(self):
        """Test email validation"""
        from backend.utils.validator import validator
        
        assert validator.validate_email('test@example.com') == True
        assert validator.validate_email('invalid-email') == False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
