/**
 * ScamShield Authentication
 */

const auth = {
    /**
     * Get stored auth token
     */
    getToken: function() {
        return localStorage.getItem('token');
    },

    /**
     * Get stored user data
     */
    getUser: function() {
        const user = localStorage.getItem('user');
        return user ? JSON.parse(user) : null;
    },

    /**
     * Check if user is logged in
     */
    isLoggedIn: function() {
        return !!this.getToken();
    },

    /**
     * Save auth data
     */
    saveAuth: function(token, user) {
        localStorage.setItem('token', token);
        localStorage.setItem('user', JSON.stringify(user));
    },

    /**
     * Clear auth data (logout)
     */
    clearAuth: function() {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
    },

    /**
     * Logout user
     */
    logout: function() {
        this.clearAuth();
        window.location.href = 'index.html';
    },

    /**
     * Get auth headers for API requests
     */
    getAuthHeaders: function() {
        const token = this.getToken();
        return token ? { 'Authorization': `Bearer ${token}` } : {};
    },

    /**
     * Register a new user
     */
    register: async function(email, username, password) {
        const response = await fetch('/api/auth/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email,
                username,
                password
            })
        });

        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'Registration failed');
        }

        return data;
    },

    /**
     * Login user
     */
    login: async function(email, password) {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                email,
                password
            })
        });

        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'Login failed');
        }

        return data;
    },

    /**
     * Setup logout button handler
     */
    setupLogout: function() {
        const logoutBtn = document.getElementById('logout-btn');
        
        if (logoutBtn) {
            logoutBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.logout();
            });
        }
    },

    /**
     * Check authentication and redirect if not logged in
     */
    requireAuth: function() {
        if (!this.isLoggedIn()) {
            window.location.href = 'login.html';
            return false;
        }
        return true;
    }
};

// Auto-setup logout when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    auth.setupLogout();
});
