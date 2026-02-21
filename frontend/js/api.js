/**
 * ScamShield API Client
 */

const API_BASE_URL = '/api';

class APIClient {
    constructor() {
        this.baseURL = API_BASE_URL;
    }

    /**
     * Get authentication headers
     */
    getHeaders() {
        const headers = {
            'Content-Type': 'application/json'
        };

        const token = localStorage.getItem('token');
        if (token) {
            headers['Authorization'] = `Bearer ${token}`;
        }

        return headers;
    }

    /**
     * Make API request
     */
    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        
        const config = {
            ...options,
            headers: {
                ...this.getHeaders(),
                ...options.headers
            }
        };

        try {
            const response = await fetch(url, config);
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.message || 'API request failed');
            }

            return data;
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    }

    /**
     * GET request
     */
    async get(endpoint, params = {}) {
        const queryString = new URLSearchParams(params).toString();
        const url = queryString ? `${endpoint}?${queryString}` : endpoint;
        return this.request(url, { method: 'GET' });
    }

    /**
     * POST request
     */
    async post(endpoint, data) {
        return this.request(endpoint, {
            method: 'POST',
            body: JSON.stringify(data)
        });
    }

    /**
     * PUT request
     */
    async put(endpoint, data) {
        return this.request(endpoint, {
            method: 'PUT',
            body: JSON.stringify(data)
        });
    }

    /**
     * DELETE request
     */
    async delete(endpoint) {
        return this.request(endpoint, { method: 'DELETE' });
    }

    // ==================== Auth API ====================

    /**
     * Register user
     */
    async register(username, email, password) {
        return this.post('/auth/register', { username, email, password });
    }

    /**
     * Login user
     */
    async login(email, password) {
        return this.post('/auth/login', { email, password });
    }

    /**
     * Logout user
     */
    async logout() {
        return this.post('/auth/logout', {});
    }

    /**
     * Get current user
     */
    async getCurrentUser() {
        return this.get('/auth/me');
    }

    // ==================== Scan API ====================

    /**
     * Scan content
     */
    async scan(content, type = 'text') {
        return this.post('/scan', { content, type });
    }

    /**
     * Get scan result
     */
    async getScanResult(scanId) {
        return this.get(`/scan/${scanId}`);
    }

    /**
     * Get scan history
     */
    async getScanHistory(page = 1, perPage = 20) {
        return this.get('/scans', { page, per_page: perPage });
    }

    /**
     * Get statistics
     */
    async getStats() {
        return this.get('/stats');
    }

    // ==================== Email API ====================

    /**
     * Get emails
     */
    async getEmails(page = 1, perPage = 20) {
        return this.get('/email', { page, per_page: perPage });
    }

    /**
     * Get email by ID
     */
    async getEmail(emailId) {
        return this.get(`/email/${emailId}`);
    }

    /**
     * Connect email account
     */
    async connectEmail(config) {
        return this.post('/email/connect', config);
    }

    /**
     * Sync emails
     */
    async syncEmails() {
        return this.post('/email/sync', {});
    }

    // ==================== Admin API ====================

    /**
     * Get all users (admin)
     */
    async getUsers(page = 1, perPage = 20) {
        return this.get('/admin/users', { page, per_page: perPage });
    }

    /**
     * Get system stats (admin)
     */
    async getSystemStats() {
        return this.get('/admin/stats');
    }

    /**
     * Get blacklist (admin)
     */
    async getBlacklist(page = 1, perPage = 20) {
        return this.get('/admin/blacklist', { page, per_page: perPage });
    }

    /**
     * Add to blacklist (admin)
     */
    async addToBlacklist(entry) {
        return this.post('/admin/blacklist', entry);
    }

    /**
     * Remove from blacklist (admin)
     */
    async removeFromBlacklist(id) {
        return this.delete(`/admin/blacklist/${id}`);
    }
}

// Create global API instance
const api = new APIClient();
