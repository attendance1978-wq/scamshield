/**
 * ScamShield Realtime Client
 * WebSocket client for real-time updates
 */

class RealtimeClient {
    constructor() {
        this.socket = null;
        this.connected = false;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 3000;
    }

    /**
     * Connect to WebSocket server
     */
    connect() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}`;
        
        try {
            this.socket = new WebSocket(wsUrl);
            
            this.socket.onopen = () => {
                console.log('WebSocket connected');
                this.connected = true;
                this.reconnectAttempts = 0;
                this.onConnect();
            };
            
            this.socket.onmessage = (event) => {
                this.handleMessage(event);
            };
            
            this.socket.onclose = () => {
                console.log('WebSocket disconnected');
                this.connected = false;
                this.onDisconnect();
                this.attemptReconnect();
            };
            
            this.socket.onerror = (error) => {
                console.error('WebSocket error:', error);
            };
            
        } catch (error) {
            console.error('Failed to connect WebSocket:', error);
            this.attemptReconnect();
        }
    }

    /**
     * Handle incoming message
     */
    handleMessage(event) {
        try {
            const data = JSON.parse(event.data);
            const eventType = data.type || data.event;
            
            console.log('WebSocket message:', eventType, data);
            
            switch (eventType) {
                case 'scan_complete':
                    this.onScanComplete(data);
                    break;
                case 'scam_alert':
                    this.onScamAlert(data);
                    break;
                case 'alert':
                    this.onAlert(data);
                    break;
                case 'status_update':
                    this.onStatusUpdate(data);
                    break;
                case 'connected':
                    this.onConnected(data);
                    break;
                default:
                    console.log('Unknown event type:', eventType);
            }
            
            // Dispatch custom event
            window.dispatchEvent(new CustomEvent('scamshield:message', {
                detail: data
            }));
            
        } catch (error) {
            console.error('Failed to parse WebSocket message:', error);
        }
    }

    /**
     * Send message to server
     */
    send(event, data = {}) {
        if (!this.connected || !this.socket) {
            console.warn('WebSocket not connected');
            return false;
        }
        
        try {
            this.socket.send(JSON.stringify({
                event,
                ...data
            }));
            return true;
        } catch (error) {
            console.error('Failed to send WebSocket message:', error);
            return false;
        }
    }

    /**
     * Join room
     */
    joinRoom(room) {
        return this.send('join', { room });
    }

    /**
     * Leave room
     */
    leaveRoom(room) {
        return this.send('leave', { room });
    }

    /**
     * Request scan
     */
    requestScan(content, scanType) {
        return this.send('scan_request', {
            content,
            scan_type: scanType
        });
    }

    /**
     * Attempt to reconnect
     */
    attemptReconnect() {
        if (this.reconnectAttempts >= this.maxReconnectAttempts) {
            console.error('Max reconnection attempts reached');
            return;
        }
        
        this.reconnectAttempts++;
        console.log(`Attempting to reconnect (${this.reconnectAttempts}/${this.maxReconnectAttempts})...`);
        
        setTimeout(() => {
            this.connect();
        }, this.reconnectDelay);
    }

    /**
     * Disconnect
     */
    disconnect() {
        if (this.socket) {
            this.socket.close();
            this.socket = null;
            this.connected = false;
        }
    }

    // ==================== Event Handlers ====================

    onConnect() {
        // Join user room if logged in
        const user = JSON.parse(localStorage.getItem('user') || '{}');
        if (user.id) {
            this.joinRoom(`user:${user.id}`);
        }
    }

    onDisconnect() {
        // Handle disconnection
    }

    onScanComplete(data) {
        // Refresh dashboard
        window.dispatchEvent(new CustomEvent('scamshield:scanComplete', {
            detail: data
        }));
        
        // Show notification
        this.showNotification(
            data.is_scam ? '⚠️ Scam Detected' : '✅ Scan Complete',
            data.scan_id
        );
    }

    onScamAlert(data) {
        // Show alert notification
        this.showNotification('🚨 Scam Alert!', data.message);
        
        // Dispatch event
        window.dispatchEvent(new CustomEvent('scamshield:scamAlert', {
            detail: data
        }));
    }

    onAlert(data) {
        // Add alert to list
        window.dispatchEvent(new CustomEvent('scamshield:alert', {
            detail: data
        }));
    }

    onStatusUpdate(data) {
        // Update status indicators
        window.dispatchEvent(new CustomEvent('scamshield:statusUpdate', {
            detail: data
        }));
    }

    onConnected(data) {
        console.log('Server acknowledged connection:', data);
    }

    showNotification(title, message) {
        // Browser notification
        if ('Notification' in window && Notification.permission === 'granted') {
            new Notification(title, {
                body: message,
                icon: '/favicon.ico'
            });
        }
    }

    /**
     * Request notification permission
     */
    async requestNotificationPermission() {
        if ('Notification' in window && Notification.permission === 'default') {
            await Notification.requestPermission();
        }
    }
}

// Create global instance
const realtime = new RealtimeClient();

// Auto-connect on page load if user is logged in
document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('token');
    if (token) {
        realtime.connect();
        realtime.requestNotificationPermission();
    }
});
