/**
 * ScamShield Dashboard
 */

class Dashboard {
    constructor() {
        this.currentTab = 'email';
        this.init();
    }

    init() {
        this.setupTabs();
        this.setupScanButton();
        this.setupLogout();
        this.loadStats();
        this.loadRecentScans();
        this.initWebSocket();
    }

    setupTabs() {
        const tabBtns = document.querySelectorAll('.tab-btn');
        
        tabBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                // Update active tab button
                tabBtns.forEach(b => b.classList.remove('active'));
                btn.classList.add('active');
                
                // Update active tab content
                const tabName = btn.dataset.tab;
                this.currentTab = tabName;
                
                document.querySelectorAll('.tab-content').forEach(content => {
                    content.classList.remove('active');
                });
                document.getElementById(`${tabName}-tab`).classList.add('active');
            });
        });
    }

    setupScanButton() {
        const scanBtn = document.getElementById('scan-btn');
        
        scanBtn.addEventListener('click', async () => {
            let content = '';
            let scanType = this.currentTab;
            
            if (this.currentTab === 'email') {
                content = document.getElementById('email-input').value;
            } else if (this.currentTab === 'url') {
                content = document.getElementById('url-input').value;
            } else if (this.currentTab === 'domain') {
                content = document.getElementById('domain-input').value;
            }
            
            if (!content.trim()) {
                alert('Please enter content to scan');
                return;
            }
            
            // Show loading state
            scanBtn.disabled = true;
            scanBtn.textContent = 'Scanning...';
            
            try {
                const result = await api.scan(content, scanType);
                
                // Show result
                this.showScanResult(result);
                
                // Refresh stats and history
                this.loadStats();
                this.loadRecentScans();
                
            } catch (error) {
                alert('Scan failed: ' + error.message);
            } finally {
                scanBtn.disabled = false;
                scanBtn.textContent = 'Scan Now';
            }
        });
    }

    showScanResult(result) {
        // Create result modal or display
        const resultHtml = `
            <div class="scan-result ${result.is_scam ? 'danger' : 'safe'}">
                <div class="result-header">
                    <span class="result-icon">${result.is_scam ? '⚠️' : '✅'}</span>
                    <span class="result-title">${result.is_scam ? 'Potential Scam Detected!' : 'No Threat Detected'}</span>
                </div>
                <div class="result-details">
                    <div>
                        <span>Risk Score:</span>
                        <span>${Math.round(result.risk_score * 100)}%</span>
                    </div>
                    <div>
                        <span>Category:</span>
                        <span>${result.category || 'Unknown'}</span>
                    </div>
                    <div>
                        <span>Confidence:</span>
                        <span>${Math.round(result.confidence * 100)}%</span>
                    </div>
                </div>
            </div>
        `;
        
        // Add result to page
        const scannerSection = document.querySelector('.scanner-section');
        const existingResult = scannerSection.querySelector('.scan-result');
        
        if (existingResult) {
            existingResult.remove();
        }
        
        scannerSection.insertAdjacentHTML('beforeend', resultHtml);
    }

    setupLogout() {
        const logoutBtn = document.getElementById('logout-btn');
        
        if (logoutBtn) {
            logoutBtn.addEventListener('click', (e) => {
                e.preventDefault();
                
                localStorage.removeItem('token');
                localStorage.removeItem('user');
                window.location.href = 'index.html';
            });
        }
    }

    async loadStats() {
        try {
            const stats = await api.getStats();
            
            document.getElementById('total-scans').textContent = stats.total_scans || 0;
            document.getElementById('threats-detected').textContent = stats.scams_detected || 0;
            document.getElementById('safe-emails').textContent = (stats.total_scans - stats.scams_detected) || 0;
            document.getElementById('detection-rate').textContent = (stats.detection_rate || 0) + '%';
            
        } catch (error) {
            console.error('Failed to load stats:', error);
        }
    }

    async loadRecentScans() {
        try {
            const history = await api.getScanHistory(1, 10);
            
            const tbody = document.getElementById('results-body');
            
            if (!history.scans || history.scans.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="no-data">No scans yet. Start scanning!</td></tr>';
                return;
            }
            
            tbody.innerHTML = history.scans.map(scan => `
                <tr>
                    <td>${new Date(scan.created_at).toLocaleDateString()}</td>
                    <td>${scan.scan_type}</td>
                    <td>${this.truncate(scan.content || '', 50)}</td>
                    <td><span class="risk-badge risk-${scan.risk_level}">${this.getRiskLabel(scan.risk_level)}</span></td>
                    <td>${scan.category || '-'}</td>
                    <td>${scan.is_scam ? '⚠️ Scam' : '✅ Safe'}</td>
                </tr>
            `).join('');
            
        } catch (error) {
            console.error('Failed to load scan history:', error);
        }
    }

    getRiskLabel(level) {
        const labels = ['Low', 'Medium', 'High', 'Critical'];
        return labels[level] || 'Unknown';
    }

    truncate(text, length) {
        if (!text) return '-';
        return text.length > length ? text.substring(0, length) + '...' : text;
    }

    initWebSocket() {
        // Initialize WebSocket for real-time updates
        if (typeof RealtimeClient !== 'undefined') {
            const realtime = new RealtimeClient();
            realtime.connect();
        }
    }
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    // Check if user is logged in
    const token = localStorage.getItem('token');
    if (!token) {
        window.location.href = 'login.html';
        return;
    }
    
    // Load user info
    const user = JSON.parse(localStorage.getItem('user') || '{}');
    if (user.username) {
        document.getElementById('user-name').textContent = user.username;
    }
    
    // Initialize dashboard
    new Dashboard();
});
