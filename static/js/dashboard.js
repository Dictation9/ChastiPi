// Dashboard JavaScript for real-time updates

class Dashboard {
    constructor() {
        this.updateInterval = 2000; // Update every 2 seconds
        this.init();
    }

    init() {
        this.updateChastityStatus();
        this.updateKeyManagement();
        this.updateAccessHistory();
        // Set up periodic updates
        setInterval(() => {
            this.updateChastityStatus();
            this.updateKeyManagement();
            this.updateAccessHistory();
        }, this.updateInterval * 3); // Update every 6 seconds
    }

    async updateSystemInfo() {
        try {
            const response = await fetch('/api/system-info');
            const data = await response.json();
            
            if (response.ok) {
                this.updateMetrics(data);
            } else {
                console.error('Failed to fetch system info:', data.error);
            }
        } catch (error) {
            console.error('Error fetching system info:', error);
        }
    }

    async updateProcesses() {
        try {
            const response = await fetch('/api/processes');
            const data = await response.json();
            
            if (response.ok) {
                this.updateProcessTable(data);
            } else {
                console.error('Failed to fetch processes:', data.error);
            }
        } catch (error) {
            console.error('Error fetching processes:', error);
        }
    }

    async updateChastityStatus() {
        try {
            const response = await fetch('/api/chastity-status');
            const data = await response.json();
            
            if (response.ok) {
                this.updateChastityMetrics(data);
            } else {
                console.error('Failed to fetch chastity status:', data.error);
            }
        } catch (error) {
            console.error('Error fetching chastity status:', error);
        }
    }

    async updateKeyManagement() {
        try {
            const response = await fetch('/api/key-management-summary');
            const data = await response.json();
            if (response.ok) {
                this.updateKeyManagementDisplay(data);
            } else {
                console.error('Failed to fetch key management summary:', data.error);
            }
        } catch (error) {
            console.error('Error fetching key management summary:', error);
        }
    }

    updateKeyManagementDisplay(data) {
        const digitalKeys = document.getElementById('digital-keys');
        const backupKeys = document.getElementById('backup-keys');
        const emergencyKeys = document.getElementById('emergency-keys');
        if (digitalKeys) digitalKeys.textContent = `${data.digital_keys} Active`;
        if (backupKeys) backupKeys.textContent = `${data.backup_keys} Available`;
        if (emergencyKeys) emergencyKeys.textContent = `${data.emergency_keys} Available`;
    }

    async updateAccessHistory() {
        try {
            const response = await fetch('/api/device-access-history');
            const data = await response.json();
            if (response.ok) {
                this.updateAccessHistoryDisplay(data);
            } else {
                console.error('Failed to fetch access history:', data.error);
            }
        } catch (error) {
            console.error('Error fetching access history:', error);
        }
    }

    updateAccessHistoryDisplay(data) {
        const lastAccess = document.getElementById('last-access');
        const totalSessions = document.getElementById('total-sessions');
        const avgDuration = document.getElementById('avg-duration');
        if (lastAccess) lastAccess.textContent = data.last_access || '--';
        if (totalSessions) totalSessions.textContent = data.total_sessions || '--';
        if (avgDuration) avgDuration.textContent = data.avg_duration || '--';
    }

    updateMetrics(data) {
        // Add updating animation
        const elements = [
            'cpu-percent', 'cpu-progress',
            'memory-percent', 'memory-progress', 'memory-used', 'memory-total',
            'disk-percent', 'disk-progress', 'disk-used', 'disk-total',
            'platform', 'hostname', 'timestamp'
        ];
        
        elements.forEach(id => {
            const element = document.getElementById(id);
            if (element) {
                element.classList.add('updating');
                setTimeout(() => element.classList.remove('updating'), 500);
            }
        });

        // Update CPU
        const cpuPercent = document.getElementById('cpu-percent');
        const cpuProgress = document.getElementById('cpu-progress');
        if (cpuPercent && cpuProgress) {
            cpuPercent.textContent = Math.round(data.cpu_percent);
            cpuProgress.style.width = `${data.cpu_percent}%`;
            
            // Change color based on usage
            if (data.cpu_percent > 80) {
                cpuProgress.style.background = 'linear-gradient(90deg, #f56565, #e53e3e)';
            } else if (data.cpu_percent > 60) {
                cpuProgress.style.background = 'linear-gradient(90deg, #ed8936, #dd6b20)';
            } else {
                cpuProgress.style.background = 'linear-gradient(90deg, #48bb78, #38a169)';
            }
        }

        // Update Memory
        const memoryPercent = document.getElementById('memory-percent');
        const memoryProgress = document.getElementById('memory-progress');
        const memoryUsed = document.getElementById('memory-used');
        const memoryTotal = document.getElementById('memory-total');
        
        if (memoryPercent && memoryProgress) {
            memoryPercent.textContent = Math.round(data.memory_percent);
            memoryProgress.style.width = `${data.memory_percent}%`;
            
            if (data.memory_percent > 80) {
                memoryProgress.style.background = 'linear-gradient(90deg, #f56565, #e53e3e)';
            } else if (data.memory_percent > 60) {
                memoryProgress.style.background = 'linear-gradient(90deg, #ed8936, #dd6b20)';
            } else {
                memoryProgress.style.background = 'linear-gradient(90deg, #48bb78, #38a169)';
            }
        }
        
        if (memoryUsed && memoryTotal) {
            memoryUsed.textContent = data.memory_used;
            memoryTotal.textContent = data.memory_total;
        }

        // Update Disk
        const diskPercent = document.getElementById('disk-percent');
        const diskProgress = document.getElementById('disk-progress');
        const diskUsed = document.getElementById('disk-used');
        const diskTotal = document.getElementById('disk-total');
        
        if (diskPercent && diskProgress) {
            diskPercent.textContent = Math.round(data.disk_percent);
            diskProgress.style.width = `${data.disk_percent}%`;
            
            if (data.disk_percent > 80) {
                diskProgress.style.background = 'linear-gradient(90deg, #f56565, #e53e3e)';
            } else if (data.disk_percent > 60) {
                diskProgress.style.background = 'linear-gradient(90deg, #ed8936, #dd6b20)';
            } else {
                diskProgress.style.background = 'linear-gradient(90deg, #48bb78, #38a169)';
            }
        }
        
        if (diskUsed && diskTotal) {
            diskUsed.textContent = data.disk_used;
            diskTotal.textContent = data.disk_total;
        }

        // Update System Info
        const platform = document.getElementById('platform');
        const hostname = document.getElementById('hostname');
        const timestamp = document.getElementById('timestamp');
        
        if (platform) platform.textContent = data.platform;
        if (hostname) hostname.textContent = data.hostname;
        if (timestamp) {
            const date = new Date(data.timestamp);
            timestamp.textContent = date.toLocaleTimeString();
        }
    }

    updateChastityMetrics(data) {
        // Update lock status
        const lockStatus = document.getElementById('lock-status');
        if (lockStatus) {
            lockStatus.textContent = data.lock_status;
            lockStatus.className = `status ${data.lock_status}`;
        }

        // Update time remaining
        const timeRemaining = document.getElementById('time-remaining');
        if (timeRemaining) {
            timeRemaining.textContent = data.time_remaining;
        }

        // Update keyholder status
        const keyholderStatus = document.getElementById('keyholder-status');
        if (keyholderStatus) {
            keyholderStatus.textContent = data.keyholder_approved ? 'Approved' : 'Pending';
            keyholderStatus.style.color = data.keyholder_approved ? '#38a169' : '#ed8936';
        }

        // Update emergency status
        const emergencyStatus = document.getElementById('emergency-status');
        if (emergencyStatus) {
            emergencyStatus.textContent = data.emergency_available ? 'Available' : 'Unavailable';
            emergencyStatus.style.color = data.emergency_available ? '#38a169' : '#e53e3e';
        }
    }

    updateProcessTable(processes) {
        const tbody = document.getElementById('processes-body');
        if (!tbody) return;

        if (processes.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="loading">No processes found</td></tr>';
            return;
        }

        tbody.innerHTML = processes.map(proc => `
            <tr>
                <td>${proc.pid || 'N/A'}</td>
                <td>${proc.name || 'Unknown'}</td>
                <td>${proc.cpu_percent ? Math.round(proc.cpu_percent) : '0'}%</td>
                <td>${proc.memory_percent ? Math.round(proc.memory_percent) : '0'}%</td>
            </tr>
        `).join('');
    }
}

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', () => {
    new Dashboard();
});

// Add some visual feedback for network status
window.addEventListener('online', () => {
    console.log('Network connection restored');
});

window.addEventListener('offline', () => {
    console.log('Network connection lost');
});

// Action button functions
function requestAccess() {
    alert('Requesting access... This would integrate with the actual ChastiPi system.');
}

function emergencyRelease() {
    if (confirm('Are you sure you want to initiate emergency release? This action cannot be undone.')) {
        alert('Emergency release initiated. Please contact your keyholder immediately.');
    }
}

function checkDevice() {
    alert('Device check requested. Please take a photo for verification.');
}

function viewHistory() {
    alert('Opening access history... This would show detailed logs and statistics.');
}

// Update functionality
async function checkForUpdates(btn) {
    let updateBtn = btn;
    const originalText = updateBtn.innerHTML;
    try {
        updateBtn.innerHTML = '<span class="action-icon">⏳</span><span class="action-text">Checking...</span>';
        updateBtn.disabled = true;
        
        const response = await fetch('/api/check-updates');
        const data = await response.json();
        
        if (response.ok) {
            if (data.has_updates) {
                showUpdateDialog(data);
            } else {
                showNotification('No updates available', 'info');
            }
        } else {
            showNotification('Error checking for updates: ' + data.error, 'error');
        }
    } catch (error) {
        showNotification('Error checking for updates: ' + error.message, 'error');
    } finally {
        updateBtn.innerHTML = originalText;
        updateBtn.disabled = false;
    }
}

function showUpdateDialog(updateInfo) {
    const dialog = document.createElement('div');
    dialog.className = 'update-dialog';
    dialog.innerHTML = `
        <div class="update-dialog-content">
            <div class="update-dialog-header">
                <h3>🔄 Updates Available</h3>
                <button class="close-btn" onclick="closeUpdateDialog()">&times;</button>
            </div>
            <div class="update-dialog-body">
                <p><strong>${updateInfo.message}</strong></p>
                ${updateInfo.branch ? `<p>Branch: <code>${updateInfo.branch}</code></p>` : ''}
                ${updateInfo.latest_commit ? `<p>Latest: <code>${updateInfo.latest_commit}</code></p>` : ''}
                ${updateInfo.local_commit ? `<p>Current: <code>${updateInfo.local_commit}</code></p>` : ''}
                
                <div class="update-options">
                    <h4>Update Options:</h4>
                    <button class="update-btn primary" onclick="performUpdate('full')">
                        <span class="update-icon">🚀</span>
                        Full Update (Code + Dependencies + System)
                    </button>
                    <button class="update-btn secondary" onclick="performUpdate('code')">
                        <span class="update-icon">📝</span>
                        Code Only
                    </button>
                    <button class="update-btn secondary" onclick="performUpdate('deps')">
                        <span class="update-icon">📦</span>
                        Dependencies Only
                    </button>
                    <button class="update-btn secondary" onclick="performUpdate('system')">
                        <span class="update-icon">🖥️</span>
                        System Packages Only
                    </button>
                </div>
            </div>
        </div>
    `;
    
    document.body.appendChild(dialog);
    
    // Add styles if not already present
    if (!document.getElementById('update-dialog-styles')) {
        const styles = document.createElement('style');
        styles.id = 'update-dialog-styles';
        styles.textContent = `
            .update-dialog {
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0, 0, 0, 0.5);
                display: flex;
                justify-content: center;
                align-items: center;
                z-index: 1000;
            }
            
            .update-dialog-content {
                background: white;
                border-radius: 12px;
                box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
                max-width: 500px;
                width: 90%;
                max-height: 80vh;
                overflow-y: auto;
            }
            
            .update-dialog-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 20px;
                border-bottom: 1px solid #e5e7eb;
            }
            
            .update-dialog-header h3 {
                margin: 0;
                color: #1f2937;
            }
            
            .close-btn {
                background: none;
                border: none;
                font-size: 24px;
                cursor: pointer;
                color: #6b7280;
                padding: 0;
                width: 30px;
                height: 30px;
                display: flex;
                align-items: center;
                justify-content: center;
                border-radius: 50%;
                transition: background-color 0.2s;
            }
            
            .close-btn:hover {
                background-color: #f3f4f6;
            }
            
            .update-dialog-body {
                padding: 20px;
            }
            
            .update-dialog-body p {
                margin: 10px 0;
                color: #374151;
            }
            
            .update-dialog-body code {
                background: #f3f4f6;
                padding: 2px 6px;
                border-radius: 4px;
                font-family: monospace;
                font-size: 0.9em;
            }
            
            .update-options {
                margin-top: 20px;
            }
            
            .update-options h4 {
                margin: 0 0 15px 0;
                color: #1f2937;
            }
            
            .update-btn {
                display: flex;
                align-items: center;
                gap: 10px;
                width: 100%;
                padding: 12px 16px;
                margin: 8px 0;
                border: 1px solid #d1d5db;
                border-radius: 8px;
                background: white;
                cursor: pointer;
                transition: all 0.2s;
                font-size: 14px;
                text-align: left;
            }
            
            .update-btn:hover {
                background: #f9fafb;
                border-color: #9ca3af;
            }
            
            .update-btn.primary {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border-color: #667eea;
            }
            
            .update-btn.primary:hover {
                background: linear-gradient(135deg, #5a67d8 0%, #6b46c1 100%);
            }
            
            .update-btn.secondary {
                background: white;
                color: #374151;
            }
            
            .update-icon {
                font-size: 16px;
            }
        `;
        document.head.appendChild(styles);
    }
}

function closeUpdateDialog() {
    const dialog = document.querySelector('.update-dialog');
    if (dialog) {
        dialog.remove();
    }
}

async function performUpdate(updateType) {
    try {
        // Show loading state
        const updateBtns = document.querySelectorAll('.update-btn');
        updateBtns.forEach(btn => {
            btn.disabled = true;
            btn.innerHTML = '<span class="update-icon">⏳</span>Starting update...';
        });
        
        const response = await fetch('/api/perform-update', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ type: updateType })
        });
        
        const data = await response.json();
        
        if (response.ok && data.success) {
            showNotification(`Update started successfully! (${updateType})`, 'success');
            closeUpdateDialog();
            
            // Start monitoring update progress
            monitorUpdateProgress();
        } else {
            showNotification('Error starting update: ' + (data.error || 'Unknown error'), 'error');
            // Restore button states
            updateBtns.forEach(btn => {
                btn.disabled = false;
                btn.innerHTML = btn.getAttribute('data-original-content') || btn.innerHTML;
            });
        }
    } catch (error) {
        showNotification('Error performing update: ' + error.message, 'error');
        // Restore button states
        const updateBtns = document.querySelectorAll('.update-btn');
        updateBtns.forEach(btn => {
            btn.disabled = false;
            btn.innerHTML = btn.getAttribute('data-original-content') || btn.innerHTML;
        });
    }
}

function monitorUpdateProgress() {
    const progressInterval = setInterval(async () => {
        try {
            const response = await fetch('/api/update-status');
            const data = await response.json();
            
            if (response.ok) {
                if (!data.is_running) {
                    clearInterval(progressInterval);
                    showNotification('Update completed! The system may restart.', 'success');
                    
                    // Optionally refresh the page after a delay
                    setTimeout(() => {
                        if (confirm('Update completed. Would you like to refresh the page?')) {
                            window.location.reload();
                        }
                    }, 3000);
                } else {
                    // Update is still running
                    showNotification('Update in progress...', 'info');
                }
            }
        } catch (error) {
            console.error('Error monitoring update progress:', error);
        }
    }, 5000); // Check every 5 seconds
}

function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <span class="notification-icon">${type === 'success' ? '✅' : type === 'error' ? '❌' : type === 'warning' ? '⚠️' : 'ℹ️'}</span>
            <span class="notification-message">${message}</span>
            <button class="notification-close" onclick="this.parentElement.parentElement.remove()">&times;</button>
        </div>
    `;
    
    // Add notification styles if not already present
    if (!document.getElementById('notification-styles')) {
        const styles = document.createElement('style');
        styles.id = 'notification-styles';
        styles.textContent = `
            .notification {
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 1001;
                max-width: 400px;
                animation: slideIn 0.3s ease-out;
            }
            
            .notification-content {
                display: flex;
                align-items: center;
                gap: 10px;
                padding: 12px 16px;
                border-radius: 8px;
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
                font-size: 14px;
            }
            
            .notification-success {
                background: #d1fae5;
                border: 1px solid #10b981;
                color: #065f46;
            }
            
            .notification-error {
                background: #fee2e2;
                border: 1px solid #ef4444;
                color: #991b1b;
            }
            
            .notification-warning {
                background: #fef3c7;
                border: 1px solid #f59e0b;
                color: #92400e;
            }
            
            .notification-info {
                background: #dbeafe;
                border: 1px solid #3b82f6;
                color: #1e40af;
            }
            
            .notification-close {
                background: none;
                border: none;
                font-size: 18px;
                cursor: pointer;
                color: inherit;
                opacity: 0.7;
                margin-left: auto;
            }
            
            .notification-close:hover {
                opacity: 1;
            }
            
            @keyframes slideIn {
                from {
                    transform: translateX(100%);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }
        `;
        document.head.appendChild(styles);
    }
    
    document.body.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.remove();
        }
    }, 5000);
} 