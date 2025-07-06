// Keyholder Dashboard JavaScript
let deviceStatus = {};
let accessHistory = [];
let notifications = [];
let deviceSettings = {};

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    loadDeviceStatus();
    loadAccessHistory();
    loadNotifications();
    loadDeviceSettings();
    
    // Refresh data every 30 seconds
    setInterval(() => {
        loadDeviceStatus();
        loadNotifications();
    }, 30000);
});

// Load device status
async function loadDeviceStatus() {
    try {
        const response = await fetch('/api/chastity-status');
        const data = await response.json();
        
        if (data.error) {
            console.error('Error loading device status:', data.error);
            return;
        }
        
        deviceStatus = data;
        updateDeviceStatusDisplay();
    } catch (error) {
        console.error('Error loading device status:', error);
    }
}

// Update device status display
function updateDeviceStatusDisplay() {
    const statusElement = document.getElementById('device-status');
    const lockStateElement = document.getElementById('lock-state');
    const timeRemainingElement = document.getElementById('time-remaining');
    const lastActivityElement = document.getElementById('last-activity');
    
    if (statusElement) {
        statusElement.textContent = deviceStatus.device_connected ? 'Online' : 'Offline';
        const statusIndicator = statusElement.previousElementSibling;
        if (statusIndicator) {
            statusIndicator.className = deviceStatus.device_connected ? 
                'status-indicator status-online' : 'status-indicator status-offline';
        }
    }
    
    if (lockStateElement) {
        lockStateElement.textContent = deviceStatus.lock_status || 'Unknown';
    }
    
    if (timeRemainingElement) {
        timeRemainingElement.textContent = deviceStatus.time_remaining || 'Unknown';
    }
    
    if (lastActivityElement) {
        // Calculate time since last check
        if (deviceStatus.last_check) {
            const lastCheck = new Date(deviceStatus.last_check);
            const now = new Date();
            const diffMs = now - lastCheck;
            const diffHours = Math.floor(diffMs / (1000 * 60 * 60));
            const diffMinutes = Math.floor((diffMs % (1000 * 60 * 60)) / (1000 * 60));
            
            if (diffHours > 0) {
                lastActivityElement.textContent = `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
            } else {
                lastActivityElement.textContent = `${diffMinutes} minute${diffMinutes > 1 ? 's' : ''} ago`;
            }
        } else {
            lastActivityElement.textContent = 'Unknown';
        }
    }
}

// Load access history
async function loadAccessHistory() {
    try {
        const response = await fetch('/api/keyholder/access-history');
        const data = await response.json();
        
        if (Array.isArray(data)) {
            accessHistory = data;
            updateAccessHistoryDisplay();
        }
    } catch (error) {
        console.error('Error loading access history:', error);
    }
}

// Update access history display
function updateAccessHistoryDisplay() {
    const historyContainer = document.getElementById('access-history');
    if (!historyContainer) return;
    
    if (accessHistory.length === 0) {
        historyContainer.innerHTML = '<p style="text-align: center; color: #666; padding: 20px;">No access history available</p>';
        return;
    }
    
    const historyHTML = accessHistory.map(item => {
        const timestamp = new Date(item.timestamp);
        const formattedTime = timestamp.toLocaleString();
        
        let actionIcon = '🔓';
        let actionClass = 'unlock';
        
        if (item.action === 'lock') {
            actionIcon = '🔒';
            actionClass = 'lock';
        } else if (item.action === 'emergency_release') {
            actionIcon = '🚨';
            actionClass = 'emergency';
        }
        
        return `
            <div class="history-item ${actionClass}">
                <div class="history-header">
                    <div class="history-action">${actionIcon} ${item.action.replace('_', ' ').toUpperCase()}</div>
                    <div class="history-time">${formattedTime}</div>
                </div>
                <div class="history-details">
                    <strong>Reason:</strong> ${item.reason || 'No reason provided'}<br>
                    <strong>Duration:</strong> ${item.duration || 'N/A'}<br>
                    <strong>Approved by:</strong> ${item.approved_by || 'System'}
                </div>
            </div>
        `;
    }).join('');
    
    historyContainer.innerHTML = historyHTML;
}

// Load notifications
async function loadNotifications() {
    try {
        const response = await fetch('/api/keyholder/notifications');
        const data = await response.json();
        
        if (Array.isArray(data)) {
            notifications = data;
            updateNotificationsDisplay();
        }
    } catch (error) {
        console.error('Error loading notifications:', error);
    }
}

// Update notifications display
function updateNotificationsDisplay() {
    const notificationsContainer = document.getElementById('notifications');
    if (!notificationsContainer) return;
    
    if (notifications.length === 0) {
        notificationsContainer.innerHTML = '<p style="text-align: center; color: #666; padding: 20px;">No notifications</p>';
        return;
    }
    
    const notificationsHTML = notifications.map(item => {
        const timestamp = new Date(item.timestamp);
        const formattedTime = timestamp.toLocaleString();
        
        let typeIcon = '📢';
        if (item.type === 'access_request') typeIcon = '🔓';
        else if (item.type === 'device_status') typeIcon = '📊';
        else if (item.type === 'system_alert') typeIcon = '⚠️';
        
        return `
            <div class="notification-item ${item.read ? '' : 'unread'}" onclick="markNotificationRead(${item.id})">
                <div class="notification-header">
                    <div class="notification-type">${typeIcon} ${item.type.replace('_', ' ').toUpperCase()}</div>
                    <div class="notification-time">${formattedTime}</div>
                </div>
                <div class="notification-message">${item.message}</div>
            </div>
        `;
    }).join('');
    
    notificationsContainer.innerHTML = notificationsHTML;
}

// Mark notification as read
async function markNotificationRead(notificationId) {
    try {
        const response = await fetch('/api/keyholder/notifications', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ notification_id: notificationId })
        });
        
        if (response.ok) {
            // Reload notifications to update the display
            loadNotifications();
        }
    } catch (error) {
        console.error('Error marking notification as read:', error);
    }
}

// Load device settings
async function loadDeviceSettings() {
    try {
        const response = await fetch('/api/keyholder/device-settings');
        const data = await response.json();
        
        if (data.error) {
            console.error('Error loading device settings:', data.error);
            return;
        }
        
        deviceSettings = data;
        updateDeviceSettingsDisplay();
    } catch (error) {
        console.error('Error loading device settings:', error);
    }
}

// Update device settings display
function updateDeviceSettingsDisplay() {
    const settingsContainer = document.getElementById('device-settings');
    if (!settingsContainer) return;
    
    const settingsHTML = `
        <div class="setting-item">
            <div class="setting-label">Emergency Release</div>
            <div class="setting-value">
                <label class="toggle-switch">
                    <input type="checkbox" ${deviceSettings.emergency_enabled ? 'checked' : ''} onchange="updateSetting('emergency_enabled', this.checked)">
                    <span class="slider"></span>
                </label>
            </div>
        </div>
        <div class="setting-item">
            <div class="setting-label">Notifications</div>
            <div class="setting-value">
                <label class="toggle-switch">
                    <input type="checkbox" ${deviceSettings.notifications_enabled ? 'checked' : ''} onchange="updateSetting('notifications_enabled', this.checked)">
                    <span class="slider"></span>
                </label>
            </div>
        </div>
        <div class="setting-item">
            <div class="setting-label">Auto Lock</div>
            <div class="setting-value">
                <label class="toggle-switch">
                    <input type="checkbox" ${deviceSettings.auto_lock_enabled ? 'checked' : ''} onchange="updateSetting('auto_lock_enabled', this.checked)">
                    <span class="slider"></span>
                </label>
            </div>
        </div>
        <div class="setting-item">
            <div class="setting-label">Require Approval</div>
            <div class="setting-value">
                <label class="toggle-switch">
                    <input type="checkbox" ${deviceSettings.require_approval ? 'checked' : ''} onchange="updateSetting('require_approval', this.checked)">
                    <span class="slider"></span>
                </label>
            </div>
        </div>
        <div class="setting-item">
            <div class="setting-label">Session Timeout</div>
            <div class="setting-value">${Math.floor(deviceSettings.session_timeout / 3600)} hours</div>
        </div>
        <div class="setting-item">
            <div class="setting-label">Max Session Duration</div>
            <div class="setting-value">${Math.floor(deviceSettings.max_session_duration / 3600)} hours</div>
        </div>
    `;
    
    settingsContainer.innerHTML = settingsHTML;
}

// Update device setting
async function updateSetting(setting, value) {
    try {
        const response = await fetch('/api/keyholder/device-settings', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ [setting]: value })
        });
        
        if (response.ok) {
            // Update local settings
            deviceSettings[setting] = value;
            showNotification(`Setting updated: ${setting} = ${value}`);
        } else {
            console.error('Error updating setting');
            // Revert the toggle
            loadDeviceSettings();
        }
    } catch (error) {
        console.error('Error updating setting:', error);
        // Revert the toggle
        loadDeviceSettings();
    }
}

// Control device
async function controlDevice(action) {
    try {
        const response = await fetch('/api/keyholder/device-control', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ action: action })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification(`Device ${action} successful`);
            // Reload device status
            loadDeviceStatus();
            // Reload access history
            loadAccessHistory();
        } else {
            showNotification(`Error: ${data.error || 'Unknown error'}`, 'error');
        }
    } catch (error) {
        console.error('Error controlling device:', error);
        showNotification('Error controlling device', 'error');
    }
}

// Emergency release
function emergencyRelease() {
    const modal = document.getElementById('emergencyModal');
    if (modal) {
        modal.style.display = 'block';
    }
}

// Close modal
function closeModal() {
    const modal = document.getElementById('emergencyModal');
    if (modal) {
        modal.style.display = 'none';
    }
}

// Confirm emergency release
async function confirmEmergencyRelease() {
    try {
        const response = await fetch('/api/keyholder/device-control', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ action: 'emergency_release' })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification('Emergency release activated', 'warning');
            closeModal();
            // Reload data
            loadDeviceStatus();
            loadAccessHistory();
        } else {
            showNotification(`Error: ${data.error || 'Unknown error'}`, 'error');
        }
    } catch (error) {
        console.error('Error during emergency release:', error);
        showNotification('Error during emergency release', 'error');
    }
}

// Show notification
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 20px;
        border-radius: 8px;
        color: white;
        font-weight: 500;
        z-index: 1001;
        max-width: 300px;
        word-wrap: break-word;
    `;
    
    // Set background color based on type
    switch (type) {
        case 'success':
            notification.style.backgroundColor = '#28a745';
            break;
        case 'error':
            notification.style.backgroundColor = '#dc3545';
            break;
        case 'warning':
            notification.style.backgroundColor = '#ffc107';
            notification.style.color = '#212529';
            break;
        default:
            notification.style.backgroundColor = '#667eea';
    }
    
    notification.textContent = message;
    document.body.appendChild(notification);
    
    // Remove notification after 3 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.parentNode.removeChild(notification);
        }
    }, 3000);
}

// Close modal when clicking outside
window.onclick = function(event) {
    const modal = document.getElementById('emergencyModal');
    if (event.target === modal) {
        closeModal();
    }
} 