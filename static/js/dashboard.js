// Dashboard JavaScript for ChastiPi

document.addEventListener('DOMContentLoaded', function() {
    loadLockStatus();
    loadRecentActivity();
    loadUpdateStatus();
});

async function loadLockStatus() {
    try {
        const response = await fetch('/status');
        const status = await response.json();
        
        const statusElement = document.getElementById('lock-status');
        statusElement.innerHTML = `
            <p><strong>Status:</strong> ${status.locked ? '🔒 Locked' : '🔓 Unlocked'}</p>
            <p><strong>Since:</strong> ${status.since}</p>
            <p><strong>Next Photo Due:</strong> ${status.next_photo_due || 'Not set'}</p>
        `;
    } catch (error) {
        console.error('Error loading lock status:', error);
        document.getElementById('lock-status').innerHTML = '<p>Error loading status</p>';
    }
}

async function loadRecentActivity() {
    try {
        // This would typically fetch from an activity endpoint
        const activityElement = document.getElementById('recent-activity');
        activityElement.innerHTML = `
            <div class="event-item">
                <strong>Punishment Generated</strong><br>
                <small>${new Date().toLocaleDateString()}</small>
            </div>
            <div class="event-item">
                <strong>Photo Uploaded</strong><br>
                <small>${new Date().toLocaleDateString()}</small>
            </div>
        `;
    } catch (error) {
        console.error('Error loading recent activity:', error);
    }
}

async function loadUpdateStatus() {
    try {
        const response = await fetch('/update/status');
        const status = await response.json();
        
        const updateElement = document.getElementById('update-status');
        
        if (status.error) {
            updateElement.innerHTML = `
                <div class="update-error">
                    <p><strong>⚠️ Error checking for updates:</strong> ${status.error}</p>
                    <button onclick="loadUpdateStatus()" class="btn btn-warning">🔄 Retry</button>
                </div>
            `;
        } else if (status.update_available) {
            updateElement.innerHTML = `
                <div class="update-available">
                    <p><strong>🆕 Update Available!</strong></p>
                    <p>Version ${status.latest_version} is available (current: ${status.current_version})</p>
                    <div class="update-actions">
                        <a href="/update/dashboard" class="btn btn-success">📥 Download Update</a>
                        <button onclick="loadUpdateStatus()" class="btn btn-secondary">🔄 Check Again</button>
                    </div>
                </div>
            `;
        } else {
            updateElement.innerHTML = `
                <div class="update-current">
                    <p><strong>✅ System Up to Date</strong></p>
                    <p>Current version: ${status.current_version}</p>
                    <p><small>Last checked: ${status.last_check ? new Date(status.last_check).toLocaleDateString() : 'Never'}</small></p>
                    <div class="update-actions">
                        <button onclick="loadUpdateStatus()" class="btn btn-secondary">🔄 Check Again</button>
                        <a href="/update/dashboard" class="btn btn-primary">⚙️ Update Settings</a>
                    </div>
                </div>
            `;
        }
    } catch (error) {
        console.error('Error loading update status:', error);
        document.getElementById('update-status').innerHTML = `
            <div class="update-error">
                <p><strong>⚠️ Error checking for updates:</strong> Network error</p>
                <button onclick="loadUpdateStatus()" class="btn btn-warning">🔄 Retry</button>
            </div>
        `;
    }
} 