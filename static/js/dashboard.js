// Dashboard JavaScript for ChastiPi

document.addEventListener('DOMContentLoaded', function() {
    loadLockStatus();
    loadRecentActivity();
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