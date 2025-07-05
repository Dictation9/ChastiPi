// System Monitor JavaScript for real-time updates

class SystemMonitor {
    constructor() {
        this.updateInterval = 2000; // Update every 2 seconds
        this.init();
    }

    init() {
        this.updateSystemInfo();
        this.updateProcesses();
        
        // Set up periodic updates
        setInterval(() => {
            this.updateSystemInfo();
        }, this.updateInterval);
        
        setInterval(() => {
            this.updateProcesses();
        }, this.updateInterval * 2); // Update processes less frequently
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

// Initialize system monitor when page loads
document.addEventListener('DOMContentLoaded', () => {
    new SystemMonitor();
});

// Add some visual feedback for network status
window.addEventListener('online', () => {
    console.log('Network connection restored');
});

window.addEventListener('offline', () => {
    console.log('Network connection lost');
}); 