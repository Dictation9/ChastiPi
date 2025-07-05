from flask import Flask, render_template, request, jsonify
import os
import psutil
import platform
from datetime import datetime

app = Flask(__name__)

# Raspberry Pi optimized settings
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['TEMPLATES_AUTO_RELOAD'] = True

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/system')
def system():
    """System monitoring dashboard"""
    return render_template('system.html')

@app.route('/api/chastity-status')
def chastity_status():
    """API endpoint to get chastity device status"""
    try:
        # This would integrate with actual chastity management features
        return jsonify({
            'device_connected': True,
            'lock_status': 'locked',
            'time_remaining': '2 days, 14 hours',
            'last_check': '2024-01-15T10:30:00',
            'keyholder_approved': True,
            'emergency_available': True
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/system-info')
def system_info():
    """API endpoint to get system information"""
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        return jsonify({
            'cpu_percent': cpu_percent,
            'memory_percent': memory.percent,
            'memory_used': memory.used // (1024**3),  # GB
            'memory_total': memory.total // (1024**3),  # GB
            'disk_percent': disk.percent,
            'disk_used': disk.used // (1024**3),  # GB
            'disk_total': disk.total // (1024**3),  # GB
            'platform': platform.system(),
            'hostname': platform.node(),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/processes')
def get_processes():
    """API endpoint to get running processes"""
    try:
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # Sort by CPU usage and return top 10
        processes.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
        return jsonify(processes[:10])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Run on all interfaces for network access
    app.run(host='0.0.0.0', port=5000, debug=False) 