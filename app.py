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

@app.route('/api/check-updates')
def check_updates():
    """API endpoint to check for available updates"""
    try:
        import subprocess
        import os
        
        # Check if we're in a git repository
        if not os.path.exists('.git'):
            return jsonify({
                'has_updates': False,
                'message': 'Not a git repository',
                'update_type': 'none'
            })
        
        # Check for remote changes
        try:
            # Fetch latest changes
            subprocess.run(['git', 'fetch', 'origin'], capture_output=True, check=True)
            
            # Get local and remote commit hashes
            local_commit = subprocess.run(['git', 'rev-parse', 'HEAD'], 
                                        capture_output=True, text=True, check=True).stdout.strip()
            
            # Try main branch first, then master
            try:
                remote_commit = subprocess.run(['git', 'rev-parse', 'origin/main'], 
                                            capture_output=True, text=True, check=True).stdout.strip()
                branch = 'main'
            except subprocess.CalledProcessError:
                try:
                    remote_commit = subprocess.run(['git', 'rev-parse', 'origin/master'], 
                                                capture_output=True, text=True, check=True).stdout.strip()
                    branch = 'master'
                except subprocess.CalledProcessError:
                    return jsonify({
                        'has_updates': False,
                        'message': 'No remote branch found',
                        'update_type': 'none'
                    })
            
            has_updates = local_commit != remote_commit
            
            if has_updates:
                # Get commit information
                try:
                    remote_info = subprocess.run(['git', 'log', '--oneline', '-1', f'origin/{branch}'], 
                                              capture_output=True, text=True, check=True).stdout.strip()
                except:
                    remote_info = f"New commits available on {branch}"
                
                return jsonify({
                    'has_updates': True,
                    'message': f'Updates available on {branch} branch',
                    'update_type': 'code',
                    'branch': branch,
                    'latest_commit': remote_info,
                    'local_commit': local_commit[:8],
                    'remote_commit': remote_commit[:8]
                })
            else:
                return jsonify({
                    'has_updates': False,
                    'message': 'Code is up to date',
                    'update_type': 'none'
                })
                
        except subprocess.CalledProcessError as e:
            return jsonify({
                'has_updates': False,
                'message': f'Error checking updates: {str(e)}',
                'update_type': 'error'
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/perform-update', methods=['POST'])
def perform_update():
    """API endpoint to perform system updates"""
    try:
        import subprocess
        import json
        
        data = request.get_json()
        update_type = data.get('type', 'full')  # full, code, deps, system
        
        # Validate update type
        if update_type not in ['full', 'code', 'deps', 'system']:
            return jsonify({'error': 'Invalid update type'}), 400
        
        # Check if update script exists
        if not os.path.exists('update.sh'):
            return jsonify({'error': 'Update script not found'}), 404
        
        # Make update script executable
        os.chmod('update.sh', 0o755)
        
        # Prepare command based on update type
        if update_type == 'full':
            cmd = ['./update.sh', '--full']
        elif update_type == 'code':
            cmd = ['./update.sh', '--code']
        elif update_type == 'deps':
            cmd = ['./update.sh', '--deps']
        elif update_type == 'system':
            cmd = ['./update.sh', '--system']
        
        # Run update in background
        try:
            # Start the update process
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Return immediately with process info
            return jsonify({
                'success': True,
                'message': f'Update started (type: {update_type})',
                'process_id': process.pid,
                'update_type': update_type
            })
            
        except subprocess.CalledProcessError as e:
            return jsonify({
                'success': False,
                'error': f'Update failed: {str(e)}',
                'update_type': update_type
            }), 500
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/update-status')
def update_status():
    """API endpoint to check update process status"""
    try:
        import subprocess
        
        # Check if update process is running
        try:
            result = subprocess.run(['pgrep', '-f', 'update.sh'], 
                                  capture_output=True, text=True, check=True)
            is_running = bool(result.stdout.strip())
        except subprocess.CalledProcessError:
            is_running = False
        
        # Check for recent update logs
        log_files = ['chastipi.log', 'update.log']
        recent_logs = []
        
        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    # Get last 10 lines of log
                    result = subprocess.run(['tail', '-10', log_file], 
                                          capture_output=True, text=True, check=True)
                    recent_logs.append({
                        'file': log_file,
                        'content': result.stdout
                    })
                except:
                    pass
        
        return jsonify({
            'is_running': is_running,
            'recent_logs': recent_logs
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Run on all interfaces for network access
    app.run(host='0.0.0.0', port=5000, debug=False) 