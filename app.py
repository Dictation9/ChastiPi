from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file, Response
from flask_session import Session
import os
import psutil
import platform
from datetime import datetime
from functools import wraps
import logging
from logging.handlers import RotatingFileHandler
import smtplib
from email.message import EmailMessage

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this-in-production')
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Raspberry Pi optimized settings
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.config['TEMPLATES_AUTO_RELOAD'] = True

# Keyholder credentials (in production, use proper authentication)
KEYHOLDER_USERNAME = os.environ.get('KEYHOLDER_USERNAME', 'keyholder')
KEYHOLDER_PASSWORD = os.environ.get('KEYHOLDER_PASSWORD', 'secure123')

# Ensure logs directory exists
os.makedirs('logs', exist_ok=True)

# Set up logging
log_formatter = logging.Formatter('%(asctime)s %(levelname)s %(name)s: %(message)s')
log_file = 'logs/app.log'
file_handler = RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=5)
file_handler.setFormatter(log_formatter)
file_handler.setLevel(logging.INFO)

app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)

app.logger.info('ChastiPi app started')

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'keyholder_logged_in' not in session:
            return redirect(url_for('keyholder_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')

@app.route('/system')
def system():
    """System monitoring dashboard"""
    return render_template('system.html')

@app.route('/keyholder/login', methods=['GET', 'POST'])
def keyholder_login():
    """Keyholder login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == KEYHOLDER_USERNAME and password == KEYHOLDER_PASSWORD:
            session['keyholder_logged_in'] = True
            session['keyholder_username'] = username
            return redirect(url_for('keyholder_dashboard'))
        else:
            return render_template('keyholder_login.html', error='Invalid credentials')
    
    return render_template('keyholder_login.html')

@app.route('/keyholder/logout')
def keyholder_logout():
    """Keyholder logout"""
    session.pop('keyholder_logged_in', None)
    session.pop('keyholder_username', None)
    return redirect(url_for('keyholder_login'))

@app.route('/keyholder/dashboard')
@login_required
def keyholder_dashboard():
    """Keyholder dashboard page"""
    return render_template('keyholder_dashboard.html')

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
        app.logger.error(f'/api/chastity-status error: {e}', exc_info=True)
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

# Keyholder-specific API endpoints
@app.route('/api/keyholder/device-control', methods=['POST'])
@login_required
def keyholder_device_control():
    """API endpoint for keyholder device control"""
    try:
        data = request.get_json()
        action = data.get('action')
        
        if action == 'unlock':
            # Simulate unlocking device
            return jsonify({
                'success': True,
                'message': 'Device unlocked successfully',
                'action': 'unlock',
                'timestamp': datetime.now().isoformat()
            })
        elif action == 'lock':
            # Simulate locking device
            return jsonify({
                'success': True,
                'message': 'Device locked successfully',
                'action': 'lock',
                'timestamp': datetime.now().isoformat()
            })
        elif action == 'emergency_release':
            # Simulate emergency release
            return jsonify({
                'success': True,
                'message': 'Emergency release activated',
                'action': 'emergency_release',
                'timestamp': datetime.now().isoformat()
            })
        else:
            return jsonify({'error': 'Invalid action'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/keyholder/access-history')
@login_required
def keyholder_access_history():
    """API endpoint to get access history for keyholder"""
    try:
        # Simulate access history data
        history = [
            {
                'id': 1,
                'action': 'unlock',
                'timestamp': '2024-01-15T10:30:00',
                'duration': '2 hours',
                'reason': 'Cleaning',
                'approved_by': 'keyholder'
            },
            {
                'id': 2,
                'action': 'lock',
                'timestamp': '2024-01-15T12:30:00',
                'duration': '0',
                'reason': 'Session ended',
                'approved_by': 'keyholder'
            },
            {
                'id': 3,
                'action': 'unlock',
                'timestamp': '2024-01-12T14:00:00',
                'duration': '1 hour',
                'reason': 'Medical check',
                'approved_by': 'keyholder'
            }
        ]
        
        return jsonify(history)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/keyholder/device-settings', methods=['GET', 'POST'])
@login_required
def keyholder_device_settings():
    """API endpoint for keyholder device settings"""
    try:
        if request.method == 'GET':
            # Return current settings
            return jsonify({
                'emergency_enabled': True,
                'notifications_enabled': True,
                'auto_lock_enabled': False,
                'session_timeout': 3600,  # 1 hour in seconds
                'max_session_duration': 7200,  # 2 hours in seconds
                'require_approval': True
            })
        else:
            # Update settings
            data = request.get_json()
            # In a real implementation, you would save these settings
            return jsonify({
                'success': True,
                'message': 'Settings updated successfully'
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/keyholder/notifications', methods=['GET', 'POST'])
@login_required
def keyholder_notifications():
    """API endpoint for keyholder notifications"""
    try:
        if request.method == 'GET':
            # Return recent notifications
            notifications = [
                {
                    'id': 1,
                    'type': 'access_request',
                    'message': 'Access request received from device',
                    'timestamp': '2024-01-15T10:25:00',
                    'read': False
                },
                {
                    'id': 2,
                    'type': 'device_status',
                    'message': 'Device locked successfully',
                    'timestamp': '2024-01-15T12:30:00',
                    'read': True
                },
                {
                    'id': 3,
                    'type': 'system_alert',
                    'message': 'Low battery warning',
                    'timestamp': '2024-01-15T09:15:00',
                    'read': False
                }
            ]
            
            return jsonify(notifications)
        else:
            # Mark notification as read
            data = request.get_json()
            notification_id = data.get('notification_id')
            
            return jsonify({
                'success': True,
                'message': f'Notification {notification_id} marked as read'
            })
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/logs/<logtype>')
@login_required
def view_log(logtype):
    log_map = {
        'app': 'logs/app.log',
        'backup': 'logs/backup.log',
        'update': 'logs/update.log',
    }
    log_file = log_map.get(logtype)
    if not log_file or not os.path.exists(log_file):
        return Response('Log not found', status=404)
    if request.args.get('download') == '1':
        return send_file(log_file, as_attachment=True)
    with open(log_file, 'r') as f:
        content = f.read()[-100_000:]  # Show last 100k chars
    return Response(f'<pre style="white-space: pre-wrap; word-break: break-all;">{content}</pre>', mimetype='text/html')

@app.route('/logs/view')
@login_required
def logs_viewer():
    return render_template('logs_viewer.html')

@app.route('/logs/level', methods=['GET', 'POST'])
@login_required
def log_level():
    root_logger = logging.getLogger()
    if request.method == 'POST':
        data = request.get_json()
        level = data.get('level', 'INFO').upper()
        if level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            return jsonify({'error': 'Invalid log level'}), 400
        for logger_name in ['', 'backup_manager', 'werkzeug', 'flask.app']:
            logging.getLogger(logger_name).setLevel(getattr(logging, level))
        app.logger.info(f'Log level changed to {level} by {session.get("keyholder_username") or "user"}')
        return jsonify({'level': level})
    # GET: return current level
    level = logging.getLogger().getEffectiveLevel()
    level_name = logging.getLevelName(level)
    return jsonify({'level': level_name})

def send_alert_email(subject, body):
    smtp_server = str(os.environ.get('ALERT_EMAIL_SMTP', ''))
    smtp_user = str(os.environ.get('ALERT_EMAIL_USER', ''))
    smtp_pass = str(os.environ.get('ALERT_EMAIL_PASS', ''))
    email_from = str(os.environ.get('ALERT_EMAIL_FROM', ''))
    email_to = str(os.environ.get('ALERT_EMAIL_TO', ''))
    if not all([smtp_server, smtp_user, smtp_pass, email_from, email_to]):
        app.logger.warning('Alert email not sent: missing SMTP config')
        return
    try:
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = email_from
        msg['To'] = email_to
        msg.set_content(body)
        with smtplib.SMTP_SSL(smtp_server) as server:
            server.login(smtp_user, smtp_pass)
            server.send_message(msg)
        app.logger.info(f'Alert email sent to {email_to}')
    except Exception as e:
        app.logger.error(f'Failed to send alert email: {e}')

# Flask error handler for 500 errors
@app.errorhandler(500)
def handle_500(e):
    user = session.get('keyholder_username') or 'unknown'
    err_msg = f'500 error for user {user}: {e}'
    app.logger.critical(err_msg, exc_info=True)
    send_alert_email('ChastiPi CRITICAL ERROR', err_msg)
    return render_template('500.html', error=str(e)), 500

if __name__ == '__main__':
    # Run on all interfaces for network access
    app.run(host='0.0.0.0', port=5000, debug=False) 