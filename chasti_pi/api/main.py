"""
Main API routes for ChastiPi
"""
from flask import Blueprint, render_template, request, jsonify, redirect, url_for, flash
from datetime import datetime
import json
import subprocess

from chasti_pi.services.config_service import ConfigService
from chasti_pi.services.key_storage_service import KeyStorageService
from chasti_pi.services.cage_check_service import CageCheckService
from chasti_pi.services.punishment_service import PunishmentService
from chasti_pi.services.time_verification_service import TimeVerificationService
from chasti_pi.core.config import config

# Initialize services
config_service = ConfigService()
key_storage_service = KeyStorageService()
cage_check_service = CageCheckService()
punishment_service = PunishmentService()
time_verification_service = TimeVerificationService()

# Create blueprint
main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    """Main landing page"""
    return render_template('main/index.html')

@main_bp.route('/dashboard')
def dashboard():
    """Main dashboard"""
    # Get system status
    keyholder_registered = config.is_keyholder_registered()
    keyholder_email = config.get("keyholder.default_keyholder_email", "")
    
    # Get active requests
    active_requests = key_storage_service.get_active_requests()
    
    # Get recent cage checks
    recent_cage_checks = cage_check_service.get_recent_checks(limit=5)
    
    # Get punishment statistics
    punishment_stats = punishment_service.get_statistics()
    
    # Get time verification status
    time_status = time_verification_service.get_status()
    
    return render_template('main/dashboard.html',
                         keyholder_registered=keyholder_registered,
                         keyholder_email=keyholder_email,
                         active_requests=active_requests,
                         recent_cage_checks=recent_cage_checks,
                         punishment_stats=punishment_stats,
                         time_status=time_status)

@main_bp.route('/time-status')
def time_status():
    """Time verification status page"""
    status = time_verification_service.get_status()
    return render_template('main/time_status.html', status=status)

@main_bp.route('/settings')
def settings():
    """Settings page - wearer access only"""
    # Get wearer-accessible settings
    settings_data = config_service.get_all_settings("wearer")
    keyholder_registered = config.is_keyholder_registered()
    keyholder_email = config.get("keyholder.default_keyholder_email", "")
    
    # Get configuration info
    config_info = config_service.get_config_info("wearer")
    permission_info = config_service.get_permission_info()
    
    return render_template('main/settings.html',
                         settings=settings_data,
                         keyholder_registered=keyholder_registered,
                         keyholder_email=keyholder_email,
                         config_info=config_info,
                         permission_info=permission_info)

@main_bp.route('/settings', methods=['POST'])
def update_settings():
    """Update settings - wearer access only"""
    try:
        # Get form data
        updates = {}
        for key, value in request.form.items():
            if '.' in key:  # Only process valid setting keys
                section, setting = key.split('.', 1)
                if section not in updates:
                    updates[section] = {}
                updates[section][setting] = value
        
        # Convert boolean values
        for section in updates:
            for key, value in updates[section].items():
                if value.lower() in ('true', 'false'):
                    updates[section][key] = value.lower() == 'true'
                elif value.isdigit():
                    updates[section][key] = int(value)
        
        # Update settings with wearer permissions
        errors = config_service.update_settings(updates, "wearer")
        
        if errors:
            flash(f"Settings updated with errors: {', '.join(errors)}", "error")
        else:
            flash("Settings updated successfully!", "success")
        
        return redirect(url_for('main.settings'))
    
    except Exception as e:
        flash(f"Error updating settings: {str(e)}", "error")
        return redirect(url_for('main.settings'))

@main_bp.route('/api/status')
def api_status():
    """API endpoint for system status"""
    try:
        # Get system status
        keyholder_registered = config.is_keyholder_registered()
        keyholder_email = config.get("keyholder.default_keyholder_email", "")
        
        # Get active requests count
        active_requests = key_storage_service.get_active_requests()
        active_count = len(active_requests)
        
        # Get pending cage checks
        pending_checks = cage_check_service.get_pending_checks()
        pending_count = len(pending_checks)
        
        # Get time verification status
        time_status = time_verification_service.get_status()
        
        # Get punishment statistics
        punishment_stats = punishment_service.get_statistics()
        
        return jsonify({
            "status": "online",
            "timestamp": datetime.now().isoformat(),
            "keyholder": {
                "registered": keyholder_registered,
                "email": keyholder_email if keyholder_registered else None
            },
            "requests": {
                "active": active_count,
                "pending": active_count
            },
            "cage_checks": {
                "pending": pending_count
            },
            "time_verification": {
                "enabled": time_status.get("enabled", False),
                "synced": time_status.get("synced", False),
                "drift_seconds": time_status.get("drift_seconds", 0)
            },
            "punishments": {
                "total": punishment_stats.get("total", 0),
                "completed": punishment_stats.get("completed", 0),
                "pending": punishment_stats.get("pending", 0)
            }
        })
    
    except Exception as e:
        return jsonify({
            "status": "error",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500

@main_bp.route('/api/config/export')
def api_export_config():
    """Export configuration (wearer access only)"""
    try:
        config_text = config_service.export_config("wearer")
        return jsonify({
            "success": True,
            "config": config_text,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@main_bp.route('/api/config/import', methods=['POST'])
def api_import_config():
    """Import configuration (wearer access only)"""
    try:
        config_text = request.json.get('config', '')
        if not config_text:
            return jsonify({
                "success": False,
                "error": "No configuration provided"
            }), 400
        
        errors = config_service.import_config(config_text, "wearer")
        
        if errors:
            return jsonify({
                "success": False,
                "errors": errors
            }), 400
        
        return jsonify({
            "success": True,
            "message": "Configuration imported successfully"
        })
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@main_bp.route('/api/config/templates')
def api_config_templates():
    """Get configuration templates (wearer access only)"""
    try:
        templates = config_service.get_config_templates("wearer")
        return jsonify({
            "success": True,
            "templates": templates
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@main_bp.route('/api/config/info')
def api_config_info():
    """Get configuration information (wearer access only)"""
    try:
        config_info = config_service.get_config_info("wearer")
        permission_info = config_service.get_permission_info()
        
        return jsonify({
            "success": True,
            "config_info": config_info,
            "permission_info": permission_info
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@main_bp.route('/api/config/backup', methods=['POST'])
def api_backup_config():
    """Create configuration backup (wearer access only)"""
    try:
        backup_file = config_service.backup_config()
        return jsonify({
            "success": True,
            "backup_file": backup_file,
            "message": "Configuration backed up successfully"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@main_bp.route('/api/config/restore', methods=['POST'])
def api_restore_config():
    """Restore configuration from backup (wearer access only)"""
    try:
        backup_file = request.json.get('backup_file', '')
        if not backup_file:
            return jsonify({
                "success": False,
                "error": "No backup file specified"
            }), 400
        
        success = config_service.restore_config(backup_file)
        
        if success:
            return jsonify({
                "success": True,
                "message": "Configuration restored successfully"
            })
        else:
            return jsonify({
                "success": False,
                "error": "Failed to restore configuration"
            }), 500
    
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@main_bp.route('/api/encryption/status')
def api_encryption_status():
    """Get encryption status information"""
    try:
        encryption_status = config.get_encryption_status()
        return jsonify({
            "success": True,
            "encryption_status": encryption_status
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@main_bp.route('/api/permissions/info')
def api_permissions_info():
    """Get permission information"""
    try:
        permission_info = config_service.get_permission_info()
        return jsonify({
            "success": True,
            "permission_info": permission_info
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@main_bp.route('/update/manual', methods=['POST'])
def manual_update():
    """Pull latest code from GitHub and update dependencies."""
    try:
        # Pull latest code
        git_pull = subprocess.run(['git', 'pull'], capture_output=True, text=True, timeout=60)
        git_output = git_pull.stdout + '\n' + git_pull.stderr
        
        # Update dependencies
        pip_install = subprocess.run(['pip3', 'install', '-r', 'requirements.txt'], capture_output=True, text=True, timeout=120)
        pip_output = pip_install.stdout + '\n' + pip_install.stderr

        return jsonify({
            'success': True,
            'git_output': git_output,
            'pip_output': pip_output
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}) 