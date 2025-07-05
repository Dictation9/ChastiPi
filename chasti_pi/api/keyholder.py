"""
Keyholder API for ChastiPi
Handles device registration, key requests, and approval management
"""
from flask import Blueprint, request, jsonify, render_template, redirect, url_for, flash, session
from datetime import datetime
import json
from pathlib import Path
import os

from ..services.key_storage_service import KeyStorageService
from ..services.email_service import EmailService
from ..services.config_service import ConfigService
from ..services.keyholder_config_service import KeyholderConfigService
from ..core.config import config

# Create blueprint
keyholder_bp = Blueprint('keyholder', __name__, url_prefix='/keyholder')

# Initialize services
key_storage = KeyStorageService()
email_service = EmailService()
config_service = ConfigService()
keyholder_config_service = KeyholderConfigService()

# Plugin management
PLUGINS_PATH = Path(__file__).parent.parent.parent / "plugins"
WEARER_SETTINGS_PATH = Path(__file__).parent.parent.parent / "data" / "wearer_settings.json"

def load_wearer_settings():
    if WEARER_SETTINGS_PATH.exists():
        with open(WEARER_SETTINGS_PATH, "r") as f:
            return json.load(f)
    return {}

def save_wearer_settings(settings):
    with open(WEARER_SETTINGS_PATH, "w") as f:
        json.dump(settings, f, indent=2)

@keyholder_bp.route('/dashboard')
def dashboard():
    """Keyholder dashboard"""
    # Get active requests
    active_requests = key_storage.get_active_requests()
    
    # Get recent activity
    recent_activity = key_storage.get_recent_activity(limit=10)
    
    # Get statistics
    stats = key_storage.get_statistics()
    
    # Get configuration info
    config_info = config_service.get_config_info("keyholder")
    
    # Get keyholder email
    keyholder_email = config.get("keyholder.default_keyholder_email", "")
    
    # Get pending requests
    pending_requests = key_storage.get_pending_requests()
    
    # Get devices
    devices = key_storage.get_all_devices()
    
    # Get client IP and network status
    client_ip = request.remote_addr
    is_remote = False  # This could be enhanced to detect actual remote access
    
    # Plugin management
    plugins = []
    for plugin_file in PLUGINS_PATH.glob("*.py"):
        if plugin_file.name.startswith("__"): continue
        plugins.append(plugin_file.stem)
    enabled_plugins = set(config.get('plugins.enabled_plugins', []))
    plugin_states = {p: (p in enabled_plugins) for p in plugins}
    
    wearer_settings = load_wearer_settings()
    
    return render_template('keyholder/dashboard.html',
                         active_requests=active_requests,
                         recent_activity=recent_activity,
                         stats=stats,
                         config_info=config_info,
                         keyholder_email=keyholder_email,
                         pending_requests=pending_requests,
                         devices=devices,
                         client_ip=client_ip,
                         is_remote=is_remote,
                         plugin_states=plugin_states,
                         wearer_settings=wearer_settings)

@keyholder_bp.route('/digital-keyholder')
def digital_keyholder():
    """Digital Keyholder Work in Progress page"""
    return render_template('keyholder/digital_keyholder.html')

@keyholder_bp.route('/register', methods=['GET', 'POST'])
def register():
    """Register keyholder email"""
    if request.method == 'POST':
        email = request.form.get('email')
        
        if not email:
            flash('Email address is required', 'error')
            return redirect(url_for('keyholder.register'))
        
        try:
            # Set keyholder email in configuration
            config.set("keyholder.default_keyholder_email", email, "keyholder")
            
            # If this is the first setup, mark it as complete
            if not config.get('system.setup_complete'):
                config.set('system.setup_complete', True, 'admin')
                flash('Initial setup complete! Welcome.', 'success')

            # Send confirmation email
            email_service.send_keyholder_registration_confirmation(email)
            
            flash(f'Keyholder email {email} registered successfully!', 'success')

            # Redirect to the correct dashboard based on the role selected during setup
            if session.get('user_role') == 'keyholder':
                return redirect(url_for('keyholder.dashboard'))
            else:
                return redirect(url_for('main.dashboard'))
        
        except Exception as e:
            flash(f'Error registering keyholder: {str(e)}', 'error')
            return redirect(url_for('keyholder.register'))
    
    # Pass the user role to the template to customize the text if needed
    user_role = session.get('user_role', 'keyholder')
    return render_template('keyholder/register.html', user_role=user_role)

@keyholder_bp.route('/requests')
def requests():
    """View all key requests"""
    # Get all requests
    all_requests = key_storage.get_all_requests()
    
    # Get statistics
    stats = key_storage.get_statistics()
    
    return render_template('keyholder/requests.html',
                         requests=all_requests,
                         stats=stats)

@keyholder_bp.route('/approve/<request_id>', methods=['GET', 'POST'])
def approve_request(request_id):
    """Approve a key request"""
    request_data = key_storage.get_request(request_id)
    
    if not request_data:
        flash('Request not found', 'error')
        return redirect(url_for('keyholder.requests'))
    
    if request.method == 'POST':
        duration = request.form.get('duration')
        duration_unit = request.form.get('duration_unit', 'hours')
        
        try:
            # Approve the request
            key_storage.approve_request(request_id, duration, duration_unit)
            
            # Send approval email
            email_service.send_key_approval_notification(request_data['email'], duration, duration_unit)
            
            flash('Request approved successfully!', 'success')
            return redirect(url_for('keyholder.requests'))
        
        except Exception as e:
            flash(f'Error approving request: {str(e)}', 'error')
    
    return render_template('keyholder/approve.html', request_data=request_data)

@keyholder_bp.route('/deny/<request_id>', methods=['POST'])
def deny_request(request_id):
    """Deny a key request"""
    request_data = key_storage.get_request(request_id)
    
    if not request_data:
        flash('Request not found', 'error')
        return redirect(url_for('keyholder.requests'))
    
    try:
        # Deny the request
        key_storage.deny_request(request_id)
        
        # Send denial email
        email_service.send_key_denial_notification(request_data['email'])
        
        flash('Request denied successfully!', 'success')
    
    except Exception as e:
        flash(f'Error denying request: {str(e)}', 'error')
    
    return redirect(url_for('keyholder.requests'))

@keyholder_bp.route('/extend/<request_id>', methods=['POST'])
def extend_request(request_id):
    """Extend a key request duration"""
    request_data = key_storage.get_request(request_id)
    
    if not request_data:
        flash('Request not found', 'error')
        return redirect(url_for('keyholder.requests'))
    
    duration = request.form.get('duration')
    duration_unit = request.form.get('duration_unit', 'hours')
    
    try:
        # Extend the request
        key_storage.extend_request(request_id, duration, duration_unit)
        
        # Send extension notification
        email_service.send_key_extension_notification(request_data['email'], duration, duration_unit)
        
        flash('Request extended successfully!', 'success')
    
    except Exception as e:
        flash(f'Error extending request: {str(e)}', 'error')
    
    return redirect(url_for('keyholder.requests'))

@keyholder_bp.route('/reduce/<request_id>', methods=['POST'])
def reduce_request(request_id):
    """Reduce a key request duration"""
    request_data = key_storage.get_request(request_id)
    
    if not request_data:
        flash('Request not found', 'error')
        return redirect(url_for('keyholder.requests'))
    
    duration = request.form.get('duration')
    duration_unit = request.form.get('duration_unit', 'hours')
    
    try:
        # Reduce the request
        key_storage.reduce_request(request_id, duration, duration_unit)
        
        # Send reduction notification
        email_service.send_key_reduction_notification(request_data['email'], duration, duration_unit)
        
        flash('Request reduced successfully!', 'success')
    
    except Exception as e:
        flash(f'Error reducing request: {str(e)}', 'error')
    
    return redirect(url_for('keyholder.requests'))

@keyholder_bp.route('/emergency/<request_id>', methods=['POST'])
def emergency_release(request_id):
    """Emergency release for a key request"""
    request_data = key_storage.get_request(request_id)
    
    if not request_data:
        flash('Request not found', 'error')
        return redirect(url_for('keyholder.requests'))
    
    try:
        # Emergency release
        key_storage.emergency_release(request_id)
        
        # Send emergency notification
        email_service.send_emergency_release_notification(request_data['email'])
        
        flash('Emergency release activated!', 'success')
    
    except Exception as e:
        flash(f'Error with emergency release: {str(e)}', 'error')
    
    return redirect(url_for('keyholder.requests'))

@keyholder_bp.route('/access/<request_id>')
def access_key(request_id):
    """Access key code for approved request"""
    request_data = key_storage.get_request(request_id)
    
    if not request_data:
        flash('Request not found', 'error')
        return redirect(url_for('keyholder.requests'))
    
    if request_data['status'] != 'approved':
        flash('Request is not approved', 'error')
        return redirect(url_for('keyholder.requests'))
    
    # Get the key code
    key_code = key_storage.get_key_code(request_id)
    
    return render_template('keyholder/access.html',
                         request_data=request_data,
                         key_code=key_code)

@keyholder_bp.route('/config')
def config_dashboard():
    """Configuration dashboard for keyholder"""
    # Get all settings accessible to keyholder
    settings = config_service.get_all_settings("keyholder")
    
    # Get configuration info
    config_info = config_service.get_config_info("keyholder")
    permission_info = config_service.get_permission_info()
    
    # Get available templates
    templates = config_service.get_config_templates("keyholder")
    
    return render_template('keyholder/config_dashboard.html',
                         settings=settings,
                         config_info=config_info,
                         permission_info=permission_info,
                         templates=templates)

@keyholder_bp.route('/config', methods=['POST'])
def update_config():
    """Update configuration settings"""
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
                elif value.replace('.', '').isdigit():
                    updates[section][key] = float(value)
        
        # Update settings with keyholder permissions
        errors = config_service.update_settings(updates, "keyholder")
        
        if errors:
            flash(f"Settings updated with errors: {', '.join(errors)}", "error")
        else:
            flash("Configuration updated successfully!", "success")
        
        return redirect(url_for('keyholder.config_dashboard'))
    
    except Exception as e:
        flash(f"Error updating configuration: {str(e)}", "error")
        return redirect(url_for('keyholder.config_dashboard'))

@keyholder_bp.route('/config/export')
def export_config():
    """Export configuration as text file"""
    try:
        config_text = config_service.export_config("keyholder")
        
        from flask import Response
        response = Response(config_text, mimetype='text/plain')
        response.headers['Content-Disposition'] = f'attachment; filename=chastipi_config_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
        return response
    
    except Exception as e:
        flash(f"Error exporting configuration: {str(e)}", "error")
        return redirect(url_for('keyholder.config_dashboard'))

@keyholder_bp.route('/config/import', methods=['POST'])
def import_config():
    """Import configuration from text file"""
    try:
        if 'config_file' not in request.files:
            flash('No file uploaded', 'error')
            return redirect(url_for('keyholder.config_dashboard'))
        
        file = request.files['config_file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('keyholder.config_dashboard'))
        
        if file:
            config_text = file.read().decode('utf-8')
            errors = config_service.import_config(config_text, "keyholder")
            
            if errors:
                flash(f"Configuration imported with errors: {', '.join(errors)}", "error")
            else:
                flash("Configuration imported successfully!", "success")
    
    except Exception as e:
        flash(f"Error importing configuration: {str(e)}", "error")
    
    return redirect(url_for('keyholder.config_dashboard'))

@keyholder_bp.route('/config/backup', methods=['POST'])
def backup_config():
    """Create configuration backup"""
    try:
        backup_file = config_service.backup_config()
        flash(f"Configuration backed up to {backup_file}", "success")
    
    except Exception as e:
        flash(f"Error creating backup: {str(e)}", "error")
    
    return redirect(url_for('keyholder.config_dashboard'))

@keyholder_bp.route('/config/restore', methods=['POST'])
def restore_config():
    """Restore configuration from backup"""
    try:
        backup_file = request.form.get('backup_file')
        if not backup_file:
            flash('No backup file specified', 'error')
            return redirect(url_for('keyholder.config_dashboard'))
        
        success = config_service.restore_config(backup_file)
        
        if success:
            flash("Configuration restored successfully!", "success")
        else:
            flash("Failed to restore configuration", "error")
    
    except Exception as e:
        flash(f"Error restoring configuration: {str(e)}", "error")
    
    return redirect(url_for('keyholder.config_dashboard'))

@keyholder_bp.route('/email-instructions')
def email_instructions():
    """Show email management instructions"""
    return render_template('keyholder/email_instructions.html')

@keyholder_bp.route('/configure-email')
def configure_email():
    """Configure email settings"""
    # Get current email settings
    email_settings = config_service.get_section("email", "keyholder")
    
    return render_template('keyholder/configure_email.html',
                         email_settings=email_settings)

@keyholder_bp.route('/configure-email', methods=['POST'])
def update_email_config():
    """Update email configuration"""
    try:
        # Get form data
        updates = {}
        for key, value in request.form.items():
            if key.startswith('email.'):
                setting = key.replace('email.', '')
                if 'email' not in updates:
                    updates['email'] = {}
                updates['email'][setting] = value
        
        # Convert boolean values
        if 'email' in updates:
            for key, value in updates['email'].items():
                if value.lower() in ('true', 'false'):
                    updates['email'][key] = value.lower() == 'true'
                elif value.isdigit():
                    updates['email'][key] = int(value)
        
        # Update settings
        errors = config_service.update_settings(updates, "keyholder")
        
        if errors:
            flash(f"Email settings updated with errors: {', '.join(errors)}", "error")
        else:
            flash("Email configuration updated successfully!", "success")
        
        return redirect(url_for('keyholder.configure_email'))
    
    except Exception as e:
        flash(f"Error updating email configuration: {str(e)}", "error")
        return redirect(url_for('keyholder.configure_email'))

# API endpoints for AJAX requests
@keyholder_bp.route('/api/requests')
def api_requests():
    """Get all requests as JSON"""
    try:
        requests = key_storage.get_all_requests()
        return jsonify({
            "success": True,
            "requests": requests
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@keyholder_bp.route('/api/requests/<request_id>')
def api_request(request_id):
    """Get specific request as JSON"""
    try:
        request_data = key_storage.get_request(request_id)
        if request_data:
            return jsonify({
                "success": True,
                "request": request_data
            })
        else:
            return jsonify({
                "success": False,
                "error": "Request not found"
            }), 404
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@keyholder_bp.route('/api/requests/<request_id>/approve', methods=['POST'])
def api_approve_request(request_id):
    """Approve request via API"""
    try:
        data = request.get_json()
        duration = data.get('duration')
        duration_unit = data.get('duration_unit', 'hours')
        
        key_storage.approve_request(request_id, duration, duration_unit)
        
        return jsonify({
            "success": True,
            "message": "Request approved successfully"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@keyholder_bp.route('/api/requests/<request_id>/deny', methods=['POST'])
def api_deny_request(request_id):
    """Deny request via API"""
    try:
        key_storage.deny_request(request_id)
        
        return jsonify({
            "success": True,
            "message": "Request denied successfully"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@keyholder_bp.route('/api/requests/<request_id>/extend', methods=['POST'])
def api_extend_request(request_id):
    """Extend request via API"""
    try:
        data = request.get_json()
        duration = data.get('duration')
        duration_unit = data.get('duration_unit', 'hours')
        
        key_storage.extend_request(request_id, duration, duration_unit)
        
        return jsonify({
            "success": True,
            "message": "Request extended successfully"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@keyholder_bp.route('/api/requests/<request_id>/reduce', methods=['POST'])
def api_reduce_request(request_id):
    """Reduce request via API"""
    try:
        data = request.get_json()
        duration = data.get('duration')
        duration_unit = data.get('duration_unit', 'hours')
        
        key_storage.reduce_request(request_id, duration, duration_unit)
        
        return jsonify({
            "success": True,
            "message": "Request reduced successfully"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@keyholder_bp.route('/api/requests/<request_id>/emergency', methods=['POST'])
def api_emergency_release(request_id):
    """Emergency release via API"""
    try:
        key_storage.emergency_release(request_id)
        
        return jsonify({
            "success": True,
            "message": "Emergency release activated"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@keyholder_bp.route('/api/config/export')
def api_export_config():
    """Export configuration via API"""
    try:
        config_text = config_service.export_config("keyholder")
        return jsonify({
            "success": True,
            "config": config_text
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@keyholder_bp.route('/api/config/import', methods=['POST'])
def api_import_config():
    """Import configuration via API"""
    try:
        data = request.get_json()
        config_text = data.get('config', '')
        
        if not config_text:
            return jsonify({
                "success": False,
                "error": "No configuration provided"
            }), 400
        
        errors = config_service.import_config(config_text, "keyholder")
        
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

@keyholder_bp.route('/api/config/info')
def api_config_info():
    """Get configuration information via API"""
    try:
        config_info = config_service.get_config_info("keyholder")
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

@keyholder_bp.route('/api/plugins', methods=['GET'])
def get_plugins():
    """Return list of plugins and their enabled/disabled state."""
    plugins = []
    for plugin_file in PLUGINS_PATH.glob("*.py"):
        if plugin_file.name.startswith("__"): continue
        plugins.append(plugin_file.stem)
    enabled_plugins = set(config.get('plugins.enabled_plugins', []))
    plugin_states = {p: (p in enabled_plugins) for p in plugins}
    return jsonify(plugin_states)

@keyholder_bp.route('/api/plugins/toggle', methods=['POST'])
def toggle_plugin():
    """Enable or disable a plugin."""
    data = request.get_json()
    plugin = data.get('plugin')
    enable = data.get('enable')
    enabled_plugins = set(config.get('plugins.enabled_plugins', []))
    if enable:
        enabled_plugins.add(plugin)
    else:
        enabled_plugins.discard(plugin)
    config.set('plugins.enabled_plugins', list(enabled_plugins))
    return jsonify({"success": True, "plugin": plugin, "enabled": enable})

@keyholder_bp.route('/api/wearer-settings', methods=['GET'])
def api_get_wearer_settings():
    return jsonify(load_wearer_settings())

@keyholder_bp.route('/api/wearer-settings', methods=['POST'])
def api_set_wearer_settings():
    data = request.get_json()
    wearer = data.get('wearer')
    required_cage_checks = data.get('required_cage_checks')
    cage_check_time = data.get('cage_check_time')
    cage_check_email_notification = data.get('cage_check_email_notification')
    settings = load_wearer_settings()
    if wearer not in settings:
        settings[wearer] = {}
    if required_cage_checks is not None:
        settings[wearer]['required_cage_checks'] = required_cage_checks
    if cage_check_time is not None:
        settings[wearer]['cage_check_time'] = cage_check_time
    if cage_check_email_notification is not None:
        settings[wearer]['cage_check_email_notification'] = cage_check_email_notification
    save_wearer_settings(settings)
    return jsonify({"success": True, "wearer": wearer, "required_cage_checks": required_cage_checks, "cage_check_time": cage_check_time, "cage_check_email_notification": cage_check_email_notification}) 