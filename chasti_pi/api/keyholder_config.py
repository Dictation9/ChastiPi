"""
Keyholder Configuration API for ChastiPi
Handles configuration management, import/export, and settings customization
"""
from flask import Blueprint, request, jsonify, render_template, send_file
from datetime import datetime
import json
import tempfile
import os
from pathlib import Path

from ..services.keyholder_config_service import KeyholderConfigService

# Create blueprint
keyholder_config_bp = Blueprint('keyholder_config', __name__, url_prefix='/keyholder/config')

# Initialize service
config_service = KeyholderConfigService()

@keyholder_config_bp.route('/')
def config_dashboard():
    """Keyholder configuration dashboard"""
    keyholder_email = request.args.get('keyholder_email')
    
    if not keyholder_email:
        return render_template('keyholder/config_dashboard.html', 
                             error="Keyholder email required",
                             config_info={},
                             templates=[],
                             stats={},
                             keyholder_email="")
    
    # Get current configuration
    config = config_service.get_keyholder_config(keyholder_email)
    templates = config_service.get_config_templates()
    stats = config_service.get_config_statistics()
    
    return render_template('keyholder/config_dashboard.html',
                         config=config,
                         templates=templates,
                         stats=stats,
                         keyholder_email=keyholder_email)

@keyholder_config_bp.route('/settings', methods=['GET', 'POST'])
def manage_settings():
    """Manage configuration settings"""
    keyholder_email = request.args.get('keyholder_email')
    
    if not keyholder_email:
        return jsonify({'error': 'Keyholder email required'}), 400
    
    if request.method == 'GET':
        config = config_service.get_keyholder_config(keyholder_email)
        return render_template('keyholder/config_settings.html',
                             config=config,
                             keyholder_email=keyholder_email)
    
    # Handle POST request
    try:
        data = request.get_json() if request.is_json else request.form
        
        # Extract settings from form data
        settings = {
            'cage_check': {
                'enabled': data.get('cage_check_enabled', 'true').lower() == 'true',
                'reminder_delay_hours': int(data.get('reminder_delay_hours', 1)),
                'final_warning_hours': int(data.get('final_warning_hours', 6)),
                'expiry_warning_hours': int(data.get('expiry_warning_hours', 2)),
                'code_expiry_hours': int(data.get('code_expiry_hours', 24)),
                'max_retries': int(data.get('max_retries', 3)),
                'auto_escalate': data.get('auto_escalate', 'true').lower() == 'true'
            },
            'notifications': {
                'email_enabled': data.get('email_enabled', 'true').lower() == 'true',
                'sms_enabled': data.get('sms_enabled', 'false').lower() == 'true',
                'push_enabled': data.get('push_enabled', 'false').lower() == 'true',
                'notification_frequency': data.get('notification_frequency', 'standard'),
                'custom_messages': {
                    'initial': data.get('custom_initial_message', ''),
                    'reminder': data.get('custom_reminder_message', ''),
                    'final_warning': data.get('custom_final_warning_message', ''),
                    'expiry': data.get('custom_expiry_message', '')
                }
            },
            'punishment': {
                'auto_generate': data.get('auto_generate', 'false').lower() == 'true',
                'default_duration_hours': int(data.get('default_duration_hours', 24)),
                'max_duration_hours': int(data.get('max_duration_hours', 168)),
                'require_photo_verification': data.get('require_photo_verification', 'true').lower() == 'true',
                'qr_code_required': data.get('qr_code_required', 'true').lower() == 'true',
                'ocr_verification': data.get('ocr_verification', 'true').lower() == 'true',
                'ocr_accuracy_threshold': float(data.get('ocr_accuracy_threshold', 0.8))
            },
            'keyholder': {
                'auto_approve_emergency': data.get('auto_approve_emergency', 'false').lower() == 'true',
                'emergency_timeout_hours': int(data.get('emergency_timeout_hours', 2)),
                'require_reason': data.get('require_reason', 'true').lower() == 'true',
                'max_concurrent_requests': int(data.get('max_concurrent_requests', 3)),
                'request_history_days': int(data.get('request_history_days', 30)),
                'email_notifications': data.get('email_notifications', 'true').lower() == 'true',
                'approval_timeout_hours': int(data.get('approval_timeout_hours', 24))
            },
            'security': {
                'require_2fa': data.get('require_2fa', 'false').lower() == 'true',
                'session_timeout_hours': int(data.get('session_timeout_hours', 12)),
                'max_failed_attempts': int(data.get('max_failed_attempts', 5)),
                'lockout_duration_minutes': int(data.get('lockout_duration_minutes', 30)),
                'ip_whitelist': data.get('ip_whitelist', '').split(','),
                'device_whitelist': data.get('device_whitelist', '').split(',')
            },
            'appearance': {
                'theme': data.get('theme', 'default'),
                'language': data.get('language', 'en'),
                'timezone': data.get('timezone', 'UTC'),
                'date_format': data.get('date_format', 'YYYY-MM-DD'),
                'time_format': data.get('time_format', '24h')
            },
            'automation': {
                'auto_lock_after_release': data.get('auto_lock_after_release', 'true').lower() == 'true',
                'auto_lock_delay_minutes': int(data.get('auto_lock_delay_minutes', 30)),
                'scheduled_checks': json.loads(data.get('scheduled_checks', '[]')),
                'auto_punishment_on_failure': data.get('auto_punishment_on_failure', 'false').lower() == 'true',
                'punishment_duration_hours': int(data.get('punishment_duration_hours', 48))
            },
            'reporting': {
                'daily_reports': data.get('daily_reports', 'false').lower() == 'true',
                'weekly_reports': data.get('weekly_reports', 'true').lower() == 'true',
                'monthly_reports': data.get('monthly_reports', 'true').lower() == 'true',
                'report_recipients': data.get('report_recipients', '').split(','),
                'include_statistics': data.get('include_statistics', 'true').lower() == 'true',
                'include_charts': data.get('include_charts', 'true').lower() == 'true'
            }
        }
        
        # Update configuration
        success = config_service.update_keyholder_config(keyholder_email, settings)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Configuration updated successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to update configuration'
            }), 500
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error updating configuration: {str(e)}'
        }), 500

@keyholder_config_bp.route('/export', methods=['GET', 'POST'])
def export_config():
    """Export configuration for a keyholder"""
    try:
        if request.method == 'GET':
            keyholder_email = request.args.get('keyholder_email')
            if not keyholder_email:
                return jsonify({'error': 'Keyholder email required'}), 400
            
            return render_template('keyholder/config_export.html',
                                 keyholder_email=keyholder_email)
        
        # Handle POST request
        data = request.get_json() if request.is_json else request.form
        keyholder_email = data.get('keyholder_email')
        
        if not keyholder_email:
            return jsonify({'error': 'Keyholder email required'}), 400
        
        # Export configuration
        export_data = config_service.export_config(keyholder_email)
        
        if not export_data:
            return jsonify({'error': 'No configuration found for this keyholder'}), 404
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(export_data, f, indent=2, default=str)
            temp_file = f.name
        
        # Generate filename
        filename = f"chastipi_config_{keyholder_email.replace('@', '_').replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        return send_file(
            temp_file,
            as_attachment=True,
            download_name=filename,
            mimetype='application/json'
        )
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error exporting configuration: {str(e)}'
        }), 500

@keyholder_config_bp.route('/import', methods=['GET', 'POST'])
def import_config():
    """Import configuration for a keyholder"""
    try:
        if request.method == 'GET':
            keyholder_email = request.args.get('keyholder_email')
            if not keyholder_email:
                return jsonify({'error': 'Keyholder email required'}), 400
            
            return render_template('keyholder/config_import.html',
                                 keyholder_email=keyholder_email)
        
        # Handle POST request
        keyholder_email = request.form.get('keyholder_email')
        
        if not keyholder_email:
            return jsonify({'error': 'Keyholder email required'}), 400
        
        if 'config_file' not in request.files:
            return jsonify({'error': 'No configuration file uploaded'}), 400
        
        file = request.files['config_file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not file.filename.endswith('.json'):
            return jsonify({'error': 'Only JSON files are supported'}), 400
        
        # Read and parse configuration file
        try:
            config_data = json.load(file)
        except json.JSONDecodeError:
            return jsonify({'error': 'Invalid JSON file'}), 400
        
        # Import configuration
        success = config_service.import_config(keyholder_email, config_data)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Configuration imported successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to import configuration'
            }), 500
            
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error importing configuration: {str(e)}'
        }), 500

@keyholder_config_bp.route('/templates')
def list_templates():
    """List available configuration templates"""
    try:
        templates = config_service.get_config_templates()
        return jsonify({'templates': templates})
    except Exception as e:
        return jsonify({'error': f'Error getting templates: {str(e)}'}), 500

@keyholder_config_bp.route('/templates/<template_id>/apply', methods=['POST'])
def apply_template(template_id):
    """Apply a configuration template"""
    try:
        data = request.get_json() if request.is_json else request.form
        keyholder_email = data.get('keyholder_email')
        
        if not keyholder_email:
            return jsonify({'error': 'Keyholder email required'}), 400
        
        success = config_service.apply_template(keyholder_email, template_id)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Template applied successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to apply template'
            }), 500
            
    except Exception as e:
        return jsonify({'error': f'Error applying template: {str(e)}'}), 500

@keyholder_config_bp.route('/api/settings/<keyholder_email>')
def get_settings(keyholder_email):
    """Get configuration settings for a keyholder"""
    try:
        config = config_service.get_keyholder_config(keyholder_email)
        if not config:
            return jsonify({'error': 'No configuration found'}), 404
        
        return jsonify({'config': config})
    except Exception as e:
        return jsonify({'error': f'Error getting settings: {str(e)}'}), 500

@keyholder_config_bp.route('/api/settings/<keyholder_email>', methods=['PUT'])
def update_settings(keyholder_email):
    """Update configuration settings via API"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        success = config_service.update_keyholder_config(keyholder_email, data)
        
        if success:
            return jsonify({
                'success': True,
                'message': 'Settings updated successfully'
            })
        else:
            return jsonify({
                'success': False,
                'error': 'Failed to update settings'
            }), 500
            
    except Exception as e:
        return jsonify({'error': f'Error updating settings: {str(e)}'}), 500

@keyholder_config_bp.route('/api/statistics')
def get_statistics():
    """Get configuration statistics"""
    try:
        stats = config_service.get_config_statistics()
        return jsonify({'statistics': stats})
    except Exception as e:
        return jsonify({'error': f'Error getting statistics: {str(e)}'}), 500 