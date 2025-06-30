"""
Webhook API for ChastiPi
Handles email webhooks and external integrations
"""
from flask import Blueprint, request, jsonify
import logging
from datetime import datetime
import json
import base64

from ..services.email_reply_service import EmailReplyService

# Create blueprint
webhook_bp = Blueprint('webhook', __name__, url_prefix='/webhook')

# Initialize service
email_reply_service = EmailReplyService()

logger = logging.getLogger(__name__)

@webhook_bp.route('/email', methods=['POST'])
def email_webhook():
    """Handle incoming email webhooks"""
    try:
        # Get webhook data
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        # Extract email information
        from_email = data.get('from', {}).get('email')
        subject = data.get('subject', '')
        body = data.get('text', '')
        html_body = data.get('html', '')
        
        if not from_email:
            return jsonify({'error': 'No sender email provided'}), 400
        
        # Extract attachments if present
        attachments = []
        if 'attachments' in data:
            for attachment in data['attachments']:
                attachment_info = {
                    'filename': attachment.get('filename', ''),
                    'content_type': attachment.get('content_type', ''),
                    'content': attachment.get('content', '')
                }
                
                # Decode base64 content if present
                if attachment_info['content'] and attachment_info['content'].startswith('data:'):
                    # Handle data URL format
                    try:
                        content_parts = attachment_info['content'].split(',', 1)
                        if len(content_parts) == 2:
                            attachment_info['content'] = base64.b64decode(content_parts[1]).decode('utf-8')
                    except Exception as e:
                        logger.error(f"Error decoding attachment content: {str(e)}")
                        attachment_info['content'] = ''
                
                attachments.append(attachment_info)
        
        # Process the email reply
        result = email_reply_service.process_email_reply(
            from_email=from_email,
            subject=subject,
            body=body,
            attachments=attachments
        )
        
        # Log the result
        logger.info(f"Email webhook processed: {result}")
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error processing email webhook: {str(e)}")
        return jsonify({'error': f'Error processing webhook: {str(e)}'}), 500

@webhook_bp.route('/test', methods=['GET'])
def test_webhook():
    """Test webhook endpoint"""
    return jsonify({
        'status': 'success',
        'message': 'Webhook endpoint is working',
        'timestamp': datetime.now().isoformat()
    })

@webhook_bp.route('/email/test', methods=['POST'])
def test_email_webhook():
    """Test email webhook with sample data"""
    try:
        # Sample test data
        test_data = {
            'from': {
                'email': 'test@example.com',
                'name': 'Test User'
            },
            'subject': 'Test Email',
            'text': 'This is a test email with settings command',
            'html': '<p>This is a test email with settings command</p>'
        }
        
        # Process test email
        result = email_reply_service.process_email_reply(
            from_email=test_data['from']['email'],
            subject=test_data['subject'],
            body=test_data['text']
        )
        
        return jsonify({
            'status': 'success',
            'test_data': test_data,
            'result': result
        })
        
    except Exception as e:
        logger.error(f"Error in test webhook: {str(e)}")
        return jsonify({'error': f'Test failed: {str(e)}'}), 500

@webhook_bp.route('/email/settings', methods=['POST'])
def test_settings_webhook():
    """Test settings command webhook"""
    try:
        # Test settings request
        test_data = {
            'from': {
                'email': 'keyholder@example.com',
                'name': 'Test Keyholder'
            },
            'subject': 'Settings Request',
            'text': 'Please send me the settings configuration file',
            'html': '<p>Please send me the settings configuration file</p>'
        }
        
        # Process settings request
        result = email_reply_service.process_email_reply(
            from_email=test_data['from']['email'],
            subject=test_data['subject'],
            body=test_data['text']
        )
        
        return jsonify({
            'status': 'success',
            'test_data': test_data,
            'result': result
        })
        
    except Exception as e:
        logger.error(f"Error in settings test webhook: {str(e)}")
        return jsonify({'error': f'Settings test failed: {str(e)}'}), 500

@webhook_bp.route('/email/config-import', methods=['POST'])
def test_config_import_webhook():
    """Test configuration import webhook"""
    try:
        # Sample configuration file content
        config_content = """# ChastiPi Configuration File
# Generated: 2023-12-01 14:30:22
# Keyholder: test@example.com

# Cage Check Settings
cage_check_enabled=true
reminder_delay=1
final_warning=6
code_expiry=24

# Notification Settings
email_enabled=true
sms_enabled=false
notification_frequency=standard

# Punishment Settings
auto_punishment=false
punishment_duration=24
require_photo=true

# Keyholder Settings
auto_approve_emergency=false
require_reason=true
max_requests=3

# Security Settings
require_2fa=false
session_timeout=12

# Appearance Settings
theme=default
language=en
timezone=UTC

# Automation Settings
auto_lock=true

# Reporting Settings
daily_reports=false
weekly_reports=true
"""
        
        # Test configuration import
        test_data = {
            'from': {
                'email': 'keyholder@example.com',
                'name': 'Test Keyholder'
            },
            'subject': 'Configuration Import',
            'text': 'Here is my updated configuration file',
            'html': '<p>Here is my updated configuration file</p>',
            'attachments': [
                {
                    'filename': 'config.txt',
                    'content_type': 'text/plain',
                    'content': config_content
                }
            ]
        }
        
        # Process configuration import
        result = email_reply_service.process_email_reply(
            from_email=test_data['from']['email'],
            subject=test_data['subject'],
            body=test_data['text'],
            attachments=test_data['attachments']
        )
        
        return jsonify({
            'status': 'success',
            'test_data': test_data,
            'result': result
        })
        
    except Exception as e:
        logger.error(f"Error in config import test webhook: {str(e)}")
        return jsonify({'error': f'Config import test failed: {str(e)}'}), 500

@webhook_bp.route('/status', methods=['GET'])
def webhook_status():
    """Get webhook status and configuration"""
    try:
        # Check email service configuration
        email_configured = email_reply_service.email_service.is_configured()
        
        status = {
            'status': 'operational',
            'timestamp': datetime.now().isoformat(),
            'services': {
                'email_service': email_configured,
                'key_storage': True,
                'config_service': True
            },
            'endpoints': {
                'email_webhook': '/webhook/email',
                'test_webhook': '/webhook/test',
                'status': '/webhook/status'
            },
            'supported_commands': [
                'settings',
                'status',
                'help',
                'approve',
                'deny',
                'extend',
                'reduce',
                'emergency'
            ],
            'file_types': [
                'config.txt',
                'config.json'
            ]
        }
        
        return jsonify(status)
        
    except Exception as e:
        logger.error(f"Error getting webhook status: {str(e)}")
        return jsonify({
            'status': 'error',
            'error': f'Error getting status: {str(e)}'
        }), 500 