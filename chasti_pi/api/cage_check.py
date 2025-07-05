from flask import Blueprint, jsonify, request, render_template
from datetime import datetime
import logging
import os
from werkzeug.utils import secure_filename
from ..services.cage_check_service import CageCheckService

logger = logging.getLogger(__name__)

# Create blueprint
cage_check_bp = Blueprint('cage_check', __name__, url_prefix='/cage-check')

# Initialize service
cage_check_service = CageCheckService()

# Configure upload settings
UPLOAD_FOLDER = 'uploads/cage_checks'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'mp4', 'mov', 'avi', 'wmv', 'flv', 'webm'}

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@cage_check_bp.route('/dashboard')
def dashboard():
    """Cage check dashboard for keyholders"""
    try:
        cage_service = CageCheckService()
        
        # Get all check requests
        all_checks = cage_service.get_all_check_requests()
        
        # Get statistics
        stats = {
            'total': len(all_checks),
            'pending': len([c for c in all_checks if c['status'] == 'pending']),
            'completed': len([c for c in all_checks if c['status'] == 'completed']),
            'failed': len([c for c in all_checks if c['status'] == 'failed']),
            'expired': len([c for c in all_checks if c['status'] == 'expired'])
        }
        
        return render_template('cage_check/dashboard.html', 
                             checks=all_checks, 
                             stats=stats)
    except Exception as e:
        logger.error(f"Error in cage check dashboard: {str(e)}")
        return jsonify({'error': 'Failed to load dashboard'}), 500

@cage_check_bp.route('/request', methods=['GET', 'POST'])
def create_request():
    """Create a new cage check request"""
    if request.method == 'GET':
        return render_template('cage_check/request.html')
    
    try:
        data = request.get_json() if request.is_json else request.form
        
        keyholder_email = data.get('keyholder_email')
        device_name = data.get('device_name')
        check_type = data.get('check_type', 'cage')
        reason = data.get('reason')
        wearer_email = data.get('wearer_email')  # New parameter
        
        if not keyholder_email or not device_name:
            return jsonify({'error': 'Keyholder email and device name are required'}), 400
        
        cage_service = CageCheckService()
        
        # Create the request with wearer email
        check_request = cage_service.create_cage_check_request(
            keyholder_email=keyholder_email,
            device_name=device_name,
            check_type=check_type,
            reason=reason,
            wearer_email=wearer_email  # Include wearer email
        )
        
        if check_request:
            return jsonify({
                'success': True,
                'message': 'Cage check request created successfully',
                'request': check_request
            })
        else:
            return jsonify({'error': 'Failed to create cage check request'}), 500
            
    except Exception as e:
        logger.error(f"Error creating cage check request: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@cage_check_bp.route('/upload', methods=['GET', 'POST'])
def upload_verification():
    """Upload verification photo for cage check"""
    if request.method == 'GET':
        return render_template('cage_check/upload.html')
    
    try:
        if 'photo' not in request.files:
            return jsonify({'error': 'No photo uploaded'}), 400
        
        photo = request.files['photo']
        request_id = request.form.get('request_id')
        
        if not request_id:
            return jsonify({'error': 'Request ID is required'}), 400
        
        if photo.filename == '':
            return jsonify({'error': 'No photo selected'}), 400
        
        cage_service = CageCheckService()
        
        # Process the verification
        result = cage_service.verify_cage_check(request_id, photo)
        
        if result:
            return jsonify({
                'success': True,
                'message': 'Verification processed successfully',
                'result': result
            })
        else:
            return jsonify({'error': 'Failed to process verification'}), 500
            
    except Exception as e:
        logger.error(f"Error uploading verification: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@cage_check_bp.route('/api/requests', methods=['GET'])
def get_requests():
    """Get all cage check requests"""
    try:
        cage_service = CageCheckService()
        requests = cage_service.get_all_check_requests()
        return jsonify({'requests': requests})
    except Exception as e:
        logger.error(f"Error getting cage check requests: {str(e)}")
        return jsonify({'error': 'Failed to get requests'}), 500

@cage_check_bp.route('/api/request/<request_id>', methods=['GET'])
def get_request(request_id):
    """Get a specific cage check request"""
    try:
        cage_service = CageCheckService()
        check_request = cage_service.get_check_request(request_id)
        
        if check_request:
            return jsonify({'request': check_request})
        else:
            return jsonify({'error': 'Request not found'}), 404
            
    except Exception as e:
        logger.error(f"Error getting cage check request: {str(e)}")
        return jsonify({'error': 'Failed to get request'}), 500

@cage_check_bp.route('/api/notifications', methods=['GET'])
def get_notifications():
    """Get pending notifications for wearer dashboard"""
    try:
        wearer_email = request.args.get('wearer_email')
        cage_service = CageCheckService()
        
        notifications = cage_service.get_pending_notifications(wearer_email)
        return jsonify({'notifications': notifications})
        
    except Exception as e:
        logger.error(f"Error getting notifications: {str(e)}")
        return jsonify({'error': 'Failed to get notifications'}), 500

@cage_check_bp.route('/api/check-notifications', methods=['POST'])
def check_notifications():
    """Background task to check and send notifications"""
    try:
        cage_service = CageCheckService()
        cage_service.check_and_send_notifications()
        
        return jsonify({
            'success': True,
            'message': 'Notification check completed'
        })
        
    except Exception as e:
        logger.error(f"Error checking notifications: {str(e)}")
        return jsonify({'error': 'Failed to check notifications'}), 500

@cage_check_bp.route('/api/statistics', methods=['GET'])
def get_statistics():
    """Get cage check statistics"""
    try:
        cage_service = CageCheckService()
        all_checks = cage_service.get_all_check_requests()
        
        stats = {
            'total': len(all_checks),
            'pending': len([c for c in all_checks if c['status'] == 'pending']),
            'completed': len([c for c in all_checks if c['status'] == 'completed']),
            'failed': len([c for c in all_checks if c['status'] == 'failed']),
            'expired': len([c for c in all_checks if c['status'] == 'expired']),
            'recent_24h': len([c for c in all_checks if 
                              (datetime.now() - datetime.fromisoformat(c['created_at'])).days == 0])
        }
        
        return jsonify({'statistics': stats})
        
    except Exception as e:
        logger.error(f"Error getting statistics: {str(e)}")
        return jsonify({'error': 'Failed to get statistics'}), 500

@cage_check_bp.route('/api/verify-code', methods=['POST'])
def verify_code():
    """Verify a code manually (for testing)"""
    try:
        if not request.is_json:
            return jsonify({
                'success': False,
                'error': 'JSON data required'
            }), 400
        
        data = request.json
        code = data.get('code')
        request_id = data.get('request_id')
        
        if not code or not request_id:
            return jsonify({
                'success': False,
                'error': 'code and request_id are required'
            }), 400
        
        # Get the check request
        check_request = cage_check_service.get_check_request(request_id)
        if not check_request:
            return jsonify({
                'success': False,
                'error': 'Check request not found'
            }), 404
        
        # Check if code matches
        expected_code = check_request['verification_code']
        is_valid = code.upper() == expected_code.upper()
        
        return jsonify({
            'success': True,
            'data': {
                'code_provided': code,
                'expected_code': expected_code,
                'is_valid': is_valid,
                'request_id': request_id
            }
        })
        
    except Exception as e:
        logger.error(f"Error verifying code: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500 