from flask import Blueprint, jsonify, request
from datetime import datetime
import logging
from ..services.time_verification_service import TimeVerificationService

logger = logging.getLogger(__name__)

# Create blueprint
time_verification_bp = Blueprint('time_verification', __name__, url_prefix='/api/time')

# Initialize service
time_service = TimeVerificationService()

@time_verification_bp.route('/status', methods=['GET'])
def get_time_status():
    """Get comprehensive time status including NTP verification"""
    try:
        status = time_service.get_time_status()
        return jsonify({
            'success': True,
            'data': status,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error getting time status: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@time_verification_bp.route('/verify', methods=['GET'])
def verify_time():
    """Verify system time against NTP servers"""
    try:
        verification = time_service.verify_system_time()
        return jsonify({
            'success': True,
            'data': verification,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        logger.error(f"Error verifying time: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@time_verification_bp.route('/sync', methods=['POST'])
def sync_time():
    """Sync system time with NTP servers (requires sudo privileges)"""
    try:
        # Check if user wants to force sync
        force = request.json.get('force', False) if request.is_json else False
        
        if not force:
            # First verify current time
            verification = time_service.verify_system_time()
            if verification.get('valid', False):
                return jsonify({
                    'success': True,
                    'message': 'System time is already accurate',
                    'data': verification
                })
        
        # Attempt to sync
        result = time_service.sync_system_time()
        
        if result.get('success', False):
            return jsonify({
                'success': True,
                'message': 'System time synchronized successfully',
                'data': result
            })
        else:
            return jsonify({
                'success': False,
                'error': result.get('error', 'Unknown error'),
                'recommendation': result.get('recommendation', '')
            }), 400
            
    except Exception as e:
        logger.error(f"Error syncing time: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@time_verification_bp.route('/validate', methods=['POST'])
def validate_timestamp():
    """Validate a timestamp against current verified time"""
    try:
        if not request.is_json:
            return jsonify({
                'success': False,
                'error': 'JSON data required'
            }), 400
        
        data = request.json
        timestamp_str = data.get('timestamp')
        max_age_hours = data.get('max_age_hours', 24)
        
        if not timestamp_str:
            return jsonify({
                'success': False,
                'error': 'timestamp field required'
            }), 400
        
        try:
            timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except ValueError:
            return jsonify({
                'success': False,
                'error': 'Invalid timestamp format. Use ISO format (YYYY-MM-DDTHH:MM:SS)'
            }), 400
        
        result = time_service.validate_timestamp(timestamp, max_age_hours)
        
        return jsonify({
            'success': True,
            'data': result,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error validating timestamp: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@time_verification_bp.route('/check', methods=['GET'])
def quick_check():
    """Quick time check for security validation"""
    try:
        verification = time_service.verify_system_time()
        
        # Return simplified response for security checks
        return jsonify({
            'success': True,
            'time_valid': verification.get('valid', False),
            'drift_seconds': verification.get('drift_seconds'),
            'system_time': verification.get('system_time'),
            'ntp_time': verification.get('ntp_time'),
            'warning': None if verification.get('valid', False) else verification.get('recommendation')
        })
        
    except Exception as e:
        logger.error(f"Error in quick time check: {str(e)}")
        return jsonify({
            'success': False,
            'time_valid': False,
            'error': str(e)
        }), 500 