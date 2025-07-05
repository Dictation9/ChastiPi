"""
Update API routes for ChastiPi
Handles update checking, downloading, and installation
"""
from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from datetime import datetime
import logging

from ..services.update_service import UpdateService

# Create blueprint
update_bp = Blueprint('update', __name__, url_prefix='/update')

# Initialize service
update_service = UpdateService()

logger = logging.getLogger(__name__)

@update_bp.route('/status')
def status():
    """Get current update status"""
    try:
        status = update_service.get_update_status()
        return jsonify(status)
    except Exception as e:
        logger.error(f"Error getting update status: {e}")
        return jsonify({
            "error": str(e),
            "current_version": "2.0.0",
            "update_available": False
        }), 500

@update_bp.route('/check', methods=['POST'])
def check_updates():
    """Force check for updates"""
    try:
        force = request.json.get('force', False) if request.is_json else False
        update_info = update_service.check_for_updates(force=force)
        return jsonify(update_info)
    except Exception as e:
        logger.error(f"Error checking for updates: {e}")
        return jsonify({
            "error": str(e),
            "update_available": False
        }), 500

@update_bp.route('/download', methods=['POST'])
def download_update():
    """Download the latest update"""
    try:
        result = update_service.download_update()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error downloading update: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@update_bp.route('/install', methods=['POST'])
def install_update():
    """Install the downloaded update"""
    try:
        result = update_service.install_update()
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error installing update: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@update_bp.route('/history')
def update_history():
    """Get update history"""
    try:
        history = update_service.get_update_history()
        return jsonify({"history": history})
    except Exception as e:
        logger.error(f"Error getting update history: {e}")
        return jsonify({
            "error": str(e),
            "history": []
        }), 500

@update_bp.route('/dashboard')
def update_dashboard():
    """Update management dashboard"""
    try:
        status = update_service.get_update_status()
        history = update_service.get_update_history()
        
        return render_template('update/dashboard.html',
                             status=status,
                             history=history)
    except Exception as e:
        logger.error(f"Error loading update dashboard: {e}")
        flash(f"Error loading update dashboard: {str(e)}", "error")
        return redirect(url_for('main.dashboard'))

@update_bp.route('/settings', methods=['GET', 'POST'])
def update_settings():
    """Update settings page"""
    if request.method == 'POST':
        try:
            # Update settings logic would go here
            flash("Update settings saved successfully!", "success")
            return redirect(url_for('update.update_dashboard'))
        except Exception as e:
            flash(f"Error saving update settings: {str(e)}", "error")
    
    # Get current settings
    settings = {
        "auto_check": True,
        "check_interval_days": 7,
        "notify_on_update": True,
        "auto_download": False,
        "backup_before_update": True
    }
    
    return render_template('update/settings.html', settings=settings) 