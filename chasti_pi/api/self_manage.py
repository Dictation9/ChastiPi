"""
Self-Management API routes for ChastiPi
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash
from chasti_pi.services.self_manage_service import SelfManageService

self_manage_bp = Blueprint('self_manage', __name__, url_prefix='/self-manage')
self_manage_service = SelfManageService()

@self_manage_bp.route('/dashboard')
def dashboard():
    """Dashboard for self-managed mode"""
    lock_status = self_manage_service.get_lock_status()
    return render_template('self_manage/dashboard.html', lock_status=lock_status)

@self_manage_bp.route('/start-lock', methods=['GET', 'POST'])
def start_lock():
    """Page to start a new self-managed lock"""
    if request.method == 'POST':
        try:
            duration = int(request.form.get('duration'))
            duration_unit = request.form.get('duration_unit')
            
            if duration <= 0:
                flash("Duration must be a positive number.", "error")
                return redirect(url_for('self_manage.start_lock'))

            result = self_manage_service.start_lock(duration, duration_unit)
            
            if 'error' in result:
                flash(f"Error starting lock: {result['error']}", "error")
            else:
                flash(f"Lock started successfully! Your key will be available in {result['time_remaining']}.", "success")
                return redirect(url_for('self_manage.dashboard'))
        
        except (ValueError, TypeError):
            flash("Invalid duration provided.", "error")
        except Exception as e:
            flash(f"An unexpected error occurred: {str(e)}", "error")

    return render_template('self_manage/start_lock.html')

@self_manage_bp.route('/emergency-release', methods=['POST'])
def emergency_release():
    """Initiate an emergency release"""
    result = self_manage_service.start_emergency_release()
    
    if 'error' in result:
        flash(f"Error: {result['error']}", "error")
    else:
        flash(result['message'], "success")
        
    return redirect(url_for('self_manage.dashboard')) 