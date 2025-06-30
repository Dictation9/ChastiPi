"""
Setup API routes for ChastiPi
Handles the initial user role selection and setup flow
"""
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from chasti_pi.core.config import config

setup_bp = Blueprint('setup', __name__, url_prefix='/setup')

@setup_bp.route('/welcome')
def welcome():
    """Display the role selection page for initial setup"""
    # If setup is already complete, redirect to the main dashboard
    if config.get('system.setup_complete'):
        return redirect(url_for('main.dashboard'))
    
    return render_template('setup/welcome.html')

@setup_bp.route('/select-role', methods=['POST'])
def select_role():
    """Handle the user's role selection"""
    role = request.form.get('role')
    
    # Validate the submitted role
    if role not in ['wearer', 'keyholder', 'self_managed']:
        return redirect(url_for('setup.welcome'))

    # Store the selected role in the configuration and session
    config.set('system.user_role', role, 'admin')
    session['user_role'] = role

    # Set the keyholder mode based on the selection
    if role == 'self_managed':
        config.set('keyholder.mode', 'self_managed', 'admin')
        # Mark setup as complete for self-managed mode
        config.set('system.setup_complete', True, 'admin')
        flash('Self-management mode enabled. Welcome!', 'success')
        # This will require a new blueprint, which I will create next
        return redirect(url_for('self_manage.dashboard'))
    else:
        config.set('keyholder.mode', 'keyholder_managed', 'admin')
        # For wearer/keyholder, setup completes upon keyholder registration
        if role == 'wearer':
            return redirect(url_for('main.dashboard'))
        elif role == 'keyholder':
            return redirect(url_for('keyholder.register'))
    
    return redirect(url_for('setup.welcome')) 