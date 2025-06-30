"""
Calendar API routes for ChastiPi
"""
from flask import Blueprint, render_template, jsonify
from chasti_pi.services.calendar_service import CalendarService

bp = Blueprint('calendar', __name__)
calendar_service = CalendarService()

@bp.route('/')
def calendar_view():
    """Calendar interface"""
    return render_template('calendar/index.html')

@bp.route('/events')
def get_events():
    """Get calendar events"""
    try:
        events = calendar_service.get_events()
        return jsonify(events)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@bp.route('/add_event', methods=['POST'])
def add_event():
    """Add calendar event"""
    try:
        # TODO: Implement event addition
        return jsonify({"message": "Event added successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500 