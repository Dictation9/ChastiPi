"""
Punishment API routes for ChastiPi
"""
import os
from flask import Blueprint, render_template, request, jsonify, send_file
from chasti_pi.services.punishment_service import PunishmentService

bp = Blueprint('punishment', __name__)
punishment_service = PunishmentService()

@bp.route('/')
def punishment_page():
    """Punishment generation page"""
    return render_template('punishment/generate.html')

@bp.route('/generate')
def generate_punishment():
    """Generate unique punishment sheet with QR code"""
    try:
        result = punishment_service.generate_punishment()
        return jsonify({
            "success": True,
            "message": "Unique punishment sheet generated successfully",
            "data": result
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@bp.route('/<punishment_id>')
def get_punishment(punishment_id):
    """Get specific punishment details"""
    try:
        punishment = punishment_service.get_punishment_by_id(punishment_id)
        if punishment:
            return jsonify({
                "success": True,
                "data": punishment
            })
        else:
            return jsonify({
                "success": False,
                "error": "Punishment not found"
            }), 404
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@bp.route('/verify/<punishment_id>')
def verify_punishment(punishment_id):
    """Verify punishment completion"""
    try:
        result = punishment_service.verify_punishment(punishment_id)
        if isinstance(result, tuple):
            return jsonify({
                "success": False,
                "error": result[0]["error"]
            }), result[1]
        else:
            return jsonify({
                "success": True,
                "message": result["message"]
            })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@bp.route('/history')
def punishment_history():
    """Get punishment history"""
    try:
        history = punishment_service.get_history()
        return jsonify({
            "success": True,
            "data": history,
            "count": len(history)
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@bp.route('/stats')
def punishment_stats():
    """Get punishment statistics"""
    try:
        history = punishment_service.get_history()
        total = len(history)
        completed = sum(1 for p in history if p.get("completed", False))
        pending = total - completed
        
        return jsonify({
            "success": True,
            "data": {
                "total_punishments": total,
                "completed": completed,
                "pending": pending,
                "completion_rate": (completed / total * 100) if total > 0 else 0
            }
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@bp.route('/download/<punishment_id>/<file_type>')
def download_punishment_file(punishment_id, file_type):
    """Download punishment PDF or QR code"""
    try:
        punishment = punishment_service.get_punishment_by_id(punishment_id)
        if not punishment:
            return jsonify({
                "success": False,
                "error": "Punishment not found"
            }), 404
        
        if file_type == "pdf":
            file_path = punishment.get("pdf_path")
            filename = punishment.get("pdf_filename", f"{punishment_id}.pdf")
        elif file_type == "qr":
            file_path = punishment.get("qr_path")
            filename = punishment.get("qr_filename", f"{punishment_id}_qr.png")
        else:
            return jsonify({
                "success": False,
                "error": "Invalid file type"
            }), 400
        
        if not file_path or not os.path.exists(file_path):
            return jsonify({
                "success": False,
                "error": "File not found"
            }), 404
        
        from flask import send_file
        return send_file(file_path, as_attachment=True, download_name=filename)
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500 