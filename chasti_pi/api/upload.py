"""
Upload API routes for ChastiPi
"""
from flask import Blueprint, render_template, request, jsonify
from chasti_pi.services.upload_service import UploadService

bp = Blueprint('upload', __name__)
upload_service = UploadService()

@bp.route('/')
def upload_form():
    """Upload form interface"""
    return render_template('upload/index.html')

@bp.route('/photo', methods=['POST'])
def upload_photo():
    """Upload and process photo with QR code scanning and OCR verification"""
    try:
        if 'photo' not in request.files:
            return jsonify({
                "success": False,
                "error": "No photo provided"
            }), 400
        
        file = request.files['photo']
        if file.filename == '':
            return jsonify({
                "success": False,
                "error": "No file selected"
            }), 400
        
        result = upload_service.process_photo(file)
        
        if "error" in result:
            return jsonify({
                "success": False,
                "error": result["error"]
            }), 400
        
        # Format response based on QR detection and OCR results
        if result.get("qr_detected"):
            if result.get("punishment_found"):
                # Check OCR verification results
                verification_results = result.get("verification_results")
                ocr_results = result.get("ocr_results")
                
                if verification_results and verification_results.get("verified"):
                    return jsonify({
                        "success": True,
                        "message": "✅ QR code detected and handwritten codes verified successfully!",
                        "data": {
                            "qr_detected": True,
                            "punishment_id": result["punishment_id"],
                            "punishment_data": result["punishment_data"],
                            "ocr_performed": True,
                            "handwritten_verified": True,
                            "accuracy": verification_results.get("accuracy", 0),
                            "matched_codes": verification_results.get("matched_codes", []),
                            "total_matched": verification_results.get("total_matched", 0),
                            "total_expected": verification_results.get("total_expected", 0),
                            "file_path": result["file_path"],
                            "filename": result["filename"]
                        }
                    })
                elif ocr_results:
                    return jsonify({
                        "success": False,
                        "error": f"Handwritten codes verification failed. Accuracy: {verification_results.get('accuracy', 0):.1f}%",
                        "data": {
                            "qr_detected": True,
                            "punishment_id": result["punishment_id"],
                            "punishment_data": result["punishment_data"],
                            "ocr_performed": True,
                            "handwritten_verified": False,
                            "accuracy": verification_results.get("accuracy", 0),
                            "detected_numbers": ocr_results.get("detected_numbers", []),
                            "expected_codes": result["punishment_data"].get("codes", []),
                            "file_path": result["file_path"],
                            "filename": result["filename"]
                        }
                    }), 400
                else:
                    return jsonify({
                        "success": False,
                        "error": "QR code detected but no handwritten codes could be read",
                        "data": {
                            "qr_detected": True,
                            "punishment_id": result["punishment_id"],
                            "punishment_data": result["punishment_data"],
                            "ocr_performed": False,
                            "file_path": result["file_path"],
                            "filename": result["filename"]
                        }
                    }), 400
            else:
                return jsonify({
                    "success": False,
                    "error": "QR code detected but no matching punishment found",
                    "data": {
                        "qr_detected": True,
                        "qr_data": result["qr_data"],
                        "file_path": result["file_path"]
                    }
                }), 404
        else:
            return jsonify({
                "success": True,
                "message": "Photo uploaded successfully (no QR code detected)",
                "data": {
                    "qr_detected": False,
                    "file_path": result["file_path"],
                    "filename": result["filename"]
                }
            })
            
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@bp.route('/verify/<punishment_id>', methods=['POST'])
def verify_upload(punishment_id):
    """Verify uploaded photo against specific punishment with OCR"""
    try:
        if 'photo' not in request.files:
            return jsonify({
                "success": False,
                "error": "No photo provided"
            }), 400
        
        file = request.files['photo']
        result = upload_service.verify_punishment_photo(file, punishment_id)
        
        if "error" in result:
            return jsonify({
                "success": False,
                "error": result["error"]
            }), 400
        
        if result.get("verification_success") and result.get("handwritten_verified"):
            return jsonify({
                "success": True,
                "message": "✅ Punishment verified successfully with handwritten codes!",
                "data": {
                    "punishment_id": punishment_id,
                    "verified": True,
                    "handwritten_verified": True,
                    "verification_message": result.get("verification_message"),
                    "punishment_verified": result.get("punishment_verified")
                }
            })
        elif result.get("verification_success"):
            return jsonify({
                "success": False,
                "error": "QR code matches but handwritten verification failed",
                "data": {
                    "punishment_id": punishment_id,
                    "qr_verified": True,
                    "handwritten_verified": False,
                    "verification_message": result.get("verification_message")
                }
            }), 400
        else:
            return jsonify({
                "success": False,
                "error": "QR code in photo doesn't match the specified punishment",
                "data": {
                    "detected_qr": result.get("qr_data"),
                    "target_punishment": punishment_id
                }
            }), 400
            
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@bp.route('/history')
def upload_history():
    """Get upload history with QR scanning and OCR results"""
    try:
        history = upload_service.get_upload_history()
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

@bp.route('/punishment/<punishment_id>')
def get_punishment_uploads(punishment_id):
    """Get all uploads related to a specific punishment"""
    try:
        uploads = upload_service.get_punishment_uploads(punishment_id)
        return jsonify({
            "success": True,
            "data": uploads,
            "count": len(uploads)
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500 