"""
Upload service for ChastiPi
"""
import os
from pathlib import Path
from werkzeug.utils import secure_filename
from datetime import datetime
import json
import re

class UploadService:
    """Service for handling photo uploads and OCR processing"""
    
    def __init__(self, upload_folder="uploads"):
        self.upload_folder = Path(upload_folder)
        self.upload_folder.mkdir(exist_ok=True)
        self.allowed_extensions = {'png', 'jpg', 'jpeg', 'gif'}
        self.history_file = Path("data/upload_history.json")
        self.history_file.parent.mkdir(exist_ok=True)
        self._load_history()
    
    def _load_history(self):
        """Load upload history"""
        if self.history_file.exists():
            with open(self.history_file, 'r') as f:
                self.history = json.load(f)
        else:
            self.history = []
    
    def _save_history(self):
        """Save upload history"""
        with open(self.history_file, 'w') as f:
            json.dump(self.history, f, indent=2)
    
    def allowed_file(self, filename):
        """Check if file extension is allowed"""
        return '.' in filename and \
               filename.rsplit('.', 1)[1].lower() in self.allowed_extensions
    
    def _scan_qr_code(self, image_path):
        """Scan QR code from image and return decoded data"""
        try:
            # Import cv2 here to avoid import issues
            import cv2
            
            # Read image
            image = cv2.imread(str(image_path))
            if image is None:
                return None
            
            # Convert to grayscale
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            
            # Create QR code detector
            qr_detector = cv2.QRCodeDetector()
            
            # Detect and decode QR code
            data, bbox, _ = qr_detector.detectAndDecode(gray)
            
            if data and len(data) > 0:
                return data.strip()
            
            return None
            
        except Exception as e:
            print(f"QR scanning error: {e}")
            return None
    
    def _extract_punishment_id_from_qr(self, qr_data):
        """Extract punishment ID from QR code data"""
        if not qr_data:
            return None
        
        # QR code should contain the punishment ID directly
        # Format: PUN_YYYYMMDD_HHMMSS_XXXXXXXX
        if qr_data.startswith('PUN_'):
            return qr_data
        
        return None
    
    def _find_punishment_by_id(self, punishment_id):
        """Find punishment record by ID"""
        try:
            from chasti_pi.services.punishment_service import PunishmentService
            punishment_service = PunishmentService()
            return punishment_service.get_punishment_by_id(punishment_id)
        except Exception as e:
            print(f"Error finding punishment: {e}")
            return None
    
    def _read_handwritten_numbers(self, image_path):
        """Read handwritten numbers from the punishment sheet using OCR"""
        try:
            # Import OCR libraries
            import pytesseract
            from PIL import Image
            import cv2
            import numpy as np
            
            # Read image
            image = cv2.imread(str(image_path))
            if image is None:
                return None
            
            # Convert to grayscale
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            
            # Apply image preprocessing to improve OCR accuracy
            # Resize image for better OCR
            height, width = gray.shape
            scale_factor = 2
            resized = cv2.resize(gray, (width * scale_factor, height * scale_factor))
            
            # Apply threshold to get black text on white background
            _, thresh = cv2.threshold(resized, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            
            # Convert back to PIL Image for tesseract
            pil_image = Image.fromarray(thresh)
            
            # Configure tesseract for better number recognition
            custom_config = r'--oem 3 --psm 6 -c tessedit_char_whitelist=0123456789'
            
            # Extract text
            text = pytesseract.image_to_string(pil_image, config=custom_config)
            
            # Extract 6-digit numbers (the punishment codes)
            numbers = re.findall(r'\b\d{6}\b', text)
            
            return numbers
            
        except Exception as e:
            print(f"OCR error: {e}")
            return None
    
    def _verify_handwritten_codes(self, detected_numbers, expected_codes):
        """Verify that detected numbers match expected codes"""
        if not detected_numbers or not expected_codes:
            return {
                "verified": False,
                "matched_codes": [],
                "missing_codes": expected_codes,
                "extra_codes": detected_numbers,
                "accuracy": 0.0
            }
        
        # Convert to sets for comparison
        detected_set = set(detected_numbers)
        expected_set = set(expected_codes)
        
        # Find matches
        matched_codes = detected_set.intersection(expected_set)
        missing_codes = expected_set - detected_set
        extra_codes = detected_set - expected_set
        
        # Calculate accuracy
        accuracy = len(matched_codes) / len(expected_codes) * 100
        
        return {
            "verified": len(matched_codes) >= len(expected_codes) * 0.8,  # 80% threshold
            "matched_codes": list(matched_codes),
            "missing_codes": list(missing_codes),
            "extra_codes": list(extra_codes),
            "accuracy": accuracy,
            "total_expected": len(expected_codes),
            "total_detected": len(detected_numbers),
            "total_matched": len(matched_codes)
        }
    
    def process_photo(self, file):
        """Process uploaded photo and scan for QR codes and handwritten numbers"""
        if file and self.allowed_file(file.filename):
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            new_filename = f"{timestamp}_{filename}"
            file_path = self.upload_folder / new_filename
            
            file.save(str(file_path))
            
            # Scan for QR code
            qr_data = self._scan_qr_code(file_path)
            punishment_id = None
            punishment_data = None
            ocr_results = None
            verification_results = None
            
            if qr_data:
                punishment_id = self._extract_punishment_id_from_qr(qr_data)
                if punishment_id:
                    punishment_data = self._find_punishment_by_id(punishment_id)
                    
                    # If punishment found, read handwritten numbers
                    if punishment_data and punishment_data.get("codes"):
                        expected_codes = punishment_data["codes"]
                        detected_numbers = self._read_handwritten_numbers(file_path)
                        
                        if detected_numbers:
                            verification_results = self._verify_handwritten_codes(
                                detected_numbers, expected_codes
                            )
                            ocr_results = {
                                "detected_numbers": detected_numbers,
                                "verification": verification_results
                            }
            
            # Add to history
            upload_record = {
                "filename": new_filename,
                "original_name": file.filename,
                "uploaded_at": datetime.now().isoformat(),
                "file_path": str(file_path),
                "qr_data": qr_data,
                "punishment_id": punishment_id,
                "punishment_found": str(punishment_data is not None),
                "ocr_results": ocr_results,
                "verification_results": verification_results,
                "processed": "True",
                "processing_result": {
                    "qr_detected": str(qr_data is not None),
                    "punishment_linked": str(punishment_data is not None),
                    "ocr_performed": str(ocr_results is not None),
                    "punishment_data": punishment_data
                }
            }
            self.history.append(upload_record)
            self._save_history()
            
            return {
                "message": "Photo uploaded and processed successfully",
                "filename": new_filename,
                "file_path": str(file_path),
                "qr_detected": qr_data is not None,
                "qr_data": qr_data,
                "punishment_id": punishment_id,
                "punishment_found": punishment_data is not None,
                "punishment_data": punishment_data,
                "ocr_results": ocr_results,
                "verification_results": verification_results
            }
        
        return {"error": "Invalid file type"}
    
    def verify_punishment_photo(self, file, punishment_id=None):
        """Verify uploaded photo against specific punishment or auto-detect"""
        result = self.process_photo(file)
        
        if "error" in result:
            return result
        
        # If no specific punishment_id provided, try to auto-detect from QR
        if not punishment_id and result.get("punishment_id"):
            punishment_id = result["punishment_id"]
        
        if punishment_id:
            result["target_punishment_id"] = punishment_id
            result["verification_success"] = result.get("punishment_id") == punishment_id
            
            # Check if OCR verification was successful
            verification_results = result.get("verification_results")
            if verification_results and verification_results.get("verified"):
                result["handwritten_verified"] = True
                result["verification_message"] = f"Handwritten codes verified with {verification_results['accuracy']:.1f}% accuracy"
            else:
                result["handwritten_verified"] = False
                if verification_results:
                    result["verification_message"] = f"Handwritten verification failed. Accuracy: {verification_results['accuracy']:.1f}%"
                else:
                    result["verification_message"] = "No handwritten codes detected"
            
            # If both QR and handwritten verification successful, mark punishment as verified
            if result["verification_success"] and result.get("handwritten_verified"):
                try:
                    from chasti_pi.services.punishment_service import PunishmentService
                    punishment_service = PunishmentService()
                    verification_result = punishment_service.verify_punishment(punishment_id)
                    
                    # Handle verification result properly
                    if isinstance(verification_result, dict):
                        result["punishment_verified"] = verification_result
                    else:
                        result["punishment_verified"] = {"message": "Verification completed"}
                        
                except Exception as e:
                    result["verification_error"] = str(e)
        
        return result
    
    def get_upload_history(self):
        """Get upload history with QR scanning results"""
        return self.history
    
    def get_punishment_uploads(self, punishment_id):
        """Get all uploads related to a specific punishment"""
        return [upload for upload in self.history if upload.get("punishment_id") == punishment_id] 