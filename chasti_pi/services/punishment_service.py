"""
Punishment service for ChastiPi
"""
import os
import uuid
import qrcode
import random
import hashlib
from fpdf import FPDF
from pathlib import Path
from datetime import datetime
import json

class PunishmentService:
    """Service for managing punishment sheets and QR codes"""
    
    def __init__(self, upload_folder="uploads"):
        self.upload_folder = Path(upload_folder)
        self.upload_folder.mkdir(exist_ok=True)
        
        # Create subdirectories for better organization
        self.qr_folder = self.upload_folder / "qr_codes"
        self.pdf_folder = self.upload_folder / "pdfs"
        self.qr_folder.mkdir(exist_ok=True)
        self.pdf_folder.mkdir(exist_ok=True)
        
        self.history_file = Path("data/punishment_history.json")
        self.history_file.parent.mkdir(exist_ok=True)
        self._load_history()
    
    def _load_history(self):
        """Load punishment history"""
        if self.history_file.exists():
            with open(self.history_file, 'r') as f:
                self.history = json.load(f)
        else:
            self.history = []
    
    def _save_history(self):
        """Save punishment history"""
        with open(self.history_file, 'w') as f:
            json.dump(self.history, f, indent=2)
    
    def _generate_unique_codes(self, count=20):
        """Generate truly unique codes that haven't been used before"""
        used_codes = set()
        
        # Collect all previously used codes
        for record in self.history:
            used_codes.update(record.get("codes", []))
        
        # Generate new unique codes
        new_codes = []
        attempts = 0
        max_attempts = count * 100  # Prevent infinite loops
        
        while len(new_codes) < count and attempts < max_attempts:
            # Generate a more complex code with timestamp component
            timestamp = int(datetime.now().timestamp() * 1000) % 1000000
            random_part = random.randint(0, 999999)
            combined = (timestamp + random_part + attempts) % 1000000
            code = f"{combined:06d}"
            
            if code not in used_codes and code not in new_codes:
                new_codes.append(code)
            
            attempts += 1
        
        # If we couldn't generate enough unique codes, add some with extra randomness
        while len(new_codes) < count:
            extra_code = f"{random.randint(0, 999999):06d}"
            if extra_code not in used_codes and extra_code not in new_codes:
                new_codes.append(extra_code)
        
        return new_codes
    
    def _generate_unique_id(self):
        """Generate a unique punishment ID with timestamp"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_part = str(uuid.uuid4())[:8]
        return f"PUN_{timestamp}_{unique_part}"
    
    def generate_punishment(self):
        """Generate unique punishment sheet with QR code"""
        # Generate unique punishment ID
        punishment_id = self._generate_unique_id()
        
        # Generate unique codes that haven't been used before
        codes = self._generate_unique_codes(20)
        
        # Create timestamp for file naming
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Generate QR code with unique filename
        qr_filename = f"{punishment_id}_qr_{timestamp}.png"
        qr_path = self.qr_folder / qr_filename
        qr = qrcode.make(punishment_id)
        with open(qr_path, 'wb') as f:
            qr.save(f)
        
        # Generate PDF with unique filename
        pdf_filename = f"{punishment_id}_sheet_{timestamp}.pdf"
        pdf_path = self.pdf_folder / pdf_filename
        self._generate_pdf(pdf_path, codes, qr_path, punishment_id)
        
        # Create unique hash for additional verification
        content_hash = hashlib.md5(f"{punishment_id}{''.join(codes)}".encode()).hexdigest()[:8]
        
        # Save to history with enhanced metadata
        punishment_record = {
            "id": punishment_id,
            "content_hash": content_hash,
            "created": datetime.now().isoformat(),
            "created_timestamp": timestamp,
            "codes": codes,
            "qr_path": str(qr_path),
            "pdf_path": str(pdf_path),
            "qr_filename": qr_filename,
            "pdf_filename": pdf_filename,
            "completed": False,
            "attempts": 0,
            "verification_attempts": []
        }
        self.history.append(punishment_record)
        self._save_history()
        
        return {
            "punishment_id": punishment_id,
            "content_hash": content_hash,
            "qr_path": str(qr_path),
            "pdf_path": str(pdf_path),
            "qr_filename": qr_filename,
            "pdf_filename": pdf_filename,
            "codes_count": len(codes),
            "created": punishment_record["created"],
            "message": "Unique punishment sheet generated successfully"
        }
    
    def _generate_pdf(self, pdf_path, codes, qr_path, punishment_id):
        """Generate PDF punishment sheet with unique content"""
        pdf = FPDF()
        pdf.add_page()
        
        # Header with unique identifier
        pdf.set_font("Arial", "B", 16)
        pdf.cell(0, 10, "Chastity Punishment Sheet", ln=True, align="C")
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 8, f"ID: {punishment_id}", ln=True, align="C")
        pdf.set_font("Arial", "", 10)
        pdf.cell(0, 6, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
        
        pdf.set_font("Arial", "", 12)
        pdf.ln(10)
        pdf.multi_cell(0, 8, "Write each number next to it clearly and submit a photo once done.")
        pdf.multi_cell(0, 8, "Each punishment sheet is unique and cannot be reused.")
        pdf.ln(5)
        
        # Add QR code
        pdf.image(str(qr_path), x=165, y=260, w=30)
        
        # Add unique codes in a more organized layout
        pdf.set_font("Arial", "", 12)
        spacing_y = 8
        pdf.set_y(50)
        
        for idx, code in enumerate(codes):
            x = 10 if idx < 10 else 100
            y = 50 + (idx % 10) * spacing_y
            pdf.set_xy(x, y)
            pdf.set_font("Arial", "B", 12)
            pdf.cell(20, 8, code)
            pdf.set_font("Arial", "", 12)
            pdf.cell(60, 8, "_" * 20)
        
        # Add footer with verification info
        pdf.set_y(250)
        pdf.set_font("Arial", "", 8)
        hash_string = f"{punishment_id}{''.join(codes)}"
        verification_hash = hashlib.md5(hash_string.encode()).hexdigest()[:8]
        pdf.cell(0, 4, f"Verification Hash: {verification_hash}", ln=True)
        
        pdf.output(str(pdf_path))
    
    def verify_punishment(self, punishment_id):
        """Verify punishment completion"""
        for record in self.history:
            if record["id"] == punishment_id:
                if record["completed"]:
                    return {"error": "Punishment already completed"}, 400
                
                record["completed"] = True
                record["completed_at"] = datetime.now().isoformat()
                record["attempts"] += 1
                self._save_history()
                return {"message": "Punishment verified successfully"}
        
        return {"error": "Punishment not found"}, 404
    
    def get_history(self):
        """Get punishment history"""
        return self.history
    
    def get_punishment_by_id(self, punishment_id):
        """Get specific punishment by ID"""
        for record in self.history:
            if record["id"] == punishment_id:
                return record
        return None
    
    def is_punishment_unique(self, punishment_id):
        """Check if punishment ID is unique"""
        return not any(record["id"] == punishment_id for record in self.history) 