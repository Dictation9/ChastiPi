from flask import Flask, render_template, request, redirect, url_for
import os
import uuid
import qrcode
import random
from fpdf import FPDF
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_punishment')
def generate_punishment():
    punishment_id = str(uuid.uuid4())
    codes = [f"{random.randint(0, 999999):06d}" for _ in range(20)]

    # Save QR
    qr_path = os.path.join(UPLOAD_FOLDER, f"{punishment_id}_qr.png")
    qr = qrcode.make(punishment_id)
    qr.save(qr_path)

    # Save PDF
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Chastity Punishment Sheet", ln=True, align="C")
    pdf.set_font("Arial", "", 12)
    pdf.ln(10)
    pdf.multi_cell(0, 8, "Write each number next to it clearly and submit a photo once done.")
    pdf.ln(5)

    pdf.image(qr_path, x=165, y=260, w=30)

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

    pdf_path = os.path.join(UPLOAD_FOLDER, f"{punishment_id}_sheet.pdf")
    pdf.output(pdf_path)

    return f"Punishment sheet generated: <a href='/{pdf_path}'>{pdf_path}</a>"

if __name__ == "__main__":
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    app.run(host="0.0.0.0", port=5000, debug=True)
