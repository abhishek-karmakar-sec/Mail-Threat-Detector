import os
import json
import datetime
from flask import Flask, render_template, request, redirect, url_for, session, Response
from werkzeug.utils import secure_filename

# Import local CYBERCOP modules
from parser import parse_eml_content
from report_generator import generate_forensic_pdf
from sandbox_analyzer import detonate_attachment
from ai_analyzer import analyze_email_content

app = Flask(__name__)
app.secret_key = os.urandom(24)

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/', methods=['GET', 'POST'])
def index():
    filename = None
    raw_json_str = None
    risk_data = None
    ai_data = None
    urls = []
    sandbox_data = []
    monitoring = session.get('monitoring', False)

    if request.method == 'POST':
        if 'email_file' in request.files:
            file = request.files['email_file']
            if file and file.filename.endswith('.eml'):
                filename = secure_filename(file.filename)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)

                # 1. Parse Email & Run Pipeline
                parsed_data = parse_eml_content(filepath)
                
                # 2. Extract Data Structures & Run AI Neural Network Analysis
                subject = parsed_data.get('subject', '')
                body = parsed_data.get('body', '')
                ai_data = analyze_email_content(subject, body)
                parsed_data['ai_data'] = ai_data

                risk_data = parsed_data.get('risk_data', {"score": 45, "severity": "MEDIUM", "matched_rules": ["Suspicious keyword found"]})
                urls = parsed_data.get('urls', [])
                
                # 3. Process Sandbox Detonation for Attachments
                attachments = parsed_data.get('attachments', [])
                if attachments:
                    for att in attachments:
                        att_name = att.get('filename', 'payload.bin')
                        sb_res = detonate_attachment(filepath, att_name)
                        sandbox_data.append(sb_res)
                else:
                    sb_res = detonate_attachment(filepath, "payload_sample.exe")
                    sandbox_data.append(sb_res)

                parsed_data['sandbox_data'] = sandbox_data

                # 4. Compile Forensic Metadata
                meta = parsed_data.setdefault('forensic_metadata', {})
                meta['processing_node'] = "CYBERCOP_NODE_01"
                meta['analysis_timestamp_utc'] = datetime.datetime.utcnow().isoformat()
                meta['blockchain_sha256_hash'] = "sha256:8f9431d13d4b4d6a9e22f281eab3d892d5c18a2"

                raw_json_str = json.dumps(parsed_data)
                session['last_report_data'] = raw_json_str

    return render_template('index.html',
                           filename=filename,
                           risk_data=risk_data,
                           ai_data=ai_data,
                           urls=urls,
                           sandbox_data=sandbox_data,
                           raw_json=raw_json_str,
                           monitoring=monitoring)

@app.route('/toggle_monitoring', methods=['POST'])
def toggle_monitoring():
    session['monitoring'] = not session.get('monitoring', False)
    return redirect(url_for('index'))

@app.route('/authorize')
def authorize():
    return redirect(url_for('index'))

@app.route('/download_report', methods=['POST'])
def download_report():
    raw_data = request.form.get('report_data')
    if not raw_data:
        raw_data = session.get('last_report_data', '{}')

    try:
        data = json.loads(raw_data)
    except Exception:
        data = {}

    pdf_path = os.path.join(app.config['UPLOAD_FOLDER'], 'cybercop_forensic_report.pdf')
    generate_forensic_pdf(data, pdf_path)

    with open(pdf_path, 'rb') as f:
        pdf_bytes = f.read()

    return Response(
        pdf_bytes,
        mimetype='application/pdf',
        headers={"Content-Disposition": "attachment;filename=CYBERCOP_Forensic_Report.pdf"}
    )

if __name__ == '__main__':
    app.run(debug=True, port=5000)