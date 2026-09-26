import time
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.platypus.flowables import HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT

def draw_dark_bg(canvas, doc):
    """Draws a solid dark slate background across the entire PDF page canvas."""
    canvas.saveState()
    canvas.setFillColor(colors.HexColor('#05080f'))
    canvas.rect(0, 0, doc.pagesize[0], doc.pagesize[1], fill=1, stroke=0)
    canvas.restoreState()

def generate_forensic_pdf(data, output_path):
    """Generates a systematic, clean, and fully dark-themed forensic PDF report."""
    
    doc = SimpleDocTemplate(
        output_path, pagesize=letter,
        rightMargin=30, leftMargin=30,
        topMargin=40, bottomMargin=40
    )
    
    elements = []
    styles = getSampleStyleSheet()
    
    # --- CYBERCOP DARK THEME PALETTE ---
    color_card = colors.HexColor('#0f141e')
    color_border = colors.HexColor('#1e293b')
    color_accent = colors.HexColor('#0ea5e9')
    color_muted = colors.HexColor('#94a3b8')
    
    # Controlled typography with explicit leading to prevent text overlapping
    title_style = ParagraphStyle(
        'TitleStyle', fontName='Helvetica-Bold', fontSize=20, leading=24,
        textColor=colors.white, alignment=TA_CENTER, spaceAfter=8
    )
    heading_style = ParagraphStyle(
        'HeadingStyle', fontName='Helvetica-Bold', fontSize=10, leading=14,
        textColor=colors.white, backColor=color_card, 
        alignment=TA_LEFT, spaceBefore=14, spaceAfter=6, borderPadding=6
    )
    normal_mono = ParagraphStyle('Mono', fontName='Courier', fontSize=8, leading=12, textColor=colors.HexColor('#cbd5e1'), spaceAfter=2)
    bold_mono = ParagraphStyle('MonoBold', fontName='Courier-Bold', fontSize=8, leading=12, textColor=colors.white)

    # --- 1. HEADER & BRANDING ---
    elements.append(Paragraph("CYBERCOP // THREAT INTELLIGENCE", title_style))
    elements.append(HRFlowable(width="100%", color=color_accent, thickness=1.5, spaceBefore=0, spaceAfter=12))

    # --- 2. REPORT METADATA GRID ---
    meta = data.get('forensic_metadata', {})
    meta_table_data = [
        [Paragraph("OPERATOR ID:", normal_mono), Paragraph("ATIK_007", bold_mono), 
         Paragraph("DNS RESOLVER:", normal_mono), Paragraph(meta.get('dns_resolver', '9.9.9.9'), bold_mono)],
        [Paragraph("PROCESSING NODE:", normal_mono), Paragraph(meta.get('processing_node', 'CYBERCOP_NODE_01'), bold_mono),
         Paragraph("UTC TIMESTAMP:", normal_mono), Paragraph(meta.get('analysis_timestamp_utc', 'N/A')[:19].replace('T', ' '), bold_mono)]
    ]
    t_meta = Table(meta_table_data, colWidths=[105, 147, 105, 147])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), color_card),
        ('GRID', (0, 0), (-1, -1), 0.5, color_border),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(t_meta)
    elements.append(Spacer(1, 10))

    # --- 3. THREAT EXECUTIVE SUMMARY ---
    elements.append(Paragraph("/// EXECUTIVE THREAT SUMMARY", heading_style))
    
    risk = data.get('risk_data', {})
    severity = risk.get('severity', 'UNKNOWN').upper()
    sev_color = colors.HexColor('#ef4444') if severity in ['HIGH', 'CRITICAL'] else (colors.HexColor('#f59e0b') if severity == 'MEDIUM' else colors.HexColor('#10b981'))
    
    sev_styled = Paragraph(f"<font color='{sev_color.hexval()}'><b>{severity}</b></font>", bold_mono)
    
    exec_data = [
        [Paragraph("HEURISTIC RISK SCORE", normal_mono), Paragraph("AI PHISHING CONFIDENCE", normal_mono), Paragraph("SEVERITY LEVEL", normal_mono)],
        [Paragraph(str(risk.get('score', 0)), bold_mono), Paragraph(str(data.get('ai_data', {}).get('percentage', 'N/A')), bold_mono), sev_styled]
    ]
    t_exec = Table(exec_data, colWidths=[174, 174, 156])
    t_exec.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), color_card),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 0.5, color_border),
        ('PADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(t_exec)

    rules = risk.get('matched_rules', [])
    if rules:
        elements.append(Spacer(1, 6))
        elements.append(Paragraph("<b>TRIGGERED HEURISTIC SIGNATURES:</b>", normal_mono))
        for r in rules:
            elements.append(Paragraph(f"<font color='#0ea5e9'>■</font> {r}", normal_mono))
    elements.append(Spacer(1, 10))

    # --- 4. EXTRACTED URL INDICATORS ---
    elements.append(Paragraph("/// NETWORK INDICATORS: EXTRACTED URLs", heading_style))
    urls = data.get('urls', [])
    if urls:
        url_table_data = [
            [Paragraph("DOMAIN", bold_mono), Paragraph("FULL URL", bold_mono), Paragraph("STATUS", bold_mono)]
        ]
        for u in urls:
            domain = Paragraph(u.get('domain', 'N/A'), normal_mono)
            url_str = Paragraph(u.get('original_url', 'N/A'), normal_mono)
            status_val = u.get('reputation', {}).get('status', 'UNKNOWN')
            status_p = Paragraph(status_val, normal_mono)
            url_table_data.append([domain, url_str, status_p])
            
        t_urls = Table(url_table_data, colWidths=[110, 314, 80])
        t_urls.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), color_border),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [color_card, colors.HexColor('#0b0f17')]),
            ('GRID', (0, 0), (-1, -1), 0.5, color_border),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(t_urls)
    else:
        elements.append(Paragraph("No URLs detected in payload.", normal_mono))

    # --- 5. MITRE ATT&CK MAPPING ---
    elements.append(Paragraph("/// MITRE ATT&CK FRAMEWORK MAPPING", heading_style))
    mitre = meta.get('mitre_attack_matrix', [])
    if mitre:
        mitre_table_data = [
            [Paragraph("TACTIC", bold_mono), Paragraph("ID", bold_mono), Paragraph("TECHNIQUE", bold_mono)]
        ]
        for m in mitre:
            mitre_table_data.append([
                Paragraph(m.get('tactic', ''), normal_mono),
                Paragraph(m.get('id', ''), normal_mono),
                Paragraph(m.get('technique', ''), normal_mono)
            ])
            
        t_mitre = Table(mitre_table_data, colWidths=[110, 64, 330])
        t_mitre.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), color_border),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [color_card, colors.HexColor('#0b0f17')]),
            ('GRID', (0, 0), (-1, -1), 0.5, color_border),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(t_mitre)
    else:
        elements.append(Paragraph("No specific MITRE techniques mapped.", normal_mono))

    # --- 6. SANDBOX DETONATION TELEMETRY ---
    elements.append(Paragraph("/// SANDBOX DETONATION TELEMETRY", heading_style))
    sandbox = data.get('sandbox_data', [])
    if sandbox:
        sb_table_data = [
            [Paragraph("FILENAME", bold_mono), Paragraph("VERDICT", bold_mono), Paragraph("STATUS", bold_mono)]
        ]
        for s in sandbox:
            rep = s.get('sandbox_report', {})
            sb_table_data.append([
                Paragraph(s.get('filename', 'Unknown'), normal_mono),
                Paragraph(rep.get('verdict', 'N/A'), normal_mono),
                Paragraph(rep.get('status', 'N/A'), normal_mono)
            ])
        t_sb = Table(sb_table_data, colWidths=[170, 100, 234])
        t_sb.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), color_border),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('GRID', (0, 0), (-1, -1), 0.5, color_border),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(t_sb)
    else:
        elements.append(Paragraph("No attachments detonated.", normal_mono))

    # --- 7. IMMUTABLE CHAIN OF CUSTODY ---
    elements.append(Paragraph("/// IMMUTABLE CHAIN OF CUSTODY", heading_style))
    hash_val = meta.get('blockchain_sha256_hash', 'PENDING')
    
    elements.append(Paragraph("Cryptographic SHA-256 evidence record appended to the local CYBERCOP ledger.", normal_mono))
    elements.append(Spacer(1, 4))
    
    hash_table_data = [
        [Paragraph("LEDGER HASH:", normal_mono), Paragraph(hash_val, bold_mono)]
    ]
    t_hash = Table(hash_table_data, colWidths=[90, 414])
    t_hash.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), color_card),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('GRID', (0, 0), (-1, -1), 0.5, color_accent),
        ('PADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(t_hash)
    
    elements.append(Spacer(1, 15))
    elements.append(HRFlowable(width="100%", color=color_border, thickness=1, spaceBefore=0, spaceAfter=5))
    elements.append(Paragraph("☣ POWERED BY UMBRELLA CORPORATION ☣", ParagraphStyle('Footer', fontName='Courier-Bold', fontSize=7, leading=9, textColor=colors.HexColor('#ef4444'), alignment=TA_CENTER)))

    # Build PDF with the dark background canvas callback applied to all pages
    doc.build(elements, onFirstPage=draw_dark_bg, onLaterPages=draw_dark_bg)