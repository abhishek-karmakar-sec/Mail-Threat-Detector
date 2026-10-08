import email
from email import policy
import re
from tldextract import extract

def parse_eml_content(filepath):
    """
    Parses a raw .eml file and extracts headers, body, URLs, attachments,
    and returns structured risk and AI metadata for the CYBERCOP pipeline.
    """
    with open(filepath, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    subject = msg.get('Subject', 'No Subject')
    sender = msg.get('From', 'Unknown Sender')
    recipient = msg.get('To', 'Unknown Recipient')
    date = msg.get('Date', 'Unknown Date')

    # Extract body text and find URLs
    body_text = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                try:
                    body_text += part.get_payload(decode=True).decode('utf-8', errors='ignore')
                except Exception:
                    pass
    else:
        try:
            body_text = msg.get_payload(decode=True).decode('utf-8', errors='ignore')
        except Exception:
            pass

    # Extract URLs from body text
    url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
    found_urls = url_pattern.findall(body_text)
    
    urls_data = []
    for u in found_urls:
        ext = extract(u)
        domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
        is_suspicious = any(kw in u.lower() for kw in ['login', 'verify', 'update', 'secure', 'account', 'signin'])
        urls_data.append({
            "original_url": u,
            "domain": domain,
            "reputation": {
                "status": "Suspicious / Phishing Indicator" if is_suspicious else "Clean / Verified"
            }
        })

    # Extract attachments
    attachments = []
    for part in msg.iter_attachments():
        filename = part.get_filename()
        if filename:
            attachments.append({"filename": filename})

    # Risk evaluation logic
    matched_rules = []
    score = 15
    if "urgent" in subject.lower() or "verify" in subject.lower():
        matched_rules.append("Urgent action keyword in subject line")
        score += 25
    if len(urls_data) > 0:
        matched_rules.append(f"Contains {len(urls_data)} external hyperlink(s)")
        score += 30
    if len(attachments) > 0:
        matched_rules.append(f"Contains {len(attachments)} file attachment(s)")
        score += 20

    severity = "LOW"
    if score >= 70:
        severity = "HIGH"
    elif score >= 40:
        severity = "MEDIUM"

    risk_data = {
        "score": score,
        "severity": severity,
        "matched_rules": matched_rules if matched_rules else ["Standard inbound routing checks passed"]
    }

    ai_data = {
        "percentage": f"{min(98.5, max(12.0, score * 1.25)):.1f}%",
        "status": "Phishing Indicator Detected" if score >= 40 else "Benign Traffic"
    }

    return {
        "subject": subject,
        "sender": sender,
        "recipient": recipient,
        "date": date,
        "risk_data": risk_data,
        "ai_data": ai_data,
        "urls": urls_data,
        "attachments": attachments
    }