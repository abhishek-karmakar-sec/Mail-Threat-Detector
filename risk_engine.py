def calculate_risk_score(parsed_data, analysis_data, url_data, ip_intel):
    score = 0
    matched_rules = []
    
    # 1. Email Authentication Failures (Balanced)
    # Explicit failures are highly suspicious (+15)
    # Missing headers get a minor penalty (+5) since many safe emails lack full corporate signatures
    for auth_type in ['spf', 'dkim', 'dmarc']:
        val = analysis_data.get(auth_type, '').lower().strip()
        
        if val in ['fail', 'softfail', 'error']:
            score += 15
            matched_rules.append(f"{auth_type.upper()} explicit failure (+15)")
        elif val in ['none', 'not found', 'missing', '']:
            score += 5
            matched_rules.append(f"{auth_type.upper()} record missing or none (+5)")
            
    # 2. Reply-To Mismatch
    headers = parsed_data.get('headers', {})
    from_addr = headers.get('From', '')
    reply_to = headers.get('Reply-To', '')
    if reply_to and from_addr.strip().lower() != reply_to.strip().lower():
        score += 10
        matched_rules.append("Reply-To mismatch: Replies go to a different address than sender (+10)")
        
    # 3. Threat Intelligence (URLs & IPs)
    has_suspicious = False
    has_malicious = False
    
    for u in url_data:
        rep = u.get('reputation', {})
        if isinstance(rep, dict):
            if rep.get('malicious', 0) > 0:
                has_malicious = True
            elif rep.get('suspicious', 0) > 0:
                has_suspicious = True
            
    for ip, rep in ip_intel.items():
        if isinstance(rep, dict):
            if rep.get('malicious', 0) > 0:
                has_malicious = True
            elif rep.get('suspicious', 0) > 0:
                has_suspicious = True
            
    if has_malicious:
        score += 25
        matched_rules.append("Malicious IOC detected in URLs or IPs (+25)")
    if has_suspicious:
        score += 15
        matched_rules.append("Suspicious URL/IP detected (+15)")
        
    # 4. Content Language Analysis
    body = parsed_data.get('body', '').lower()
    
    urgency_keywords = ['urgent', 'immediately', 'act now', 'action required', 'overdue', 'suspended']
    if any(keyword in body for keyword in urgency_keywords):
        score += 10
        matched_rules.append("Urgency language detected (+10)")
        
    credential_keywords = ['password', 'login', 'verify', 'credentials', 'account', 'secure']
    if any(keyword in body for keyword in credential_keywords):
        score += 10
        matched_rules.append("Credential language detected (+10)")
        
    # 5. Attachment Checks
    attachments = parsed_data.get('attachments', [])
    if attachments:
        score += 5
        matched_rules.append(f"Contains file attachments ({len(attachments)}) (+5)")
        
    # 6. Calculate Final Severity (Balanced Thresholds)
    if score >= 70:
        severity = "Critical 🔴"
    elif score >= 45:
        severity = "High 🟠"
    elif score >= 20:
        severity = "Medium 🟡"
    else:
        severity = "Low 🟢"
        
    return {
        "score": score,
        "severity": severity,
        "matched_rules": matched_rules,
        "disclaimer": "Note: This is a heuristic score based on predefined static rules. It is for analysis purposes and does not represent an absolute guarantee of compromise."
    }