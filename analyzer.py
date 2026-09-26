import email
from email import policy
from email.parser import BytesParser
import re
import json

def extract_domain(email_address):
    """Extracts the domain from an email address string (e.g., 'Jane <jane@example.com>' -> 'example.com')"""
    if not email_address:
        return None
    match = re.search(r'@([\w.-]+)', email_address)
    return match.group(1).lower() if match else None

def analyze_headers(file_path):
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    # 1. Extract Target Headers
    headers = {
        "From": msg.get("From", ""),
        "Reply-To": msg.get("Reply-To", ""),
        "Return-Path": msg.get("Return-Path", ""),
        "Received": msg.get_all("Received", []),
        "Authentication-Results": msg.get("Authentication-Results", "")
    }

    report = {
        "summary": "Clean",
        "flags": [],
        "domain_alignment": {},
        "authentication": {},
        "routing_hops": len(headers["Received"])
    }

    # 2. Domain Alignment Analysis (Spoofing Check)
    from_domain = extract_domain(headers["From"])
    return_path_domain = extract_domain(headers["Return-Path"])
    reply_to_domain = extract_domain(headers["Reply-To"])

    report["domain_alignment"] = {
        "from_domain": from_domain,
        "return_path_domain": return_path_domain,
        "reply_to_domain": reply_to_domain
    }

    if return_path_domain and from_domain != return_path_domain:
        report["flags"].append("WARNING: 'From' domain does not match 'Return-Path'. This is a common sign of spoofing.")
        report["summary"] = "Suspicious"
    
    if reply_to_domain and from_domain != reply_to_domain:
        report["flags"].append("NOTICE: 'Reply-To' domain differs from 'From' domain. Verify if this is expected.")

    # 3. Authentication Results Analysis
    auth_header = headers["Authentication-Results"].lower()
    
    # Check SPF
    if "spf=pass" in auth_header:
        report["authentication"]["spf"] = "Pass"
    elif "spf=" in auth_header:
        report["authentication"]["spf"] = "Fail/SoftFail"
        report["flags"].append("WARNING: SPF check failed.")
        report["summary"] = "Suspicious"
    else:
        report["authentication"]["spf"] = "Not Found"

    # Check DKIM
    if "dkim=pass" in auth_header:
        report["authentication"]["dkim"] = "Pass"
    elif "dkim=" in auth_header:
        report["authentication"]["dkim"] = "Fail"
        report["flags"].append("WARNING: DKIM signature check failed.")
        report["summary"] = "Suspicious"
    else:
        report["authentication"]["dkim"] = "Not Found"

    # Check DMARC
    if "dmarc=pass" in auth_header:
        report["authentication"]["dmarc"] = "Pass"
    elif "dmarc=" in auth_header:
        report["authentication"]["dmarc"] = "Fail"
        report["flags"].append("WARNING: DMARC policy check failed.")
        report["summary"] = "Suspicious"
    else:
        report["authentication"]["dmarc"] = "Not Found"

    return report

if __name__ == "__main__":
    try:
        # Run the analyzer on the sample email we created earlier
        analysis_result = analyze_headers('sample.eml')
        print("--- EMAIL SECURITY ANALYSIS REPORT ---")
        print(json.dumps(analysis_result, indent=4))
    except FileNotFoundError:
        print("Error: 'sample.eml' not found. Please ensure it exists in the directory.")