import email
import re
import json
from email import policy
from email.parser import BytesParser

def extract_urls(text):
    # Matches http://, https://, and www. links
    url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
    return list(set(re.findall(url_pattern, text)))

def extract_ips(text):
    # Matches standard IPv4 addresses
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ips = re.findall(ip_pattern, text)
    # Filter valid IPs (0-255 range)
    return list(set([ip for ip in ips if all(0 <= int(part) <= 255 for part in ip.split('.'))]))

def parse_email(file_path):
    # Read the raw .eml file
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    # 1. Map the specific headers to your exact JSON schema
    parsed_data = {
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "reply_to": msg.get("Reply-To", ""),
        "return_path": msg.get("Return-Path", ""),
        "received": msg.get_all("Received", []),
        "authentication_results": msg.get("Authentication-Results", ""),
        "body": "",
        "urls": [],
        "ips": []
    }

  # 2. Extract the Body (handles both plain text and multipart/HTML emails)
    body_content = ""
    
    print(f"\n--- DEBUG: Parsing Email Structure ---")
    print(f"Is multipart? {msg.is_multipart()}")
    
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))
            print(f"Found part: {content_type}")
            
            if content_type in ["text/plain", "text/html"] and "attachment" not in content_disposition:
                try:
                    body_content += part.get_content() + "\n"
                    print("Successfully used get_content()")
                except Exception as e:
                    print(f"Error with get_content(): {e}")
                    # Fallback to raw payload decoding
                    try:
                        raw_payload = part.get_payload(decode=True)
                        if raw_payload:
                            body_content += raw_payload.decode('utf-8', errors='ignore') + "\n"
                            print("Successfully used fallback get_payload()")
                    except Exception as fallback_e:
                        print(f"Fallback also failed: {fallback_e}")
    else:
        print(f"Single part email: {msg.get_content_type()}")
        try:
            body_content = msg.get_content()
            print("Successfully used get_content()")
        except Exception as e:
            print(f"Error with get_content(): {e}")
            # Fallback to raw payload decoding
            raw_payload = msg.get_payload(decode=True)
            if raw_payload:
                body_content = raw_payload.decode('utf-8', errors='ignore')
                print("Successfully used fallback get_payload()")
            
    parsed_data["body"] = body_content.strip()
    print("--- DEBUG END ---\n")

    # 3. Extract URLs and IPs
    parsed_data["urls"] = extract_urls(parsed_data["body"])
    
    # We check both the body AND the "Received" headers for IPs, 
    # as routing IPs are highly valuable for email analysis.
    text_to_scan_for_ips = parsed_data["body"] + " " + " ".join(parsed_data["received"])
    parsed_data["ips"] = extract_ips(text_to_scan_for_ips)

    return parsed_data

if __name__ == "__main__":
    # Execute the parser and print the formatted JSON
    # Ensure you have a 'sample.eml' file in your directory
    try:
        result = parse_email('sample')
        print(json.dumps(result, indent=4))
    except FileNotFoundError:
        print("sample.eml' file in this directory to test.")