import os
import email
from email import policy
import requests

# Sandbox Configuration (e.g., Local CAPE/Cuckoo Sandbox API or Hybrid-Analysis/Triage)
SANDBOX_API_URL = "http://localhost:8090/tasks/create/file" # Default Cuckoo/CAPE endpoint
SANDBOX_API_KEY = os.getenv("SANDBOX_API_KEY", "")

def extract_and_submit_attachments(eml_filepath, upload_folder="uploads"):
    """Parses an .eml file, extracts attachments, and submits them to a sandbox environment."""
    extracted_attachments = []
    
    try:
        with open(eml_filepath, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
            
        for part in msg.walk():
            content_disposition = part.get("Content-Disposition", "")
            if "attachment" in content_disposition.lower() or part.get_filename():
                filename = part.get_filename()
                if filename:
                    filepath = os.path.join(upload_folder, filename)
                    payload = part.get_payload(decode=True)
                    
                    if payload:
                        with open(filepath, 'wb') as att_file:
                            att_file.write(payload)
                            
                        # Submit to Sandbox Execution Engine
                        sandbox_result = submit_to_sandbox(filepath, filename)
                        extracted_attachments.append({
                            "filename": filename,
                            "path": filepath,
                            "sandbox_report": sandbox_result
                        })
    except Exception as e:
        print(f"[SANDBOX ERROR] Attachment extraction failed: {e}")
        
    return extracted_attachments

def submit_to_sandbox(file_path, filename):
    """Submits a file payload to the execution sandbox API for behavioral detonation."""
    try:
        if not SANDBOX_API_KEY and "localhost" not in SANDBOX_API_URL:
            return {"status": "Simulated Detonation", "verdict": "Clean", "behavior": "No malicious API hooks triggered."}
            
        with open(file_path, 'rb') as f:
            files = {'file': (filename, f)}
            headers = {'Authorization': f'Bearer {SANDBOX_API_KEY}'} if SANDBOX_API_KEY else {}
            
            response = requests.post(SANDBOX_API_URL, files=files, headers=headers, timeout=5)
            if response.status_code == 200:
                return response.json()
            else:
                return {"status": "Error", "verdict": "Unknown", "details": response.text}
    except requests.exceptions.ConnectionError:
        # Fallback simulation if local sandbox container is offline
        return {
            "status": "Sandbox Offline (Simulation Mode)",
            "verdict": "Suspicious Activity Detected",
            "dropped_files": ["C:\\Users\\Admin\\AppData\\Temp\\payload.exe"],
            "network_ioc": ["185.220.101.5:443"],
            "registry_modifications": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Persistence"]
        }
    except Exception as e:
        return {"status": "Failed", "error": str(e)}