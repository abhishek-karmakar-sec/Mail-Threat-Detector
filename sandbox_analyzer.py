import hashlib
import os

def detonate_attachment(file_storage_or_path, filename):
    """
    Simulates an isolated sandbox detonation for email attachments,
    generating realistic behavioral telemetry for the CYBERCOP pipeline.
    """
    file_bytes = b""
    if hasattr(file_storage_or_path, 'read'):
        try:
            file_storage_or_path.seek(0)
            file_bytes = file_storage_or_path.read()
            file_storage_or_path.seek(0)
        except Exception:
            pass
    elif file_storage_or_path and os.path.exists(str(file_storage_or_path)):
        with open(file_storage_or_path, 'rb') as f:
            file_bytes = f.read()
            
    sha256_hash = hashlib.sha256(file_bytes).hexdigest() if file_bytes else "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    ext = filename.lower().split('.')[-1] if '.' in filename else ''
    
    verdict = "SAFE"
    status = "Execution completed in isolated container. No anomalous activity."
    behaviors = []

    if ext in ['exe', 'scr', 'bat', 'cmd', 'pif']:
        verdict = "MALICIOUS"
        status = "Critical system alteration detected. Attempted outbound C2 connection."
        behaviors = [
            "Dropped executable payload to %APPDATA%",
            "Modified Windows Registry run keys for persistence",
            "Initiated unauthorized TCP connection to external IP (Port 443)"
        ]
    elif ext in ['js', 'vbs', 'wsf', 'ps1']:
        verdict = "HIGH RISK"
        status = "Obfuscated script execution detected interacting with WScript/PowerShell."
        behaviors = [
            "Executed obfuscated PowerShell cradle",
            "Queried local machine architecture via WMI",
            "Attempted memory injection into explorer.exe"
        ]
    elif ext in ['pdf', 'docx', 'xlsx']:
        verdict = "SUSPICIOUS"
        status = "Embedded macro/URI action triggered within document container."
        behaviors = [
            "Document opened external URI reference",
            "Attempted template injection from remote server"
        ]
    else:
        verdict = "CLEAN"
        status = "Static analysis indicates standard non-executable document format."
        behaviors = ["No system calls intercepted", "Zero network traffic generated"]

    return {
        "filename": filename,
        "sha256": sha256_hash,
        "sandbox_report": {
            "verdict": verdict,
            "status": status,
            "behaviors": behaviors,
            "isolated_environment": "CYBERCOP_CONTAINER_V2"
        }
    }