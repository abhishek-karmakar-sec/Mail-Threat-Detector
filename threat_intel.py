import requests
import base64

# You must replace this with your free VirusTotal API Key
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY_HERE"
HEADERS = {"x-apikey": VT_API_KEY}

def format_reputation(stats):
    """Parses the raw VirusTotal stats into a simple risk profile."""
    if not stats:
        return {"status": "Unknown", "malicious": 0, "suspicious": 0, "clean": 0}
    
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    clean = stats.get("harmless", 0) + stats.get("undetected", 0)
    
    if malicious > 0:
        status = "Malicious 🔴"
    elif suspicious > 0:
        status = "Suspicious 🟡"
    elif clean > 0:
        status = "Clean 🟢"
    else:
        status = "Unknown ⚪"
        
    return {
        "status": status,
        "malicious": malicious,
        "suspicious": suspicious,
        "clean": clean
    }

def check_ip_reputation(ip_address):
    """Fetches threat intelligence for an IP address."""
    if VT_API_KEY == "YOUR_VIRUSTOTAL_API_KEY_HERE":
        return {"error": "Missing API Key"}
        
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    
    try:
        response = requests.get(url, headers=HEADERS, timeout=5)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return format_reputation(stats)
    except requests.RequestException:
        pass
        
    return {"error": "API request failed or rate limited"}

def check_url_reputation(target_url):
    """Fetches threat intelligence for a URL."""
    if VT_API_KEY == "ec08704f14ba2c0d82fe34486a6116f0be4b232e8ac38336a83a028986930625":
        return {"error": "Missing API Key"}

    # VirusTotal API v3 requires the URL to be base64url encoded without padding
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    try:
        response = requests.get(url, headers=HEADERS, timeout=5)
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return format_reputation(stats)
    except requests.RequestException:
        pass
        
    return {"error": "API request failed or rate limited"}

if __name__ == "__main__":
    # Test block
    print("Testing IP:", check_ip_reputation("8.8.8.8"))
    print("Testing URL:", check_url_reputation("https://google.com"))