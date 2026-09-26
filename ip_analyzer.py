import sqlite3
import requests
import time

DB_FILE = 'ip_geolocation.db'

def init_db():
    """Initializes the SQLite database to store IP geolocation data."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS ip_data (
            ip TEXT PRIMARY KEY,
            country TEXT,
            city TEXT,
            isp TEXT,
            asn TEXT,
            latitude REAL,
            longitude REAL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def fetch_geolocation(ip_address):
    """Fetches geolocation data from ip-api.com."""
    # fields parameter limits the JSON response to exactly what we need
    url = f"http://ip-api.com/json/{ip_address}?fields=status,country,city,lat,lon,isp,as"
    
    try:
        response = requests.get(url, timeout=5)
        data = response.json()
        
        if data.get("status") == "success":
            return {
                "ip": ip_address,
                "country": data.get("country", "Unknown"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "asn": data.get("as", "Unknown"),  # ip-api returns ASN under the 'as' key
                "latitude": data.get("lat", 0.0),
                "longitude": data.get("lon", 0.0),
                "context_warning": "Geolocation is for context only. Do not use this as the sole basis for declaring an email malicious."
            }
    except requests.RequestException:
        pass
        
    return None

def save_to_database(geo_data):
    """Saves the extracted geolocation profile to the SQLite database."""
    if not geo_data:
        return

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO ip_data 
        (ip, country, city, isp, asn, latitude, longitude)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        geo_data['ip'],
        geo_data['country'],
        geo_data['city'],
        geo_data['isp'],
        geo_data['asn'],
        geo_data['latitude'],
        geo_data['longitude']
    ))
    conn.commit()
    conn.close()

def analyze_and_store_ips(ip_list):
    """Main function to process a list of IPs, fetch their data, and store them."""
    init_db()
    results = []
    
    for ip in ip_list:
        geo_data = fetch_geolocation(ip)
        if geo_data:
            save_to_database(geo_data)
            results.append(geo_data)
            
        # Free API rate limiting (ip-api allows 45 requests per minute)
        time.sleep(1.5)
        
    return results

if __name__ == "__main__":
    # Test the script independently
    test_ips = ["8.8.8.8", "1.1.1.1"]
    print("Fetching and storing IP data...")
    data = analyze_and_store_ips(test_ips)
    for record in data:
        print(record)