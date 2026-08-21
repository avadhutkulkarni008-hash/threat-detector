import base64
import os
import time
import requests
from dotenv import load_dotenv

load_dotenv()
API_KEY = os.getenv("VT_API_KEY")

HEADERS = {
    "accept": "application/json",
    "x-apikey": API_KEY
}

def print_report(target, stats, target_type):
    print("\n==========================================")
    print(f"       THREAT REPORT ({target_type.upper()})         ")
    print("==========================================")
    print(f"Target     : {target}")
    print(f"Malicious  : {stats['malicious']}")
    print(f"Suspicious : {stats['suspicious']}")
    print(f"Undetected : {stats['undetected']}")
    print(f"Harmless   : {stats['harmless']}")
    print("==========================================\n")

def check_hash(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    print(f"[*] Querying VirusTotal for Hash: {file_hash}...")
    try:
        response = requests.get(url, headers=HEADERS)
        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            print_report(file_hash, stats, "File Hash")
        elif response.status_code == 404:
            print("[!] Hash not found in VirusTotal database.")
        else:
            print(f"[!] API Error: Status Code {response.status_code}")
    except Exception as e:
        print(f"[!] Connection failed: {e}")

def submit_and_get_url_report(target_url):
    print("[*] Submitting URL to VirusTotal for new analysis...")
    scan_endpoint = "https://www.virustotal.com/api/v3/urls"
    data = {"url": target_url}
    
    response = requests.post(scan_endpoint, headers=HEADERS, data=data)
    if response.status_code == 200:
        analysis_id = response.json()["data"]["id"]
        print("[*] Scan submitted! Waiting 10 seconds for results...")
        time.sleep(10)
        
        analysis_endpoint = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        analysis_resp = requests.get(analysis_endpoint, headers=HEADERS)
        response = requests.post(scan_endpoint, headers=HEADERS, data={"url": target_url})
        if analysis_resp.status_code == 200:
            stats = analysis_resp.json()["data"]["attributes"]["stats"]
            print_report(target_url, stats, "URL")
        else:
            print("[!] Failed to fetch analysis results.")
    else:
        print(f"[!] Submission Error: Status Code {response.status_code}")

def check_url(target_url):
    url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
    api_endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    print(f"[*] Querying VirusTotal for URL: {target_url}...")
    try:
        response = requests.get(api_endpoint, headers=HEADERS)
        if response.status_code == 200:
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            print_report(target_url, stats, "URL")
        elif response.status_code == 404:
            print("[!] URL not found in database. Initiating live scan...")
            submit_and_get_url_report(target_url)
        else:
            print(f"[!] API Error: Status Code {response.status_code}")
    except Exception as e:
        print(f"[!] Connection failed: {e}")

if __name__ == "__main__":
    if not API_KEY or API_KEY == "your_virustotal_api_key_here":
        print("[!] Error: Please set your valid VT_API_KEY in the .env file.")
        exit()

    print("--- Phishing URL & Malware Hash Detector ---")
    print("1. Scan File Hash (MD5 / SHA-256)")
    print("2. Scan URL")
    choice = input("Select option (1 or 2): ").strip()

    if choice == "1":
        target_hash = input("Enter file hash: ").strip()
        if target_hash:
            check_hash(target_hash)
    elif choice == "2":
        target_url = input("Enter full URL (e.g., https://example.com): ").strip()
        if target_url:
            check_url(target_url)
    else:
        print("[!] Invalid option selected.")