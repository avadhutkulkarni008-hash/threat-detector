# Threat Detector (Phishing URL & Malware Hash Scanner)

A lightweight Python CLI tool that integrates with the **VirusTotal API (v3)** to scan file hashes (MD5/SHA-256) and URLs for malicious threats, automatically saving scan logs locally.

---

## 🛠️ Complete Setup & Execution

### Option A: Setup on Linux / Kali Linux

Open your terminal and run the following commands:

```bash
# 1. Clone the repository
git clone [https://github.com/avadhutkulkarni008-hash/threat-detector.git](https://github.com/avadhutkulkarni008-hash/threat-detector.git)

# 2. Navigate into the project folder
cd threat-detector

# 3. Create a Python virtual environment
python3 -m venv venv

# 4. Activate the virtual environment
source venv/bin/activate

# 5. Install required dependencies
pip install -r requirements.txt

# 6. Create the .env file with your VirusTotal API key
echo "VT_API_KEY=your_virustotal_api_key_here" > .env

# 7. Run the Threat Detector
python3 app.py
