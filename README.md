# Threat Detector (Phishing URL & Malware Hash Scanner)

A lightweight Python CLI application that interacts with the **VirusTotal API (v3)** to analyze suspicious file hashes and URLs for potential malicious threats.

## 🚀 Features

* **File Hash Analysis:** Look up existing MD5 or SHA-256 file hashes against VirusTotal's threat database.
* **URL Analysis:** Check indexed URLs or automatically submit unseen URLs for live threat scanning.
* **Automated Logging:** Saves all scan results directly into `scan_reports.txt` for record-keeping.

---

## 🛠️ Prerequisites & Setup

### 1. Clone the Repository
```bash
git clone [https://github.com/avadhutkulkarni008-hash/threat-detector.git](https://github.com/avadhutkulkarni008-hash/threat-detector.git)
cd threat-detector
