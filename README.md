# **JavaScript Reconnaissance & Secret Hunter**

---

## **Description**
**JS Recon Tool** is a multi-purpose utility designed to discover, download, and analyze JavaScript files to uncover sensitive data (AWS keys, API tokens, personal information, etc.).

- **Passive & Active URL Collection** (GAU, Katana, Waybackurls, Hakrawler)
- **JavaScript Brute-Force** (Common JS paths)
- **Active HTML Parsing** (Extracting `<script src="...">` tags)
- **Secret Scanning** (Regex, GF, TruffleHog, SecretFinder)
- **Parallel Processing** (ThreadPoolExecutor for fast scanning)
- **TLS Bypass Support** (`--insecure` flag to accept self-signed certificates)

---

## **Installation**

### **1. Requirements**
- **Python 3.8+**
- **Go (1.19+)** – Required for `httpx`, `gau`, `katana`, `waybackurls`, `hakrawler`, `gf`
- **Curl / Wget** – For downloading JavaScript files
- **TruffleHog** (optional) – For deeper secret scanning
- **SecretFinder** (optional) – For automated secret detection

---

### **2. Installing Tools**
```bash
# Python packages
pip install -r requirements.txt  # (if available)

# Go tools
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/tomnomnom/gf@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/hakluke/hakrawler@latest

# TruffleHog (optional)
wget https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_Linux_x86_64.tar.gz
tar -xzf trufflehog_Linux_x86_64.tar.gz
sudo mv trufflehog /usr/local/bin/

# SecretFinder (optional)
git clone https://github.com/m4ll0k/SecretFinder.git
cd SecretFinder && pip install -r requirements.txt
```

---

## **Usage**

### **1. Single Domain Scan**
```bash
python3 jsrecon.py --domain example.com -o output/ --insecure --threads 50
```
- `--domain` – Domain to scan.
- `-o output/` – Directory to store results.
- `--insecure` – Skip TLS certificate validation (for self-signed certificates).
- `--threads 50` – Increase parallel processing threads.

---

### **2. Scan Multiple Domains from a List**
```bash
python3 jsrecon.py -s domains.txt -o output/ --insecure --threads 50
```
- `-s domains.txt` – File containing a list of domains (one per line).

---

### **3. Additional Parameters**
| Parameter | Description |
|-----------|-------------|
| `--scan-all-js` | Scan all JavaScript files (default skips libraries). |
| `--skip-live-check` | Skip live host verification with `httpx`. |
| `--skip-url-collection` | Skip URL collection (use existing results). |
| `--skip-download` | Only extract JavaScript URLs without downloading. |

---

## **Output Structure**
```
output/
├── live/                  # Live hosts
│   └── live.txt
├── urls/                  # Collected URLs
│   └── all_urls.txt
├── js/                    # JavaScript file metadata
│   ├── js_urls.txt        # All JavaScript URLs
│   └── custom_js.txt      # Non-library JavaScript files
├── js/downloaded/         # Downloaded JavaScript files
│   ├── *.js               # JavaScript files
│   └── _failed.txt        # Failed downloads
├── secrets/               # Secret scanning results
│   ├── final_report.txt   # Final report
│   ├── raw/               # Raw results
│   │   ├── regex_findings.json
│   │   ├── gf_*.txt
│   │   ├── trufflehog.json
│   │   └── SecretFinder/
└── logs/                  # Log files
    └── run_YYYYMMDD_HHMMSS.log
```

---

## **Secret Scanning Results**
| **Type** | **Description** | **Example** |
|----------|----------------|-------------|
| AWS Access Key | AWS user access keys | `AKIAIOSFODNN7EXAMPLE` |
| AWS Secret Key | AWS secret access keys | `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` |
| Google API Key | Google API keys | `AIzaSyDqXy8XJ5QpZ5J5J5J5J5J5J5J5J5J5J5` |
| GitHub Token | GitHub personal tokens | `ghp_abc123...` |
| Slack Token | Slack tokens | `xoxb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx` |
| Stripe Key | Stripe payment keys | `sk_test_51ABC123...` |
| JWT Token | JSON Web Tokens | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c` |
| Firebase URL | Firebase configurations | `https://project.firebaseio.com` |
| Private Key | Private key blocks | ```-----BEGIN RSA PRIVATE KEY----- MIIEpAIBAAKCAQEA... -----END RSA PRIVATE KEY-----``` |
| Password in URL | URLs with embedded passwords | `http://admin:SuperSecret123@site.com` |

---

## **Examples**

### **1. Testing Kapital Bank’s Pre-Production Environment**
```bash
python3 jsrecon.py --domain pre-cb.kapitalbank.az -o kapitalbank_test/ --insecure --threads 30
```
- **Results:** Check `kapitalbank_test/secrets/final_report.txt` for sensitive findings.

---

### **2. Parallel Scan of Multiple Domains**
```bash
python3 jsrecon.py -s top_domains.txt -o bulk_scan/ --threads 100 --insecure
```
- **`top_domains.txt`** – File containing domains to scan.

---

### **3. Extract JavaScript URLs Without Downloading**
```bash
python3 jsrecon.py --domain example.com -o js_only/ --skip-download
```
- **Results:** Check `js_only/js/custom_js.txt` for JavaScript URLs.

---

## **Performance & Optimization**
| **Parameter** | **Description** | **Recommended Value** |
|---------------|----------------|-----------------------|
| `--threads` | Increase parallel processing threads | 30-100 |
| `--insecure` | Skip TLS certificate validation | For self-signed certificates |
| `--scan-all-js` | Scan all JavaScript files | When libraries need inspection |
| `--skip-live-check` | Skip live host verification | When using cached results |

---

## **License**
This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

