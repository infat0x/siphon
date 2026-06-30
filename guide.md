# Siphon-Go Linux Guide

### 1. Build
Ensure you have **Go** (v1.21+) installed on your system. Open your terminal, navigate to the project directory, and compile the application:

```bash
cd siphon-go
go build -o siphon-go main.go
```

*(This will generate a ready-to-use executable named `siphon-go`)*

### 2. Run
To run the tool on Linux, use `./` followed by the same flags you used in the Python version:

**For a single domain:**
```bash
./siphon-go -domain example.com -o output_folder
```

**For a list of subdomains:**
```bash
./siphon-go -s subdomains.txt -o output_folder -t 50
```

**For AI Analysis on an existing report:**
```bash
./siphon-go -file output_folder/secrets/final_report.txt -ai
```

### 3. Dependencies
Just like the Python version, this tool requires several external security tools. Make sure they are installed and available in your system's PATH (e.g., `/usr/local/bin/` or `$GOPATH/bin/`):
* **Collectors:** `httpx`, `gau`, `waybackurls`, `katana`, `hakrawler`, `subjs`, `cariddi`
* **Scanners:** `trufflehog`, `gitleaks`, `jsluice`, `nuclei`, `gf`, `git-dumper`
