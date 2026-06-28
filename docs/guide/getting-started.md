# Getting Started

## What is Siphon?

SIPHON is a Go-based utility for discovering, downloading, and analyzing JavaScript files to uncover sensitive data like API keys, tokens, and credentials through passive/active URL collection, brute-forcing, HTML parsing, and secret scanning.

It utilizes a linear workflow to chain multiple tools together, ensuring maximum coverage while filtering out noise.

## Requirements

Before running Siphon, you must have the following tools installed and accessible in your `$PATH`:

### Required Collectors
- `httpx`
- `gau`
- `waybackurls`
- `katana`
- `hakrawler`
- `subjs`
- `cariddi`

### Required Scanners
- `trufflehog`
- `gitleaks`
- `jsluice`
- `nuclei`
- `gf`
- `jsleak`
- `mantra`

You can use the provided `install_tools.sh` to install all dependencies automatically.

## Installation

```bash
git clone https://github.com/infat0x/siphon.git
cd siphon
./install_tools.sh
```

### Build from Source
Ensure you have **Go** (v1.21+) installed on your system.
```bash
go build -o siphon main.go
sudo mv siphon /usr/local/bin/
```

## Usage

**For a single domain:**
```bash
siphon -domain example.com -o output_folder
```

**For a list of subdomains:**
```bash
siphon -s subdomains.txt -o output_folder -t 50
```

### AI Configuration

To enable AI-based false-positive filtering, create a `.env` file (or `~/.siphon.env`) and add your preferred provider:

```env
AI_API_KEY=sk-your-api-key
AI_MODEL=gpt-4o-mini
AI_API_URL=https://api.openai.com/v1/chat/completions
```
