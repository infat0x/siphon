#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                    jsrecon.py  —  JS Recon & Secret Hunter               ║
# ║                              v4  •  Production Grade                     ║
# ╠══════════════════════════════════════════════════════════════════════════╣
# ║  Pipeline:                                                               ║
# ║    subs.txt / --domain → httpx (live check) → URL harvest (gau +         ║
# ║    katana + waybackurls + hakrawler) → active <script> parsing →         ║
# ║    JS brute-force → JS filter → curl/wget download → secret scanning     ║
# ╠══════════════════════════════════════════════════════════════════════════╣
# ║  Usage:                                                                  ║
# ║    python3 jsrecon.py --domain example.com -o output/                    ║
# ║    python3 jsrecon.py --domain example.com -o output/ --insecure         ║
# ║    python3 jsrecon.py -s subs.txt -o output/ [options]                   ║
# ║    python3 jsrecon.py -s subs.txt -o output/ --insecure --threads 50     ║
# ║    python3 jsrecon.py -s subs.txt -o output/ --scan-all-js               ║
# ║    python3 jsrecon.py -s subs.txt -o output/ --skip-live-check           ║
# ║    python3 jsrecon.py -s subs.txt -o output/ --skip-url-collection       ║
# ║    python3 jsrecon.py -s subs.txt -o output/ --skip-download             ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse


# ═══════════════════════════════════════════════════════════════════════════
# ANSI COLOURS
# ═══════════════════════════════════════════════════════════════════════════

RESET  = "\033[0m";  BOLD   = "\033[1m"
GREEN  = "\033[92m"; YELLOW = "\033[93m"
RED    = "\033[91m"; CYAN   = "\033[96m"
BLUE   = "\033[94m"; MAGENTA= "\033[95m"
DIM    = "\033[2m";  WHITE  = "\033[97m"


def clr(text: str, colour: str) -> str:
    return f"{colour}{text}{RESET}"


def ok(msg: str)   -> str: return f"  {GREEN}✔{RESET}  {msg}"
def warn(msg: str) -> str: return f"  {YELLOW}⚠{RESET}  {msg}"
def err(msg: str)  -> str: return f"  {RED}✘{RESET}  {msg}"
def info(msg: str) -> str: return f"  {CYAN}→{RESET}  {msg}"


# ═══════════════════════════════════════════════════════════════════════════
# GLOBAL INSECURE FLAG
# Set once in main() from --insecure arg.  All helpers read this.
# ═══════════════════════════════════════════════════════════════════════════

INSECURE: bool = False   # mutated by main()


# ═══════════════════════════════════════════════════════════════════════════
# TOOL REGISTRY
# ═══════════════════════════════════════════════════════════════════════════

REQUIRED_TOOLS: dict[str, str] = {
    "httpx":      "go install github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "gau":        "go install github.com/lc/gau/v2/cmd/gau@latest",
    "katana":     "go install github.com/projectdiscovery/katana/cmd/katana@latest",
    "gf":         "go install github.com/tomnomnom/gf@latest",
    "trufflehog": "https://github.com/trufflesecurity/trufflehog/releases",
}

OPTIONAL_TOOLS: dict[str, str] = {
    "curl":        "pre-installed on most systems",
    "wget":        "apt install wget  /  brew install wget",
    "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
    "hakrawler":   "go install github.com/hakluke/hakrawler@latest",
    "anew":        "go install github.com/tomnomnom/anew@latest",
}

GAU_PROVIDERS = "wayback,commoncrawl,otx,urlscan"


# ═══════════════════════════════════════════════════════════════════════════
# FILTER PATTERNS
# ═══════════════════════════════════════════════════════════════════════════

JS_EXCLUDE_RE = re.compile(
    r"jquery|react(?:\.js|-dom|-router)?|angular(?:js)?|vue\.js|ember|backbone|"
    r"bootstrap|lodash|underscore|moment\.js|axios|webpack|babel|polyfill|"
    r"modernizr|d3\.js|three\.js|chart\.js|socket\.io|amplify|"
    r"google-analytics|gtag|gtm|fbevents|recaptcha|stripe|twilio|"
    r"intercom|sentry|datadog|newrelic|hotjar|gsap|swiper|slick|"
    r"fontawesome|material-ui|tailwind|semantic\.js|foundation|"
    r"\.min\.js|/vendor/|/bundle|/chunk|/node_modules/|/bower_components/|"
    r"\.[a-f0-9]{8,}\.js|-[a-f0-9]{8,}\.js|"
    r"runtime\.|/common\.|manifest\.|/framework\.|/lib/|/libs/",
    re.IGNORECASE,
)

SECRET_PATTERNS: dict[str, str] = {
    "AWS Access Key":      r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":      r"(?i)aws.{0,30}secret.{0,30}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Google API Key":      r"AIza[0-9A-Za-z\-_]{35}",
    "GitHub Token":        r"gh[pousr]_[A-Za-z0-9_]{36,}",
    "Slack Token":         r"xox[baprs]-[0-9A-Za-z\-]{10,}",
    "Slack Webhook":       r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+",
    "Stripe Key":          r"(?:sk|pk)_(test|live)_[0-9a-zA-Z]{24,}",
    "SendGrid Key":        r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
    "JWT Token":           r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+",
    "Bearer Token":        r"[Bb]earer\s+[A-Za-z0-9\-_\.]{20,}",
    "Private Key Block":   r"-----BEGIN\s(?:RSA\s)?PRIVATE KEY-----",
    "Password in URL":     r"[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@",
    "Firebase URL":        r"https?://[a-z0-9\-]+\.firebaseio\.com",
    "Mailgun Key":         r"key-[0-9a-zA-Z]{32}",
    "NPM Token":           r"npm_[A-Za-z0-9]{36}",
    "Telegram Bot Token":  r"[0-9]{8,10}:[a-zA-Z0-9_\-]{35}",
    "Twilio Account SID":  r"AC[a-zA-Z0-9]{32}",
    "Twilio Auth Token":   r"(?i)twilio.{0,20}['\"][a-f0-9]{32}['\"]",
    "Heroku API Key":      r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "Azure Storage Key":   r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
    "DigitalOcean Token":  r"dop_v1_[a-f0-9]{64}",
    "Cloudinary URL":      r"cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[a-z0-9]+",
    "Generic API Key":     r"(?i)(?:api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|secret[_\-]?key)['\"\s:=]+([A-Za-z0-9_\-]{20,})",
    "Generic Secret":      r"(?i)(?:secret|password|passwd|pwd)\s*[=:]\s*['\"]([A-Za-z0-9_\-!@#$%^&*]{12,})['\"]",
}

FALSE_POSITIVE_RE = re.compile(
    r"^[a-z_\-]+$|^[0-9\.]+$|example\.com|localhost|placeholder|"
    r"your[_\-]?key|my[_\-]?secret|<[A-Z_]+>|\$\{[A-Z_]+\}|"
    r"xxx+|test[_\-]key|dummy|changeme|insert[_\-]here|"
    r"REPLACE_ME|TODO|FIXME|\*{4,}",
    re.IGNORECASE,
)

COMMON_JS_PATHS: list[str] = [
    "/app.js","/main.js","/index.js","/bundle.js","/init.js",
    "/config.js","/settings.js","/env.js","/constants.js",
    "/api.js","/utils.js","/helpers.js","/common.js","/global.js",
    "/auth.js","/router.js","/routes.js","/store.js","/services.js",
    "/js/app.js","/js/main.js","/js/index.js","/js/config.js",
    "/js/api.js","/js/utils.js","/js/helpers.js","/js/auth.js",
    "/static/js/app.js","/static/js/main.js","/static/js/index.js",
    "/assets/js/app.js","/assets/js/main.js","/assets/js/config.js",
    "/assets/js/api.js","/assets/js/utils.js",
    "/dist/app.js","/dist/main.js","/dist/bundle.js",
    "/build/app.js","/build/main.js","/build/bundle.js",
    "/public/js/app.js","/public/js/main.js",
    "/src/app.js","/src/main.js","/src/index.js",
    "/v1/app.js","/v2/app.js","/api/config.js",
    "/wp-content/themes/app.js","/wp-includes/js/api.js",
]

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


# ═══════════════════════════════════════════════════════════════════════════
# BANNER
# ═══════════════════════════════════════════════════════════════════════════

def banner() -> None:
    print(f"""{BOLD}{RED}
   ██╗███████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
   ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
   ██║███████╗██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
   ██║╚════██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
   ██║███████║██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
   ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{RESET}{DIM}   v4  •  JS Recon & Secret Hunter  •  curl/wget downloader{RESET}
   {DIM}gau + katana + waybackurls + hakrawler + active scrape + brute{RESET}
""")


# ═══════════════════════════════════════════════════════════════════════════
# TOOL CHECK
# ═══════════════════════════════════════════════════════════════════════════

def check_tools() -> bool:
    print(f"\n{BOLD}  Tool Check{RESET}")
    print(f"  {'─'*50}")

    missing = []
    for tool, install in REQUIRED_TOOLS.items():
        found = shutil.which(tool)
        if found:
            print(f"  {GREEN}✔{RESET}  {BOLD}{tool:<16}{RESET} {DIM}{found}{RESET}")
        else:
            missing.append((tool, install))
            print(f"  {RED}✘{RESET}  {BOLD}{tool:<16}{RESET} {DIM}→ {install}{RESET}")

    print()
    for tool, install in OPTIONAL_TOOLS.items():
        found = shutil.which(tool)
        status = f"{GREEN}✔{RESET}" if found else f"{YELLOW}~{RESET}"
        label  = DIM + "optional" + RESET if not found else ""
        print(f"  {status}  {tool:<16} {label}")

    print()
    if missing:
        print(clr(f"  [!] {len(missing)} required tool(s) missing. Install them and retry.\n", RED))
        return False

    # Detect download backend
    if shutil.which("curl"):
        print(info(f"Download backend : {BOLD}curl{RESET}"))
    elif shutil.which("wget"):
        print(info(f"Download backend : {BOLD}wget{RESET}"))
    else:
        print(warn("Neither curl nor wget found — using Python urllib as fallback"))

    return True


# ═══════════════════════════════════════════════════════════════════════════
# DIRECTORY SETUP
# ═══════════════════════════════════════════════════════════════════════════

def setup_dirs(base: Path) -> dict[str, Path]:
    dirs: dict[str, Path] = {
        "base":    base,
        "live":    base / "live",
        "urls":    base / "urls",
        "js":      base / "js",
        "dl":      base / "js" / "downloaded",
        "secrets": base / "secrets",
        "raw":     base / "secrets" / "raw",
        "logs":    base / "logs",
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    return dirs


# ═══════════════════════════════════════════════════════════════════════════
# LOGGER
# ═══════════════════════════════════════════════════════════════════════════

def setup_logger(log_dir: Path) -> logging.Logger:
    log = logging.getLogger("jsrecon")
    log.setLevel(logging.DEBUG)
    fh = logging.FileHandler(
        log_dir / f"run_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    )
    fh.setFormatter(logging.Formatter("%(asctime)s  [%(levelname)-8s]  %(message)s"))
    log.addHandler(fh)
    return log


# ═══════════════════════════════════════════════════════════════════════════
# PROGRESS BAR
# ═══════════════════════════════════════════════════════════════════════════

class ProgressBar:
    WIDTH = 36

    def __init__(self, total: int, label: str = ""):
        self.total = max(total, 1)
        self.label = label
        self.n     = 0
        self.t0    = time.time()

    def update(self, n: int = 1, suffix: str = "") -> None:
        self.n = min(self.n + n, self.total)
        pct    = self.n / self.total
        done   = int(self.WIDTH * pct)
        bar    = f"{GREEN}{'█' * done}{DIM}{'░' * (self.WIDTH - done)}{RESET}"
        elapsed = time.time() - self.t0
        eta_s   = (elapsed / self.n * (self.total - self.n)) if self.n else 0
        eta_str = f"ETA {int(eta_s)}s" if eta_s < 3600 else f"ETA {eta_s / 3600:.1f}h"

        line = (
            f"\r  {BOLD}{self.label:<22}{RESET}"
            f"[{bar}] {CYAN}{pct * 100:5.1f}%{RESET}"
            f"  {self.n}/{self.total}  {DIM}{eta_str}  {suffix}{RESET}"
        )
        sys.stdout.write(line)
        sys.stdout.flush()

        if self.n >= self.total:
            sys.stdout.write(
                f"\r  {BOLD}{self.label:<22}{RESET}"
                f"[{GREEN}{'█' * self.WIDTH}{RESET}]"
                f" {GREEN}100.0%{RESET}  done in {elapsed:.1f}s"
                f"{'                    '}\n"
            )
            sys.stdout.flush()


# ═══════════════════════════════════════════════════════════════════════════
# HTTP HELPERS  (curl → wget → urllib fallback)
# Respects global INSECURE flag:
#   curl  → adds  -k / --insecure
#   wget  → adds  --no-check-certificate  (already default, kept explicit)
#   urllib → wraps with ssl.create_default_context(check_hostname=False)
# ═══════════════════════════════════════════════════════════════════════════

def _curl_fetch(url: str, timeout: int, head_only: bool = False) -> Optional[bytes]:
    """
    Primary downloader: curl.

    --insecure / -k  added when global INSECURE=True — skips TLS cert
                     verification (self-signed certs, internal CAs, etc.)
    """
    cmd = [
        "curl",
        "--silent",
        "--location",
        "--compressed",
        "--max-time",    str(timeout),
        "--retry",       "2",
        "--retry-delay", "1",
        "--fail",
        "--user-agent",  USER_AGENT,
        "--header",      "Accept: */*",
        "--max-filesize","15728640",   # 15 MB
    ]
    if INSECURE:
        cmd.append("--insecure")      # -k  skip TLS verification
    if head_only:
        cmd.append("--head")
    else:
        cmd += ["--output", "-"]      # write to stdout
    cmd.append(url)

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 10)
        return result.stdout if result.returncode == 0 else None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def _wget_fetch(url: str, timeout: int) -> Optional[bytes]:
    """
    Fallback downloader: wget.
    --no-check-certificate  skip TLS verification when INSECURE=True.
    """
    cmd = [
        "wget",
        "--quiet",
        f"--timeout={timeout}",
        "--tries=2",
        f"--user-agent={USER_AGENT}",
        "--no-check-certificate",     # always set; harmless for valid certs
        "-O", "-",
        url,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 10)
        return result.stdout if result.returncode == 0 else None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def _urllib_fetch(url: str, timeout: int) -> Optional[bytes]:
    """
    Last-resort fallback using stdlib urllib.
    Creates an unverified SSL context when INSECURE=True.
    """
    import ssl
    import urllib.request as ureq

    ctx: Optional[ssl.SSLContext] = None
    if INSECURE:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

    try:
        req = ureq.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
        with ureq.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read(15 * 1024 * 1024)   # 15 MB cap
    except Exception:
        return None


def fetch(url: str, timeout: int = 15) -> Optional[str]:
    """
    Download URL content as a decoded string.
    Tries curl → wget → urllib in order.
    Returns None on any failure.
    """
    raw: Optional[bytes] = None

    if shutil.which("curl"):
        raw = _curl_fetch(url, timeout)
    if raw is None and shutil.which("wget"):
        raw = _wget_fetch(url, timeout)
    if raw is None:
        raw = _urllib_fetch(url, timeout)

    if raw and len(raw) > 50:
        return raw.decode("utf-8", errors="replace")
    return None


def head_ok(url: str, timeout: int = 8) -> bool:
    """
    Probe whether a URL exists and is JavaScript.
    Uses curl --head (fast, no body download).
    Passes --insecure when INSECURE=True.
    """
    if shutil.which("curl"):
        cmd = [
            "curl",
            "--silent", "--head",
            "--location",
            f"--max-time={timeout}",
            "--fail",
            f"--user-agent={USER_AGENT}",
            "--write-out", "%{http_code}|||%{content_type}",
            "--output", "/dev/null",
        ]
        if INSECURE:
            cmd.append("--insecure")
        cmd.append(url)

        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 3)
            out = r.stdout.strip()
            if "|||" in out:
                code, ct = out.rsplit("|||", 1)
                return (
                    code.strip() == "200"
                    and ("javascript" in ct or "ecmascript" in ct or url.endswith(".js"))
                )
        except Exception:
            pass

    content = fetch(url, timeout=timeout)
    return bool(content and len(content) > 50)


def url_to_filename(url: str, dl_dir: Path) -> Path:
    """Convert a URL to a safe, deterministic filename inside dl_dir."""
    parsed   = urlparse(url)
    raw_name = f"{parsed.netloc}{parsed.path}".lstrip("/")
    raw_name = re.sub(r"[^\w.\-]", "_", raw_name)[:160]
    uid      = hashlib.sha256(url.encode()).hexdigest()[:6]
    filename = f"{uid}_{raw_name}"
    if not filename.endswith(".js"):
        filename += ".js"
    return dl_dir / filename


# ═══════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def is_js_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return path.endswith(".js") or ".js?" in path or ".js#" in path


def dedup(lst: list) -> list:
    seen: set = set()
    out: list = []
    for x in lst:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def normalise_host(host: str) -> str:
    """
    Ensure a host string is a proper URL (adds https:// if missing).
    Accepts bare domain: example.com  →  https://example.com
    """
    host = host.strip()
    if not host.startswith("http://") and not host.startswith("https://"):
        host = "https://" + host
    return host.rstrip("/")


def bare_domain(host: str) -> str:
    """Extract just the netloc/domain from a URL or bare domain string."""
    parsed = urlparse(normalise_host(host))
    return parsed.netloc or host.replace("https://", "").replace("http://", "").rstrip("/")


# ═══════════════════════════════════════════════════════════════════════════
# STEP 1 — LIVE HOST DETECTION
# ═══════════════════════════════════════════════════════════════════════════

def run_httpx(subs_file: Path, live_file: Path,
              threads: int, log: logging.Logger) -> list[str]:
    print(clr(f"\n{'━'*60}", DIM))
    print(clr("  [1/5]  Live Host Detection  →  httpx", BOLD))
    if INSECURE:
        print(clr("         ⚠  TLS verification disabled (--insecure)", YELLOW))
    print(clr(f"{'━'*60}", DIM))

    cmd = [
        "httpx",
        "-l",            str(subs_file),
        "-threads",      str(threads),
        "-silent",
        "-no-color",
        "-o",            str(live_file),
        "-timeout",      "10",
        "-retries",      "2",
        "-follow-redirects",
        "-status-code",
        "-title",
        "-tech-detect",
        "-web-server",
    ]
    if INSECURE:
        cmd.append("-no-verify-ssl")   # httpx flag for skipping TLS verification

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired:
        print(err("httpx timed out — partial results may be used"))

    live: list[str] = []
    if live_file.exists():
        for line in live_file.read_text().splitlines():
            url = line.strip().split(" ")[0]
            if url.startswith("http"):
                live.append(url)
        live = dedup(live)
        live_file.write_text("\n".join(live) + "\n")

    print(ok(f"{BOLD}{len(live)}{RESET} live hosts  →  {DIM}{live_file}{RESET}"))
    log.info("httpx: %d live hosts", len(live))
    return live


# ═══════════════════════════════════════════════════════════════════════════
# STEP 2 — URL COLLECTION
# ═══════════════════════════════════════════════════════════════════════════

def run_gau(host: str, timeout: int = 120) -> list[str]:
    """
    Passive URL harvesting from wayback, commoncrawl, otx, urlscan.

    Note: gau does not have a native --insecure flag; it queries public
    archives (not the target directly), so TLS to the target is not
    relevant here.  The archives themselves use valid TLS.
    """
    bare = bare_domain(host)
    cmd = [
        "gau",
        "--providers", GAU_PROVIDERS,
        "--threads",   "5",
        "--retries",   "3",
        "--timeout",   str(timeout),
        "--blacklist", "ttf,woff,woff2,eot,svg,png,jpg,jpeg,gif,ico,css,pdf,mp4,mp3,zip",
        bare,
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 30)
        return [l.strip() for l in r.stdout.splitlines() if l.strip().startswith("http")]
    except Exception:
        return []


def run_katana(url: str, timeout: int = 120) -> list[str]:
    """
    Active crawler with headless JS engine.
    -no-sandbox and -ignore-query-params added.
    -insecure passed when INSECURE=True.
    """
    cmd = [
        "katana",
        "-u",           url,
        "-jc",
        "-kf",          "all",
        "-aff",
        "-depth",       "5",
        "-concurrency", "20",
        "-parallelism", "10",
        "-timeout",     str(timeout),
        "-silent",
        "-no-color",
        "-ef",          "css,png,jpg,jpeg,gif,ico,svg,ttf,woff,woff2,eot,pdf,mp4,mp3,zip",
        "-strategy",    "depth-first",
    ]
    if INSECURE:
        cmd.append("-insecure")        # katana flag for skipping TLS verification

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 30)
        return [l.strip() for l in r.stdout.splitlines() if l.strip().startswith("http")]
    except Exception:
        return []


def run_waybackurls(host: str, timeout: int = 90) -> list[str]:
    if not shutil.which("waybackurls"):
        return []
    bare = bare_domain(host)
    try:
        r = subprocess.run(
            ["waybackurls", bare],
            capture_output=True, text=True, timeout=timeout,
        )
        return [l.strip() for l in r.stdout.splitlines() if l.strip().startswith("http")]
    except Exception:
        return []


def run_hakrawler(url: str, timeout: int = 90) -> list[str]:
    if not shutil.which("hakrawler"):
        return []
    cmd = ["hakrawler", "-url", url, "-depth", "3", "-js", "-plain"]
    if INSECURE:
        cmd.append("-insecure")        # hakrawler supports -insecure

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return [l.strip() for l in r.stdout.splitlines() if l.strip().startswith("http")]
    except Exception:
        return []


# ── Active <script src="…"> extraction ──────────────────────────────────────

class ScriptTagParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.srcs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        if tag.lower() == "script":
            for k, v in attrs:
                if k.lower() == "src" and v and not v.startswith("data:"):
                    self.srcs.append(v.strip())


def parse_script_tags(base_url: str, html: str) -> list[str]:
    parser = ScriptTagParser()
    try:
        parser.feed(html)
    except Exception:
        pass
    parsed = urlparse(base_url)
    out: list[str] = []
    for src in parser.srcs:
        if src.startswith("//"):
            src = f"{parsed.scheme}:{src}"
        elif not src.startswith("http"):
            src = urljoin(base_url, src)
        out.append(src)
    return out


def active_html_scrape(live_hosts: list[str], threads: int,
                       log: logging.Logger) -> list[str]:
    """Fetch every live host's HTML and extract <script src="…"> tags."""
    print(info("Active HTML scrape  <script src> extraction …"))
    found: set[str] = set()
    pb = ProgressBar(len(live_hosts), "HTML scrape")

    def scrape(url: str) -> list[str]:
        html = fetch(url, timeout=15)
        return parse_script_tags(url, html) if html else []

    with ThreadPoolExecutor(max_workers=min(threads, 30)) as ex:
        futs = {ex.submit(scrape, u): u for u in live_hosts}
        for fut in as_completed(futs):
            try:
                found.update(fut.result())
            except Exception:
                pass
            pb.update(1, f"({len(found)} scripts)")

    log.info("HTML scrape: %d script URLs", len(found))
    return list(found)


def brute_js_paths(live_hosts: list[str], threads: int,
                   log: logging.Logger) -> list[str]:
    """Probe common JS paths on every live host using curl --head."""
    print(info(f"Brute-force  {len(COMMON_JS_PATHS)} common JS paths …"))
    tasks = [h.rstrip("/") + p for h in live_hosts for p in COMMON_JS_PATHS]
    found: list[str] = []
    pb = ProgressBar(len(tasks), "JS path brute")

    with ThreadPoolExecutor(max_workers=min(threads, 60)) as ex:
        futs = {ex.submit(head_ok, u): u for u in tasks}
        for fut in as_completed(futs):
            url = futs[fut]
            try:
                if fut.result():
                    found.append(url)
            except Exception:
                pass
            pb.update(1, f"({len(found)} found)")

    log.info("Brute JS paths: %d", len(found))
    return found


def collect_urls(live_hosts: list[str], urls_file: Path,
                 threads: int, log: logging.Logger) -> list[str]:
    print(clr(f"\n{'━'*60}", DIM))
    print(clr("  [2/5]  URL Collection", BOLD))
    print(clr(f"{'━'*60}", DIM))
    print(info(f"Sources: {DIM}gau ({GAU_PROVIDERS})  katana (-jc)  "
               f"waybackurls  hakrawler  active-HTML{RESET}\n"))
    log.info("URL collection: %d hosts", len(live_hosts))

    all_urls: set[str] = set()

    tasks = [
        (tool, host)
        for host in live_hosts
        for tool in ("gau", "katana", "waybackurls", "hakrawler")
    ]
    pb = ProgressBar(len(tasks), "Passive sources")

    def _passive(args: tuple[str, str]) -> list[str]:
        tool, target = args
        dispatch = {
            "gau":         run_gau,
            "katana":      run_katana,
            "waybackurls": run_waybackurls,
            "hakrawler":   run_hakrawler,
        }
        return dispatch[tool](target)

    with ThreadPoolExecutor(max_workers=min(threads, 24)) as ex:
        futs = {ex.submit(_passive, t): t for t in tasks}
        for fut in as_completed(futs):
            try:
                all_urls.update(fut.result())
            except Exception as exc:
                log.debug("passive error: %s", exc)
            pb.update(1, f"({len(all_urls)} urls)")

    scripts = active_html_scrape(live_hosts, threads, log)
    all_urls.update(scripts)
    print(ok(f"Active HTML scrape   +{len(scripts):,} script URLs"))

    result = dedup(sorted(all_urls))
    urls_file.write_text("\n".join(result) + "\n")
    print(ok(f"Total unique URLs    {BOLD}{len(result):,}{RESET}  →  {DIM}{urls_file}{RESET}"))
    log.info("URL collection: %d unique", len(result))
    return result


# ═══════════════════════════════════════════════════════════════════════════
# STEP 3 — JS EXTRACTION + BRUTE + FILTER
# ═══════════════════════════════════════════════════════════════════════════

def extract_js_urls(
    all_urls: list[str],
    live_hosts: list[str],
    js_dir: Path,
    threads: int,
    log: logging.Logger,
) -> tuple[list[str], list[str]]:
    print(clr(f"\n{'━'*60}", DIM))
    print(clr("  [3/5]  JS Extraction & Filtering", BOLD))
    print(clr(f"{'━'*60}", DIM))

    js_set: set[str] = {u for u in all_urls if is_js_url(u)}
    print(ok(f"From URL collection    {len(js_set):,}"))

    brute = brute_js_paths(live_hosts, threads, log)
    js_set.update(brute)
    print(ok(f"From brute-force paths +{len(brute):,}"))

    js_all    = dedup(sorted(js_set))
    js_custom = [u for u in js_all if not JS_EXCLUDE_RE.search(u)]

    (js_dir / "js_urls.txt").write_text("\n".join(js_all)    + "\n")
    (js_dir / "custom_js.txt").write_text("\n".join(js_custom) + "\n")

    print(ok(f"JS total (all)         {BOLD}{len(js_all):,}{RESET}"))
    print(ok(f"JS custom (no libs)    {BOLD}{len(js_custom):,}{RESET}"))
    log.info("JS: all=%d  custom=%d", len(js_all), len(js_custom))
    return js_all, js_custom


# ═══════════════════════════════════════════════════════════════════════════
# STEP 4 — DOWNLOAD JS FILES TO DISK
# ═══════════════════════════════════════════════════════════════════════════

def download_js(
    js_urls: list[str],
    dl_dir: Path,
    threads: int,
    log: logging.Logger,
) -> dict[str, Path]:
    """Download every JS URL and save to dl_dir with a deterministic filename."""
    print(clr(f"\n{'━'*60}", DIM))
    print(clr("  [4/5]  Downloading JS Files  →  disk", BOLD))
    if INSECURE:
        print(clr("         ⚠  TLS verification disabled (--insecure)", YELLOW))
    print(clr(f"{'━'*60}", DIM))

    backend = (
        "curl" if shutil.which("curl") else
        "wget" if shutil.which("wget") else
        "urllib"
    )
    insecure_tag = f"  {YELLOW}[insecure]{RESET}" if INSECURE else ""
    print(info(f"Backend: {BOLD}{backend}{RESET}{insecure_tag}   target: {BOLD}{dl_dir}{RESET}\n"))
    log.info("Downloading %d JS files via %s (insecure=%s)", len(js_urls), backend, INSECURE)

    downloaded: dict[str, Path] = {}
    failed: list[str] = []
    pb = ProgressBar(len(js_urls), "Downloading JS")

    def _download_one(url: str) -> tuple[str, Optional[Path]]:
        content = fetch(url, timeout=20)
        if not content or len(content) < 50:
            return url, None
        filepath = url_to_filename(url, dl_dir)
        try:
            filepath.write_text(content, encoding="utf-8", errors="replace")
            return url, filepath
        except OSError as exc:
            log.debug("write error %s: %s", filepath, exc)
            return url, None

    with ThreadPoolExecutor(max_workers=min(threads, 40)) as ex:
        futs = {ex.submit(_download_one, u): u for u in js_urls}
        for fut in as_completed(futs):
            url, path = fut.result()
            if path:
                downloaded[url] = path
            else:
                failed.append(url)
            pb.update(1, f"({len(downloaded)} ok  {len(failed)} fail)")

    if failed:
        (dl_dir / "_failed.txt").write_text("\n".join(failed) + "\n")

    total_size = sum(p.stat().st_size for p in downloaded.values()) / 1024
    print(ok(f"Downloaded  : {BOLD}{len(downloaded)}{RESET}/{len(js_urls)}  "
             f"({total_size:.1f} KB total)"))
    print(ok(f"Saved to    : {BOLD}{dl_dir}{RESET}"))
    if failed:
        print(warn(f"Failed      : {len(failed)}  →  {DIM}{dl_dir}/_failed.txt{RESET}"))

    log.info("Downloaded: %d  failed: %d  size: %.1f KB", len(downloaded), len(failed), total_size)
    return downloaded


# ═══════════════════════════════════════════════════════════════════════════
# STEP 5 — SECRET SCANNING
# ═══════════════════════════════════════════════════════════════════════════

Finding = dict[str, str]


def scan_regex(dl_map: dict[str, Path], raw_dir: Path,
               log: logging.Logger) -> list[Finding]:
    findings: list[Finding] = []
    compiled = {name: re.compile(pat) for name, pat in SECRET_PATTERNS.items()}

    for url, filepath in dl_map.items():
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for name, rx in compiled.items():
            for m in rx.finditer(content):
                snippet = m.group(0)[:200]
                if len(snippet) < 12 or FALSE_POSITIVE_RE.search(snippet):
                    continue
                findings.append({
                    "tool":  "regex",
                    "type":  name,
                    "url":   url,
                    "file":  str(filepath),
                    "match": snippet,
                    "line":  str(content[: m.start()].count("\n") + 1),
                })

    (raw_dir / "regex_findings.json").write_text(json.dumps(findings, indent=2))
    log.info("regex: %d findings", len(findings))
    return findings


def scan_gf(dl_map: dict[str, Path], raw_dir: Path,
            log: logging.Logger) -> list[Finding]:
    if not shutil.which("gf"):
        return []

    lines_list: list[str] = []
    for url, filepath in dl_map.items():
        try:
            for line in filepath.read_text(encoding="utf-8", errors="replace").splitlines():
                lines_list.append(f"{url}: {line}")
        except OSError:
            continue
    combined = "\n".join(lines_list)

    GF_PATTERNS = [
        "aws-keys", "base64", "cors", "firebase", "json-sec", "jwt",
        "php-errors", "rce", "redirect", "s3-buckets", "secrets",
        "servers", "sqli", "ssrf", "ssti", "takeovers", "xss",
    ]
    findings: list[Finding] = []
    for pat in GF_PATTERNS:
        try:
            r = subprocess.run(
                ["gf", pat],
                input=combined, capture_output=True, text=True, timeout=60,
            )
            if r.stdout.strip():
                (raw_dir / f"gf_{pat}.txt").write_text(r.stdout)
                for line in r.stdout.splitlines():
                    if line.strip():
                        findings.append({
                            "tool":  "gf",
                            "type":  pat,
                            "url":   line.split(":")[0],
                            "file":  "",
                            "match": line[:300],
                            "line":  "",
                        })
        except Exception:
            pass

    log.info("gf: %d findings", len(findings))
    return findings


def scan_trufflehog(dl_dir: Path, raw_dir: Path,
                    log: logging.Logger) -> list[Finding]:
    if not shutil.which("trufflehog"):
        return []
    findings: list[Finding] = []
    try:
        r = subprocess.run(
            [
                "trufflehog", "filesystem",
                "--directory",    str(dl_dir),
                "--json",
                "--no-update",
                "--only-verified",
            ],
            capture_output=True, text=True, timeout=300,
        )
        (raw_dir / "trufflehog.json").write_text(r.stdout)
        for line in r.stdout.splitlines():
            try:
                obj = json.loads(line)
                findings.append({
                    "tool":  "trufflehog",
                    "type":  obj.get("DetectorName", "unknown"),
                    "url":   str(obj.get("SourceMetadata", ""))[:200],
                    "file":  str(obj.get("SourceMetadata", ""))[:200],
                    "match": str(obj.get("Raw", ""))[:200],
                    "line":  "",
                })
            except Exception:
                pass
    except Exception as exc:
        log.warning("trufflehog: %s", exc)

    log.info("trufflehog: %d findings", len(findings))
    return findings


def _find_secretfinder() -> Optional[str]:
    candidates = [
        "SecretFinder.py",
        os.path.expanduser("~/tools/SecretFinder/SecretFinder.py"),
        "/opt/SecretFinder/SecretFinder.py",
    ]
    for p in candidates:
        if Path(p).exists():
            return p
    return shutil.which("SecretFinder.py")


def scan_secretfinder(dl_map: dict[str, Path], raw_dir: Path,
                      log: logging.Logger) -> list[Finding]:
    sf = _find_secretfinder()
    if not sf:
        return []
    findings: list[Finding] = []
    pb = ProgressBar(len(dl_map), "SecretFinder")
    for url, filepath in dl_map.items():
        try:
            r = subprocess.run(
                ["python3", sf, "-i", str(filepath), "-o", "cli"],
                capture_output=True, text=True, timeout=30,
            )
            for line in r.stdout.splitlines():
                if line.strip() and not line.startswith("["):
                    findings.append({
                        "tool":  "SecretFinder",
                        "type":  "auto",
                        "url":   url,
                        "file":  str(filepath),
                        "match": line[:300],
                        "line":  "",
                    })
        except Exception:
            pass
        pb.update(1)

    log.info("SecretFinder: %d findings", len(findings))
    return findings


def dedup_findings(lst: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    out: list[Finding] = []
    for f in lst:
        key = f"{f.get('type', '')}|{f.get('match', '')[:80]}"
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def write_report(
    all_findings: list[Finding],
    report_file: Path,
    stats: dict,
    log: logging.Logger,
) -> None:
    high_conf = dedup_findings([
        f for f in all_findings
        if len(f.get("match", "")) >= 12
        and not FALSE_POSITIVE_RE.search(f.get("match", ""))
    ])

    by_type: dict[str, list[Finding]] = {}
    for f in high_conf:
        by_type.setdefault(f["type"], []).append(f)

    sep   = "═" * 70
    lines = [
        sep,
        "  JS RECON SECRET HUNTER  —  FINAL REPORT",
        f"  Generated      : {datetime.now():%Y-%m-%d  %H:%M:%S}",
        f"  Mode           : {'single-domain' if stats.get('single_domain') else 'multi-subdomain'}",
        f"  TLS verify     : {'disabled (--insecure)' if INSECURE else 'enabled'}",
        f"  Live hosts     : {stats.get('live', 0):,}",
        f"  URLs collected : {stats.get('urls', 0):,}",
        f"  JS files total : {stats.get('js_all', 0):,}",
        f"  JS custom      : {stats.get('js_custom', 0):,}",
        f"  JS downloaded  : {stats.get('js_dl', 0):,}",
        f"  Raw findings   : {len(all_findings):,}",
        f"  High-confidence: {len(high_conf):,}",
        sep, "",
    ]

    if not high_conf:
        lines += [
            "  No high-confidence secrets found.",
            "  ─ Check secrets/raw/regex_findings.json for raw matches.",
            "  ─ Check secrets/raw/trufflehog.json for TruffleHog output.",
            "",
        ]
    else:
        for stype, items in sorted(by_type.items(), key=lambda x: -len(x[1])):
            lines += [
                f"┌─  {stype}  ({len(items)} finding{'s' if len(items) > 1 else ''})",
            ]
            for item in items:
                lines += [
                    f"│   Tool  : {item.get('tool', '─')}",
                    f"│   URL   : {item.get('url', '─')}",
                    f"│   File  : {item.get('file', '─')}",
                    f"│   Line  : {item.get('line', '─')}",
                    f"│   Match : {item.get('match', '─')[:150]}",
                    "│",
                ]
            lines.append("")

    report_file.write_text("\n".join(lines))
    print(ok(f"Report           →  {BOLD}{report_file}{RESET}"))
    print(ok(f"High-confidence findings : {BOLD}{len(high_conf)}{RESET}"))
    log.info("Report: %d high-confidence findings", len(high_conf))


def run_secret_scanning(
    dl_map: dict[str, Path],
    dirs: dict[str, Path],
    stats: dict,
    log: logging.Logger,
) -> None:
    print(clr(f"\n{'━'*60}", DIM))
    print(clr("  [5/5]  Secret Scanning  (all tools in parallel)", BOLD))
    print(clr(f"{'━'*60}", DIM))

    all_findings: list[Finding] = []

    with ThreadPoolExecutor(max_workers=4) as ex:
        futs: dict = {
            ex.submit(scan_regex,        dl_map, dirs["raw"], log): "regex",
            ex.submit(scan_gf,           dl_map, dirs["raw"], log): "gf",
            ex.submit(scan_trufflehog,   dirs["dl"], dirs["raw"], log): "trufflehog",
            ex.submit(scan_secretfinder, dl_map, dirs["raw"], log): "SecretFinder",
        }
        for fut in as_completed(futs):
            tool = futs[fut]
            try:
                res = fut.result()
                all_findings.extend(res)
                icon = GREEN + "✔" + RESET if res else DIM + "─" + RESET
                print(f"  {icon}  {tool:<16} {len(res):>5} findings")
            except Exception as exc:
                log.warning("%s error: %s", tool, exc)
                print(warn(f"{tool:<16} skipped ({exc})"))

    write_report(all_findings, dirs["secrets"] / "final_report.txt", stats, log)


# ═══════════════════════════════════════════════════════════════════════════
# ARGUMENT PARSING
# ═══════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="jsrecon",
        description="JS Recon & Secret Hunter  —  v4  (curl/wget downloader)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Single domain scan
  python3 jsrecon.py --domain example.com -o out/
  python3 jsrecon.py --domain https://example.com -o out/ --insecure

  # Multi-subdomain scan from file
  python3 jsrecon.py -s subs.txt -o out/
  python3 jsrecon.py -s subs.txt -o out/ --insecure --threads 50

  # Advanced options
  python3 jsrecon.py --domain example.com -o out/ --scan-all-js
  python3 jsrecon.py -s subs.txt -o out/ --skip-live-check
  python3 jsrecon.py -s subs.txt -o out/ --skip-url-collection
  python3 jsrecon.py -s subs.txt -o out/ --skip-download
        """,
    )

    # ── Input (mutually exclusive: --domain OR -s/--subs) ─────────────────
    input_grp = ap.add_mutually_exclusive_group(required=True)
    input_grp.add_argument(
        "-d", "--domain",
        metavar="HOST",
        help="Single domain/host to scan  (e.g. example.com or https://example.com)",
    )
    input_grp.add_argument(
        "-s", "--subs",
        metavar="FILE",
        help="Path to subdomains list (one per line)",
    )

    ap.add_argument("-o", "--output",  required=True,  metavar="DIR",
                    help="Output directory")
    ap.add_argument("-t", "--threads", type=int, default=30, metavar="N",
                    help="Concurrent worker threads (default: 30)")
    ap.add_argument(
        "--insecure",
        action="store_true",
        help=(
            "Disable TLS/SSL certificate verification. "
            "Useful for self-signed certs or internal targets. "
            "Passed as: curl -k / wget --no-check-certificate / "
            "httpx -no-verify-ssl / katana -insecure / hakrawler -insecure"
        ),
    )
    ap.add_argument("--scan-all-js", action="store_true",
                    help="Scan ALL JS files including known libraries")
    ap.add_argument("--skip-live-check", action="store_true",
                    help="Skip httpx — reuse existing live.txt")
    ap.add_argument("--skip-url-collection", action="store_true",
                    help="Skip URL harvest — reuse existing all_urls.txt")
    ap.add_argument("--skip-download", action="store_true",
                    help="Stop after JS extraction (no download or scanning)")
    return ap.parse_args()


# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════

def main() -> None:
    global INSECURE

    args = parse_args()

    # ── Apply global insecure flag ─────────────────────────────────────────
    INSECURE = args.insecure

    banner()

    # ── Resolve input: --domain or --subs ─────────────────────────────────
    single_domain: bool = False
    subs_file: Path

    if args.domain:
        # Single-domain mode: create a temporary subs file with one entry
        single_domain = True
        domain_url = normalise_host(args.domain)
        tmp_subs   = Path(args.output) / "_domain_input.txt"
        tmp_subs.parent.mkdir(parents=True, exist_ok=True)
        tmp_subs.write_text(domain_url + "\n")
        subs_file = tmp_subs
        print(info(f"Mode   : {BOLD}single-domain{RESET}  →  {domain_url}"))
    else:
        subs_file = Path(args.subs)
        if not subs_file.exists():
            print(err(f"File not found: {subs_file}"))
            sys.exit(1)

    subs = [l.strip() for l in subs_file.read_text().splitlines() if l.strip()]
    if not subs:
        print(err("Input is empty — no hosts to scan."))
        sys.exit(1)

    print(info(f"{BOLD}{len(subs):,}{RESET} host(s) loaded"))

    # ── Insecure notice ────────────────────────────────────────────────────
    if INSECURE:
        print(warn(
            f"{YELLOW}--insecure{RESET} active — "
            "TLS certificate errors will be ignored across all tools."
        ))

    if not check_tools():
        sys.exit(1)

    dirs = setup_dirs(Path(args.output))
    log  = setup_logger(dirs["logs"])
    log.info(
        "START  input=%s  output=%s  threads=%d  insecure=%s  single_domain=%s",
        subs_file, args.output, args.threads, INSECURE, single_domain,
    )
    print(info(f"Output root: {BOLD}{dirs['base']}{RESET}"))

    stats: dict = {"single_domain": single_domain}

    # ── 1. Live hosts ──────────────────────────────────────────────────────
    live_file = dirs["live"] / "live.txt"
    if args.skip_live_check and live_file.exists():
        live = [l.strip() for l in live_file.read_text().splitlines() if l.strip()]
        print(clr(f"\n[1/5]  Skipped httpx  —  {len(live):,} hosts from live.txt", YELLOW))
    elif single_domain:
        # For a single known domain, skip httpx and use it directly
        live = [normalise_host(args.domain)]
        live_file.write_text("\n".join(live) + "\n")
        print(clr(f"\n[1/5]  Single-domain mode — skipping httpx probe", YELLOW))
        print(ok(f"Target: {BOLD}{live[0]}{RESET}"))
    else:
        live = run_httpx(subs_file, live_file, args.threads, log)

    stats["live"] = len(live)
    if not live:
        print(err("No live hosts found. Exiting."))
        sys.exit(0)

    # ── 2. URL collection ──────────────────────────────────────────────────
    urls_file = dirs["urls"] / "all_urls.txt"
    if args.skip_url_collection and urls_file.exists():
        all_urls = [l.strip() for l in urls_file.read_text().splitlines() if l.strip()]
        print(clr(f"\n[2/5]  Skipped collection  —  {len(all_urls):,} URLs loaded", YELLOW))
    else:
        all_urls = collect_urls(live, urls_file, args.threads, log)

    stats["urls"] = len(all_urls)

    # ── 3. JS extraction & filter ──────────────────────────────────────────
    js_all, js_custom = extract_js_urls(all_urls, live, dirs["js"], args.threads, log)
    stats["js_all"]    = len(js_all)
    stats["js_custom"] = len(js_custom)

    if args.skip_download:
        print(clr("\n  [--skip-download] Stopping after JS extraction.", YELLOW))
        print(info(f"All JS   →  {dirs['js'] / 'js_urls.txt'}"))
        print(info(f"Custom   →  {dirs['js'] / 'custom_js.txt'}"))
        sys.exit(0)

    # ── 4. Download ────────────────────────────────────────────────────────
    targets = js_all if args.scan_all_js else js_custom
    if not targets:
        print(warn("No JS targets. Try --scan-all-js"))
        sys.exit(0)

    dl_map = download_js(targets, dirs["dl"], args.threads, log)
    stats["js_dl"] = len(dl_map)

    if not dl_map:
        print(warn("No JS files downloaded successfully."))
        sys.exit(0)

    # ── 5. Secret scanning ─────────────────────────────────────────────────
    run_secret_scanning(dl_map, dirs, stats, log)

    # ── Summary ────────────────────────────────────────────────────────────
    insecure_line = f"  {YELLOW}⚠  TLS verification was disabled (--insecure){RESET}\n" if INSECURE else ""
    print(f"""
{BOLD}{GREEN}  ╔══════════════════════════════════════╗
  ║      Pipeline Complete  ✔           ║
  ╚══════════════════════════════════════╝{RESET}
{insecure_line}
  {DIM}{"─"*38}{RESET}
  Live hosts       : {stats["live"]:>8,}
  URLs collected   : {stats["urls"]:>8,}
  JS total         : {stats["js_all"]:>8,}
  JS custom        : {stats["js_custom"]:>8,}
  JS downloaded    : {stats["js_dl"]:>8,}
  {DIM}{"─"*38}{RESET}
  Output  →  {BOLD}{dirs["base"]}{RESET}
  Report  →  {BOLD}{dirs["secrets"] / "final_report.txt"}{RESET}
""")
    log.info("DONE")


if __name__ == "__main__":
    main()

