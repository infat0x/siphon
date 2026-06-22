#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║                    jsrecon.py  —  JS Recon & Secret Hunter               ║
# ║                              v5  •  Production Grade                     ║
# ╠══════════════════════════════════════════════════════════════════════════╣
# ║  Pipeline:                                                               ║
# ║    subs.txt / --domain → httpx (live check) → URL harvest (gau +         ║
# ║    katana + waybackurls + hakrawler) → active <script> parsing →         ║
# ║    JS brute-force → JS filter → curl/wget download → secret scanning     ║
# ║                                                                          ║
# ║  v5 Improvements:                                                        ║
# ║    • Smarter downloader: exponential backoff, content validation,        ║
# ║      per-domain rate-limiting, HTTP→HTTPS fallback, alt extensions       ║
# ║    • Gitleaks secret scanner integrated alongside gf/trufflehog          ║
# ║    • Higher entropy threshold tuning per pattern category                ║
# ╠══════════════════════════════════════════════════════════════════════════╣
# ║  Usage:                                                                  ║
# ║    python3 jsrecon.py -s subs.txt -o output/ --skip-download             ║
# ╚══════════════════════════════════════════════════════════════════════════╝

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import math
import os
import re
import shutil
import subprocess
import sys
import time
import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse


# ═══════════════════════════════════════════════════════════════════════════
# ANSI COLOURS
# ═══════════════════════════════════════════════════════════════════════════

RESET   = "\033[0m";  BOLD    = "\033[1m"
GREEN   = "\033[92m"; YELLOW  = "\033[93m"
RED     = "\033[91m"; CYAN    = "\033[96m"
BLUE    = "\033[94m"; MAGENTA = "\033[95m"
DIM     = "\033[2m";  WHITE   = "\033[97m"


def clr(text: str, colour: str) -> str:
    return f"{colour}{text}{RESET}"


def ok(msg: str)   -> str: return f"  {GREEN}✔{RESET}  {msg}"
def warn(msg: str) -> str: return f"  {YELLOW}⚠{RESET}  {msg}"
def err(msg: str)  -> str: return f"  {RED}✘{RESET}  {msg}"
def info(msg: str) -> str: return f"  {CYAN}→{RESET}  {msg}"


# ═══════════════════════════════════════════════════════════════════════════
# GLOBAL FLAGS  (set once in main())
# ═══════════════════════════════════════════════════════════════════════════

INSECURE: bool = False   # mutated by main()


# ═══════════════════════════════════════════════════════════════════════════
# PER-DOMAIN RATE LIMITER
# Prevents hammering a single host → reduces 429 / connection-reset failures
# ═══════════════════════════════════════════════════════════════════════════

_DOMAIN_LOCKS: dict[str, threading.Semaphore] = defaultdict(lambda: threading.Semaphore(4))
_DOMAIN_LAST:  dict[str, float]               = defaultdict(float)
_DOMAIN_MUTEX: threading.Lock                 = threading.Lock()

# Minimum seconds between requests to the same domain
_DOMAIN_DELAY = 0.15


def _domain_key(url: str) -> str:
    return urlparse(url).netloc.lower()


def _acquire_domain(url: str) -> None:
    """Block until it is safe to make another request to url's domain."""
    key = _domain_key(url)
    _DOMAIN_LOCKS[key].acquire()
    with _DOMAIN_MUTEX:
        gap = time.monotonic() - _DOMAIN_LAST[key]
        if gap < _DOMAIN_DELAY:
            time.sleep(_DOMAIN_DELAY - gap)
        _DOMAIN_LAST[key] = time.monotonic()


def _release_domain(url: str) -> None:
    _DOMAIN_LOCKS[_domain_key(url)].release()


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
    "curl":            "pre-installed on most systems",
    "wget":            "apt install wget  /  brew install wget",
    "waybackurls":     "go install github.com/tomnomnom/waybackurls@latest",
    "hakrawler":       "go install github.com/hakluke/hakrawler@latest",
    "anew":            "go install github.com/tomnomnom/anew@latest",
    # v5: Gitleaks added as optional scanner
    "gitleaks":        "https://github.com/gitleaks/gitleaks/releases  OR  brew install gitleaks",
    # v6: New tools
    "SecretFinder.py": "git clone https://github.com/m4ll0k/SecretFinder  (manual path detection)",
    "subjs":           "go install github.com/lc/subjs@latest",
    "jsluice":         "go install github.com/BishopFox/jsluice/cmd/jsluice@latest",
    "jsleak":          "go install github.com/byt3hx/jsleak@latest",
    "nuclei":          "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "cariddi":         "go install github.com/edoardottt/cariddi/cmd/cariddi@latest",
    "ffuf":            "go install github.com/ffuf/ffuf/v2@latest",
    "git-dumper":      "pip install git-dumper  OR  pip3 install git-dumper --break-system-packages",
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
    # ---------------------------------------------------------
    # COMPREHENSIVE SECRET PATTERNS (100+ Total)
    # ---------------------------------------------------------
    # AWS
    "AWS Access Key":      r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key":      r"(?i)aws.{0,30}secret.{0,30}['\"][0-9a-zA-Z/+]{40}['\"]",
    "AWS MWS Auth Token":  r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "AWS Session Token":   r"(?i)aws_session_token(?:[=:\"\']){1,3}([a-zA-Z0-9/+=]{16,})",
    
    # GitHub / GitLab / Bitbucket
    "GitHub PAT":          r"gh[pousr]_[A-Za-z0-9_]{36,}",
    "GitHub Fine-grained": r"github_pat_[A-Za-z0-9_]{82}",
    "GitHub OAuth":        r"gho_[a-zA-Z0-9]{36}",
    "GitLab PAT":          r"glpat-[A-Za-z0-9_\-]{20}",
    "Bitbucket Client ID": r"client_id=[a-zA-Z0-9]{32}",
    "Bitbucket Secret":    r"client_secret=[a-zA-Z0-9_\-]{64}",
    
    # Google
    "Google API Key":      r"AIza[0-9A-Za-z\-_]{35}",
    "Google Cloud Key":    r"GOOG[\w\W]{10,30}",
    "Google OAuth":        r"ya29\.[0-9A-Za-z\-_]+",
    "GCP Service Account": r"\"type\": \"service_account\"",
    
    # Slack
    "Slack Token":         r"xox[baprs]-[0-9A-Za-z\-]{10,}",
    "Slack Webhook":       r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+",
    
    # Payments (Stripe, Square, PayPal)
    "Stripe Standard Key": r"(?:sk|pk)_(test|live)_[0-9a-zA-Z]{24,}",
    "Stripe Restricted":   r"rk_(test|live)_[0-9a-zA-Z]{24,}",
    "Square Access Token": r"EAAA[a-zA-Z0-9]{60}",
    "Square OAuth":        r"sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}",
    "PayPal Client ID":    r"Ad-[a-zA-Z0-9]{16,}",
    "PayPal Secret":       r"E[a-zA-Z0-9_-]{16,}",
    
    # Email / Messaging (Mailgun, SendGrid, Mailchimp, Twilio, Telegram)
    "SendGrid Key":        r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
    "Mailgun Key":         r"key-[0-9a-zA-Z]{32}",
    "Mailgun Pub Key":     r"pubkey-[0-9a-zA-Z]{32}",
    "Mailchimp Key":       r"[0-9a-f]{32}-us[0-9]{1,2}",
    "Twilio Account SID":  r"AC[a-zA-Z0-9]{32}",
    "Twilio Auth Token":   r"(?i)twilio.{0,20}['\"][a-f0-9]{32}['\"]",
    "Twilio API Key":      r"SK[0-9a-fA-F]{32}",
    "Telegram Bot Token":  r"[0-9]{8,10}:[a-zA-Z0-9_\-]{35}",
    "Discord Bot Token":   r"([NMO][a-zA-Z0-9_-]{23,27}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27})",
    "Discord Webhook":     r"https://discord\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_-]+",
    
    # Cloud & Infrastructure (Azure, Heroku, DigitalOcean, Pulumi, Vercel)
    "Azure Client Secret": r"(?i)client.?secret.{0,20}['\"][a-zA-Z0-9~_\-.]{34,}['\"]",
    "Azure Storage Key":   r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}",
    "Azure Tenant ID":     r"tenant(?:_id|Id)?(?:[\s=:\'\"]+)([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    "Heroku API Key":      r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "DigitalOcean Token":  r"dop_v1_[a-f0-9]{64}",
    "Pulumi Token":        r"pul-[a-f0-9]{40}",
    "Vercel Token":        r"[\s=:\'\"]([A-Za-z0-9_\-]{24})[\s=:\'\"]",
    
    # Monitoring & Logging (Datadog, New Relic, Sentry, Grafana, PagerDuty)
    "Datadog Token":       r"ddp_[a-zA-Z0-9_\-]{32}",
    "New Relic Key":       r"(?i)NRRA-[a-fA-F0-9]{27}",
    "Sentry Token":        r"sntrys_[a-zA-Z0-9_\-]{64}",
    "Grafana Token":       r"glc_[A-Za-z0-9+/]{32,}",
    "PagerDuty Token":     r"pd-[A-Za-z0-9_\-]{20}",
    
    # SaaS / Tools / Platforms
    "Algolia API Key":     r"(?i)algolia.{0,20}['\"][a-zA-Z0-9]{32}['\"]",
    "Artifactory Token":   r"(?:\s|=|:|\"|\^)AKC[a-zA-Z0-9]{10,}",
    "Asana Token":         r"0\/[0-9a-fA-F]{32}",
    "Auth0 Token":         r"auth0(?:\||[a-zA-Z0-9_\-]{32})",
    "Calendly Token":      r"eyJhb[a-zA-Z0-9_\-]{20,}",
    "CircleCI Token":      r"(?i)circleci.{0,20}['\"][a-f0-9]{40}['\"]",
    "Databricks Token":    r"dapi[a-f0-9]{32}",
    "Dropbox Token":       r"sl\.[a-zA-Z0-9_\-]{15,}",
    "Figma Token":         r"figd_[a-zA-Z0-9\-_]{39}",
    "HubSpot Token":       r"pat-[a-z]{2}-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
    "Intercom Token":      r"dG9r:[a-zA-Z0-9_\-]{20,}",
    "Kraken Key":          r"[A-Za-z0-9_\-]{80,90}",
    "Linear API Key":      r"lin_api_[a-zA-Z0-9]{40}",
    "LinkedIn ID":         r"(?i)linkedin(?:_client)?_id(?:[\s=:\'\"]+)([a-zA-Z0-9]{14})",
    "Mapbox Token":        r"pk\.eyJ1[a-zA-Z0-9_\-\.]+",
    "Notion Token":        r"secret_[a-zA-Z0-9]{43}",
    "NPM Token":           r"npm_[A-Za-z0-9]{36}",
    "OpenAI API Key":      r"sk-[a-zA-Z0-9]{48}",
    "Plaid Client ID":     r"client_id(?:[\s=:\'\"]+)([a-f0-9]{24})",
    "Plaid Secret":        r"secret(?:[\s=:\'\"]+)([a-f0-9]{30})",
    "Postman API Key":     r"PMAK-[a-fA-F0-9]{24}-[a-fA-F0-9]{34}",
    "RubyGems Token":      r"rubygems_[a-f0-9]{48}",
    "Salesforce Token":    r"(?i)salesforce.{0,20}['\"][0-9A-Za-z!@#$%^&*()_+]{40,80}['\"]",
    "Shopify Token":       r"shpat_[a-fA-F0-9]{32}",
    "Spotify Secret":      r"(?i)spotify.{0,20}['\"][a-zA-Z0-9]{32}['\"]",
    "Supabase Token":      r"sbp_[a-zA-Z0-9]{40}",
    "Typeform Token":      r"tfp_[a-zA-Z0-9]{40}",
    "Vault Token":         r"hvs\.[a-zA-Z0-9_\-]{90,}",
    "WPEngine Token":      r"['\"]wpe_auth['\"].{0,5}['\"][a-z0-9]{40}['\"]",
    "Zendesk Token":       r"(?i)zendesk.{0,20}['\"][a-zA-Z0-9]{40}['\"]",
    "Cloudinary URL":      r"cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[a-z0-9]+",
    "Contentful Token":    r"(?i)contentful(?:_api)?_key(?:[\s=:\'\"]+)([a-zA-Z0-9\-_]{43})",
    "Netlify Token":       r"(?i)netlify.{0,20}['\"][a-zA-Z0-9\-_]{40,43}['\"]",
    
    # Passwords & Generic Auth
    "JWT Token":           r"eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+",
    "Bearer Token":        r"(?i)[Bb]earer\s+[A-Za-z0-9\-_\.]{20,}",
    "Basic Auth":          r"(?i)Basic\s+[A-Za-z0-9+/=]{20,}",
    "Password in URL":     r"[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@",
    "Firebase URL":        r"https?://[a-z0-9\-]+\.firebaseio\.com",
    "Internal API URL":    r"(?i)https?://(?:api|internal|dev|staging|admin)\.[a-z0-9\-]+\.[a-z]{2,}/",
    
    # Encryption / SSH / Keys
    "Private Key Block":   r"-----BEGIN\s(?:RSA\s|DSA\s|EC\s)?PRIVATE KEY-----",
    "SSH RSA Private":     r"-----BEGIN OPENSSH PRIVATE KEY-----",
    "SSH DSA Private":     r"-----BEGIN DSA PRIVATE KEY-----",
    "SSH EC Private":      r"-----BEGIN EC PRIVATE KEY-----",
    "PGP Private Block":   r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    
    # Cryptos and Wallets (Basic matchers)
    "Bitcoin Address":     r"(?i)(?:bitcoin|btc).{0,20}['\"](1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[q-z0-9]{39,59})['\"]",
    "Ethereum Address":    r"(?i)(?:ethereum|eth).{0,20}['\"](0x[a-fA-F0-9]{40})['\"]",
    
    # Generic Catches
    "Generic API Key":     r"(?i)(?:api[_\-]?key|apikey|access[_\-]?token|auth[_\-]?token|secret[_\-]?key)['\"\s:=]+([A-Za-z0-9_\-]{20,})",
    "Generic Secret":      r"(?i)(?:secret|password|passwd|pwd)\s*[=:]\s*['\"]([A-Za-z0-9_\-!@#$%^&*]{12,})['\"]",
    "Generic Client ID":   r"(?i)(?:client[_\-]?id|appid)['\"\s:=]+([A-Za-z0-9_\-]{15,})",
    "Generic Refresh Tok": r"(?i)(?:refresh[_\-]?token)['\"\s:=]+([A-Za-z0-9_\-]{20,})",
    "Generic Bearer Var":  r"(?i)(?:bearer|jwt)[_\-]?token['\"\s:=]+([A-Za-z0-9_\-\.]{20,})",
    
    # Miscellaneous APIs
    "Airtable API Key":    r"key[0-9a-zA-Z]{13}",
    "Amplitude API Key":   r"(?i)amplitude.{0,20}['\"][a-f0-9]{32}['\"]",
    "AppSync API Key":     r"da2-[a-z0-9]{26}",
    "Braintree Token":     r"access_token\$[a-z0-9]{5,10}\$[a-z0-9]{30,}",
    "Buildkite Token":     r"bkua_[0-9a-zA-Z]{40}",
    "ButterCMS Token":     r"(?i)butter.{0,20}['\"][0-9a-f]{40}['\"]",
    "Campfire Token":      r"(?i)campfire.{0,20}['\"][a-f0-9]{40}['\"]",
    "Canny API Key":       r"(?i)canny.{0,20}['\"][0-9a-f]{32}['\"]",
    "Clearbit Key":        r"sk_[0-9a-f]{32}",
    "Coda Token":          r"(?i)coda.{0,20}['\"][a-zA-Z0-9_\-]{40,60}['\"]",
    "Coinbase API Key":    r"(?i)coinbase.{0,20}['\"][a-zA-Z0-9_\-]{30,50}['\"]",
    "Confluent Key":       r"(?i)confluent.{0,20}['\"][a-zA-Z0-9]{30,40}['\"]",
    "Courier API Key":     r"pk_[a-z]{4}_[A-Z0-9]{26}",
    "CustomerIO Key":      r"(?i)customerio.{0,20}['\"][0-9a-f]{32}['\"]",
    "Drip API Key":        r"(?i)drip.{0,20}['\"][a-zA-Z0-9_\-]{30,50}['\"]",
    "Dynatrace Token":     r"dt0c01\.[A-Z0-9]{24}\.[A-Z0-9]{64}",
    "Easypost API Key":    r"EZAK[a-zA-Z0-9]{50,}",
    "Fastly Token":        r"(?i)fastly.{0,20}['\"][a-zA-Z0-9_\-]{32}['\"]",
    "Firebase Cloud Mess": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
    "Flutterwave Key":     r"FLWSECK_TEST-[a-h0-9]{32}-X",
    "Frameio Token":       r"fio-u-[a-zA-Z0-9\-_]{64}",
    "Gitter Token":        r"(?i)gitter.{0,20}['\"][a-f0-9]{40}['\"]",
    "HashiCorp TF Token":  r"[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9_\-]{60,}",
    "IronMQ Token":        r"(?i)ironmq.{0,20}['\"][a-zA-Z0-9_\-]{30,50}['\"]",
    "KeenIO API Key":      r"(?i)keenio.{0,20}['\"][A-Z0-9]{64}['\"]",
    "LaunchDarkly Token":  r"sdk-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
    "Lokalise Token":      r"(?i)lokalise.{0,20}['\"][a-f0-9]{40}['\"]",
    "MacStadium Token":    r"(?i)macstadium.{0,20}['\"][a-zA-Z0-9]{30,50}['\"]",
    "Mattermost Token":    r"(?i)mattermost.{0,20}['\"][a-zA-Z0-9]{26}['\"]",
    "MessageBird Key":     r"(?i)messagebird.{0,20}['\"][a-zA-Z0-9]{25}['\"]",
    "Mixpanel API Key":    r"(?i)mixpanel.{0,20}['\"][a-f0-9]{32}['\"]",
    "Pendo Token":         r"(?i)pendo.{0,20}['\"][a-f0-9]{32}['\"]",
    "Picqer API Key":      r"(?i)picqer.{0,20}['\"][a-zA-Z0-9_\-]{30,50}['\"]",
    "Ramp Token":          r"(?i)ramp.{0,20}['\"][a-zA-Z0-9_\-]{30,50}['\"]",
    "Sanity API Key":      r"sk[a-zA-Z0-9]{40,}",
    "Scalingo Token":      r"tk-[a-zA-Z0-9_\-]{40,}",
    "Segment API Key":     r"(?i)segment.{0,20}['\"][a-zA-Z0-9_\-]{32}['\"]",
    "Smartling Token":     r"(?i)smartling.{0,20}['\"][a-zA-Z0-9_\-]{40}['\"]",
    "SonarQube Token":     r"sq[a-z]{3}_[a-f0-9]{40}",
    "StackHawk Token":     r"hawk\.[a-zA-Z0-9_\-]{20}\.[a-zA-Z0-9_\-]{20}",
    "TravisCI Token":      r"(?i)travis.{0,20}['\"][a-zA-Z0-9_\-]{22}['\"]",
    "WorkOS API Key":      r"sk_[a-zA-Z0-9]{20,}",
    "Yandex API Key":      r"AQVN[A-Za-z0-9_\-]{35,}",
}

# Per-pattern minimum entropy override.
# High-structure patterns (JWTs, AWS keys) have naturally lower entropy thresholds
# because they follow a fixed format.  Generic patterns need a higher bar.
_PATTERN_ENTROPY: dict[str, float] = {
    "AWS Access Key":      3.5,
    "AWS MWS Auth Token":  3.0,
    "JWT Token":           3.0,
    "Private Key Block":   2.5,   # fixed header, very distinctive
    "Firebase URL":        2.0,
    "Password in URL":     2.5,
    "Internal API URL":    2.0,
    "Generic API Key":     3.8,
    "Generic Secret":      3.8,
    "Bearer Token":        3.5,
    "Mailchimp Key":       3.0,
}
_DEFAULT_ENTROPY = 3.0            # applied when no override exists

FALSE_POSITIVE_RE = re.compile(
    r"^[a-z_\-]+$|^[0-9\.]+$|example\.com|localhost|placeholder|"
    r"your[_\-]?key|my[_\-]?secret|<[A-Z_]+>|\$\{[A-Z_]+\}|"
    r"xxx+|test[_\-]key|dummy|changeme|insert[_\-]here|"
    r"REPLACE_ME|TODO|FIXME|\*{4,}|"
    r"1234567890|abcdefgh|aaaaaaa|0000000|"
    r"process\.env\.|window\.__ENV__|__NEXT",
    re.IGNORECASE,
)

COMMON_JS_PATHS: list[str] = [
    # General / Webpack / Bundlers
    "/app.js","/main.js","/index.js","/bundle.js","/init.js",
    "/config.js","/settings.js","/env.js","/constants.js",
    "/api.js","/utils.js","/helpers.js","/common.js","/global.js",
    "/auth.js","/router.js","/routes.js","/store.js","/services.js",
    "/vendors.js","/chunk.js","/core.js","/base.js",
    
    # Common directories
    "/js/app.js","/js/main.js","/js/index.js","/js/config.js",
    "/js/api.js","/js/utils.js","/js/helpers.js","/js/auth.js",
    "/js/bundle.js","/js/vendors.js",
    "/static/js/app.js","/static/js/main.js","/static/js/index.js","/static/js/bundle.js",
    "/assets/js/app.js","/assets/js/main.js","/assets/js/config.js",
    "/assets/js/api.js","/assets/js/utils.js","/assets/application.js",
    "/dist/app.js","/dist/main.js","/dist/bundle.js","/dist/index.js",
    "/build/app.js","/build/main.js","/build/bundle.js","/build/static/js/main.js",
    "/public/js/app.js","/public/js/main.js",
    "/src/app.js","/src/main.js","/src/index.js",
    "/scripts/app.js","/scripts/main.js","/scripts/bundle.js",
    "/app/app.js","/app/main.js","/admin/app.js","/admin/main.js",
    
    # APIs & Configs
    "/v1/app.js","/v2/app.js","/api/config.js","/api/v1/config.js",
    "/config/config.js","/config/index.js","/env.production.js",
    
    # Frameworks (Next, Nuxt, WP, etc)
    "/_next/static/chunks/main.js","/_next/static/chunks/app-pages.js",
    "/_next/static/chunks/pages/_app.js","/_next/static/chunks/webpack.js",
    "/_nuxt/app.js", "/_nuxt/entry.js",
    "/wp-content/themes/app.js","/wp-includes/js/api.js",
    "/build/static/js/main.chunk.js","/build/static/js/2.chunk.js",
    "/assets/index.js","/assets/vendor.js"
]

USER_AGENTS: list[str] = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/17.4 Safari/605.1.15"
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) "
        "Gecko/20100101 Firefox/124.0"
    ),
]

# Primary UA (most compatible with CDN configs)
USER_AGENT = USER_AGENTS[0]

# ─── Content patterns that indicate an error page, not JS ─────────────────
_HTML_ERROR_RE = re.compile(
    r"<html|<!doctype\s+html|<title>4\d{2}|<title>5\d{2}|"
    r"Access Denied|403 Forbidden|404 Not Found|"
    r"<body",
    re.IGNORECASE,
)


# ═══════════════════════════════════════════════════════════════════════════
# BANNER
# ═══════════════════════════════════════════════════════════════════════════

def banner() -> None:
    print(f"""{BOLD}{CYAN}
   ██╗███████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
   ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
   ██║███████╗██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
   ██║╚════██║██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
   ██║███████║██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
   ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{RESET}{DIM}   v6  •  Siphon  •  curl/wget downloader{RESET}
   {DIM}gau + katana + waybackurls + hakrawler + active scrape + brute{RESET}
   {DIM}Scanners: regex  gf  trufflehog  gitleaks  SecretFinder  jsluice  jsleak  nuclei  cariddi{RESET}
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
        "git":     base / "git_dumps",
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    return dirs


# ═══════════════════════════════════════════════════════════════════════════
# LOGGER
# ═══════════════════════════════════════════════════════════════════════════

def setup_logger(log_dir: Path) -> logging.Logger:
    log = logging.getLogger("siphon")
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
# HTTP HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _curl_fetch(url: str, timeout: int, ua: str = USER_AGENT) -> Optional[bytes]:
    """
    Primary downloader: curl.
    v5 improvements:
      • --retry-all-errors catches transient network failures
      • --connect-timeout separate from total timeout
      • Accepts custom User-Agent for rotation
      • --compressed handles gzip/br transparently
    """
    cmd = [
        "curl",
        "--silent",
        "--location",
        "--compressed",
        "--connect-timeout", "10",
        "--max-time",        str(timeout),
        "--retry",           "3",
        "--retry-delay",     "2",
        "--retry-all-errors",
        "--fail",
        "--user-agent",      ua,
        "--header",          "Accept: */*",
        "--header",          "Accept-Language: en-US,en;q=0.9",
        "--header",          "Accept-Encoding: gzip, deflate, br",
        "--max-filesize",    "15728640",   # 15 MB
    ]
    if INSECURE:
        cmd.append("--insecure")
    cmd += ["--output", "-", url]

    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 15)
        return result.stdout if result.returncode == 0 else None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def _wget_fetch(url: str, timeout: int, ua: str = USER_AGENT) -> Optional[bytes]:
    cmd = [
        "wget",
        "--quiet",
        f"--timeout={timeout}",
        "--tries=3",
        f"--user-agent={ua}",
        "--no-check-certificate",
        "--header=Accept: */*",
        "--header=Accept-Language: en-US,en;q=0.9",
        "-O", "-",
        url,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 15)
        return result.stdout if result.returncode == 0 else None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def _urllib_fetch(url: str, timeout: int, ua: str = USER_AGENT) -> Optional[bytes]:
    import ssl
    import urllib.request as ureq

    ctx: Optional[ssl.SSLContext] = None
    if INSECURE:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

    try:
        req = ureq.Request(
            url,
            headers={
                "User-Agent":      ua,
                "Accept":          "*/*",
                "Accept-Language": "en-US,en;q=0.9",
            },
        )
        with ureq.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read(15 * 1024 * 1024)
    except Exception:
        return None


def _is_valid_js(content: bytes) -> bool:
    """
    Return False if content looks like an HTML error page rather than JS.
    Checks the first 512 bytes only (fast heuristic).
    """
    head = content[:512].decode("utf-8", errors="replace")
    return not bool(_HTML_ERROR_RE.search(head))


def fetch(url: str, timeout: int = 15) -> Optional[str]:
    """
    Download URL content as a decoded string.

    v5 improvements over v4:
      • Per-domain rate limiting (acquire/release semaphore)
      • Exponential backoff on None result (up to 3 attempts)
      • Rotate User-Agent on each retry
      • Content validation — reject HTML error pages masquerading as JS
      • HTTP→HTTPS fallback when http:// URL returns nothing
      • Strip BOM / null bytes before returning

    Tries curl → wget → urllib in order for each attempt.
    """
    _acquire_domain(url)
    try:
        return _fetch_inner(url, timeout)
    finally:
        _release_domain(url)


def _fetch_inner(url: str, timeout: int) -> Optional[str]:
    """Core fetch logic (called inside domain rate-limit context)."""
    # Attempt 1 (normal) + 2 retries with backoff
    for attempt in range(3):
        if attempt:
            sleep_t = 2 ** attempt          # 2s, 4s
            time.sleep(sleep_t)

        ua  = USER_AGENTS[attempt % len(USER_AGENTS)]
        raw: Optional[bytes] = None

        if shutil.which("curl"):
            raw = _curl_fetch(url, timeout, ua)
        if raw is None and shutil.which("wget"):
            raw = _wget_fetch(url, timeout, ua)
        if raw is None:
            raw = _urllib_fetch(url, timeout, ua)

        if raw and len(raw) > 50 and _is_valid_js(raw):
            decoded = raw.decode("utf-8", errors="replace")
            # Strip UTF-8 BOM + null bytes that break regex scanners
            decoded = decoded.lstrip("\ufeff").replace("\x00", "")
            return decoded

    # Last-chance: try HTTP if HTTPS failed (or vice-versa)
    alt_url = _flip_scheme(url)
    if alt_url and alt_url != url:
        raw = None
        if shutil.which("curl"):
            raw = _curl_fetch(alt_url, timeout)
        if raw is None and shutil.which("wget"):
            raw = _wget_fetch(alt_url, timeout)
        if raw is None:
            raw = _urllib_fetch(alt_url, timeout)

        if raw and len(raw) > 50 and _is_valid_js(raw):
            decoded = raw.decode("utf-8", errors="replace").lstrip("\ufeff").replace("\x00", "")
            return decoded

    return None


def _flip_scheme(url: str) -> Optional[str]:
    """Return the same URL with http↔https scheme swapped."""
    if url.startswith("https://"):
        return "http://" + url[8:]
    if url.startswith("http://"):
        return "https://" + url[7:]
    return None


ALT_EXTENSIONS = [".jsx", ".ts", ".mjs", ".cjs"]


def head_ok(url: str, timeout: int = 8) -> bool:
    """
    Probe whether a URL exists and is JavaScript.
    Uses curl --head (fast, no body download).
    FIX-3: tries alternate extensions (.jsx, .ts, .mjs, .cjs) on 404.
    """
    if _head_ok_single(url, timeout):
        return True
    # FIX-3: try alternate extensions for .js URLs
    if url.endswith(".js"):
        base_url = url[:-3]
        for ext in ALT_EXTENSIONS:
            if _head_ok_single(base_url + ext, timeout):
                return True
    return False


def _head_ok_single(url: str, timeout: int = 8) -> bool:
    """Check a single URL via HEAD request."""
    if shutil.which("curl"):
        cmd = [
            "curl",
            "--silent", "--head",
            "--location",
            f"--max-time={timeout}",
            "--connect-timeout", "6",
            "--fail",
            f"--user-agent={USER_AGENT}",
            "--write-out", "%{http_code}|||%{content_type}",
            "--output", "/dev/null",
        ]
        if INSECURE:
            cmd.append("--insecure")
        cmd.append(url)

        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            out = r.stdout.strip()
            if "|||" in out:
                code, ct = out.rsplit("|||", 1)
                return (
                    code.strip() == "200"
                    and ("javascript" in ct or "ecmascript" in ct
                         or url.endswith((".js", ".jsx", ".ts", ".mjs", ".cjs")))
                )
        except Exception:
            pass

    content = fetch(url, timeout=timeout)
    return bool(content and len(content) > 50)


def url_to_filename(url: str, dl_dir: Path) -> Path:
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
    host = host.strip()
    if not host.startswith("http://") and not host.startswith("https://"):
        host = "https://" + host
    return host.rstrip("/")


def bare_domain(host: str) -> str:
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
        cmd.append("-no-verify-ssl")

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
        cmd.append("-insecure")

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
        cmd.append("-insecure")

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return [l.strip() for l in r.stdout.splitlines() if l.strip().startswith("http")]
    except Exception:
        return []


def run_subjs(url: str, timeout: int = 60) -> list[str]:
    """
    subjs-i verilən URL üzərində işlət.
    stdout-da hər sətirdə bir JS URL qaytarır.
    Katana-nın -jc flag-i oxşar işi görür amma subjs daha sürətlidir
    sadə JS URL toplama üçün.
    """
    if not shutil.which("subjs"):
        return []
    try:
        r = subprocess.run(
            ["subjs"],
            input=url + "\n",
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return [
            line.strip()
            for line in r.stdout.splitlines()
            if line.strip().startswith("http")
        ]
    except Exception:
        return []


def run_cariddi(url: str, raw_dir: Path,
                timeout: int = 120) -> tuple[list[str], list[Finding]]:
    """
    cariddi-ni URL üzərində işlət.

    İki şey qaytarır:
      1. Tapılan URL-lər (collect_urls pipeline-ına qatılır)
      2. Birbaşa tapılan secret findings (run_secret_scanning-ə göndərilir)

    Flags:
        -s       secrets scanning aktiv et
        -e       endpoint-ləri çıxar
        -plain   sadə text output (JSON deyil)
    """
    if not shutil.which("cariddi"):
        return [], []

    urls_found:    list[str]     = []
    secrets_found: list[Finding] = []

    try:
        r = subprocess.run(
            ["cariddi", "-s", "-e", "-plain"],
            input=url + "\n",
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        for line in r.stdout.splitlines():
            line = line.strip()
            if not line:
                continue

            if line.startswith("[SECRET]"):
                # Format: [SECRET] <type>: <value> (<url>)
                secret_part = line[len("[SECRET]"):].strip()
                if len(secret_part) < 8:
                    continue
                if FALSE_POSITIVE_RE.search(secret_part):
                    continue
                secrets_found.append({
                    "tool":    "cariddi",
                    "type":    "auto",
                    "url":     url,
                    "file":    "",
                    "match":   secret_part[:200],
                    "line":    "",
                    "entropy": f"{shannon_entropy(secret_part):.2f}",
                })
            elif line.startswith("http"):
                urls_found.append(line)

    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass

    return urls_found, secrets_found


class ScriptTagParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.srcs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        tag_lower = tag.lower()
        if tag_lower == "script":
            for k, v in attrs:
                if k.lower() == "src" and v and not v.startswith("data:"):
                    self.srcs.append(v.strip())
        elif tag_lower == "link":
            for k, v in attrs:
                if k.lower() == "href" and v and not v.startswith("data:"):
                    val = v.strip()
                    path = urlparse(val).path.lower()
                    if path.endswith(".js") or ".js?" in path or ".js#" in path:
                        self.srcs.append(val)


def parse_script_tags(base_url: str, html: str) -> list[str]:
    parser = ScriptTagParser()
    try:
        parser.feed(html)
    except Exception:
        pass

    # Inline Regex Scraping
    inline_absolute = re.findall(r"(https?://[a-zA-Z0-9.\-/_]+/[a-zA-Z0-9.\-_]+\.js(?:\?[a-zA-Z0-9=&_\.\-]+)?)", html)
    inline_relative = re.findall(r"['\"](/[a-zA-Z0-9.\-/_]+\.js(?:\?[a-zA-Z0-9=&_\.\-]+)?)['\"]", html)
    
    for match in inline_absolute:
        parser.srcs.append(match)
    for match in inline_relative:
        parser.srcs.append(match)

    parsed = urlparse(base_url)
    out: list[str] = []
    for src in set(parser.srcs):
        if src.startswith("//"):
            src = f"{parsed.scheme}:{src}"
        elif not src.startswith("http"):
            src = urljoin(base_url, src)
        out.append(src)
    return out


def active_html_scrape(live_hosts: list[str], threads: int,
                       log: logging.Logger) -> list[str]:
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
    """
    Mövcud head_ok() loop-u saxla, ffuf varsa onu istifadə et.
    ffuf bir host üçün bütün path-ları tək subprocess-də yoxlayır.
    """
    print(info(f"Brute-force  {len(COMMON_JS_PATHS)} common JS paths …"))
    found: list[str] = []

    if shutil.which("ffuf"):
        # ffuf path-ları wordlist faylına yaz
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as wf:
            wf.write("\n".join(COMMON_JS_PATHS))
            wl_path = wf.name

        pb = ProgressBar(len(live_hosts), "ffuf JS brute")
        for host in live_hosts:
            try:
                r = subprocess.run(
                    [
                        "ffuf",
                        "-u",  host.rstrip("/") + "FUZZ",
                        "-w",  wl_path,
                        "-mc", "200",
                        "-t",  str(min(threads, 50)),
                        "-o",  os.devnull,
                        "-of", "json",
                        "-s",
                        "-H", f"User-Agent: {USER_AGENT}",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                # ffuf -s ilə sadə text output: hər 200 cavab üçün URL
                for line in r.stdout.splitlines():
                    line = line.strip()
                    if line.startswith("http"):
                        found.append(line)
            except Exception:
                pass
            pb.update(1, f"({len(found)} found)")

        Path(wl_path).unlink(missing_ok=True)

    else:
        # Fallback: mövcud head_ok() loop-u
        tasks = [h.rstrip("/") + p for h in live_hosts for p in COMMON_JS_PATHS]
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
               f"waybackurls  hakrawler  subjs  cariddi  active-HTML{RESET}\n"))
    log.info("URL collection: %d hosts", len(live_hosts))

    all_urls: set[str] = set()

    tasks = [
        (tool, host)
        for host in live_hosts
        for tool in ("gau", "katana", "waybackurls", "hakrawler", "subjs")
    ]
    pb = ProgressBar(len(tasks), "Passive sources")

    def _passive(args: tuple[str, str]) -> list[str]:
        tool, target = args
        dispatch = {
            "gau":         run_gau,
            "katana":      run_katana,
            "waybackurls": run_waybackurls,
            "hakrawler":   run_hakrawler,
            "subjs":       run_subjs,
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

    # ── cariddi crawl + secret scan ──
    cariddi_all_urls:    list[str]     = []
    cariddi_all_secrets: list[Finding] = []

    if shutil.which("cariddi"):
        print(info("cariddi crawl + secret scan …"))
        with ThreadPoolExecutor(max_workers=min(threads, 10)) as ex:
            cfuts = {ex.submit(run_cariddi, h, urls_file.parent, 120): h for h in live_hosts}
            for cfut in as_completed(cfuts):
                try:
                    c_urls, c_secrets = cfut.result()
                    cariddi_all_urls.extend(c_urls)
                    cariddi_all_secrets.extend(c_secrets)
                except Exception:
                    pass
        all_urls.update(cariddi_all_urls)
        print(ok(f"cariddi   +{len(cariddi_all_urls):,} URLs  {len(cariddi_all_secrets)} secrets"))

    # Write cariddi secrets for run_secret_scanning to read
    (urls_file.parent / "cariddi_secrets.json").write_text(
        json.dumps(cariddi_all_secrets, indent=2)
    )

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
    """
    Download every JS URL and save to dl_dir.

    v5 improvements:
      • fetch() now has per-domain rate-limiting + exponential backoff
      • Content validation rejects HTML error pages
      • HTTP↔HTTPS scheme fallback inside fetch()
      • File deduplication by SHA-256 hash (avoid saving identical content twice)
    """
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
    print(info(
        f"Backend : {BOLD}{backend}{RESET}{insecure_tag}   "
        f"target : {BOLD}{dl_dir}{RESET}  "
        f"(retry=3 + backoff + scheme-fallback)\n"
    ))
    log.info("Downloading %d JS files via %s (insecure=%s)", len(js_urls), backend, INSECURE)

    downloaded: dict[str, Path] = {}
    failed: list[str] = []
    _seen_hashes: set[str] = set()   # dedup identical content
    pb = ProgressBar(len(js_urls), "Downloading JS")

    def _download_one(url: str) -> tuple[str, Optional[Path]]:
        content = fetch(url, timeout=20)
        if not content or len(content) < 50:
            return url, None

        # Deduplicate identical files (e.g. CDN mirrors)
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        if content_hash in _seen_hashes:
            # Return a dummy path to count as "ok" but don't write duplicate
            return url, Path("/dev/null")
        _seen_hashes.add(content_hash)

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
                if str(path) != "/dev/null":
                    downloaded[url] = path
                # else: duplicate, silently skip
            else:
                failed.append(url)
            pb.update(1, f"({len(downloaded)} ok  {len(failed)} fail)")

    if failed:
        (dl_dir / "_failed.txt").write_text("\n".join(failed) + "\n")

    total_size = sum(
        p.stat().st_size for p in downloaded.values() if p.exists()
    ) / 1024
    success_rate = (
        100 * len(downloaded) / len(js_urls) if js_urls else 0
    )
    print(ok(
        f"Downloaded  : {BOLD}{len(downloaded)}{RESET}/{len(js_urls)}  "
        f"({success_rate:.1f}% success  •  {total_size:.1f} KB total)"
    ))
    print(ok(f"Saved to    : {BOLD}{dl_dir}{RESET}"))
    if failed:
        print(warn(f"Failed      : {len(failed)}  →  {DIM}{dl_dir}/_failed.txt{RESET}"))

    log.info(
        "Downloaded: %d  failed: %d  size: %.1f KB  success_rate: %.1f%%",
        len(downloaded), len(failed), total_size, success_rate,
    )
    return downloaded


# ═══════════════════════════════════════════════════════════════════════════
# STEP 5 — SECRET SCANNING
# ═══════════════════════════════════════════════════════════════════════════

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((f / len(s)) * math.log2(f / len(s)) for f in freq.values())


Finding = dict[str, str]


def scan_regex(dl_map: dict[str, Path], raw_dir: Path,
               log: logging.Logger) -> list[Finding]:
    findings: list[Finding] = []
    compiled = {name: re.compile(pat) for name, pat in SECRET_PATTERNS.items()}

    for url, filepath in dl_map.items():
        if not filepath.exists():
            continue
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for name, rx in compiled.items():
            min_entropy = _PATTERN_ENTROPY.get(name, _DEFAULT_ENTROPY)
            for m in rx.finditer(content):
                snippet = m.group(0)[:200]
                if len(snippet) < 12 or FALSE_POSITIVE_RE.search(snippet):
                    continue
                entropy = shannon_entropy(snippet)
                if entropy < min_entropy:
                    continue
                start   = max(0, m.start() - 100)
                end     = min(len(content), m.end() + 100)
                context = content[start:end].replace("\n", " ")[:300]
                findings.append({
                    "tool":    "regex",
                    "type":    name,
                    "url":     url,
                    "entropy": f"{entropy:.2f}",
                    "file":    str(filepath),
                    "match":   snippet,
                    "context": context,
                    "line":    str(content[: m.start()].count("\n") + 1),
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
        if not filepath.exists():
            continue
        try:
            for line in filepath.read_text(encoding="utf-8", errors="replace").splitlines():
                lines_list.append(f"{url}: {line}")
        except OSError:
            continue
    combined = "\n".join(lines_list)

    GF_PATTERNS = [
        "aws-keys", "base64", "firebase", "json-sec", "jwt",
        "php-errors", "s3-buckets", "secrets", "servers",
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
                    if not line.strip():
                        continue
                    # FIX-2: use ": " separator to correctly extract URL
                    match_part = line.split(": ", 1)[-1] if ": " in line else line
                    if len(match_part.strip()) < 15:
                        continue
                    if FALSE_POSITIVE_RE.search(match_part):
                        continue
                    if shannon_entropy(match_part.strip()) < 3.2:
                        continue
                    findings.append({
                        "tool":  "gf",
                        "type":  pat,
                        "url":   line.split(": ", 1)[0] if ": " in line else "",
                        "file":  "",
                        "match": match_part[:300],
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
                "--directory", str(dl_dir),
                "--json",
                "--no-update",
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


# ─── Gitleaks ───────────────────────────────────────────────────────────────

def scan_gitleaks(dl_dir: Path, raw_dir: Path,
                  log: logging.Logger) -> list[Finding]:
    """
    Run Gitleaks in filesystem mode over the downloaded JS directory.

    Gitleaks uses a comprehensive built-in ruleset (200+ detectors) including
    AWS, GCP, Azure, GitHub, Stripe, Twilio, and many more — complementing
    TruffleHog's detector engine and our custom regex patterns.

    Command:
        gitleaks detect
            --source  <dl_dir>   ← scan the downloaded JS files
            --no-git             ← directory scan, not a git repo
            --report-format json
            --report-path       <raw_dir>/gitleaks.json
            --exit-code 0        ← don't exit non-zero on findings (we handle that)
            --log-level warn     ← suppress verbose output
    """
    if not shutil.which("gitleaks"):
        return []

    report_path = raw_dir / "gitleaks.json"
    findings: list[Finding] = []

    try:
        subprocess.run(
            [
                "gitleaks", "detect",
                "--source",        str(dl_dir),
                "--no-git",
                "--report-format", "json",
                "--report-path",   str(report_path),
                "--exit-code",     "0",
                "--log-level",     "warn",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        log.warning("gitleaks: scan timed out")
        return []
    except Exception as exc:
        log.warning("gitleaks: %s", exc)
        return []

    # Parse JSON report.  Gitleaks writes an array of Finding objects.
    if not report_path.exists():
        return []

    try:
        raw_text = report_path.read_text(encoding="utf-8", errors="replace")
        if not raw_text.strip():
            return []
        data = json.loads(raw_text)
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("gitleaks: failed to parse report: %s", exc)
        return []

    if not isinstance(data, list):
        return []

    for item in data:
        if not isinstance(item, dict):
            continue

        secret_val = str(item.get("Secret", "")).strip()
        rule_id    = str(item.get("RuleID",    item.get("Description", "unknown")))
        file_path  = str(item.get("File",      ""))
        line_no    = str(item.get("StartLine", ""))
        match_str  = str(item.get("Match",     secret_val))[:200]

        # Skip empties and obvious false positives
        if len(secret_val) < 8:
            continue
        if FALSE_POSITIVE_RE.search(secret_val):
            continue
        if shannon_entropy(secret_val) < 2.8:
            continue

        findings.append({
            "tool":    "gitleaks",
            "type":    rule_id,
            "url":     "",           # gitleaks scans local files; URL not available here
            "file":    file_path,
            "match":   match_str,
            "line":    line_no,
            "entropy": f"{shannon_entropy(secret_val):.2f}",
        })

    log.info("gitleaks: %d findings", len(findings))
    return findings


# ─── SecretFinder ────────────────────────────────────────────────────────────

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
        if not filepath.exists():
            pb.update(1)
            continue
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


# ─── jsluice ────────────────────────────────────────────────────────────────

def scan_jsluice(dl_map: dict[str, Path], raw_dir: Path,
                 log: logging.Logger) -> list[Finding]:
    """
    jsluice-i hər downloaded JS faylı üzərində işlət.

    Komanda:
        jsluice secrets <filepath>

    Output: hər sətirdə bir JSON object:
        {"kind": "AWSAccessKey", "data": {"match": "AKIA..."}, "filename": "..."}

    scan_regex() ilə tamamlayıcıdır çünki jsluice kontekst anlayır —
    məsələn `const API_KEY = "abc123"` kimi assignment-ları tapır.
    """
    if not shutil.which("jsluice"):
        return []

    findings: list[Finding] = []

    for url, filepath in dl_map.items():
        if not filepath.exists():
            continue
        try:
            r = subprocess.run(
                ["jsluice", "secrets", str(filepath)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            for line in r.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # jsluice output strukturu: kind, data{match, ...}, filename, severity
                kind     = str(obj.get("kind",     "unknown"))
                data     = obj.get("data",     {})
                match_v  = str(data.get("match",   data)).strip()[:200]
                severity = str(obj.get("severity", ""))

                if len(match_v) < 8:
                    continue
                if FALSE_POSITIVE_RE.search(match_v):
                    continue
                if shannon_entropy(match_v) < 2.8:
                    continue

                findings.append({
                    "tool":    "jsluice",
                    "type":    kind,
                    "url":     url,
                    "file":    str(filepath),
                    "match":   match_v,
                    "line":    str(obj.get("line", "")),
                    "entropy": f"{shannon_entropy(match_v):.2f}",
                    "context": f"severity={severity}",
                })
        except subprocess.TimeoutExpired:
            log.debug("jsluice timeout: %s", filepath)
        except Exception as exc:
            log.debug("jsluice error %s: %s", filepath, exc)

    (raw_dir / "jsluice_findings.json").write_text(json.dumps(findings, indent=2))
    log.info("jsluice: %d findings", len(findings))
    return findings


# ─── jsleak ─────────────────────────────────────────────────────────────────

def scan_jsleak(dl_map: dict[str, Path], raw_dir: Path,
                log: logging.Logger) -> list[Finding]:
    """
    jsleak-i downloaded JS faylları üzərində işlət.

    Komanda (hər fayl üçün):
        jsleak -f <filepath> -s

    Flags:
        -s   secrets mode (secret pattern-lər axtarır)
    """
    if not shutil.which("jsleak"):
        return []

    findings: list[Finding] = []
    raw_output_lines: list[str] = []

    for url, filepath in dl_map.items():
        if not filepath.exists():
            continue
        try:
            r = subprocess.run(
                ["jsleak", "-f", str(filepath), "-s"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            for line in r.stdout.splitlines():
                line = line.strip()
                if not line or len(line) < 10:
                    continue
                if FALSE_POSITIVE_RE.search(line):
                    continue
                if shannon_entropy(line) < 2.8:
                    continue

                raw_output_lines.append(f"{url}: {line}")
                findings.append({
                    "tool":    "jsleak",
                    "type":    "secret",
                    "url":     url,
                    "file":    str(filepath),
                    "match":   line[:200],
                    "line":    "",
                    "entropy": f"{shannon_entropy(line):.2f}",
                })
        except subprocess.TimeoutExpired:
            log.debug("jsleak timeout: %s", filepath)
        except Exception as exc:
            log.debug("jsleak error %s: %s", filepath, exc)

    (raw_dir / "jsleak_findings.txt").write_text("\n".join(raw_output_lines))
    log.info("jsleak: %d findings", len(findings))
    return findings


# ─── nuclei ─────────────────────────────────────────────────────────────────

def scan_nuclei(js_urls: list[str], raw_dir: Path,
                log: logging.Logger) -> list[Finding]:
    """
    nuclei-ni JS URL-ləri üzərində exposure template-ləri ilə işlət.

    Bu funksiya downloaded faylları deyil, birbaşa JS URL-lərini tarayır.
    Çünki nuclei HTTP-üzərindən işləyir və response header-larını da yoxlayır.

    Template qrupu `http/exposures/` bunları əhatə edir:
        - tokens/  (API keys, OAuth tokens)
        - files/   (exposed config, .env, backup fayllar)
        - logs/    (debug output, error pages)
        - apis/    (swagger, graphql introspection)
    """
    if not shutil.which("nuclei"):
        return []
    if not js_urls:
        return []

    # Müvəqqəti URL siyahısı faylı yaz
    url_list = raw_dir / "_nuclei_urls.txt"
    url_list.write_text("\n".join(js_urls) + "\n")
    report_path = raw_dir / "nuclei_findings.json"

    findings: list[Finding] = []

    try:
        r = subprocess.run(
            [
                "nuclei",
                "-l",            str(url_list),
                "-t",            "http/exposures/",
                "-silent",
                "-no-color",
                "-json",
                "-o",            str(report_path),
                "-rate-limit",   "50",
                "-concurrency",  "20",
                "-timeout",      "10",
                "-no-update-templates",
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        log.warning("nuclei: scan timed out")
        return []
    except Exception as exc:
        log.warning("nuclei: %s", exc)
        return []

    # nuclei JSON output: hər sətirdə bir JSON object (newline-delimited)
    if not report_path.exists():
        return []

    try:
        for line in report_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            template_id = str(obj.get("template-id",   "unknown"))
            severity    = str(obj.get("info", {}).get("severity", ""))
            matched_at  = str(obj.get("matched-at",    ""))
            match_val   = str(obj.get("extracted-results", obj.get("matcher-name", "")))[:200]
            host        = str(obj.get("host",           matched_at))

            if FALSE_POSITIVE_RE.search(match_val):
                continue

            findings.append({
                "tool":    "nuclei",
                "type":    template_id,
                "url":     matched_at or host,
                "file":    "",
                "match":   match_val or matched_at,
                "line":    "",
                "entropy": "",
                "context": f"severity={severity}",
            })
    except Exception as exc:
        log.warning("nuclei: report parse error: %s", exc)

    log.info("nuclei: %d findings", len(findings))
    return findings


# ─── git-dumper ──────────────────────────────────────────────────────────────

def check_git_exposure(live_hosts: list[str], git_dir: Path,
                       threads: int, log: logging.Logger) -> list[Path]:
    """
    Hər live host üçün /.git/config URL-ini yoxla.
    Açıq olan varsa git-dumper ilə dump et.
    Dump edilmiş path-ları qaytarır — gitleaks/trufflehog bu path-ları da tarayacaq.
    """
    if not shutil.which("git-dumper"):
        return []

    print(info("Checking for exposed .git directories …"))
    git_urls = [h.rstrip("/") + "/.git/config" for h in live_hosts]

    # httpx ilə bütün /.git/config URL-lərini yoxla
    exposed: list[str] = []
    with ThreadPoolExecutor(max_workers=min(threads, 30)) as ex:
        futs = {ex.submit(head_ok, u, 8): u for u in git_urls}
        for fut in as_completed(futs):
            url = futs[fut]
            try:
                if fut.result():
                    base_url = url.replace("/.git/config", "")
                    exposed.append(base_url)
                    print(warn(f"Exposed .git found: {BOLD}{base_url}{RESET}"))
            except Exception:
                pass

    if not exposed:
        print(ok("No exposed .git directories found"))
        return []

    print(warn(f"{len(exposed)} exposed .git director{'y' if len(exposed)==1 else 'ies'} found — dumping …"))
    log.warning("Exposed .git: %s", exposed)

    dump_paths: list[Path] = []
    for base_url in exposed:
        # Hər domain üçün ayrıca subdirectory
        domain_slug = re.sub(r"[^\w\-]", "_", urlparse(base_url).netloc)[:60]
        dump_path   = git_dir / domain_slug
        dump_path.mkdir(parents=True, exist_ok=True)

        try:
            r = subprocess.run(
                ["git-dumper", base_url, str(dump_path)],
                capture_output=True,
                text=True,
                timeout=300,
            )
            if dump_path.exists() and any(dump_path.iterdir()):
                dump_paths.append(dump_path)
                print(ok(f"Dumped: {base_url}  →  {dump_path}"))
                log.info("git-dumper success: %s → %s", base_url, dump_path)
            else:
                print(warn(f"git-dumper: empty result for {base_url}"))
        except subprocess.TimeoutExpired:
            log.warning("git-dumper timeout: %s", base_url)
        except Exception as exc:
            log.warning("git-dumper error %s: %s", base_url, exc)

    return dump_paths


# ─── Dedup + Report ─────────────────────────────────────────────────────────

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
        "  SIPHON  —  FINAL REPORT  (v6)",
        f"  Generated      : {datetime.now():%Y-%m-%d  %H:%M:%S}",
        f"  Mode           : {'single-domain' if stats.get('single_domain') else 'multi-subdomain'}",
        f"  TLS verify     : {'disabled (--insecure)' if INSECURE else 'enabled'}",
        f"  Live hosts     : {stats.get('live', 0):,}",
        f"  URLs collected : {stats.get('urls', 0):,}",
        f"  JS files total : {stats.get('js_all', 0):,}",
        f"  JS custom      : {stats.get('js_custom', 0):,}",
        f"  JS downloaded  : {stats.get('js_dl', 0):,}",
        f"  DL success     : {stats.get('dl_rate', '─')}",
        f"  Raw findings   : {len(all_findings):,}",
        f"  High-confidence: {len(high_conf):,}",
        sep, "",
    ]

    if not high_conf:
        lines += [
            "  No high-confidence secrets found.",
            "  ─ Check secrets/raw/regex_findings.json   for regex scanner output.",
            "  ─ Check secrets/raw/trufflehog.json        for TruffleHog output.",
            "  ─ Check secrets/raw/gitleaks.json          for Gitleaks output.",
            "  ─ Check secrets/raw/jsluice_findings.json  for jsluice output.",
            "  ─ Check secrets/raw/jsleak_findings.txt    for jsleak output.",
            "  ─ Check secrets/raw/nuclei_findings.json   for Nuclei exposure output.",
            "  ─ Check cariddi_secrets.json               for cariddi findings.",
            "  ─ Check git_dumps/                         for dumped .git repositories.",
            "",
        ]
    else:
        for stype, items in sorted(by_type.items(), key=lambda x: -len(x[1])):
            lines += [
                f"┌─  {stype}  ({len(items)} finding{'s' if len(items) > 1 else ''})",
            ]
            for item in items:
                lines += [
                    f"│   Tool    : {item.get('tool', '─')}",
                    f"│   URL     : {item.get('url', '─')}",
                    f"│   File    : {item.get('file', '─')}",
                    f"│   Line    : {item.get('line', '─')}",
                    f"│   Entropy : {item.get('entropy', '─')}",
                    f"│   Match   : {item.get('match', '─')[:150]}",
                    "│",
                ]
            lines.append("")

    report_file.write_text("\n".join(lines))
    print(ok(f"Report           →  {BOLD}{report_file}{RESET}"))
    print(ok(f"High-confidence findings : {BOLD}{len(high_conf)}{RESET}"))
    log.info("Report: %d high-confidence findings", len(high_conf))


def run_secret_scanning(
    dl_map: dict[str, Path],
    js_urls: list[str],
    dirs: dict[str, Path],
    stats: dict,
    log: logging.Logger,
    git_dump_paths: list[Path] | None = None,
) -> None:
    print(clr(f"\n{'━'*60}", DIM))
    print(clr("  [5/5]  Secret Scanning  (all tools in parallel)", BOLD))
    print(clr(f"  Scanners: regex  gf  trufflehog  gitleaks  SecretFinder  jsluice  jsleak  nuclei", DIM))
    print(clr(f"{'━'*60}", DIM))

    all_findings: list[Finding] = []

    # Gitleaks wrapper: scan downloaded JS + git dumps
    def _scan_gitleaks_all() -> list[Finding]:
        results = scan_gitleaks(dirs["dl"], dirs["raw"], log)
        if git_dump_paths:
            for dump_path in git_dump_paths:
                results.extend(scan_gitleaks(dump_path, dirs["raw"], log))
        return results

    with ThreadPoolExecutor(max_workers=10) as ex:
        futs: dict = {
            ex.submit(scan_regex,        dl_map,     dirs["raw"], log): "regex",
            ex.submit(scan_gf,           dl_map,     dirs["raw"], log): "gf",
            ex.submit(scan_trufflehog,   dirs["dl"], dirs["raw"], log): "trufflehog",
            ex.submit(_scan_gitleaks_all):                              "gitleaks",
            ex.submit(scan_secretfinder, dl_map,     dirs["raw"], log): "SecretFinder",
            ex.submit(scan_jsluice,      dl_map,     dirs["raw"], log): "jsluice",
            ex.submit(scan_jsleak,       dl_map,     dirs["raw"], log): "jsleak",
            ex.submit(scan_nuclei,       js_urls,    dirs["raw"], log): "nuclei",
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

    # Merge cariddi secrets if they exist
    cariddi_path = dirs["urls"] / "cariddi_secrets.json"
    if cariddi_path.exists():
        try:
            cariddi_data = json.loads(cariddi_path.read_text(encoding="utf-8", errors="replace"))
            if isinstance(cariddi_data, list):
                all_findings.extend(cariddi_data)
                print(f"  {GREEN}✔{RESET}  {'cariddi':<16} {len(cariddi_data):>5} findings (from crawl)")
        except Exception:
            pass

    write_report(all_findings, dirs["secrets"] / "final_report.txt", stats, log)


# ═══════════════════════════════════════════════════════════════════════════
# ARGUMENT PARSING
# ═══════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        prog="siphon",
        description="Siphon  —  v6  (curl/wget + Gitleaks)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Single domain scan
  python3 siphon.py --domain example.com -o out/
  python3 siphon.py --domain https://example.com -o out/ --insecure

  # Multi-subdomain scan from file
  python3 siphon.py -s subs.txt -o out/
  python3 siphon.py -s subs.txt -o out/ --insecure --threads 50

  # Advanced options
  python3 siphon.py --domain example.com -o out/ --scan-all-js
  python3 siphon.py -s subs.txt -o out/ --skip-live-check
  python3 siphon.py -s subs.txt -o out/ --skip-url-collection
  python3 siphon.py -s subs.txt -o out/ --skip-download
        """,
    )

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
    INSECURE = args.insecure

    banner()

    single_domain: bool = False
    subs_file: Path

    if args.domain:
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
    stats["js_dl"]  = len(dl_map)
    stats["dl_rate"] = (
        f"{100 * len(dl_map) / len(targets):.1f}%"
        if targets else "─"
    )

    if not dl_map:
        print(warn("No JS files downloaded successfully."))
        sys.exit(0)

    # ── 4b. Git exposure check ──────────────────────────────────────────────
    git_dump_paths = check_git_exposure(live, dirs["git"], args.threads, log)

    # ── 5. Secret scanning ─────────────────────────────────────────────────
    run_secret_scanning(dl_map, js_custom, dirs, stats, log, git_dump_paths)

    # ── Summary ────────────────────────────────────────────────────────────
    insecure_line = f"  {YELLOW}⚠  TLS verification was disabled (--insecure){RESET}\n" if INSECURE else ""
    print(f"""
{BOLD}{GREEN}  ╔══════════════════════════════════════╗
  ║      Pipeline Complete  ✔  (v5)     ║
  ╚══════════════════════════════════════╝{RESET}
{insecure_line}
  {DIM}{"─"*38}{RESET}
  Live hosts       : {stats["live"]:>8,}
  URLs collected   : {stats["urls"]:>8,}
  JS total         : {stats["js_all"]:>8,}
  JS custom        : {stats["js_custom"]:>8,}
  JS downloaded    : {stats["js_dl"]:>8,}
  Download rate    : {stats.get("dl_rate", "─"):>8}
  {DIM}{"─"*38}{RESET}
  Output  →  {BOLD}{dirs["base"]}{RESET}
  Report  →  {BOLD}{dirs["secrets"] / "final_report.txt"}{RESET}
""")
    log.info("DONE")


if __name__ == "__main__":
    main()
