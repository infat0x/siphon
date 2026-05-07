#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
#   Am I reachable?  ·  Domain External Reachability Scanner  ·  v3.0
#   2026 Edition  ·  Languages: az | en | ru
#
#   Usage:
#     ./jsrecon.py [OPTIONS]
#     -i <file>    Input JSON file          [default: domains.json]
#     -o <dir>     Output directory         [auto-created; default: scan_YYYYMMDD_HHMMSS]
#     -l <lang>    Language: az | en | ru   [default: az]
#     -t <sec>     HTTP timeout per host    [default: 10]
#     -w <n>       Parallel worker threads  [default: 12]
#     -h           Show help and exit
# ═══════════════════════════════════════════════════════════════════════════

BOLD='\033[1m'; DIM='\033[2m'
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
WHITE='\033[1;37m'; GRAY='\033[0;37m'; CYAN='\033[0;36m'; NC='\033[0m'

INPUT_JSON=""; OUTPUT_DIR=""; LANG_CODE="az"; TIMEOUT=10; WORKERS=12

usage() {
  echo -e "\n  ${WHITE}${BOLD}Am I reachable?${NC}  ·  Domain Scanner v3.0\n"
  echo -e "  ${GRAY}Usage:${NC} $0 [OPTIONS]\n"
  echo -e "  ${CYAN}-i <file>${NC}   Input JSON file          [default: domains.json]"
  echo -e "  ${CYAN}-o <dir>${NC}    Output directory         [default: scan_YYYYMMDD_HHMMSS]"
  echo -e "  ${CYAN}-l <lang>${NC}   Language: az | en | ru   [default: az]"
  echo -e "  ${CYAN}-t <sec>${NC}    HTTP timeout per host    [default: 10]"
  echo -e "  ${CYAN}-w <n>${NC}      Parallel worker threads  [default: 12]"
  echo -e "  ${CYAN}-h${NC}          Show this help\n"
  exit 0
}

while getopts "i:o:l:t:w:h" opt; do
  case $opt in
    i) INPUT_JSON="$OPTARG" ;;
    o) OUTPUT_DIR="$OPTARG" ;;
    l) LANG_CODE="$OPTARG" ;;
    t) TIMEOUT="$OPTARG"   ;;
    w) WORKERS="$OPTARG"   ;;
    h) usage ;;
    *) usage ;;
  esac
done

# ── Defaults ───────────────────────────────────────────────────────────────
[ -z "$INPUT_JSON" ] && INPUT_JSON="domains.json"
[ -z "$OUTPUT_DIR" ] && OUTPUT_DIR="scan_$(date +%Y%m%d_%H%M%S)"

case "$LANG_CODE" in
  az|en|ru) ;;
  *) echo -e "${RED}[!] Invalid language: $LANG_CODE  →  Use: az, en, ru${NC}"; exit 1 ;;
esac

# ── Terminal strings ───────────────────────────────────────────────────────
case "$LANG_CODE" in
  en)
    MSG_DEPS="[*] Checking dependencies...";        MSG_INSTALL="[!] Not found, installing:"
    MSG_WW_OK="[✓] WhatWeb: active";                MSG_WW_NO="[~] WhatWeb: inactive (skipped)"
    MSG_CR_OK="[✓] Screenshots: active";            MSG_CR_NO="[~] Screenshots: inactive (Chrome not found)"
    MSG_NO_IN="[ERROR] Input file not found:";      MSG_INPUT="[*] Input"
    MSG_OUTPUT="[*] Output dir";                    MSG_TIMEOUT="[*] Timeout"
    MSG_WORKERS="[*] Threads";                      MSG_DONE="[✓] Scan complete!"
    MSG_F1="  scan_results.html  — interactive report (open in browser)"
    MSG_F2="  scan_results.json  — machine-readable data"
    MSG_F3="  scan_results.csv   — spreadsheet-compatible"
    MSG_F4="  README.txt         — scan summary"
    MSG_F5="  screenshots/       — PNG files"
    ;;
  ru)
    MSG_DEPS="[*] Проверка зависимостей...";        MSG_INSTALL="[!] Не найдено, установка:"
    MSG_WW_OK="[✓] WhatWeb: активен";               MSG_WW_NO="[~] WhatWeb: неактивен (пропуск)"
    MSG_CR_OK="[✓] Скриншоты: активны";             MSG_CR_NO="[~] Скриншоты: неактивны (Chrome не найден)"
    MSG_NO_IN="[ОШИБКА] Входной файл не найден:";   MSG_INPUT="[*] Входной файл"
    MSG_OUTPUT="[*] Папка вывода";                  MSG_TIMEOUT="[*] Тайм-аут"
    MSG_WORKERS="[*] Потоков";                      MSG_DONE="[✓] Сканирование завершено!"
    MSG_F1="  scan_results.html  — интерактивный отчёт (открыть в браузере)"
    MSG_F2="  scan_results.json  — данные JSON"
    MSG_F3="  scan_results.csv   — для таблиц"
    MSG_F4="  README.txt         — краткий итог"
    MSG_F5="  screenshots/       — PNG файлы"
    ;;
  *)  # az
    MSG_DEPS="[*] Asılılıqlar yoxlanılır...";       MSG_INSTALL="[!] Tapılmadı, qurulur:"
    MSG_WW_OK="[✓] WhatWeb: aktiv";                 MSG_WW_NO="[~] WhatWeb: deaktiv (atlanır)"
    MSG_CR_OK="[✓] Ekran görüntüsü: aktiv";         MSG_CR_NO="[~] Ekran görüntüsü: deaktiv (Chrome tapılmadı)"
    MSG_NO_IN="[XƏTA] Giriş faylı tapılmadı:";      MSG_INPUT="[*] Giriş"
    MSG_OUTPUT="[*] Çıxış qovluğu";                 MSG_TIMEOUT="[*] Gözləmə"
    MSG_WORKERS="[*] İş parçası";                   MSG_DONE="[✓] Skan tamamlandı!"
    MSG_F1="  scan_results.html  — interaktiv hesabat (brauzerdə aç)"
    MSG_F2="  scan_results.json  — maşın oxunaqlı nəticələr"
    MSG_F3="  scan_results.csv   — Excel/Sheets üçün"
    MSG_F4="  README.txt         — xülasə"
    MSG_F5="  screenshots/       — PNG faylları"
    ;;
esac

# ── Banner ─────────────────────────────────────────────────────────────────
clear 2>/dev/null || true
echo -e ""
echo -e "${WHITE}${BOLD}  ┌─────────────────────────────────────────────────┐${NC}"
echo -e "${WHITE}${BOLD}  │          Am I reachable?   ·   v3.0   2026      │${NC}"
echo -e "${WHITE}${BOLD}  │        Domain External Reachability Scanner     │${NC}"
echo -e "${WHITE}${BOLD}  └─────────────────────────────────────────────────┘${NC}"
echo -e ""

# ── Dependency checks ──────────────────────────────────────────────────────
echo -e "${GRAY}${MSG_DEPS}${NC}"
SKIP_WHATWEB=0; SKIP_SCREENSHOTS=0; CHROME_BIN=""

if ! command -v whatweb &>/dev/null; then
  echo -e "${YELLOW}${MSG_INSTALL} whatweb${NC}"
  apt-get install -y whatweb -qq 2>/dev/null || \
    gem install whatweb 2>/dev/null || true
  command -v whatweb &>/dev/null || SKIP_WHATWEB=1
fi
[ $SKIP_WHATWEB -eq 0 ] && echo -e "${GREEN}${MSG_WW_OK}${NC}" \
                         || echo -e "${YELLOW}${MSG_WW_NO}${NC}"

for _bin in google-chrome-stable google-chrome chromium-browser chromium; do
  command -v "$_bin" &>/dev/null && CHROME_BIN="$_bin" && break
done

if [ -z "$CHROME_BIN" ]; then
  echo -e "${YELLOW}${MSG_INSTALL} chromium${NC}"
  apt-get install -y chromium-browser -qq 2>/dev/null || \
    apt-get install -y chromium -qq 2>/dev/null || true
  for _bin in chromium-browser chromium google-chrome-stable google-chrome; do
    command -v "$_bin" &>/dev/null && CHROME_BIN="$_bin" && break
  done
fi

if [ -n "$CHROME_BIN" ]; then
  echo -e "${GREEN}${MSG_CR_OK} (${CHROME_BIN})${NC}"
else
  echo -e "${YELLOW}${MSG_CR_NO}${NC}"
  SKIP_SCREENSHOTS=1
fi

# ── Validate input ─────────────────────────────────────────────────────────
if [ ! -f "$INPUT_JSON" ]; then
  echo -e "\n${RED}${MSG_NO_IN} ${INPUT_JSON}${NC}\n"
  exit 1
fi

# ── Create output tree ─────────────────────────────────────────────────────
mkdir -p "${OUTPUT_DIR}/screenshots"

echo -e ""
echo -e "${GRAY}${MSG_INPUT}:${NC}    ${INPUT_JSON}"
echo -e "${GRAY}${MSG_OUTPUT}:${NC}  ${OUTPUT_DIR}/"
echo -e "${GRAY}${MSG_TIMEOUT}:${NC}  ${TIMEOUT}s per host"
echo -e "${GRAY}${MSG_WORKERS}:${NC}  ${WORKERS}"
echo -e ""

PYTHON_SCRIPT="/tmp/amireachable_v3.py"

# ── Embed Python scanner ───────────────────────────────────────────────────
cat > "$PYTHON_SCRIPT" << 'PYEOF'
import json, socket, sys, csv, time, os, subprocess, base64, re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.request, urllib.error, ssl

# ── Args from bash ─────────────────────────────────────────────────────────
INPUT_JSON   = sys.argv[1]
OUTPUT_DIR   = sys.argv[2]
TIMEOUT      = int(sys.argv[3])
SKIP_WHATWEB = sys.argv[4] == "1"
SKIP_SHOTS   = sys.argv[5] == "1"
CHROME_BIN   = sys.argv[6] if len(sys.argv) > 6 and sys.argv[6] else ""
WORKERS      = int(sys.argv[7]) if len(sys.argv) > 7 else 12
LANG         = sys.argv[8] if len(sys.argv) > 8 else "az"
SHOTS_DIR    = os.path.join(OUTPUT_DIR, "screenshots")
os.makedirs(SHOTS_DIR, exist_ok=True)
START_TIME   = time.time()

# ── Language dictionaries ──────────────────────────────────────────────────
_STRINGS = {
    "az": {
        "title": "Am I reachable?",
        "subtitle": "Domain Xarici Əlçatanlıq Skanı",
        "scan_date": "Skan tarixi",
        "hosts": "host",
        "open": "açıq",
        "closed": "bağlı",
        "search_placeholder": "Host, IP, texnologiya, server axtar...",
        "all": "Hamısı",
        "f_open": "Açıq",
        "f_closed": "Bağlı",
        "f_nodns": "DNS yox",
        "f_shots": "Ekran görüntüsü",
        "col_status": "Status",
        "col_host": "Host",
        "col_domain": "Domain",
        "col_ips": "IP Ünvanlar",
        "col_http": "HTTP",
        "col_tcp": "TCP",
        "col_server": "Server",
        "col_tech": "Texnologiyalar",
        "col_sec": "Təhlükəsizlik",
        "col_url": "URL",
        "col_shot": "Ekran",
        "col_time": "Müddət",
        "zoom": "Böyüt",
        "total_scanned": "Cəmi taranmış",
        "ext_open": "Xarici əlçatan",
        "cl_nodns": "Bağlı / DNS yox",
        "shots_taken": "Ekran görüntüsü",
        "scan_dur": "Skan müddəti",
        "out_files": "Çıxış faylları",
        "apex": "apex",
        "sub": "sub",
    },
    "en": {
        "title": "Am I reachable?",
        "subtitle": "Domain External Reachability Scan",
        "scan_date": "Scan date",
        "hosts": "hosts",
        "open": "open",
        "closed": "closed",
        "search_placeholder": "Search hosts, IPs, technologies, servers...",
        "all": "All",
        "f_open": "Open",
        "f_closed": "Closed",
        "f_nodns": "No DNS",
        "f_shots": "Screenshots",
        "col_status": "Status",
        "col_host": "Host",
        "col_domain": "Domain",
        "col_ips": "IP Addresses",
        "col_http": "HTTP",
        "col_tcp": "TCP",
        "col_server": "Server",
        "col_tech": "Technologies",
        "col_sec": "Security",
        "col_url": "URL",
        "col_shot": "Screenshot",
        "col_time": "Time",
        "zoom": "Zoom",
        "total_scanned": "Total scanned",
        "ext_open": "Externally open",
        "cl_nodns": "Closed / No DNS",
        "shots_taken": "Screenshots taken",
        "scan_dur": "Scan duration",
        "out_files": "Output files",
        "apex": "apex",
        "sub": "sub",
    },
    "ru": {
        "title": "Am I reachable?",
        "subtitle": "Сканирование внешней доступности доменов",
        "scan_date": "Дата сканирования",
        "hosts": "хостов",
        "open": "открыт.",
        "closed": "закрыт.",
        "search_placeholder": "Поиск по хосту, IP, технологиям, серверу...",
        "all": "Все",
        "f_open": "Открытые",
        "f_closed": "Закрытые",
        "f_nodns": "Нет DNS",
        "f_shots": "Скриншоты",
        "col_status": "Статус",
        "col_host": "Хост",
        "col_domain": "Домен",
        "col_ips": "IP Адреса",
        "col_http": "HTTP",
        "col_tcp": "TCP",
        "col_server": "Сервер",
        "col_tech": "Технологии",
        "col_sec": "Безопасность",
        "col_url": "URL",
        "col_shot": "Скриншот",
        "col_time": "Время",
        "zoom": "Увеличить",
        "total_scanned": "Всего просканировано",
        "ext_open": "Внешне доступно",
        "cl_nodns": "Закрыто / Нет DNS",
        "shots_taken": "Скриншотов получено",
        "scan_dur": "Длительность",
        "out_files": "Выходные файлы",
        "apex": "apex",
        "sub": "sub",
    }
}
L = _STRINGS.get(LANG, _STRINGS["az"])

# ── Pre-define L lookups to avoid quote nesting in f-strings ───────────────
L_search    = L["search_placeholder"]
L_scan_date = L["scan_date"]
L_hosts     = L["hosts"]
L_open      = L["open"]
L_closed    = L["closed"]
L_all       = L["all"]
L_f_open    = L["f_open"]
L_f_closed  = L["f_closed"]
L_f_nodns   = L["f_nodns"]
L_f_shots   = L["f_shots"]
L_col_stat  = L["col_status"]
L_col_host  = L["col_host"]
L_col_dom   = L["col_domain"]
L_col_ips   = L["col_ips"]
L_col_http  = L["col_http"]
L_col_tcp   = L["col_tcp"]
L_col_srv   = L["col_server"]
L_col_tech  = L["col_tech"]
L_col_sec   = L["col_sec"]
L_col_url   = L["col_url"]
L_col_shot  = L["col_shot"]
L_col_time  = L["col_time"]
L_zoom      = L["zoom"]
L_apex      = L["apex"]
L_sub       = L["sub"]

# ── Network helpers ────────────────────────────────────────────────────────
def resolve_dns(host):
    try:
        ips = socket.getaddrinfo(host, None)
        return list(set(r[4][0] for r in ips)), None
    except socket.gaierror as e:
        return [], str(e)

def check_http(host, scheme="https"):
    url = f"{scheme}://{host}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode   = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0"
        })
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=ctx) as r:
            return r.status, r.url, dict(r.headers), None
    except urllib.error.HTTPError as e:
        return e.code, url, dict(e.headers) if hasattr(e, "headers") else {}, None
    except urllib.error.URLError as e:
        return None, url, {}, str(e.reason)
    except Exception as e:
        return None, url, {}, str(e)

def check_tcp(host, port):
    try:
        s = socket.socket()
        s.settimeout(min(TIMEOUT, 5))
        ok = s.connect_ex((host, port)) == 0
        s.close()
        return ok
    except Exception:
        return False

def classify(http_code, tcp_443, tcp_80, ips):
    if not ips:                                      return "NO_DNS",       "⛔"
    if http_code in (200,201,301,302,303,307,308):   return "OPEN",         "✅"
    if http_code in (401, 403):                      return "OPEN (Auth)",  "🔒"
    if http_code and http_code >= 400:               return "OPEN (Error)", "⚠️"
    if tcp_443 or tcp_80:                            return "TCP OPEN",     "🟡"
    if ips:                                          return "DNS ONLY",     "🟠"
    return "CLOSED", "❌"

# ── WhatWeb fingerprinting ─────────────────────────────────────────────────
def run_whatweb(host, scheme="https"):
    if SKIP_WHATWEB:
        return []
    try:
        url = f"{scheme}://{host}"
        res = subprocess.run(
            ["whatweb", "--no-errors", "-q", "--color=never", url],
            capture_output=True, text=True, timeout=15
        )
        raw = res.stdout.strip()
        if not raw:
            return []
        m = re.search(r'\[\d+\]\s+(.*)', raw)
        if not m:
            return []
        techs = []
        for part in m.group(1).split(","):
            p = part.strip()
            if p and not p.startswith("http") and len(p) < 80:
                techs.append(p)
        return techs[:15]
    except Exception:
        return []

# ── Screenshot – waits for page to fully render ────────────────────────────
def take_screenshot(host, scheme="https"):
    if SKIP_SHOTS or not CHROME_BIN:
        return None, None
    url   = f"{scheme}://{host}"
    fname = re.sub(r'[^a-zA-Z0-9._-]', '_', host).strip('_') + ".png"
    fpath = os.path.join(SHOTS_DIR, fname)

    if os.path.exists(fpath):
        os.remove(fpath)

    base_flags = [
        "--no-sandbox",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--disable-extensions",
        "--disable-background-networking",
        "--ignore-certificate-errors",
        "--ignore-ssl-errors=true",
        "--disable-popup-blocking",
        "--disable-infobars",
        "--hide-scrollbars",
        "--mute-audio",
        "--run-all-compositor-stages-before-draw",  # ensures paint is complete
        "--disable-features=TranslateUI,VizDisplayCompositor",
        "--window-size=1280,800",
        f"--screenshot={fpath}",
        "--virtual-time-budget=12000",              # fast-forward JS timers 12s
        url,
    ]

    # Try modern headless first (Chrome 112+), then legacy
    for headless in ("--headless=new", "--headless"):
        if os.path.exists(fpath):
            os.remove(fpath)
        try:
            subprocess.run(
                [CHROME_BIN, headless] + base_flags,
                capture_output=True,
                timeout=35
            )
        except subprocess.TimeoutExpired:
            pass  # file might still exist
        except Exception:
            continue

        # Wait for file to be fully written (poll up to 5 s)
        deadline = time.time() + 5.0
        while time.time() < deadline:
            time.sleep(0.4)
            if os.path.exists(fpath) and os.path.getsize(fpath) > 12_000:
                break

        if os.path.exists(fpath) and os.path.getsize(fpath) > 12_000:
            break
        if os.path.exists(fpath):
            os.remove(fpath)

    if not os.path.exists(fpath) or os.path.getsize(fpath) <= 12_000:
        return None, None

    try:
        with open(fpath, "rb") as f:
            b64 = base64.b64encode(f.read()).decode()
        return b64, fname          # keep PNG on disk AND return b64 for HTML
    except Exception:
        return None, None

# ── Main per-host scan ─────────────────────────────────────────────────────
def scan_host(entry):
    domain = entry["domain"]
    is_sub = entry.get("is_subdomain", False)
    host   = entry["host"]
    print(f"  → {host}", flush=True)

    t0 = time.time()
    ips, dns_err = resolve_dns(host)

    # Try HTTPS first, fall back to HTTP
    http_code, final_url, headers, http_err = check_http(host, "https")
    used_scheme = "https"
    if http_code is None:
        hc2, fu2, hd2, he2 = check_http(host, "http")
        if hc2:
            http_code, final_url, headers, http_err = hc2, fu2, hd2, he2
            used_scheme = "http"

    tcp_443 = check_tcp(host, 443)
    tcp_80  = check_tcp(host, 80)
    elapsed = round(time.time() - t0, 2)

    status_text, status_icon = classify(http_code, tcp_443, tcp_80, ips)

    # Case-insensitive header lookup
    hdrs         = {k.lower(): v for k, v in headers.items()}
    server       = hdrs.get("server", "")
    content_type = hdrs.get("content-type", "").split(";")[0].strip()
    hsts         = "strict-transport-security" in hdrs
    x_frame      = hdrs.get("x-frame-options", "")
    x_powered    = hdrs.get("x-powered-by", "")
    x_content    = hdrs.get("x-content-type-options", "")
    csp          = "content-security-policy" in hdrs

    # WhatWeb only on reachable hosts
    whatweb_techs = []
    if "OPEN" in status_text:
        whatweb_techs = run_whatweb(host, used_scheme)

    # Screenshot only when HTTP-reachable
    screenshot_b64, shot_fname = None, None
    if http_code and ips:
        screenshot_b64, shot_fname = take_screenshot(host, used_scheme)

    return {
        "domain":          domain,
        "host":            host,
        "is_subdomain":    is_sub,
        "dns_resolved":    len(ips) > 0,
        "ips":             ips,
        "dns_error":       dns_err,
        "http_code":       http_code,
        "http_error":      http_err,
        "final_url":       final_url,
        "scheme":          used_scheme,
        "tcp_443":         tcp_443,
        "tcp_80":          tcp_80,
        "status":          status_text,
        "status_icon":     status_icon,
        "server":          server,
        "content_type":    content_type,
        "x_powered_by":    x_powered,
        "hsts":            hsts,
        "x_frame_options": x_frame,
        "x_content_type":  x_content,
        "csp":             csp,
        "whatweb":         whatweb_techs,
        "screenshot":      screenshot_b64,
        "shot_file":       shot_fname,
        "scan_time_s":     elapsed,
        "scanned_at":      datetime.utcnow().isoformat() + "Z",
    }

# ── Load & flatten domains.json ────────────────────────────────────────────
SKIP_PREFIXES = (
    "_dmarc.", "_domainkey.", "_bbcab.", "_6a24.", "_sip.", "_sipfed.",
    "_autodiscover.", "mail._domainkey.", "k2._domainkey.", "k3._domainkey.",
    "s1._domainkey.", "s2._domainkey.", "em2443.", "selector1._domainkey.",
    "default._domainkey.", "230619", "cf2024", "frzr", "wziut", "p9up",
)

with open(INPUT_JSON) as fh:
    raw_data = json.load(fh)

entries = []
for item in raw_data:
    dom = item["domain"]
    entries.append({"domain": dom, "host": dom, "is_subdomain": False})
    for sub in item.get("subdomains", []):
        if any(sub.startswith(p) for p in SKIP_PREFIXES):
            continue
        entries.append({"domain": dom, "host": sub, "is_subdomain": True})

print(f"\n[*] Total hosts to scan : {len(entries)}  ({WORKERS} threads)\n", flush=True)

# ── Parallel scan ──────────────────────────────────────────────────────────
results = []
with ThreadPoolExecutor(max_workers=WORKERS) as ex:
    futures = {ex.submit(scan_host, e): e for e in entries}
    done = 0
    for fut in as_completed(futures):
        done += 1
        r    = fut.result()
        results.append(r)
        icon  = r["status_icon"]
        techs = ", ".join(r["whatweb"][:2]) if r["whatweb"] else "—"
        shot  = "📸" if r["screenshot"] else "  "
        print(
            f"  [{done:>4}/{len(entries)}] {icon}  "
            f"{r['host']:<45} {r['status']:<22} {techs} {shot}",
            flush=True
        )

# ── Sort by status priority then host name ─────────────────────────────────
STATUS_ORDER = {
    "OPEN": 0, "OPEN (Auth)": 1, "OPEN (Error)": 2,
    "TCP OPEN": 3, "DNS ONLY": 4, "CLOSED": 5, "NO_DNS": 6
}
results.sort(key=lambda x: (STATUS_ORDER.get(x["status"], 9), x["host"]))

# ── Aggregate stats ────────────────────────────────────────────────────────
counts     = {}
shot_count = 0
for r in results:
    counts[r["status"]] = counts.get(r["status"], 0) + 1
    if r.get("screenshot"):
        shot_count += 1

open_count   = sum(v for k, v in counts.items() if "OPEN" in k)
closed_count = counts.get("CLOSED", 0) + counts.get("NO_DNS", 0)
scan_dur     = round(time.time() - START_TIME, 1)
scan_dt      = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

# ── JSON output ────────────────────────────────────────────────────────────
json_path  = os.path.join(OUTPUT_DIR, "scan_results.json")
json_clean = [{k: v for k, v in r.items() if k not in ("screenshot", "shot_file")}
              for r in results]
with open(json_path, "w") as fh:
    json.dump({
        "tool": "Am I reachable? v3.0",
        "scan_date":   scan_dt + " UTC",
        "lang":        LANG,
        "total":       len(results),
        "open":        open_count,
        "closed":      closed_count,
        "screenshots": shot_count,
        "duration_s":  scan_dur,
        "counts":      counts,
        "results":     json_clean,
    }, fh, indent=2, ensure_ascii=False)
print(f"\n[✓] JSON  → {json_path}")

# ── CSV output ─────────────────────────────────────────────────────────────
csv_path = os.path.join(OUTPUT_DIR, "scan_results.csv")
csv_fields = [
    "status_icon", "status", "host", "domain", "is_subdomain",
    "dns_resolved", "ips", "http_code", "scheme", "tcp_443", "tcp_80",
    "server", "x_powered_by", "content_type", "hsts", "x_frame_options",
    "x_content_type", "csp", "whatweb", "final_url", "scan_time_s", "scanned_at",
]
with open(csv_path, "w", newline="", encoding="utf-8") as fh:
    w = csv.DictWriter(fh, fieldnames=csv_fields, extrasaction="ignore")
    w.writeheader()
    for r in results:
        row = dict(r)
        row["ips"]     = ", ".join(row.get("ips", []))
        row["whatweb"] = " | ".join(row.get("whatweb", []))
        row.pop("screenshot", None)
        row.pop("shot_file", None)
        row.pop("dns_error", None)
        row.pop("http_error", None)
        w.writerow(row)
print(f"[✓] CSV   → {csv_path}")

# ── HTML output ────────────────────────────────────────────────────────────
html_path = os.path.join(OUTPUT_DIR, "scan_results.html")

STATUS_COLORS = {
    "OPEN":         "#22c55e",
    "OPEN (Auth)":  "#a78bfa",
    "OPEN (Error)": "#f59e0b",
    "TCP OPEN":     "#d4d4d8",
    "DNS ONLY":     "#fb923c",
    "CLOSED":       "#ef4444",
    "NO_DNS":       "#71717a",
}

TECH_PALETTE = {
    "apache": "#f97316",    "nginx": "#6ee7b7",    "php": "#c084fc",
    "wordpress": "#fbbf24", "drupal": "#4ade80",   "joomla": "#fca5a5",
    "iis": "#e2e8f0",       "jquery": "#facc15",   "react": "#7dd3fc",
    "angular": "#f87171",   "vue": "#86efac",      "bootstrap": "#a78bfa",
    "laravel": "#fda4af",   "django": "#6ee7b7",   "ruby": "#fca5a5",
    "python": "#fde68a",    "node": "#86efac",     "express": "#d4d4d8",
    "cloudflare": "#fb923c","aws": "#fbbf24",       "google": "#60a5fa",
    "varnish": "#d8b4fe",   "mysql": "#5eead4",    "postgresql": "#93c5fd",
    "shopify": "#bbf7d0",   "wix": "#d9f99d",      "squarespace": "#e5e7eb",
    "next": "#f0f0f0",      "nuxt": "#4ade80",     "svelte": "#fdba74",
    "typescript": "#93c5fd","go": "#67e8f9",        "rust": "#fca5a5",
}

def tech_color(t):
    tl = t.lower()
    for k, c in TECH_PALETTE.items():
        if k in tl:
            return c
    return "#a1a1aa"

# ── Build table rows ────────────────────────────────────────────────────────
rows_html = ""
for idx, r in enumerate(results):
    color    = STATUS_COLORS.get(r["status"], "#71717a")
    ips_str  = ", ".join(r["ips"]) if r["ips"] else "—"
    http_str = str(r["http_code"]) if r["http_code"] else "—"
    server   = r.get("server") or "—"
    xpwr     = r.get("x_powered_by") or ""

    hsts_badge = '<span class="badge b-green">HSTS</span>' if r["hsts"] else ""
    csp_badge  = '<span class="badge b-amber">CSP</span>'  if r["csp"]  else ""
    xf_badge   = f'<span class="badge b-zinc">{r["x_frame_options"]}</span>' if r["x_frame_options"] else ""
    tcp_badges = ""
    if r["tcp_443"]: tcp_badges += '<span class="badge b-teal">443</span>'
    if r["tcp_80"]:  tcp_badges += '<span class="badge b-teal">80</span>'
    type_badge = (f'<span class="badge b-purple">{L_apex}</span>'
                  if not r["is_subdomain"]
                  else f'<span class="badge b-zinc">{L_sub}</span>')

    url_raw  = r.get("final_url") or ""
    url_disp = url_raw[:50] + ("…" if len(url_raw) > 50 else "")
    url_link = f'<a href="{url_raw}" target="_blank" class="url-link">{url_disp}</a>' if url_raw else "—"

    tech_tags = ""
    for t in r.get("whatweb", []):
        tc = tech_color(t)
        tech_tags += (f'<span class="tech-tag" '
                      f'style="background:{tc}18;color:{tc};border:1px solid {tc}35">'
                      f'{t}</span>')
    if not tech_tags:
        tech_tags = '<span class="muted">—</span>'

    xpwr_html = f'<br><span class="muted xs">{xpwr}</span>' if xpwr else ""

    if r.get("screenshot"):
        b64 = r["screenshot"]
        shot_cell = (
            f'<div class="thumb" onclick="openModal(\'m{idx}\')">'
            f'<img src="data:image/png;base64,{b64}" alt="ss" loading="lazy">'
            f'<div class="t-ovl">🔍 {L_zoom}</div>'
            f'</div>'
            f'<div id="m{idx}" class="modal" '
            f'onclick="this.classList.remove(\'open\');document.body.style.overflow=\'\'">'
            f'<div class="mbox" onclick="event.stopPropagation()">'
            f'<div class="mhdr"><code>{r["host"]}</code>'
            f'<button onclick="document.getElementById(\'m{idx}\').classList.remove(\'open\');'
            f'document.body.style.overflow=\'\'">✕</button></div>'
            f'<img src="data:image/png;base64,{b64}" alt="ss" '
            f'style="width:100%;display:block;border-radius:0 0 12px 12px">'
            f'</div></div>'
        )
    else:
        shot_cell = '<span class="muted">—</span>'

    rows_html += (
        f'<tr data-status="{r["status"]}">'
        f'<td><span class="chip">'
        f'<span class="dot" style="background:{color}"></span>'
        f'<span style="color:{color};font-weight:600">{r["status_icon"]} {r["status"]}</span>'
        f'</span></td>'
        f'<td class="mono">{r["host"]} {type_badge}</td>'
        f'<td class="muted xs">{r["domain"]}</td>'
        f'<td class="xs" style="color:#a1a1aa">{ips_str}</td>'
        f'<td><span class="http-code" style="color:{color}">{http_str}</span></td>'
        f'<td>{tcp_badges}</td>'
        f'<td class="xs" style="color:#d4d4d8">{server}{xpwr_html}</td>'
        f'<td class="tech-cell">{tech_tags}</td>'
        f'<td>{hsts_badge}{csp_badge}{xf_badge}</td>'
        f'<td>{url_link}</td>'
        f'<td class="shot-cell">{shot_cell}</td>'
        f'<td class="muted xs">{r["scan_time_s"]}s</td>'
        f'</tr>\n'
    )

# ── Stat cards ──────────────────────────────────────────────────────────────
stat_cards = ""
for status, color in STATUS_COLORS.items():
    c = counts.get(status, 0)
    if c:
        stat_cards += (
            f'<div class="stat-card" style="border-left-color:{color}">'
            f'<div class="stat-n" style="color:{color}">{c}</div>'
            f'<div class="stat-l">{status}</div>'
            f'</div>'
        )
if shot_count:
    stat_cards += (
        f'<div class="stat-card" style="border-left-color:#22d3ee">'
        f'<div class="stat-n" style="color:#22d3ee">{shot_count}</div>'
        f'<div class="stat-l">📸 Screenshots</div>'
        f'</div>'
    )

# ── Assemble HTML ───────────────────────────────────────────────────────────
cnt_tcp    = counts.get("TCP OPEN", 0)
cnt_dns    = counts.get("DNS ONLY", 0)
cnt_closed = counts.get("CLOSED", 0)
cnt_nodns  = counts.get("NO_DNS", 0)

html = f"""<!DOCTYPE html>
<html lang="{LANG}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Am I reachable?</title>
<style>
:root {{
  --bg:     #0a0a0a;
  --s1:     #111111;
  --s2:     #171717;
  --s3:     #1f1f1f;
  --bdr:    #2a2a2a;
  --bdr2:   #333333;
  --txt:    #f0f0f0;
  --muted:  #71717a;
  --sm:     #52525b;
}}
*,*::before,*::after {{ margin:0;padding:0;box-sizing:border-box }}
body {{ background:var(--bg);color:var(--txt);font-family:'Inter','Segoe UI',system-ui,sans-serif;min-height:100vh;font-size:14px;line-height:1.5 }}

/* ── Header ── */
.header {{
  background:var(--s1);
  border-bottom:1px solid var(--bdr);
  padding:52px 24px 36px;
  text-align:center;
}}
.brand {{
  font-size:42px;
  font-weight:800;
  letter-spacing:-2px;
  color:#fff;
  margin-bottom:6px;
  line-height:1;
}}
.brand em {{ font-style:normal; color:#22c55e }}
.tagline {{
  color:var(--muted);
  font-size:13px;
  margin-bottom:24px;
  letter-spacing:.5px;
  text-transform:uppercase;
}}
.search-wrap {{
  position:relative;
  max-width:540px;
  margin:0 auto 18px;
}}
.search-icon {{
  position:absolute;
  left:15px; top:50%;
  transform:translateY(-50%);
  color:var(--muted);
  pointer-events:none;
  width:16px; height:16px;
}}
#searchBox {{
  width:100%;
  background:var(--bg);
  border:1px solid var(--bdr2);
  border-radius:14px;
  padding:13px 18px 13px 44px;
  font-size:14px;
  color:var(--txt);
  outline:none;
  font-family:inherit;
  transition:border-color .2s, box-shadow .2s;
}}
#searchBox:focus {{
  border-color:#525252;
  box-shadow:0 0 0 3px rgba(255,255,255,.04);
}}
#searchBox::placeholder {{ color:var(--sm) }}
.meta {{
  color:var(--muted);
  font-size:12px;
  margin-top:4px;
}}
.meta b {{ color:#e4e4e7; font-weight:600 }}

/* ── Wrap ── */
.wrap {{ padding:24px 28px; max-width:2100px; margin:0 auto }}

/* ── Stat cards ── */
.stats {{ display:flex; flex-wrap:wrap; gap:10px; margin-bottom:20px }}
.stat-card {{
  background:var(--s2);
  border:1px solid var(--bdr);
  border-left:3px solid #71717a;
  border-radius:10px;
  padding:14px 20px;
  min-width:155px;
  transition:border-color .2s;
}}
.stat-n {{ font-size:30px; font-weight:700; line-height:1 }}
.stat-l {{ font-size:10px; color:var(--muted); margin-top:6px; text-transform:uppercase; letter-spacing:.6px }}

/* ── Filter bar ── */
.fbar {{ display:flex; gap:7px; flex-wrap:wrap; align-items:center; margin-bottom:14px }}
.fbtn {{
  background:var(--s2);
  border:1px solid var(--bdr);
  border-radius:20px;
  padding:6px 14px;
  font-size:12px;
  color:var(--muted);
  cursor:pointer;
  transition:all .15s;
  font-family:inherit;
  line-height:1.4;
}}
.fbtn:hover {{ color:var(--txt); border-color:#525252 }}
.fbtn.active {{ background:var(--s3); color:var(--txt); border-color:#525252 }}

/* ── Table ── */
.tbl-wrap {{ overflow-x:auto; border-radius:12px; border:1px solid var(--bdr) }}
table {{ width:100%; border-collapse:collapse; font-size:13px }}
thead th {{
  background:var(--s1);
  padding:10px 12px;
  text-align:left;
  color:var(--sm);
  font-weight:600;
  font-size:10px;
  text-transform:uppercase;
  letter-spacing:.6px;
  white-space:nowrap;
  border-bottom:1px solid var(--bdr);
}}
tbody tr {{ border-bottom:1px solid #141414; transition:background .1s }}
tbody tr:hover {{ background:var(--s2) }}
tbody tr:last-child {{ border-bottom:none }}
td {{ padding:9px 12px; vertical-align:middle }}

/* ── Chips ── */
.chip {{ display:inline-flex; align-items:center; gap:6px; font-size:12px; white-space:nowrap }}
.dot {{ width:7px; height:7px; border-radius:50%; flex-shrink:0 }}
.http-code {{ font-size:16px; font-weight:700 }}

/* ── Badges ── */
.badge {{ display:inline-block; padding:1px 6px; border-radius:4px; font-size:10px; font-weight:700; margin:1px }}
.b-green {{ background:#14532d25; color:#86efac; border:1px solid #14532d55 }}
.b-amber {{ background:#78350f25; color:#fcd34d; border:1px solid #78350f55 }}
.b-teal  {{ background:#134e4a25; color:#5eead4; border:1px solid #134e4a55 }}
.b-zinc  {{ background:#27272a;   color:#a1a1aa; border:1px solid #3f3f46   }}
.b-purple{{ background:#3b076422; color:#e9d5ff; border:1px solid #581c8755 }}

/* ── Misc ── */
.mono {{ font-family:'JetBrains Mono','Consolas','Fira Code',monospace; font-size:12px; color:#e4e4e7 }}
.muted {{ color:var(--muted) }}
.xs {{ font-size:11px }}
.url-link {{ color:#9ca3af; text-decoration:none; font-size:11px }}
.url-link:hover {{ color:var(--txt); text-decoration:underline }}
.tech-cell {{ max-width:240px }}
.tech-tag {{
  display:inline-block;
  padding:2px 7px;
  border-radius:5px;
  font-size:10px;
  font-weight:600;
  margin:2px 2px 2px 0;
  white-space:nowrap;
}}
.shot-cell {{ width:112px; min-width:110px }}

/* ── Thumbnails ── */
.thumb {{
  position:relative;
  width:102px; height:64px;
  border-radius:8px;
  overflow:hidden;
  cursor:pointer;
  border:1px solid var(--bdr2);
  transition:border-color .15s, transform .15s, box-shadow .15s;
}}
.thumb:hover {{ border-color:#525252; transform:scale(1.04); box-shadow:0 4px 16px rgba(0,0,0,.4) }}
.thumb img {{ width:100%; height:100%; object-fit:cover; object-position:top center }}
.t-ovl {{
  position:absolute; inset:0;
  background:rgba(0,0,0,.7);
  display:flex; align-items:center; justify-content:center;
  font-size:11px; color:#fff;
  opacity:0; transition:opacity .15s;
}}
.thumb:hover .t-ovl {{ opacity:1 }}

/* ── Modal ── */
.modal {{
  display:none;
  position:fixed; inset:0;
  background:rgba(0,0,0,.9);
  z-index:9999;
  align-items:center; justify-content:center;
  padding:20px;
  backdrop-filter:blur(6px);
}}
.modal.open {{ display:flex }}
.mbox {{
  background:var(--s1);
  border:1px solid var(--bdr2);
  border-radius:14px;
  max-width:980px; width:100%;
  max-height:92vh; overflow-y:auto;
}}
.mhdr {{
  display:flex; justify-content:space-between; align-items:center;
  padding:14px 18px;
  border-bottom:1px solid var(--bdr);
}}
.mhdr code {{ font-size:13px; color:#e4e4e7; font-family:monospace }}
.mhdr button {{
  background:none; border:none;
  color:var(--muted); font-size:22px; cursor:pointer; line-height:1;
  transition:color .15s;
}}
.mhdr button:hover {{ color:var(--txt) }}

.hidden {{ display:none !important }}

/* ── Scrollbar ── */
::-webkit-scrollbar {{ width:6px; height:6px }}
::-webkit-scrollbar-track {{ background:var(--bg) }}
::-webkit-scrollbar-thumb {{ background:var(--bdr2); border-radius:3px }}
::-webkit-scrollbar-thumb:hover {{ background:#3f3f46 }}
</style>
</head>
<body>

<div class="header">
  <div class="brand">Am I <em>reachable?</em></div>
  <div class="tagline">{L_scan_date}: {scan_dt} UTC</div>
  <div class="search-wrap">
    <svg class="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round">
      <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
    </svg>
    <input type="text" id="searchBox" placeholder="{L_search}" oninput="filterTable()" autocomplete="off" spellcheck="false">
  </div>
  <div class="meta">
    <b>{len(results)}</b> {L_hosts}
    &nbsp;&middot;&nbsp;
    <b style="color:#22c55e">{open_count}</b> {L_open}
    &nbsp;&middot;&nbsp;
    <b style="color:#ef4444">{closed_count}</b> {L_closed}
    &nbsp;&middot;&nbsp;
    📸 <b>{shot_count}</b>
    &nbsp;&middot;&nbsp;
    ⏱ <b>{scan_dur}s</b>
  </div>
</div>

<div class="wrap">
  <div class="stats">{stat_cards}</div>

  <div class="fbar">
    <button class="fbtn active" onclick="setFilter('all',this)">{L_all} ({len(results)})</button>
    <button class="fbtn" onclick="setFilter('OPEN',this)">✅ {L_f_open} ({open_count})</button>
    <button class="fbtn" onclick="setFilter('TCP OPEN',this)">🟡 TCP ({cnt_tcp})</button>
    <button class="fbtn" onclick="setFilter('DNS ONLY',this)">🟠 DNS ({cnt_dns})</button>
    <button class="fbtn" onclick="setFilter('CLOSED',this)">❌ {L_f_closed} ({cnt_closed})</button>
    <button class="fbtn" onclick="setFilter('NO_DNS',this)">⛔ {L_f_nodns} ({cnt_nodns})</button>
    <button class="fbtn" id="shotsBtn" onclick="toggleShots(this)">📸 {L_f_shots} ({shot_count})</button>
  </div>

  <div class="tbl-wrap">
    <table>
      <thead>
        <tr>
          <th>{L_col_stat}</th>
          <th>{L_col_host}</th>
          <th>{L_col_dom}</th>
          <th>{L_col_ips}</th>
          <th>{L_col_http}</th>
          <th>{L_col_tcp}</th>
          <th>{L_col_srv}</th>
          <th>🔬 {L_col_tech}</th>
          <th>{L_col_sec}</th>
          <th>{L_col_url}</th>
          <th>📸 {L_col_shot}</th>
          <th>{L_col_time}</th>
        </tr>
      </thead>
      <tbody id="tBody">
{rows_html}
      </tbody>
    </table>
  </div>
</div>

<script>
let curFilter = 'all', shotsOnly = false;

function filterTable() {{
  const q = document.getElementById('searchBox').value.toLowerCase();
  document.querySelectorAll('#tBody tr').forEach(row => {{
    const text    = row.textContent.toLowerCase();
    const status  = row.dataset.status || '';
    const hasShot = !!row.querySelector('.thumb');
    const ok = (!q || text.includes(q))
            && (curFilter === 'all' || status.includes(curFilter))
            && (!shotsOnly || hasShot);
    row.classList.toggle('hidden', !ok);
  }});
}}

function setFilter(s, btn) {{
  curFilter = s; shotsOnly = false;
  document.querySelectorAll('.fbtn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  filterTable();
}}

function toggleShots(btn) {{
  shotsOnly = !shotsOnly; curFilter = 'all';
  document.querySelectorAll('.fbtn').forEach(b => b.classList.remove('active'));
  if (shotsOnly) btn.classList.add('active');
  filterTable();
}}

function openModal(id) {{
  document.getElementById(id).classList.add('open');
  document.body.style.overflow = 'hidden';
}}

document.addEventListener('keydown', e => {{
  if (e.key === 'Escape') {{
    document.querySelectorAll('.modal.open').forEach(m => {{
      m.classList.remove('open');
      document.body.style.overflow = '';
    }});
  }}
}});
</script>
</body>
</html>"""

with open(html_path, "w", encoding="utf-8") as fh:
    fh.write(html)
print(f"[✓] HTML  → {html_path}")

# ── README.txt ─────────────────────────────────────────────────────────────
readme_path = os.path.join(OUTPUT_DIR, "README.txt")
sep = "─" * 52
with open(readme_path, "w", encoding="utf-8") as fh:
    fh.write(f"""Am I reachable?  ·  Domain Scanner v3.0  ·  2026
{sep}
{L["scan_date"]:<20}: {scan_dt} UTC
Input file          : {INPUT_JSON}
Language            : {LANG}
{sep}
{"Status":<28}  {"Count":>5}
{sep}
""")
    for s, c in sorted(counts.items(), key=lambda x: STATUS_ORDER.get(x[0], 9)):
        icon = {"OPEN":"✅","OPEN (Auth)":"🔒","OPEN (Error)":"⚠️",
                "TCP OPEN":"🟡","DNS ONLY":"🟠","CLOSED":"❌","NO_DNS":"⛔"}.get(s, "❓")
        fh.write(f"  {icon}  {s:<26} {c:>5}\n")
    fh.write(f"""
{L["total_scanned"]:<28}  {len(results):>5}
{L["ext_open"]:<28}  {open_count:>5}
{L["cl_nodns"]:<28}  {closed_count:>5}
{L["shots_taken"]:<28}  {shot_count:>5}
{L["scan_dur"]:<28}  {scan_dur}s
{sep}
{L["out_files"]}:
  scan_results.html    ← Open in browser (interactive report)
  scan_results.json    ← Machine-readable JSON
  scan_results.csv     ← Spreadsheet compatible
  screenshots/         ← {shot_count} PNG file(s)
{sep}
""")
print(f"[✓] README→ {readme_path}")

# ── Print directory tree ───────────────────────────────────────────────────
print(f"\n  📁 {OUTPUT_DIR}/")
print(f"  ├── scan_results.html")
print(f"  ├── scan_results.json")
print(f"  ├── scan_results.csv")
print(f"  ├── README.txt")
shot_files = [f for f in os.listdir(SHOTS_DIR) if f.endswith(".png")]
if shot_files:
    print(f"  └── screenshots/  ({len(shot_files)} files)")
    for i, sf in enumerate(sorted(shot_files)[:5]):
        prefix = "    └──" if i == min(4, len(shot_files)-1) else "    ├──"
        print(f"  {prefix} {sf}")
    if len(shot_files) > 5:
        print(f"       ... +{len(shot_files)-5} more")
else:
    print(f"  └── screenshots/  (empty)")

# ── Terminal summary table ─────────────────────────────────────────────────
print(f"\n{'═'*58}")
icons_map = {
    "OPEN":"✅", "OPEN (Auth)":"🔒", "OPEN (Error)":"⚠️",
    "TCP OPEN":"🟡", "DNS ONLY":"🟠", "CLOSED":"❌", "NO_DNS":"⛔"
}
for s, c in sorted(counts.items(), key=lambda x: STATUS_ORDER.get(x[0], 9)):
    icon = icons_map.get(s, "❓")
    bar  = "█" * min(c, 30)
    print(f"  {icon}  {s:<24} {c:>4}  {bar}")
print(f"{'═'*58}")
print(f"  {L['total_scanned']:<32}  {len(results)}")
print(f"  {L['ext_open']:<32}  {open_count}")
print(f"  {L['shots_taken']:<32}  {shot_count}")
print(f"  {L['scan_dur']:<32}  {scan_dur}s")
print(f"{'═'*58}\n")
PYEOF

# ── Execute Python scanner ─────────────────────────────────────────────────
SKIP_WW=0;  [ -n "${SKIP_WHATWEB:-}"    ] && SKIP_WW=1
SKIP_SS=0;  [ "${SKIP_SCREENSHOTS:-0}" = "1" ] && SKIP_SS=1

python3 "$PYTHON_SCRIPT" \
  "$INPUT_JSON" \
  "$OUTPUT_DIR" \
  "$TIMEOUT"    \
  "$SKIP_WW"    \
  "$SKIP_SS"    \
  "${CHROME_BIN}" \
  "$WORKERS"    \
  "$LANG_CODE"

# ── Final message ──────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}${MSG_DONE}${NC}"
echo -e ""
echo -e "${GRAY}${MSG_F1}${NC}"
echo -e "${GRAY}${MSG_F2}${NC}"
echo -e "${GRAY}${MSG_F3}${NC}"
echo -e "${GRAY}${MSG_F4}${NC}"
echo -e "${GRAY}${MSG_F5}${NC}"
echo ""
