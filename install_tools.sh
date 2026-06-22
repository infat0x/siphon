#!/bin/bash
# ╔══════════════════════════════════════════════════════════════╗
# ║  Siphon Tool Installer — auto install & PATH setup          ║
# ║  Run: chmod +x install_tools.sh && ./install_tools.sh       ║
# ╚══════════════════════════════════════════════════════════════╝

set -e

RED='\033[91m'; GREEN='\033[92m'; YELLOW='\033[93m'
CYAN='\033[96m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

ok()   { echo -e "  ${GREEN}✔${RESET}  $1"; }
warn() { echo -e "  ${YELLOW}⚠${RESET}  $1"; }
err()  { echo -e "  ${RED}✘${RESET}  $1"; }
info() { echo -e "  ${CYAN}→${RESET}  $1"; }

echo -e "${BOLD}${CYAN}"
echo "  ┌──────────────────────────────────────────┐"
echo "  │   Siphon Tool Installer                   │"
echo "  │   All required + optional tools           │"
echo "  └──────────────────────────────────────────┘"
echo -e "${RESET}"

# ─── Check prerequisites ───────────────────────────────────────
check_prereq() {
    local missing=0
    for cmd in go git python3 pip3 curl wget; do
        if command -v "$cmd" &>/dev/null; then
            ok "$cmd  $(command -v $cmd)"
        else
            if [ "$cmd" = "wget" ] || [ "$cmd" = "curl" ]; then
                warn "$cmd not found (optional)"
            else
                err "$cmd not found — required"
                missing=1
            fi
        fi
    done
    if [ $missing -eq 1 ]; then
        err "Install missing prerequisites first."
        exit 1
    fi
}

info "Checking prerequisites …"
check_prereq
echo ""

# ─── Ensure GOPATH/bin is in PATH ──────────────────────────────
GOBIN="$(go env GOPATH)/bin"
if [[ ":$PATH:" != *":$GOBIN:"* ]]; then
    export PATH="$PATH:$GOBIN"
    warn "Added $GOBIN to PATH for this session"
fi

# ─── Go tools ──────────────────────────────────────────────────
declare -A GO_TOOLS=(
    # Required
    ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
    ["gau"]="github.com/lc/gau/v2/cmd/gau@latest"
    ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
    ["gf"]="github.com/tomnomnom/gf@latest"
    # Optional URL collectors
    ["waybackurls"]="github.com/tomnomnom/waybackurls@latest"
    ["hakrawler"]="github.com/hakluke/hakrawler@latest"
    ["anew"]="github.com/tomnomnom/anew@latest"
    ["subjs"]="github.com/lc/subjs@latest"
    # v6 scanners & fuzzers
    ["jsluice"]="github.com/BishopFox/jsluice/cmd/jsluice@latest"
    ["jsleak"]="github.com/byt3hx/jsleak@latest"
    ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    ["cariddi"]="github.com/edoardottt/cariddi/cmd/cariddi@latest"
    ["ffuf"]="github.com/ffuf/ffuf/v2@latest"
)

info "Installing Go tools …"
echo ""
for tool in "${!GO_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        ok "${BOLD}$tool${RESET}  already installed"
    else
        info "Installing $tool …"
        if go install "${GO_TOOLS[$tool]}" 2>/dev/null; then
            ok "${BOLD}$tool${RESET}  installed"
        else
            err "$tool  failed — try manually: go install ${GO_TOOLS[$tool]}"
        fi
    fi
done
echo ""

# ─── TruffleHog (binary release) ──────────────────────────────
install_trufflehog() {
    if command -v trufflehog &>/dev/null; then
        ok "${BOLD}trufflehog${RESET}  already installed"
        return
    fi
    info "Installing trufflehog …"
    local TMP=$(mktemp -d)
    local ARCH=$(uname -m)
    local OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    [ "$ARCH" = "x86_64" ] && ARCH="amd64"
    [ "$ARCH" = "aarch64" ] && ARCH="arm64"
    local URL="https://github.com/trufflesecurity/trufflehog/releases/download/v3.95.3/trufflehog_3.95.3_${OS}_${ARCH}.tar.gz"
    if curl -sL "$URL" -o "$TMP/trufflehog.tar.gz" && \
       tar -xzf "$TMP/trufflehog.tar.gz" -C "$TMP" && \
       sudo mv "$TMP/trufflehog" /usr/local/bin/trufflehog 2>/dev/null || mv "$TMP/trufflehog" "$GOBIN/trufflehog"; then
        ok "${BOLD}trufflehog${RESET}  installed"
    else
        err "trufflehog  failed — download manually from GitHub releases"
    fi
    rm -rf "$TMP"
}
install_trufflehog

# ─── Gitleaks (binary release) ─────────────────────────────────
install_gitleaks() {
    if command -v gitleaks &>/dev/null; then
        ok "${BOLD}gitleaks${RESET}  already installed"
        return
    fi
    info "Installing gitleaks …"
    local TMP=$(mktemp -d)
    local ARCH=$(uname -m)
    local OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    [ "$ARCH" = "x86_64" ] && ARCH="x64"
    [ "$ARCH" = "aarch64" ] && ARCH="arm64"
    local URL="https://github.com/gitleaks/gitleaks/releases/download/v8.24.3/gitleaks_8.24.3_${OS}_${ARCH}.tar.gz"
    if curl -sL "$URL" -o "$TMP/gitleaks.tar.gz" && \
       tar -xzf "$TMP/gitleaks.tar.gz" -C "$TMP" && \
       sudo mv "$TMP/gitleaks" /usr/local/bin/gitleaks 2>/dev/null || mv "$TMP/gitleaks" "$GOBIN/gitleaks"; then
        ok "${BOLD}gitleaks${RESET}  installed"
    else
        err "gitleaks  failed — download manually from GitHub releases"
    fi
    rm -rf "$TMP"
}
install_gitleaks

# ─── SecretFinder (Python) ─────────────────────────────────────
install_secretfinder() {
    if command -v SecretFinder.py &>/dev/null || [ -f /opt/SecretFinder/SecretFinder.py ]; then
        ok "${BOLD}SecretFinder${RESET}  already installed"
        return
    fi
    info "Installing SecretFinder …"
    local TARGET="/opt/SecretFinder"
    if [ -w /opt ] || sudo test -w /opt 2>/dev/null; then
        sudo git clone --depth 1 https://github.com/m4ll0k/SecretFinder.git "$TARGET" 2>/dev/null || true
        sudo pip3 install -r "$TARGET/requirements.txt" --break-system-packages 2>/dev/null || \
            pip3 install -r "$TARGET/requirements.txt" 2>/dev/null || true
        sudo ln -sf "$TARGET/SecretFinder.py" /usr/local/bin/SecretFinder.py 2>/dev/null || true
        ok "${BOLD}SecretFinder${RESET}  installed → $TARGET"
    else
        local TARGET="$HOME/tools/SecretFinder"
        git clone --depth 1 https://github.com/m4ll0k/SecretFinder.git "$TARGET" 2>/dev/null || true
        pip3 install -r "$TARGET/requirements.txt" --break-system-packages 2>/dev/null || \
            pip3 install -r "$TARGET/requirements.txt" 2>/dev/null || true
        ok "${BOLD}SecretFinder${RESET}  installed → $TARGET"
    fi
}
install_secretfinder

# ─── git-dumper (pip) ──────────────────────────────────────────
install_gitdumper() {
    if command -v git-dumper &>/dev/null; then
        ok "${BOLD}git-dumper${RESET}  already installed"
        return
    fi
    info "Installing git-dumper …"
    if pip3 install git-dumper --break-system-packages 2>/dev/null || \
       pip3 install git-dumper 2>/dev/null; then
        ok "${BOLD}git-dumper${RESET}  installed"
    else
        err "git-dumper  failed — try: pip3 install git-dumper"
    fi
}
install_gitdumper

# ─── gf patterns ───────────────────────────────────────────────
install_gf_patterns() {
    local GF_DIR="$HOME/.gf"
    if [ -d "$GF_DIR" ] && [ "$(ls -A $GF_DIR 2>/dev/null)" ]; then
        ok "${BOLD}gf patterns${RESET}  already exist ($GF_DIR)"
        return
    fi
    info "Installing gf patterns …"
    mkdir -p "$GF_DIR"
    local TMP=$(mktemp -d)
    git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns.git "$TMP" 2>/dev/null || true
    cp "$TMP"/*.json "$GF_DIR/" 2>/dev/null || true
    rm -rf "$TMP"
    ok "${BOLD}gf patterns${RESET}  installed → $GF_DIR"
}
install_gf_patterns

# ─── nuclei templates ─────────────────────────────────────────
update_nuclei_templates() {
    if command -v nuclei &>/dev/null; then
        info "Updating nuclei templates …"
        nuclei -update-templates -silent 2>/dev/null || true
        ok "${BOLD}nuclei templates${RESET}  updated"
    fi
}
update_nuclei_templates

echo ""

# ─── PATH persistence ─────────────────────────────────────────
persist_path() {
    local SHELL_RC=""
    if [ -f "$HOME/.zshrc" ]; then
        SHELL_RC="$HOME/.zshrc"
    elif [ -f "$HOME/.bashrc" ]; then
        SHELL_RC="$HOME/.bashrc"
    elif [ -f "$HOME/.profile" ]; then
        SHELL_RC="$HOME/.profile"
    fi

    if [ -n "$SHELL_RC" ]; then
        if ! grep -q "GOPATH.*bin" "$SHELL_RC" 2>/dev/null; then
            echo "" >> "$SHELL_RC"
            echo "# Siphon — Go tools PATH" >> "$SHELL_RC"
            echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> "$SHELL_RC"
            ok "Added GOPATH/bin to ${BOLD}$SHELL_RC${RESET}"
        else
            ok "GOPATH/bin already in ${BOLD}$SHELL_RC${RESET}"
        fi
    else
        warn "Could not find shell RC file. Add manually:"
        echo -e "    ${DIM}export PATH=\"\$PATH:\$(go env GOPATH)/bin\"${RESET}"
    fi
}
persist_path

# ─── Final check ───────────────────────────────────────────────
echo ""
echo -e "${BOLD}${CYAN}  ┌──────────────────────────────────────────┐"
echo "  │   Installation Complete                  │"
echo -e "  └──────────────────────────────────────────┘${RESET}"
echo ""

ALL_TOOLS=(httpx gau katana gf trufflehog waybackurls hakrawler anew
           subjs jsluice jsleak nuclei cariddi ffuf gitleaks git-dumper)

installed=0
missing=0
for tool in "${ALL_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        ok "$tool"
        ((installed++))
    else
        err "$tool  — not found"
        ((missing++))
    fi
done

echo ""
echo -e "  ${GREEN}${BOLD}$installed${RESET} installed    ${RED}${BOLD}$missing${RESET} missing"
echo ""
if [ $missing -eq 0 ]; then
    echo -e "  ${GREEN}${BOLD}All tools ready! Run:${RESET}"
else
    echo -e "  ${YELLOW}${BOLD}Some tools missing. You can still run:${RESET}"
fi
echo -e "  ${DIM}python3 siphon.py --domain example.com -o output/${RESET}"
echo ""
