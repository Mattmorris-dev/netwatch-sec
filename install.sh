#!/usr/bin/env bash
# NetWatch one-line installer.
#
#   curl -fsSL https://raw.githubusercontent.com/Mattmorris-dev/netwatch-sec/main/install.sh | bash
#
# Installs the `netwatch` CLI (PyPI: netwatch-sec) with pipx when available,
# otherwise a --user pip install. System capture tools (nmap/tshark/...) are
# detected and reported — never auto-installed with sudo behind your back.
set -euo pipefail

BOLD=$'\033[1m'; GREEN=$'\033[92m'; YELLOW=$'\033[93m'; RED=$'\033[91m'; DIM=$'\033[2m'; RESET=$'\033[0m'
say()  { printf '%s\n' "${BOLD}▸ $*${RESET}"; }
ok()   { printf '%s\n' "  ${GREEN}✓${RESET} $*"; }
warn() { printf '%s\n' "  ${YELLOW}!${RESET} $*"; }

say "NetWatch installer"

# 1. Python 3.9+
if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' "${RED}python3 not found. Install Python 3.9+ and re-run.${RESET}" >&2
  exit 1
fi
PYV=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
ok "python3 $PYV"

# 2. Install the CLI — prefer pipx (isolated), fall back to pip --user.
if command -v pipx >/dev/null 2>&1; then
  say "Installing netwatch-sec via pipx"
  pipx install --force netwatch-sec >/dev/null
  ok "installed with pipx"
  BIN="$(pipx environment --value PIPX_BIN_DIR 2>/dev/null || echo "$HOME/.local/bin")"
else
  warn "pipx not found — using: pip install --user netwatch-sec"
  python3 -m pip install --user --upgrade netwatch-sec >/dev/null
  ok "installed with pip --user"
  BIN="$HOME/.local/bin"
fi

# 3. PATH hint
case ":$PATH:" in
  *":$BIN:"*) : ;;
  *) warn "add $BIN to your PATH:  echo 'export PATH=\"$BIN:\$PATH\"' >> ~/.bashrc" ;;
esac

# 4. Report optional system capture tools (Free works without them, passively).
say "Checking optional capture tools"
MISSING=()
for t in nmap tshark tcpdump iptables whois; do
  if command -v "$t" >/dev/null 2>&1; then ok "$t"; else MISSING+=("$t"); warn "$t missing"; fi
done
if [ "${#MISSING[@]}" -gt 0 ]; then
  printf '%s\n' "${DIM}  Optional full-capture deps. On Debian/Ubuntu/Pi:${RESET}"
  printf '%s\n' "${DIM}    sudo apt install -y ${MISSING[*]}${RESET}"
fi

# 5. Next steps
say "Done"
printf '%s\n' "  Run passive (no root):   ${GREEN}netwatch${RESET}"
printf '%s\n' "  Full capture (root):     ${GREEN}sudo netwatch${RESET}"
printf '%s\n' "  Exposure self-check:     ${GREEN}netwatch${RESET} ${DIM}then type 'expose'${RESET}"
printf '%s\n' "  Alerts to Discord/Slack: ${DIM}type 'alert set <https-webhook-url>'${RESET}"
printf '%s\n' "  Upgrade to Pro:          ${DIM}netwatch activate <license-key>${RESET}"
