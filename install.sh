#!/usr/bin/env bash
#
# GVA installer — sets up everything needed to run GPT_Vuln-analyzer.
#
# Installs correctly whether you run it as root or as a normal user:
#   - ./install.sh          (non-root): system packages via sudo; uv + venv for you
#   - sudo ./install.sh     (root+sudo): system packages as root; uv + venv for the
#                                        invoking user (SUDO_USER), not root
#   - ./install.sh          (pure root): system packages as root; uv installed
#                                        system-wide to /usr/local/bin
#
# Either way, system packages need elevation but uv and the Python venv are set up
# for the real (non-root) user so you can run the app without sudo.
#
# Recommended: run as your NORMAL user (do not 'sudo su' first). It elevates only
# the system-package step via sudo. Running fully as root only works if the project
# lives on a root-accessible path — user-only FUSE/media mounts (e.g. /run/host,
# /media) deny root, so use the normal-user invocation there.
#
# Usage:
#   ./install.sh              # full install (system deps + uv + python deps)
#   ./install.sh --no-system  # skip system packages (only uv + python deps)
#   ./install.sh --help
#
set -euo pipefail

# --------------------------------------------------------------------------- ui
if [ -t 1 ]; then
    RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; BLU=$'\033[34m'; RST=$'\033[0m'
else
    RED=''; GRN=''; YLW=''; BLU=''; RST=''
fi
info() { printf '%s==>%s %s\n' "$BLU" "$RST" "$*"; }
ok()   { printf '%s ok %s %s\n' "$GRN" "$RST" "$*"; }
warn() { printf '%s warn%s %s\n' "$YLW" "$RST" "$*" >&2; }
err()  { printf '%s err %s %s\n' "$RED" "$RST" "$*" >&2; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"
if [ -z "${SCRIPT_DIR:-}" ] || ! cd "$SCRIPT_DIR" 2>/dev/null; then
    err "Cannot access the project directory: $(dirname "${BASH_SOURCE[0]}")"
    if [ "$(id -u)" -eq 0 ]; then
        err "You are root, but this path looks like a user-only mount (e.g. a FUSE/media"
        err "mount under /run/host or /media). root cannot enter it."
        err "Fix: run the installer as your NORMAL user instead —"
        err "     it uses sudo only for the system-package step, so root is not needed:"
        err "         ./install.sh"
    else
        err "Check the directory permissions and try again."
    fi
    exit 1
fi

INSTALL_SYSTEM=1
for arg in "$@"; do
    case "$arg" in
        --no-system) INSTALL_SYSTEM=0 ;;
        -h|--help)
            awk 'NR>1 && /^#/ {sub(/^# ?/,""); print; next} NR>1 {exit}' "$0"; exit 0 ;;
        *) warn "Unknown option: $arg" ;;
    esac
done

have() { command -v "$1" >/dev/null 2>&1; }

# ------------------------------------------------ privilege / target-user model
# SUDO      : prefix for privileged (system package) commands
# TARGET_USER / TARGET_HOME : the (non-root) account uv + the venv are set up for
if [ "$(id -u)" -eq 0 ]; then
    IS_ROOT=1
    SUDO=""
    TARGET_USER="${SUDO_USER:-root}"
    if [ "$TARGET_USER" = "root" ]; then
        info "Running as root — system packages direct, uv installed system-wide."
    else
        info "Running as root via sudo — system packages as root, uv + venv for '$TARGET_USER'."
    fi
else
    IS_ROOT=0
    TARGET_USER="$(id -un)"
    if have sudo; then
        SUDO="sudo"
        info "Running as non-root — system packages use sudo, uv + venv for you."
    else
        SUDO=""
        warn "Non-root and no sudo; system packages may fail (uv + Python deps will still install)."
    fi
fi
TARGET_HOME="$(eval echo "~$TARGET_USER")"
USER_BIN="$TARGET_HOME/.local/bin"

# Run a command as the unprivileged target user (only when we are root and a real
# invoking user exists); otherwise run it directly.
as_target() {
    if [ "$IS_ROOT" -eq 1 ] && [ "$TARGET_USER" != "root" ]; then
        if have sudo; then
            sudo -u "$TARGET_USER" -H "$@"
        elif have runuser; then
            runuser -u "$TARGET_USER" -- "$@"
        else
            "$@"
        fi
    else
        "$@"
    fi
}

# uv for the target user (or system-wide), with the right PATH.
run_uv() { as_target env PATH="$USER_BIN:/usr/local/bin:$PATH" uv "$@"; }
uv_present() { as_target env PATH="$USER_BIN:/usr/local/bin:$PATH" sh -c 'command -v uv' >/dev/null 2>&1; }

# ----------------------------------------------------------- system packages
install_system_deps() {
    if have brew; then
        info "Installing system deps via Homebrew..."
        as_target brew install nmap wireshark || warn "brew install had issues; continuing."
        return
    fi
    if have apt-get; then
        info "Installing system deps via apt..."; $SUDO apt-get update -y || true
        $SUDO apt-get install -y nmap libssh2-1 tshark || warn "apt install had issues; continuing."; return
    fi
    if have dnf; then
        info "Installing system deps via dnf..."
        $SUDO dnf install -y nmap libssh2 wireshark-cli || warn "dnf install had issues; continuing."; return
    fi
    if have pacman; then
        info "Installing system deps via pacman..."
        $SUDO pacman -Sy --noconfirm nmap libssh2 wireshark-cli || warn "pacman install had issues; continuing."; return
    fi
    if have zypper; then
        info "Installing system deps via zypper..."
        $SUDO zypper install -y nmap libssh2-1 wireshark || warn "zypper install had issues; continuing."; return
    fi
    if have apk; then
        info "Installing system deps via apk..."
        $SUDO apk add nmap libssh2 tshark || warn "apk install had issues; continuing."; return
    fi
    if have rpm-ostree; then
        warn "Immutable OS (rpm-ostree) detected."
        if have conda; then
            info "conda found — installing a self-contained nmap (no reboot needed)..."
            as_target conda install -c conda-forge -y nmap || warn "conda nmap install failed."
        else
            info "Layering nmap/libssh2 with rpm-ostree (takes effect after reboot)..."
            $SUDO rpm-ostree install --idempotent --allow-inactive nmap libssh2 wireshark-cli \
                || warn "rpm-ostree install failed."
            warn "Reboot to apply, or install Homebrew and 'brew install nmap' for a no-reboot option."
        fi
        return
    fi
    warn "No supported package manager found. Install 'nmap' and 'tshark' manually."
}

# --------------------------------------------------------------------- uv
install_uv() {
    if uv_present; then
        ok "uv already installed ($(run_uv --version))"
        return
    fi
    local downloader=""
    if have curl; then downloader="curl -LsSf"; elif have wget; then downloader="wget -qO-"; fi

    if [ -z "$downloader" ]; then
        info "curl/wget not found — installing uv via pip for $TARGET_USER..."
        as_target sh -c 'python3 -m pip install --user uv || pip install --user uv' \
            || { err "Need curl, wget, or pip to install uv."; exit 1; }
    elif [ "$IS_ROOT" -eq 1 ] && [ "$TARGET_USER" = "root" ]; then
        info "Installing uv system-wide to /usr/local/bin..."
        $downloader https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh
    else
        info "Installing uv for user '$TARGET_USER'..."
        as_target sh -c "$downloader https://astral.sh/uv/install.sh | sh"
    fi

    uv_present || { err "uv installed but not found on PATH. Add $USER_BIN to PATH and re-run."; exit 1; }
    ok "uv installed ($(run_uv --version))"
}

# --------------------------------------------------------------------- main
if [ "$INSTALL_SYSTEM" -eq 1 ]; then
    install_system_deps
else
    info "Skipping system packages (--no-system)."
fi

install_uv

info "Installing Python dependencies with uv (creates .venv for '$TARGET_USER')..."
run_uv sync
ok "Python dependencies installed."

if [ ! -f .env ]; then
    as_target cp .env.example .env
    ok "Created .env from .env.example — add your API keys."
else
    ok ".env already exists — leaving it untouched."
fi

echo
ok "GVA is ready."
echo "Next steps:"
echo "  1. Edit .env and add at least one AI provider key (OpenAI / Anthropic / Gemini)."
echo "  2. Run (as your normal user):  uv run gpt_vuln.py --rich_menu help"
echo "  3. Example:  uv run gpt_vuln.py --target scanme.nmap.org --attack nmap --ai openai,claude,gemini"
echo
echo "Note: privileged nmap profiles auto-escalate the nmap step with sudo (prompts for your password);"
echo "      run the app itself as your normal user, not with 'sudo uv run'."
