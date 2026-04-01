#!/usr/bin/env bash
#
# setup_metis.sh - Install ARM Metis from GitHub source
#
# Requires Python >= 3.12 (same as the project).
#
#   1. Verify Python 3.12+ is available (install if missing)
#   2. Clone the Metis repository
#   3. Install Metis into the current Python environment
#   4. Verify the installation
#
# Environment variables:
#   METIS_INSTALL_DIR  - Where to clone Metis (default: ~/.local/share/metis)
#   OPENAI_API_KEY     - API key for vLLM endpoint
#   OPENAI_API_BASE    - vLLM endpoint URL
#

set -euo pipefail

METIS_REPO="https://github.com/arm/metis.git"
METIS_INSTALL_DIR="${METIS_INSTALL_DIR:-${HOME}/.local/share/metis}"

log()  { echo "[setup_metis] $*"; }
warn() { echo "[setup_metis] WARNING: $*" >&2; }
err()  { echo "[setup_metis] ERROR: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. Check / install Python >= 3.12
# ---------------------------------------------------------------------------
check_python() {
    local py=""

    for candidate in python3.13 python3.12 python3; do
        if command -v "$candidate" &>/dev/null; then
            local ver major minor
            ver=$("$candidate" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
            major=$(echo "$ver" | cut -d. -f1)
            minor=$(echo "$ver" | cut -d. -f2)
            if [ "$major" -ge 3 ] && [ "$minor" -ge 12 ]; then
                py="$candidate"
                break
            fi
        fi
    done

    if [ -z "$py" ]; then
        log "Python 3.12+ not found. Attempting to install..."
        install_python312
        py="python3.12"
    fi

    echo "$py"
}

install_python312() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        case "$ID" in
            ubuntu|debian|linuxmint|pop)
                sudo apt-get update
                sudo apt-get install -y software-properties-common
                sudo add-apt-repository -y ppa:deadsnakes/ppa
                sudo apt-get update
                sudo apt-get install -y python3.12 python3.12-venv python3.12-dev
                ;;
            fedora|rhel|centos|rocky|alma)
                sudo dnf install -y python3.12 python3.12-devel
                ;;
            arch|manjaro)
                sudo pacman -S --noconfirm python
                ;;
            *)
                err "Unsupported distro: $ID. Install Python 3.12+ manually."
                ;;
        esac
    else
        err "Cannot detect distro. Install Python 3.12+ manually."
    fi

    if ! command -v python3.12 &>/dev/null; then
        err "Python 3.12 installation failed."
    fi
}

# ---------------------------------------------------------------------------
# 2. Clone or update Metis
# ---------------------------------------------------------------------------
clone_or_update_metis() {
    if [ -d "${METIS_INSTALL_DIR}/.git" ]; then
        log "Updating existing Metis installation..."
        git -C "${METIS_INSTALL_DIR}" pull --ff-only origin main || \
            warn "git pull failed; using existing version."
    else
        log "Cloning Metis from ${METIS_REPO}..."
        mkdir -p "$(dirname "${METIS_INSTALL_DIR}")"
        git clone "${METIS_REPO}" "${METIS_INSTALL_DIR}"
    fi
}

# ---------------------------------------------------------------------------
# 3. Install into current Python environment
# ---------------------------------------------------------------------------
install_metis() {
    local py="$1"

    # If inside a virtualenv, install directly into it
    if [ -n "${VIRTUAL_ENV:-}" ]; then
        log "Installing Metis into active virtualenv: ${VIRTUAL_ENV}"
        pip install -e "${METIS_INSTALL_DIR}"
    else
        # Install into the system/user Python
        log "Installing Metis with ${py} (pip install -e)..."
        "${py}" -m pip install -e "${METIS_INSTALL_DIR}"
    fi

    # Ensure ~/.local/bin is reachable for the metis CLI entry point
    local bin_dir
    bin_dir=$("${py}" -c "import sysconfig; print(sysconfig.get_path('scripts'))" 2>/dev/null || echo "")
    if [ -n "$bin_dir" ] && [ -f "${bin_dir}/metis" ]; then
        log "Metis CLI installed at: ${bin_dir}/metis"
    fi
}

# ---------------------------------------------------------------------------
# 4. Verify
# ---------------------------------------------------------------------------
verify() {
    log "Verifying Metis installation..."

    if command -v metis &>/dev/null && metis --version 2>/dev/null; then
        log "Metis CLI: OK"
    elif python3 -c "from metis.engine import MetisEngine; print('MetisEngine OK')" 2>/dev/null; then
        log "Metis Python API: OK"
    else
        warn "Metis installed but verification failed. Check dependencies."
    fi

    # Check vLLM environment variables
    echo ""
    local all_ok=true
    if [ -z "${OPENAI_API_KEY:-}" ]; then
        warn "OPENAI_API_KEY is NOT set (required for vLLM endpoint)"
        all_ok=false
    else
        log "OPENAI_API_KEY: set"
    fi

    if [ -z "${OPENAI_API_BASE:-}" ]; then
        warn "OPENAI_API_BASE is NOT set (required for vLLM endpoint URL)"
        all_ok=false
    else
        log "OPENAI_API_BASE: ${OPENAI_API_BASE}"
    fi

    if [ "$all_ok" = false ]; then
        warn ""
        warn "Set the following environment variables for Metis AI analysis:"
        warn "  export OPENAI_API_KEY=\"your-api-key\""
        warn "  export OPENAI_API_BASE=\"http://vllm-server:8000/v1\""
        warn "  export METIS_MODEL=\"model-name\"   # optional"
    fi

    echo ""
    log "====================================="
    log "Metis source: ${METIS_INSTALL_DIR}"
    log "Python API:   python3 -c 'from metis.engine import MetisEngine'"
    log "====================================="
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "Setting up ARM Metis (AI security code review) for Python 3.12"

    local py
    py=$(check_python)
    log "Using: ${py} ($(${py} --version 2>&1))"

    clone_or_update_metis
    install_metis "${py}"
    verify
}

main "$@"
