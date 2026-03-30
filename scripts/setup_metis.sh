#!/usr/bin/env bash
#
# setup_metis.sh - Install ARM Metis from GitHub source
#
# Metis requires Python >= 3.12, so this script handles:
#   1. Checking / installing Python 3.12+
#   2. Cloning the Metis repository
#   3. Installing Metis into a virtual environment
#   4. Verifying the installation
#
# Environment variables:
#   METIS_INSTALL_DIR  - Where to clone Metis (default: ~/.local/share/metis)
#   OPENAI_API_KEY     - Required for Metis to function (OpenAI LLM provider)
#

set -euo pipefail

METIS_REPO="https://github.com/arm/metis.git"
METIS_INSTALL_DIR="${METIS_INSTALL_DIR:-${HOME}/.local/share/metis}"
METIS_VENV="${METIS_INSTALL_DIR}/.venv"
METIS_BIN_LINK="${HOME}/.local/bin/metis"

log()  { echo "[setup_metis] $*"; }
warn() { echo "[setup_metis] WARNING: $*" >&2; }
err()  { echo "[setup_metis] ERROR: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# 1. Check Python >= 3.12
# ---------------------------------------------------------------------------
check_python() {
    local py=""

    # Try common Python 3.12+ binaries
    for candidate in python3.13 python3.12 python3; do
        if command -v "$candidate" &>/dev/null; then
            local ver
            ver=$("$candidate" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
            local major minor
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
# 3. Create venv and install
# ---------------------------------------------------------------------------
install_metis() {
    local py="$1"

    log "Creating virtual environment with ${py}..."
    "${py}" -m venv "${METIS_VENV}"

    log "Installing Metis and dependencies..."
    "${METIS_VENV}/bin/pip" install --upgrade pip setuptools wheel
    "${METIS_VENV}/bin/pip" install -e "${METIS_INSTALL_DIR}"

    # Create symlink in ~/.local/bin
    mkdir -p "$(dirname "${METIS_BIN_LINK}")"
    ln -sf "${METIS_VENV}/bin/metis" "${METIS_BIN_LINK}"
    log "Symlinked: ${METIS_BIN_LINK} -> ${METIS_VENV}/bin/metis"
}

# ---------------------------------------------------------------------------
# 4. Also install metis into the current project's Python environment
# ---------------------------------------------------------------------------
install_metis_to_project() {
    if [ -n "${VIRTUAL_ENV:-}" ]; then
        log "Installing Metis into active virtual environment: ${VIRTUAL_ENV}"
        pip install -e "${METIS_INSTALL_DIR}" 2>/dev/null || \
            warn "Could not install Metis into project venv (Python version mismatch?)"
    fi
}

# ---------------------------------------------------------------------------
# 5. Verify
# ---------------------------------------------------------------------------
verify() {
    log "Verifying Metis installation..."

    if "${METIS_VENV}/bin/metis" --version 2>/dev/null; then
        log "Metis installation successful."
    elif "${METIS_VENV}/bin/python" -c "from metis.engine import MetisEngine; print('OK')" 2>/dev/null; then
        log "Metis Python API available."
    else
        warn "Metis installed but verification failed. Check dependencies."
    fi

    # Check OPENAI_API_KEY
    if [ -z "${OPENAI_API_KEY:-}" ]; then
        warn ""
        warn "OPENAI_API_KEY is NOT set."
        warn "Metis requires an LLM API key to perform security analysis."
        warn "Set it with: export OPENAI_API_KEY=\"your-key-here\""
        warn ""
        warn "Supported providers (configure in metis.yaml):"
        warn "  - OpenAI:       export OPENAI_API_KEY=..."
        warn "  - Azure OpenAI: export AZURE_OPENAI_API_KEY=..."
        warn "  - vLLM:         export VLLM_API_KEY=..."
        warn "  - Ollama:       (no key needed, local)"
    else
        log "OPENAI_API_KEY is set."
    fi

    echo ""
    log "====================================="
    log "Metis is installed at: ${METIS_INSTALL_DIR}"
    log "Binary: ${METIS_BIN_LINK}"
    log "Python API: ${METIS_VENV}/bin/python -c 'from metis.engine import MetisEngine'"
    log ""
    log "Make sure ~/.local/bin is in your PATH:"
    log "  export PATH=\"\${HOME}/.local/bin:\${PATH}\""
    log "====================================="
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    log "Setting up ARM Metis (AI security code review)"

    local py
    py=$(check_python)
    log "Using Python: ${py} ($(${py} --version 2>&1))"

    clone_or_update_metis
    install_metis "${py}"
    install_metis_to_project
    verify
}

main "$@"
