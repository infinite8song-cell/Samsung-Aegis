#!/usr/bin/env bash
#
# setup_libfuzzer.sh - Install clang and LibFuzzer on Linux
#
# Supports: Ubuntu/Debian, Fedora/RHEL, Arch Linux
# LibFuzzer is bundled with compiler-rt in modern clang (>=6.0)
#

set -euo pipefail

LLVM_VERSION="${LLVM_VERSION:-17}"

log() { echo "[setup_libfuzzer] $*"; }
err() { echo "[setup_libfuzzer] ERROR: $*" >&2; exit 1; }

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "$ID"
    elif command -v lsb_release &>/dev/null; then
        lsb_release -is | tr '[:upper:]' '[:lower:]'
    else
        err "Cannot detect Linux distribution"
    fi
}

install_debian() {
    log "Detected Debian/Ubuntu. Installing LLVM ${LLVM_VERSION}..."

    # Add LLVM apt repository
    if ! command -v wget &>/dev/null; then
        sudo apt-get update && sudo apt-get install -y wget gnupg
    fi

    wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | sudo tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc >/dev/null

    CODENAME=$(lsb_release -cs 2>/dev/null || echo "jammy")
    echo "deb http://apt.llvm.org/${CODENAME}/ llvm-toolchain-${CODENAME}-${LLVM_VERSION} main" | \
        sudo tee /etc/apt/sources.list.d/llvm.list >/dev/null

    sudo apt-get update
    sudo apt-get install -y \
        "clang-${LLVM_VERSION}" \
        "llvm-${LLVM_VERSION}" \
        "llvm-${LLVM_VERSION}-dev" \
        "lld-${LLVM_VERSION}" \
        "libclang-${LLVM_VERSION}-dev" \
        "compiler-rt-${LLVM_VERSION}" \
        cmake \
        make \
        pkg-config

    # Create unversioned symlinks
    sudo update-alternatives --install /usr/bin/clang clang "/usr/bin/clang-${LLVM_VERSION}" 100
    sudo update-alternatives --install /usr/bin/clang++ clang++ "/usr/bin/clang++-${LLVM_VERSION}" 100
    sudo update-alternatives --install /usr/bin/llvm-config llvm-config "/usr/bin/llvm-config-${LLVM_VERSION}" 100
    sudo update-alternatives --install /usr/bin/llvm-symbolizer llvm-symbolizer "/usr/bin/llvm-symbolizer-${LLVM_VERSION}" 100
}

install_fedora() {
    log "Detected Fedora/RHEL. Installing clang and compiler-rt..."
    sudo dnf install -y \
        clang \
        llvm \
        llvm-devel \
        compiler-rt \
        lld \
        cmake \
        make \
        pkg-config
}

install_arch() {
    log "Detected Arch Linux. Installing clang and compiler-rt..."
    sudo pacman -S --noconfirm \
        clang \
        llvm \
        compiler-rt \
        lld \
        cmake \
        make \
        pkg-config
}

verify_install() {
    log "Verifying installation..."

    if ! command -v clang &>/dev/null; then
        err "clang not found after installation"
    fi

    if ! command -v clang++ &>/dev/null; then
        err "clang++ not found after installation"
    fi

    CLANG_VER=$(clang --version | head -1)
    log "Installed: ${CLANG_VER}"

    # Verify LibFuzzer support
    TESTFILE=$(mktemp /tmp/fuzz_test_XXXXXX.cpp)
    cat > "${TESTFILE}" <<'EOF'
#include <stdint.h>
#include <stddef.h>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    return 0;
}
EOF

    TESTBIN="${TESTFILE%.cpp}"
    if clang++ -fsanitize=fuzzer "${TESTFILE}" -o "${TESTBIN}" 2>/dev/null; then
        log "LibFuzzer: OK (compilation test passed)"
        rm -f "${TESTBIN}"
    else
        log "WARNING: LibFuzzer compilation test failed. compiler-rt may not be properly installed."
    fi
    rm -f "${TESTFILE}"
}

main() {
    log "Setting up LLVM/clang with LibFuzzer support"

    DISTRO=$(detect_distro)
    case "$DISTRO" in
        ubuntu|debian|linuxmint|pop)
            install_debian ;;
        fedora|rhel|centos|rocky|alma)
            install_fedora ;;
        arch|manjaro|endeavouros)
            install_arch ;;
        *)
            err "Unsupported distribution: $DISTRO. Install clang and compiler-rt manually." ;;
    esac

    verify_install
    log "Setup complete. You can now build and run fuzzing harnesses."
}

main "$@"
