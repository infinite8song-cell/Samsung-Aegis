#!/usr/bin/env bash
# impl_sc300/tools/env.sh —
# Host auto-detection and tool-path defaults for impl_sc300 builds.
# Source this file from other scripts:
#   source "$(dirname "$0")/env.sh"
#
# It sets (and exports) the following if they are not already defined
# in the environment:
#   HOST_TAG          macos-arm64 | macos-x64 | ubuntu-x64 | ubuntu-arm64 | unknown
#   GNU_TC            /path/to/arm-gnu-toolchain-13.3.rel1-...-arm-none-eabi
#   QEMU              /path/to/qemu-system-arm
#   ARMCLANG          /path/to/armclang                 (ubuntu delivery only)
#   ARMAR             /path/to/armar                    (ubuntu delivery only)
#   HOST_ROLE         dev (macOS, Claude iteration)  |  delivery (Ubuntu library)

set -u

# ------------------------------------------------------------------ #
# Host detection                                                      #
# ------------------------------------------------------------------ #
_uname_s="$(uname -s 2>/dev/null || echo unknown)"
_uname_m="$(uname -m 2>/dev/null || echo unknown)"

case "${_uname_s}-${_uname_m}" in
  Darwin-arm64)   HOST_TAG=macos-arm64 ;;
  Darwin-x86_64)  HOST_TAG=macos-x64   ;;
  Linux-x86_64)   HOST_TAG=ubuntu-x64  ;;
  Linux-aarch64)  HOST_TAG=ubuntu-arm64;;
  *)              HOST_TAG=unknown     ;;
esac
export HOST_TAG

case "$HOST_TAG" in
  macos-*)  HOST_ROLE=dev      ;;
  ubuntu-*) HOST_ROLE=delivery ;;
  *)        HOST_ROLE=unknown  ;;
esac
export HOST_ROLE

# ------------------------------------------------------------------ #
# Helpers                                                             #
# ------------------------------------------------------------------ #
# Derive the toolchain *prefix* directory from a bin on PATH.
_gnutc_prefix_from_path() {
    local p
    p=$(command -v arm-none-eabi-gcc 2>/dev/null) || return 1
    [ -n "$p" ] || return 1
    dirname "$(dirname "$p")"
}
# _cmd_or <binary> <fallback-path>: prefer PATH, else fallback.
_cmd_or() {
    local p
    p=$(command -v "$1" 2>/dev/null)
    [ -n "$p" ] && { echo "$p"; return; }
    echo "$2"
}

# ------------------------------------------------------------------ #
# Per-host default tool locations                                     #
# ------------------------------------------------------------------ #
# Priority for GNU_TC:
#   1) user-set env var
#   2) per-host fixed default path, if it exists
#   3) PATH-derived prefix (e.g. /usr on Ubuntu with apt install)
case "$HOST_TAG" in
  macos-arm64)   _default_gnutc=/tmp/arm-gnu-toolchain-13.3.rel1-darwin-arm64-arm-none-eabi ;;
  macos-x64)     _default_gnutc=/tmp/arm-gnu-toolchain-13.3.rel1-darwin-x86_64-arm-none-eabi ;;
  ubuntu-x64)    _default_gnutc=/tmp/arm-gnu-toolchain-13.3.rel1-x86_64-arm-none-eabi ;;
  ubuntu-arm64)  _default_gnutc=/tmp/arm-gnu-toolchain-13.3.rel1-aarch64-arm-none-eabi ;;
  *)             _default_gnutc= ;;
esac

if [ -z "${GNU_TC:-}" ]; then
    if [ -x "${_default_gnutc}/bin/arm-none-eabi-gcc" ]; then
        GNU_TC=$_default_gnutc
    else
        GNU_TC=$(_gnutc_prefix_from_path || echo "$_default_gnutc")
    fi
fi

case "$HOST_TAG" in
  macos-arm64)
    : "${QEMU:=$(_cmd_or qemu-system-arm /opt/homebrew/bin/qemu-system-arm)}"
    : "${ARMCLANG:=}"       # not typically installed on macOS
    : "${ARMAR:=}"
    ;;
  macos-x64)
    : "${QEMU:=$(_cmd_or qemu-system-arm /usr/local/bin/qemu-system-arm)}"
    : "${ARMCLANG:=}"
    : "${ARMAR:=}"
    ;;
  ubuntu-x64|ubuntu-arm64)
    : "${QEMU:=$(_cmd_or qemu-system-arm /usr/bin/qemu-system-arm)}"
    : "${ARMCLANG:=$(_cmd_or armclang /opt/armclang/bin/armclang)}"
    : "${ARMAR:=$(_cmd_or armar    /opt/armclang/bin/armar)}"
    ;;
  *)
    : "${QEMU:=}"
    : "${ARMCLANG:=}"
    : "${ARMAR:=}"
    ;;
esac
export GNU_TC QEMU ARMCLANG ARMAR

# ------------------------------------------------------------------ #
# Sanity predicates (callers may invoke)                              #
# ------------------------------------------------------------------ #
check_gnu_tc() {
    [ -x "$GNU_TC/bin/arm-none-eabi-gcc" ]
}

check_qemu() {
    [ -x "$QEMU" ] || command -v "$QEMU" >/dev/null 2>&1
}

check_armclang() {
    [ -n "$ARMCLANG" ] && { [ -x "$ARMCLANG" ] || command -v "$ARMCLANG" >/dev/null 2>&1; }
}

report_env() {
    echo "host    : $HOST_TAG ($HOST_ROLE)"
    echo "GNU_TC  : $GNU_TC $(check_gnu_tc   && echo '[OK]' || echo '[MISSING]')"
    echo "QEMU    : $QEMU   $(check_qemu     && echo '[OK]' || echo '[MISSING]')"
    if [ "$HOST_ROLE" = delivery ]; then
        echo "ARMCLANG: $ARMCLANG $(check_armclang && echo '[OK]' || echo '[MISSING]')"
    fi
}
