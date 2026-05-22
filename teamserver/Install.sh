#!/bin/bash
# Install.sh — Havoc teamserver dependency setup
# Supports Linux (apt/apt-get) and macOS (brew).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
DATA_DIR="$ROOT_DIR/data"

OS="$(uname -s)"

# ── Install system packages ────────────────────────────────────────────
if [ "$OS" = "Darwin" ]; then
    echo "[*] macOS detected — checking Homebrew dependencies"
    if ! command -v brew &>/dev/null; then
        echo "[!] Homebrew not found. Install it first: https://brew.sh"
        exit 1
    fi
    # nasm is needed to build the Windows Demon agent shellcode
    for pkg in nasm wget; do
        if ! brew list "$pkg" &>/dev/null; then
            echo "[*] Installing $pkg via brew..."
            brew install "$pkg" >/dev/null 2>&1
        fi
    done
else
    # Linux path (original behaviour)
    echo "[*] Linux detected — checking apt dependencies"
    sudo apt -qq --yes install golang-go nasm mingw-w64 wget >/dev/null 2>&1
fi

# ── Download and extract MinGW cross-compilers ────────────────────────
# These are only needed to cross-compile the Windows Demon agent.
# The teamserver Go binary itself does not need them.

if [ ! -d "$DATA_DIR/x86_64-w64-mingw32-cross" ]; then
    mkdir -p "$DATA_DIR"

    # 64-bit toolchain
    if [ ! -f /tmp/mingw-musl-64.tgz ]; then
        echo "[*] Downloading x86_64 MinGW toolchain (~130 MB)..."
        wget https://musl.cc/x86_64-w64-mingw32-cross.tgz -q -O /tmp/mingw-musl-64.tgz
    fi

    echo "[*] Extracting x86_64 MinGW toolchain..."
    tar zxf /tmp/mingw-musl-64.tgz -C "$DATA_DIR"
    if [ $? -ne 0 ]; then
        echo "[!] Extraction failed — removing cached file so it re-downloads next run"
        rm -f /tmp/mingw-musl-64.tgz
        exit 1
    fi
fi

if [ ! -d "$DATA_DIR/i686-w64-mingw32-cross" ]; then
    mkdir -p "$DATA_DIR"

    # 32-bit toolchain
    if [ ! -f /tmp/mingw-musl-32.tgz ]; then
        echo "[*] Downloading i686 MinGW toolchain (~130 MB)..."
        wget https://musl.cc/i686-w64-mingw32-cross.tgz -q -O /tmp/mingw-musl-32.tgz
    fi

    echo "[*] Extracting i686 MinGW toolchain..."
    tar zxf /tmp/mingw-musl-32.tgz -C "$DATA_DIR"
    if [ $? -ne 0 ]; then
        echo "[!] Extraction failed — removing cached file so it re-downloads next run"
        rm -f /tmp/mingw-musl-32.tgz
        exit 1
    fi
fi

echo "[+] Install.sh complete"
