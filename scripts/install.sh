#!/usr/bin/env bash
#
# nssec installer — downloads the latest (or a specified) release .deb from
# GitHub and installs it with apt so dependencies are resolved.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/jsrobinson3/ns-security/main/scripts/install.sh | sudo bash
#   curl -fsSL .../install.sh | sudo bash -s -- --version 0.2.0
#
# Re-running with a newer release upgrades in place.
set -euo pipefail

REPO="jsrobinson3/ns-security"
VERSION="latest"

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

err() { echo "error: $*" >&2; exit 1; }

# --- preflight -------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || err "must run as root (pipe to 'sudo bash', or run with sudo)"
command -v apt-get >/dev/null 2>&1 || err "apt-get not found — this installer targets Debian/Ubuntu"
command -v curl >/dev/null 2>&1 || err "curl is required"

arch="$(dpkg --print-architecture)"
[ "$arch" = "amd64" ] || err "no prebuilt package for architecture '$arch' (only amd64 is published)"

# --- resolve the .deb download URL ----------------------------------------
if [ "$VERSION" = "latest" ]; then
  api="https://api.github.com/repos/${REPO}/releases/latest"
else
  api="https://api.github.com/repos/${REPO}/releases/tags/v${VERSION#v}"
fi

echo "Resolving release from ${api} ..."
# Pull the first amd64 .deb asset URL out of the release JSON without needing jq.
deb_url="$(curl -fsSL "$api" \
  | grep -o '"browser_download_url": *"[^"]*_amd64\.deb"' \
  | head -n1 \
  | sed 's/.*"browser_download_url": *"\([^"]*\)"/\1/')"

[ -n "$deb_url" ] || err "could not find an amd64 .deb asset for version '${VERSION}'"

# --- download & install ----------------------------------------------------
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
deb="${tmp}/$(basename "$deb_url")"

echo "Downloading ${deb_url} ..."
curl -fsSL -o "$deb" "$deb_url"

echo "Installing ${deb} ..."
# 'apt-get install ./file.deb' resolves and installs any dependencies.
apt-get install -y "$deb"

echo
echo "nssec installed: $(command -v nssec)"
nssec --version 2>/dev/null || nssec --help | head -n1 || true
