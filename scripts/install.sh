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
# Query the API separately so a failed request (404, rate limit, network) gives
# a clear message instead of an empty parse.
release_json="$(curl -fsSL "$api")" \
  || err "could not query the releases API — check the version exists and you are not rate-limited: ${api}"

# Pull the first amd64 .deb asset URL out of the release JSON without needing jq.
# The pipeline can exit non-zero when grep finds nothing, or via SIGPIPE when
# head closes early on success; '|| true' keeps set -e from aborting before the
# guard below can report a useful error.
deb_url="$(printf '%s' "$release_json" \
  | grep -o '"browser_download_url": *"[^"]*_amd64\.deb"' \
  | head -n1 \
  | sed 's/.*"browser_download_url": *"\([^"]*\)"/\1/')" || true

[ -n "$deb_url" ] || err "release '${VERSION}' has no amd64 .deb asset yet — see https://github.com/${REPO}/releases"

# --- download & install ----------------------------------------------------
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
deb="${tmp}/$(basename "$deb_url")"

echo "Downloading ${deb_url} ..."
curl -fsSL -o "$deb" "$deb_url"

echo "Installing ${deb} ..."
# nssec is a self-contained binary with no package dependencies (the .deb
# declares no Depends and ships no maintainer scripts). Install with dpkg
# directly rather than 'apt-get install': apt runs the needrestart hook, which
# on a host with a backlog of un-restarted library updates will restart
# unrelated services (apache2, mariadb, ssh, the netsapiens_* stack, ...)
# without prompting when there is no TTY. dpkg does not trigger that hook.
if ! dpkg -i "$deb"; then
  # Only reached if a future build introduces real dependencies. Resolve them,
  # but pin needrestart to list-only mode so it never restarts services
  # unprompted — it will just print what it thinks needs a restart.
  echo "Resolving dependencies ..."
  NEEDRESTART_MODE=l apt-get -f install -y
fi

echo
echo "nssec installed: $(command -v nssec)"
nssec --version 2>/dev/null || nssec --help | head -n1 || true
