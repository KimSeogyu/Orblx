#!/bin/sh
# Install orblx from a GitHub release.
#
#   curl -fsSL https://github.com/KimSeogyu/Orblx/releases/latest/download/install.sh | sh
#   curl -fsSL .../install.sh | sh -s -- --version v0.1.0 --service
#
# The script does these steps:
#   1. It finds the OS and the CPU, and selects the tarball.
#   2. It downloads the tarball, SHA256SUMS, and SHA256SUMS.sigstore.json.
#   3. It checks the cosign signature of SHA256SUMS.
#   4. It checks the SHA-256 of the tarball against SHA256SUMS.
#   5. It installs orblx in the prefix (default /usr/local/bin).
#   6. With --service, it installs the systemd unit or the launchd plist. It does not start the service.
# The script stops at the first failed check. It installs nothing after a failed check.
#
# Options and environment variables:
#   --version TAG      ORBLX_VERSION     Release tag, for example v0.1.0. Default: latest.
#   --prefix DIR       ORBLX_PREFIX      Install directory. Default: /usr/local/bin.
#   --base-url URL     ORBLX_BASE_URL    Download directory with the release files (a mirror).
#   --cosign-key FILE  ORBLX_COSIGN_KEY  Check the signature with this cosign public key.
#                                        Without it, the script checks the keyless GitHub
#                                        Actions identity of the Orblx release workflow.
#   --service          ORBLX_SERVICE=1   Also install the service file.
# The signature check needs cosign: https://docs.sigstore.dev/cosign/system_config/installation/
set -eu

REPO="KimSeogyu/Orblx"
OIDC_ISSUER="https://token.actions.githubusercontent.com"
IDENTITY_RE="^https://github\\.com/KimSeogyu/Orblx/\\.github/workflows/release\\.yml@refs/tags/v[0-9A-Za-z.+-]+\$"

version="${ORBLX_VERSION:-latest}"
prefix="${ORBLX_PREFIX:-/usr/local/bin}"
base_url="${ORBLX_BASE_URL:-}"
cosign_key="${ORBLX_COSIGN_KEY:-}"
service="${ORBLX_SERVICE:-0}"

fail() {
  echo "orblx install: error: $*" >&2
  exit 1
}

say() {
  echo "orblx install: $*"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version) [ "$#" -ge 2 ] || fail "--version needs a value."; version="$2"; shift 2 ;;
    --prefix) [ "$#" -ge 2 ] || fail "--prefix needs a value."; prefix="$2"; shift 2 ;;
    --base-url) [ "$#" -ge 2 ] || fail "--base-url needs a value."; base_url="$2"; shift 2 ;;
    --cosign-key) [ "$#" -ge 2 ] || fail "--cosign-key needs a value."; cosign_key="$2"; shift 2 ;;
    --service) service=1; shift ;;
    -h | --help) sed -n '2,26p' "$0" 2>/dev/null || true; exit 0 ;;
    *) fail "The option $1 is not known." ;;
  esac
done

case "$version" in
  latest | v[0-9]*) ;;
  *) fail "The version must be latest or a tag such as v0.1.0." ;;
esac
case "$version" in
  *[!0-9A-Za-z.+-]*) fail "The version contains a character that is not allowed." ;;
esac

os="$(uname -s)"
cpu="$(uname -m)"
case "$cpu" in
  x86_64 | amd64) cpu=x86_64 ;;
  aarch64 | arm64) cpu=aarch64 ;;
  *) fail "The CPU ${cpu} has no release build." ;;
esac
case "$os" in
  Linux) target="${cpu}-unknown-linux-gnu" ;;
  Darwin) target="${cpu}-apple-darwin" ;;
  *) fail "The OS ${os} has no release build." ;;
esac
tarball="orblx-${target}.tar.gz"

if [ -z "$base_url" ]; then
  if [ "$version" = latest ]; then
    base_url="https://github.com/${REPO}/releases/latest/download"
  else
    base_url="https://github.com/${REPO}/releases/download/${version}"
  fi
fi
case "$base_url" in
  https://*) ;;
  http://*) say "warning: ${base_url} is not HTTPS. The signature and the checksum still protect the files." ;;
  *) fail "The base URL must start with https:// or http://." ;;
esac

command -v cosign >/dev/null 2>&1 \
  || fail "cosign is not installed. The script needs cosign to check the signature. See https://docs.sigstore.dev/cosign/system_config/installation/"
if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$1" | awk '{print $1}'; }
elif command -v shasum >/dev/null 2>&1; then
  sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
else
  fail "sha256sum or shasum is necessary."
fi
if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL --proto '=https,http' --retry 2 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q -O "$2" "$1"; }
else
  fail "curl or wget is necessary."
fi

work="$(mktemp -d 2>/dev/null || mktemp -d -t orblx)"
trap 'rm -rf "$work"' EXIT INT TERM

say "target ${target} version ${version} source ${base_url}"
for file in "$tarball" SHA256SUMS SHA256SUMS.sigstore.json; do
  fetch "${base_url}/${file}" "${work}/${file}" || fail "The download of ${file} failed."
done

say "check the signature of SHA256SUMS"
if [ -n "$cosign_key" ]; then
  [ -r "$cosign_key" ] || fail "The cosign key ${cosign_key} is not readable."
  # A local key has no transparency log entry.
  cosign verify-blob --key "$cosign_key" --bundle "${work}/SHA256SUMS.sigstore.json" \
    --insecure-ignore-tlog=true "${work}/SHA256SUMS" >"${work}/cosign.log" 2>&1 \
    || fail "The signature check of SHA256SUMS failed. The script installed nothing."
else
  cosign verify-blob --bundle "${work}/SHA256SUMS.sigstore.json" \
    --certificate-identity-regexp "$IDENTITY_RE" \
    --certificate-oidc-issuer "$OIDC_ISSUER" \
    "${work}/SHA256SUMS" >"${work}/cosign.log" 2>&1 \
    || fail "The signature check of SHA256SUMS failed. The script installed nothing."
fi
say "signature ok"

say "check the SHA-256 of ${tarball}"
expected="$(awk -v name="$tarball" '$2 == name || $2 == "*" name {print $1}' "${work}/SHA256SUMS")"
[ -n "$expected" ] || fail "SHA256SUMS has no line for ${tarball}."
[ "$(printf '%s\n' "$expected" | wc -l | tr -d ' ')" = 1 ] || fail "SHA256SUMS has more than one line for ${tarball}."
actual="$(sha256 "${work}/${tarball}")"
[ "$actual" = "$expected" ] || fail "The checksum of ${tarball} is not correct. The script installed nothing."
say "checksum ok ${actual}"

mkdir "${work}/x"
tar -xzf "${work}/${tarball}" -C "${work}/x" || fail "The tarball did not extract."
dir="$(find "${work}/x" -mindepth 1 -maxdepth 1 -type d -name 'orblx-*' | sed -n 1p)"
[ -n "$dir" ] && [ -f "${dir}/orblx" ] || fail "The tarball has no orblx binary."

as_root=""
if [ ! -d "$prefix" ] || [ ! -w "$prefix" ] || [ "$service" = 1 ]; then
  if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || fail "The script needs root to write ${prefix}. sudo is not installed."
    as_root="sudo"
  fi
fi

$as_root mkdir -p "$prefix"
$as_root install -m 0755 "${dir}/orblx" "${prefix}/orblx"
say "installed ${prefix}/orblx"
"${prefix}/orblx" --version || fail "The installed orblx did not run."

if [ "$service" = 1 ]; then
  case "$os" in
    Linux)
      $as_root mkdir -p /etc/systemd/system
      $as_root install -m 0644 "${dir}/orblxd.service" /etc/systemd/system/orblxd.service
      say "installed /etc/systemd/system/orblxd.service"
      if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        $as_root systemctl daemon-reload
        say "next: sudo systemctl enable --now orblxd"
      else
        say "systemd is not running. The script did not reload systemd."
      fi
      ;;
    Darwin)
      $as_root install -m 0644 "${dir}/dev.orblx.plist" /Library/LaunchDaemons/dev.orblx.plist
      say "installed /Library/LaunchDaemons/dev.orblx.plist"
      say "next: sudo launchctl bootstrap system /Library/LaunchDaemons/dev.orblx.plist"
      ;;
  esac
fi
say "done"
