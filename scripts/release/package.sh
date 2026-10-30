#!/usr/bin/env bash
# Make one release tarball.
# Usage: scripts/release/package.sh VERSION TARGET BIN OUT_DIR
# The tarball is OUT_DIR/orblx-TARGET.tar.gz.
# The top directory in the tarball is orblx-VERSION-TARGET.
# The script does not sign. The release job writes SHA256SUMS and signs it.
set -euo pipefail

if [[ "$#" -ne 4 ]]; then
  echo "Usage: $0 VERSION TARGET BIN OUT_DIR" >&2
  exit 2
fi
version="$1"
target="$2"
bin="$3"
out_dir="$4"
root="$(cd "$(dirname "$0")/../.." && pwd)"

case "$target" in
  x86_64-unknown-linux-gnu | aarch64-unknown-linux-gnu | x86_64-apple-darwin | aarch64-apple-darwin) ;;
  *)
    echo "The target ${target} is not a release target." >&2
    exit 2
    ;;
esac
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]]; then
  echo "The version ${version} is not valid." >&2
  exit 2
fi
if [[ ! -x "$bin" ]]; then
  echo "The binary ${bin} is missing." >&2
  exit 1
fi

name="orblx-${version}-${target}"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
mkdir -p "$stage/$name" "$out_dir"
install -m 0755 "$bin" "$stage/$name/orblx"
install -m 0644 "$root/LICENSE" "$root/NOTICE" "$root/README.md" "$stage/$name/"
install -m 0644 "$root/scripts/orblxd.service" "$root/scripts/dev.orblx.plist" "$stage/$name/"
# A fixed order, owner, and time make the tarball the same for the same input.
tar_flags=(--owner=0 --group=0 --numeric-owner --sort=name --mtime=@0)
if ! tar --version 2>/dev/null | grep -q 'GNU tar'; then
  tar_flags=(--uid 0 --gid 0)
fi
tar -C "$stage" "${tar_flags[@]}" -czf "$out_dir/orblx-${target}.tar.gz" "$name"
echo "packaged orblx-${target}.tar.gz version ${version}"
