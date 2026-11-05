#!/usr/bin/env bash
# W25-44: a build from main must never print a release version.
# This check fails when the workspace version in Cargo.toml is the version of an existing
# release tag (v<version>, from `git tag`). After each tag, bump main to the next -dev version.
# Usage: scripts/check-version-not-tagged.sh [REPO_DIR]
set -euo pipefail
repo="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
version="$(awk '
  /^\[workspace\.package\]/ { in_pkg = 1; next }
  /^\[/ { in_pkg = 0 }
  in_pkg && $1 == "version" { gsub(/"/, "", $3); print $3; exit }
' "$repo/Cargo.toml")"
if [[ -z "$version" ]]; then
  echo "version_check FAIL: no [workspace.package] version in $repo/Cargo.toml" >&2
  exit 1
fi
tags="$(git -C "$repo" tag --list)" || { echo "version_check FAIL: git tag failed" >&2; exit 1; }
if [[ -z "$tags" ]]; then
  echo "version_check FAIL: git tag shows no tags (fetch the tags first)" >&2
  exit 1
fi
while IFS= read -r tag; do
  if [[ "$tag" == "v$version" || "$tag" == "$version" ]]; then
    echo "version_check FAIL: workspace version $version is the release tag $tag. Bump main to the next -dev version." >&2
    exit 1
  fi
done <<<"$tags"
echo "version_check ok: workspace version $version is not a release tag"
