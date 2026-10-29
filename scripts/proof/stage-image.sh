#!/usr/bin/env bash
# Copy the proof image files into a new directory.
# The caller passes the repository root and the orblx binary.
# The function prints the directory path.
# The caller removes the directory.

stage_proof_image() {
  local root="$1"
  local bin="$2"
  local image_dir
  image_dir="$(mktemp -d)"
  cp "$bin" "$image_dir/orblx"
  cp "$root/scripts/proof/Dockerfile" "$image_dir/Dockerfile"
  cp "$root/scripts/proof/entrypoint.sh" "$image_dir/entrypoint.sh"
  printf '%s\n' "$image_dir"
}
