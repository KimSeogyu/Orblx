#!/usr/bin/env bash
# W25-14b audit: one shared helper that makes a compose proof start from a clean state.
#
# "docker compose down -v" without all profiles keeps the containers and the volumes of the
# profiled services. An old volume can then keep old node state (for example an old
# ticket.bin) and make a proof pass for the wrong reason.
#
# proof_compose_clean PROJECT...
#   Removes every container, volume, and network with the compose label of each PROJECT,
#   for all profiles. Then it fails (return 1) if any of them is still there.
#   Use it at the start of each compose proof, after the proof lock and before the first
#   "up", "run", "build", or "create".

proof_compose_clean_docker() {
  if [[ "$(id -u)" -ne 0 ]] && declare -F as_root >/dev/null; then
    as_root docker "$@"
  else
    docker "$@"
  fi
}

proof_compose_clean() {
  local project label ids left=0
  if [[ "$#" -eq 0 ]]; then
    echo "proof_compose_clean needs a compose project name." >&2
    return 1
  fi
  for project in "$@"; do
    if [[ -z "$project" ]]; then
      echo "proof_compose_clean got an empty compose project name." >&2
      return 1
    fi
    label="label=com.docker.compose.project=${project}"
    ids="$(proof_compose_clean_docker ps -aq --filter "$label")"
    if [[ -n "$ids" ]]; then
      # shellcheck disable=SC2086
      proof_compose_clean_docker rm -f $ids >/dev/null 2>&1 || true
    fi
    ids="$(proof_compose_clean_docker volume ls -q --filter "$label")"
    if [[ -n "$ids" ]]; then
      # shellcheck disable=SC2086
      proof_compose_clean_docker volume rm -f $ids >/dev/null 2>&1 || true
    fi
    ids="$(proof_compose_clean_docker network ls -q --filter "$label")"
    if [[ -n "$ids" ]]; then
      # shellcheck disable=SC2086
      proof_compose_clean_docker network rm $ids >/dev/null 2>&1 || true
    fi
    for kind in container volume network; do
      case "$kind" in
        container) ids="$(proof_compose_clean_docker ps -aq --filter "$label")" ;;
        *) ids="$(proof_compose_clean_docker "$kind" ls -q --filter "$label")" ;;
      esac
      if [[ -n "$ids" ]]; then
        echo "The old proof ${kind} state of project ${project} is still there: $(printf '%s ' $ids)" >&2
        left=1
      fi
    done
    if [[ "$left" -eq 0 ]]; then
      echo "proof_compose_clean ${project} clean"
    fi
  done
  return "$left"
}
