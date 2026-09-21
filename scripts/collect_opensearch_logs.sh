#!/bin/bash
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

# Collect the OpenSearch workload logs from every OpenSearch unit of every model, so that they
# are available for debugging when an integration test fails.

set -uo pipefail

DESTINATION="${1:?usage: $0 <destination-dir>}"

# Print the name of every registered controller.
list_controllers() {
  juju controllers --format json 2>/dev/null |
    python3 -c 'import json, sys
print("\n".join(json.load(sys.stdin)["controllers"]))' 2>/dev/null
}

# Print the name of every model of controller "$1", except the controller's own model.
list_models() {
  juju models --controller "$1" --format json 2>/dev/null |
    python3 -c 'import json, sys
for model in json.load(sys.stdin)["models"]:
    if not model["is-controller"]:
        print(model["short-name"])' 2>/dev/null
}

# Print "<model-type> <unit>" for every OpenSearch unit of model "$1". The model type is "caas" on
# Kubernetes and "iaas" on machines.
list_units() {
  juju status --model "$1" --format json 2>/dev/null |
    python3 -c 'import json, sys
status = json.load(sys.stdin)
for application in (status.get("applications") or {}).values():
    if application.get("charm-name") in ("opensearch", "opensearch-k8s"):
        for unit in application.get("units") or {}:
            print(status["model"]["type"], unit)' 2>/dev/null
}

# Stream a gzipped tarball of the log directory of unit "$3" into the destination.
collect_unit() {
  local model="$1" substrate="$2" unit="$3" entries
  local archive="${DESTINATION}/${model/:/_}/${unit//\//-}.tar.gz"
  local -a target

  if [[ "$substrate" == "caas" ]]; then
    # The workload container runs as root and the rock has no sudo.
    target=(--container opensearch "$unit" "tar -czf - -C /var/log opensearch")
  else
    target=(--pty=false "$unit"
      "sudo tar -czf - -C /var/snap/opensearch/common/var/log opensearch")
  fi

  mkdir -p "$(dirname "$archive")"
  juju ssh --model "$model" "${target[@]}" >"$archive"

  # tar exits 1 when a file changes underneath it, which is normal on a running node, and a
  # failed tar still writes a valid but empty gzip stream. So count the entries rather than
  # trusting either the exit status or the archive being well-formed.
  entries=$(tar -tzf "$archive" 2>/dev/null | wc -l)
  if [[ "$entries" -eq 0 ]]; then
    echo "WARNING: could not collect logs from $model $unit"
    rm -f "$archive"
    return
  fi

  echo "collected $entries files from $model $unit ($(du -h "$archive" | cut -f1))"
}

main() {
  local controller model entry substrate unit
  local -a controllers=() models=() units=()

  mapfile -t controllers < <(list_controllers)
  if [[ ${#controllers[@]} -eq 0 ]]; then
    echo "no juju controllers registered, nothing to collect"
    return
  fi

  for controller in "${controllers[@]}"; do
    mapfile -t models < <(list_models "$controller")
    for model in "${models[@]}"; do
      mapfile -t units < <(list_units "$controller:$model")
      for entry in "${units[@]}"; do
        read -r substrate unit <<<"$entry"
        collect_unit "$controller:$model" "$substrate" "$unit"
      done
    done
  done
}

main
exit 0
