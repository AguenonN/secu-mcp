#!/usr/bin/env bash
# Provision the lab on GCP: one Compute Engine VM (Ubuntu 24.04) running k3s,
# SPIRE and the three lab containers. Run from your workstation.
#
#   ./provision.sh            # create VM, copy repo, install everything
#   ./provision.sh destroy    # delete the VM
#
# Tunables (env): GCP_PROJECT, GCP_ZONE, VM_NAME, MACHINE_TYPE.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${DIR}/../.." && pwd)"

PROJECT="${GCP_PROJECT:-$(gcloud config get-value project 2>/dev/null)}"
ZONE="${GCP_ZONE:-europe-west1-b}"
VM="${VM_NAME:-mcp-rogue-lab}"
MACHINE="${MACHINE_TYPE:-e2-standard-2}"
GC=(gcloud compute --project "${PROJECT}")

if [[ "${1:-}" == "destroy" ]]; then
  "${GC[@]}" instances delete "${VM}" --zone "${ZONE}" --quiet
  echo ">> ${VM} deleted."
  exit 0
fi

if ! "${GC[@]}" instances describe "${VM}" --zone "${ZONE}" >/dev/null 2>&1; then
  echo ">> Creating VM ${VM} (${MACHINE}, Ubuntu 24.04) in ${ZONE}"
  "${GC[@]}" instances create "${VM}" \
    --zone "${ZONE}" \
    --machine-type "${MACHINE}" \
    --image-family ubuntu-2404-lts-amd64 \
    --image-project ubuntu-os-cloud \
    --boot-disk-size 30GB \
    --boot-disk-type pd-balanced
else
  echo ">> VM ${VM} already exists — reusing it."
fi

echo ">> Waiting for SSH to come up"
for _ in $(seq 30); do
  if "${GC[@]}" ssh "${VM}" --zone "${ZONE}" --command "true" >/dev/null 2>&1; then
    break
  fi
  sleep 5
done

echo ">> Copying the repo to ${VM}:~/mcp_rogue"
tar -C "${REPO_ROOT}" -czf - \
  --exclude bin --exclude stolen.log --exclude 'deploy/spire/bootstrap' . \
  | "${GC[@]}" ssh "${VM}" --zone "${ZONE}" \
      --command "rm -rf ~/mcp_rogue && mkdir -p ~/mcp_rogue && tar -xzf - -C ~/mcp_rogue"

echo ">> Running setup on the VM (k3s + SPIRE + lab)"
"${GC[@]}" ssh "${VM}" --zone "${ZONE}" \
  --command "bash ~/mcp_rogue/deploy/gcp/setup-vm.sh"

echo
echo ">> Done. Run the scenarios with:"
echo "   gcloud compute ssh ${VM} --zone ${ZONE} --command 'bash ~/mcp_rogue/deploy/gcp/run-scenario.sh zerotrust-rogue'"
