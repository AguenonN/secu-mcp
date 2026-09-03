#!/usr/bin/env bash
# Bootstrap the lab's identities in SPIRE, then start the agent and both servers.
#
# What matters is what this script does not do: it registers the legitimate
# network-config server and the agent, never the rogue. The rogue can therefore
# never obtain an SVID, which is why zero-trust mode refuses it.
#
# Prerequisite: `make lab-up` (spire-server running and healthy).
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE=(docker compose -f "${DIR}/docker-compose.yml")
TD="mcp.lab"
NODE_ID="spiffe://${TD}/agent-node"
TOKEN_DIR="${DIR}/spire/bootstrap"
SERVER=(/opt/spire/bin/spire-server)

mkdir -p "${TOKEN_DIR}"

echo ">> Generating a one-time join token bound to ${NODE_ID}"
TOKEN="$("${COMPOSE[@]}" exec -T spire-server "${SERVER[@]}" \
  token generate -spiffeID "${NODE_ID}" | awk -F': ' '/Token/ {print $2}')"
if [[ -z "${TOKEN}" ]]; then
  echo "!! failed to generate join token" >&2
  exit 1
fi
printf '%s' "${TOKEN}" > "${TOKEN_DIR}/agent-token"
echo "   wrote ${TOKEN_DIR}/agent-token"

register() {
  local id="$1" label="$2"
  echo ">> Registering ${id}  (selector docker:label:mcp-lab-workload:${label})"
  "${COMPOSE[@]}" exec -T spire-server "${SERVER[@]}" entry create \
    -parentID "${NODE_ID}" \
    -spiffeID "${id}" \
    -selector "docker:label:mcp-lab-workload:${label}"
}

# LEGITIMATE workloads get identities.
register "spiffe://${TD}/network-config" "network-config"
register "spiffe://${TD}/agent"          "agent"

# The rogue is intentionally absent. Do not add it.
echo ">> The rogue has no entry and will get no SVID — by design."

echo ">> Starting spire-agent, network-config and rogue"
"${COMPOSE[@]}" --profile agent up -d spire-agent network-config rogue

echo ">> Ready. Try:"
echo "   make lab-naive-rogue        # naive agent -> rogue : robbed"
echo "   make lab-zerotrust-rogue    # zero-trust agent -> rogue : rejected"
echo "   make lab-zerotrust-legit    # zero-trust agent -> legit : real file"
