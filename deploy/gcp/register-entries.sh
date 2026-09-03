#!/usr/bin/env bash
# Register the lab identities in SPIRE — Kubernetes edition.
#
# Same principle as the compose lab: it registers the legitimate server
# (sa-legit) and the agent (sa-agent), never the rogue (sa-rogue).
#
# Prerequisite: spire-server and spire-agent running (see setup-vm.sh).
set -euo pipefail

TD="mcp.gcp.lab"
CLUSTER="mcp-gcp-lab"
NODE_ID="spiffe://${TD}/k3s-node"
EXEC=(kubectl -n spire exec spire-server-0 -c spire-server --
      /opt/spire/bin/spire-server)

# entry create fails on an exact duplicate; that just means the script already
# ran, so tolerate it.
create() {
  local out
  if out="$("${EXEC[@]}" entry create "$@" 2>&1)"; then
    echo "${out}"
  elif grep -qi "already exists" <<<"${out}"; then
    echo "   (entry already exists — ok)"
  else
    echo "${out}" >&2
    return 1
  fi
}

echo ">> Node alias for the (single) k3s node attested via k8s_psat"
create -node -spiffeID "${NODE_ID}" \
  -selector "k8s_psat:cluster:${CLUSTER}"

echo ">> Registering spiffe://${TD}/network-config  (ns mcp-lab, sa sa-legit)"
create -parentID "${NODE_ID}" \
  -spiffeID "spiffe://${TD}/network-config" \
  -selector "k8s:ns:mcp-lab" \
  -selector "k8s:sa:sa-legit"

echo ">> Registering spiffe://${TD}/agent  (ns mcp-lab, sa sa-agent)"
create -parentID "${NODE_ID}" \
  -spiffeID "spiffe://${TD}/agent" \
  -selector "k8s:ns:mcp-lab" \
  -selector "k8s:sa:sa-agent"

echo ">> Registering spiffe://${TD}/obs-bridge  (ns mcp-lab, sa sa-mcp-obs)"
create -parentID "${NODE_ID}" \
  -spiffeID "spiffe://${TD}/obs-bridge" \
  -selector "k8s:ns:mcp-lab" \
  -selector "k8s:sa:sa-mcp-obs"

echo ">> Registering spiffe://${TD}/agent-sre  (ns mcp-lab, sa sa-sre-agent)"
create -parentID "${NODE_ID}" \
  -spiffeID "spiffe://${TD}/agent-sre" \
  -selector "k8s:ns:mcp-lab" \
  -selector "k8s:sa:sa-sre-agent"

# The rogue (sa-rogue) is intentionally absent. Do not add it.
echo ">> The rogue (sa-rogue) has no entry and will get no SVID — by design."
