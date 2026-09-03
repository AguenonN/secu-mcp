#!/usr/bin/env bash
# Runs ON the GCP VM (Ubuntu 24.04). Installs k3s + docker, builds the lab
# image, imports it into k3s' containerd, deploys SPIRE then the workloads,
# and registers the identities. Idempotent — safe to re-run.
#
# Expects the repo at ~/mcp_rogue (provision.sh puts it there).
set -euo pipefail

REPO="${REPO_DIR:-${HOME}/mcp_rogue}"
export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

echo ">> [1/6] k3s (single-node)"
if ! command -v k3s >/dev/null; then
  curl -sfL https://get.k3s.io | sudo sh -s - --write-kubeconfig-mode 644
fi
sudo systemctl start k3s
# Right after first start the node object may not exist yet — wait for it to
# appear before `kubectl wait` (which errors on an empty selector).
for _ in $(seq 60); do
  kubectl get nodes --no-headers 2>/dev/null | grep -q . && break
  sleep 2
done
kubectl wait --for=condition=Ready node --all --timeout=120s

echo ">> [2/6] docker (only used to build the lab image)"
if ! command -v docker >/dev/null; then
  sudo apt-get update -qq
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io
fi

echo ">> [3/6] Build mcp-rogue-lab:local and import into k3s containerd"
sudo docker build -t mcp-rogue-lab:local -f "${REPO}/deploy/Dockerfile" "${REPO}"
sudo docker save mcp-rogue-lab:local | sudo k3s ctr images import -

echo ">> [4/6] SPIRE (server, then agent)"
kubectl apply -f "${REPO}/deploy/gcp/k8s/00-namespaces.yaml"
kubectl apply -f "${REPO}/deploy/gcp/k8s/10-spire-server.yaml"
kubectl -n spire rollout status statefulset/spire-server --timeout=300s
kubectl apply -f "${REPO}/deploy/gcp/k8s/20-spire-agent.yaml"
kubectl -n spire rollout status daemonset/spire-agent --timeout=300s

echo ">> [5/6] Register identities (legit + agent — never the rogue)"
bash "${REPO}/deploy/gcp/register-entries.sh"

echo ">> [6/6] Lab workloads + egress confinement"
kubectl apply -f "${REPO}/deploy/gcp/k8s/30-mcp-lab.yaml"
# Blast-radius lock: default-deny NetworkPolicies (enforced by k3s'
# kube-router). Even a fooled agent — or the rogue itself — cannot reach the
# Internet; exfiltration dies at the kernel.
kubectl apply -f "${REPO}/deploy/gcp/k8s/40-network-policy.yaml"
kubectl -n mcp-lab rollout status deploy/network-config --timeout=300s
kubectl -n mcp-lab rollout status deploy/rogue --timeout=300s

echo
echo ">> Ready. Try:"
echo "   bash ~/mcp_rogue/deploy/gcp/run-scenario.sh naive-rogue"
echo "   bash ~/mcp_rogue/deploy/gcp/run-scenario.sh zerotrust-rogue"
echo "   bash ~/mcp_rogue/deploy/gcp/run-scenario.sh zerotrust-legit"
