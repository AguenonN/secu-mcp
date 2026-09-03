#!/usr/bin/env bash
# Deploy the SRE / observability service onto the running lab cluster.
#
# Runs ON the VM, after setup-vm.sh. Idempotent: re-running it re-applies the
# manifests and re-issues the Grafana token.
#
#   1. monitoring stack (Prometheus, Alertmanager, Grafana, checkout-api)
#   2. a Grafana service-account token scoped to annotation writes, stored in a
#      k8s Secret the bridge mounts — the bridge never sees the admin password
#   3. SPIRE entries for the bridge and the on-call agent
#   4. the bridge itself, plus the NetworkPolicies that confine everything
set -euo pipefail

REPO="${REPO:-$HOME/mcp_rogue}"
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
K8S="${REPO}/deploy/gcp/k8s"

echo ">> [1/5] Monitoring stack"
# The Grafana admin password is generated here, not committed. Created once and
# left alone on re-runs: Grafana persists the admin credential on first start,
# so rotating the Secret afterwards would only desynchronise the two.
if ! kubectl -n monitoring get secret grafana-admin >/dev/null 2>&1; then
  echo "   generating the Grafana admin password (first deploy)"
  kubectl -n monitoring create secret generic grafana-admin \
    --from-literal=admin-user=admin \
    --from-literal=admin-password="$(head -c 24 /dev/urandom | base64 | tr -d '/+=' | cut -c1-24)"
fi
kubectl apply -f "${K8S}/50-monitoring.yaml"
kubectl -n monitoring rollout status deploy/prometheus   --timeout=300s
kubectl -n monitoring rollout status deploy/alertmanager --timeout=300s
kubectl -n monitoring rollout status deploy/grafana      --timeout=300s
kubectl -n monitoring rollout status deploy/checkout-api --timeout=300s

echo
echo ">> [2/5] Grafana service-account token for the bridge"
# Ask Grafana, through the API, for a service account limited to annotation
# writes. The token that comes back is the ONLY credential the bridge gets:
# the admin password stays in the monitoring namespace and is never mounted
# into mcp-lab.
ADMIN_USER="$(kubectl -n monitoring get secret grafana-admin -o jsonpath='{.data.admin-user}' | base64 -d)"
ADMIN_PASS="$(kubectl -n monitoring get secret grafana-admin -o jsonpath='{.data.admin-password}' | base64 -d)"

# Reach Grafana from inside the cluster: a short-lived pod in the monitoring
# namespace, which the NetworkPolicy admits on the same terms as Grafana's own
# clients. Nothing is exposed outside the node.
#
# Which HTTP client exists inside the Grafana image is not something to assume,
# so detect it once and use whichever is there.
HTTP_TOOL=""
if kubectl -n monitoring exec deploy/grafana -c grafana -- sh -c 'command -v curl' >/dev/null 2>&1; then
  HTTP_TOOL=curl
elif kubectl -n monitoring exec deploy/grafana -c grafana -- sh -c 'command -v wget' >/dev/null 2>&1; then
  HTTP_TOOL=wget
else
  echo "!! neither curl nor wget inside the Grafana container; cannot mint a token" >&2
  exit 1
fi
echo "   using ${HTTP_TOOL} inside the Grafana container"

gf() {
  local method="$1" path="$2" body="${3:-}"
  local url="http://localhost:3000${path}"
  if [[ "${HTTP_TOOL}" == "curl" ]]; then
    kubectl -n monitoring exec deploy/grafana -c grafana -- \
      curl -s -u "${ADMIN_USER}:${ADMIN_PASS}" -X "${method}" \
           -H "Content-Type: application/json" \
           ${body:+-d "${body}"} "${url}"
  else
    kubectl -n monitoring exec deploy/grafana -c grafana -- \
      wget -q -O- --auth-no-challenge \
           --user="${ADMIN_USER}" --password="${ADMIN_PASS}" \
           --method="${method}" --header="Content-Type: application/json" \
           ${body:+--body-data="${body}"} "${url}"
  fi
}

# Role Editor, not a narrower one: writing annotations through the API needs
# Editor among Grafana's basic roles (Viewer cannot). A true annotations-only
# permission exists — the fine-grained `annotations:write` — but only under
# Grafana RBAC, which is an Enterprise/Cloud feature. So this token is broader
# than the bridge strictly needs, and the confinement of that extra reach comes
# from the layers around it: the dashboard allowlist, the rate limit, and the
# fact that nothing but the bridge can reach Grafana at all.
echo "   creating service account 'mcp-obs-bridge' (role Editor — see comment)"
SA_JSON="$(gf POST /api/serviceaccounts \
  '{"name":"mcp-obs-bridge","role":"Editor","isDisabled":false}' || true)"
SA_ID="$(sed -n 's/.*"id":\([0-9]*\).*/\1/p' <<<"${SA_JSON}" | head -1)"

if [[ -z "${SA_ID}" ]]; then
  # Already exists from a previous run — look it up instead.
  SA_ID="$(gf GET '/api/serviceaccounts/search?query=mcp-obs-bridge' \
           | sed -n 's/.*"id":\([0-9]*\).*/\1/p' | head -1)"
fi
if [[ -z "${SA_ID}" ]]; then
  echo "!! could not create or find the Grafana service account" >&2
  echo "   response: ${SA_JSON}" >&2
  exit 1
fi
echo "   service account id=${SA_ID}"

# Tokens cannot be read back, so rotate on every run: delete any token this
# script created before, then mint a fresh one.
for tid in $(gf GET "/api/serviceaccounts/${SA_ID}/tokens" \
             | tr '}' '\n' | sed -n 's/.*"id":\([0-9]*\).*"name":"mcp-bridge-token".*/\1/p'); do
  gf DELETE "/api/serviceaccounts/${SA_ID}/tokens/${tid}" >/dev/null || true
done
TOKEN_JSON="$(gf POST "/api/serviceaccounts/${SA_ID}/tokens" '{"name":"mcp-bridge-token"}')"
TOKEN="$(sed -n 's/.*"key":"\([^"]*\)".*/\1/p' <<<"${TOKEN_JSON}")"
if [[ -z "${TOKEN}" ]]; then
  echo "!! Grafana did not return a token" >&2
  echo "   response: ${TOKEN_JSON}" >&2
  exit 1
fi
echo "   token minted (${#TOKEN} chars) — storing it in mcp-lab/grafana-api-token"

kubectl -n mcp-lab create secret generic grafana-api-token \
  --from-literal=token="${TOKEN}" \
  --dry-run=client -o yaml | kubectl apply -f -

echo
echo ">> [3/5] SPIRE entries for the bridge and the on-call agent"
bash "${REPO}/deploy/gcp/register-entries.sh"

echo
echo ">> [4/5] Bridge + on-call agent service accounts"
kubectl apply -f "${K8S}/60-mcp-obs.yaml"
# The Secret in the manifest carries a placeholder; the real token was applied
# above, so re-apply it after the manifest to win.
kubectl -n mcp-lab create secret generic grafana-api-token \
  --from-literal=token="${TOKEN}" \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl -n mcp-lab rollout restart deploy/mcp-obs-bridge
kubectl -n mcp-lab rollout status  deploy/mcp-obs-bridge --timeout=300s

echo
echo ">> [5/5] Egress confinement"
kubectl apply -f "${K8S}/40-network-policy.yaml"
kubectl apply -f "${K8S}/70-network-policy-obs.yaml"

echo
echo ">> Ready. Run the incident:"
echo "   bash ${REPO}/deploy/gcp/run-sre.sh incident"
echo "   bash ${REPO}/deploy/gcp/run-sre.sh compromised"
echo "   bash ${REPO}/deploy/gcp/run-sre.sh heal"
echo
echo ">> To look at the dashboards:"
echo "   kubectl -n monitoring port-forward svc/grafana 3000:3000"
echo "   then http://localhost:3000 — user 'admin', password:"
echo "   kubectl -n monitoring get secret grafana-admin -o jsonpath='{.data.admin-password}' | base64 -d"
