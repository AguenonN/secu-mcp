#!/usr/bin/env bash
# Run one lab scenario as a Kubernetes Job and print the agent's verdict.
#
#   ./run-scenario.sh naive-rogue        # naive agent -> rogue : robbed
#   ./run-scenario.sh zerotrust-rogue    # zero-trust agent -> rogue : rejected
#   ./run-scenario.sh zerotrust-legit    # zero-trust agent -> legit : real file
#
# Optional: GUARDRAIL=on ./run-scenario.sh ... adds the content-inspection
# layer on top of the identity layer.
set -euo pipefail

SC="${1:-}"
TD="mcp.gcp.lab"
NS="mcp-lab"
EXPECTED_ID="spiffe://${TD}/network-config"

case "${SC}" in
  naive-rogue)
    TRUST_MODE="naive";     ENDPOINT="https://rogue.${NS}.svc.cluster.local:8443" ;;
  zerotrust-rogue)
    TRUST_MODE="zerotrust"; ENDPOINT="https://rogue.${NS}.svc.cluster.local:8443" ;;
  zerotrust-legit)
    TRUST_MODE="zerotrust"; ENDPOINT="https://network-config.${NS}.svc.cluster.local:8443" ;;
  *)
    echo "usage: $0 naive-rogue|zerotrust-rogue|zerotrust-legit" >&2; exit 2 ;;
esac

JOB="agent-${SC}"
kubectl -n "${NS}" delete job "${JOB}" --ignore-not-found --wait=true >/dev/null

kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: ${JOB}
  namespace: ${NS}
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 3600
  template:
    metadata:
      labels:
        app: agent
    spec:
      serviceAccountName: sa-agent
      restartPolicy: Never
      containers:
        - name: agent
          image: mcp-rogue-lab:local
          imagePullPolicy: Never
          command: ["/usr/local/bin/agent"]
          env:
            - name: TRUST_MODE
              value: "${TRUST_MODE}"
            - name: MCP_ENDPOINT
              value: "${ENDPOINT}"
            - name: MCP_EXPECTED_ID
              value: "${EXPECTED_ID}"
            - name: SPIFFE_ENDPOINT_SOCKET
              value: "unix:///spiffe/api.sock"
            - name: GUARDRAIL
              value: "${GUARDRAIL:-off}"
          volumeMounts:
            - name: spiffe
              mountPath: /spiffe
              readOnly: true
      volumes:
        - name: spiffe
          hostPath:
            path: /run/spire/sockets
            type: Directory
EOF

echo ">> Waiting for the agent to finish..."
phase=""
for _ in $(seq 60); do
  phase="$(kubectl -n "${NS}" get pods -l "job-name=${JOB}" \
           -o jsonpath='{.items[0].status.phase}' 2>/dev/null || true)"
  [[ "${phase}" == "Succeeded" || "${phase}" == "Failed" ]] && break
  sleep 2
done

echo
echo "=== agent logs (${SC}) ==="
kubectl -n "${NS}" logs "job/${JOB}" || true
echo "==========================="
echo

case "${SC}" in
  naive-rogue)
    echo ">> Agent robbed. The rogue's side of the story:"
    kubectl -n "${NS}" logs deploy/rogue --tail=3 ;;
  zerotrust-rogue)
    if [[ "${phase}" == "Failed" ]]; then
      echo ">> Pod status: Failed — the handshake was refused because the rogue"
      echo "   holds no SVID. The failure IS the successful defence."
    fi ;;
  zerotrust-legit)
    echo ">> Identity proven (${EXPECTED_ID}) — the real router.conf came back." ;;
esac
