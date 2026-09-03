# Déploiement GCP — k3s single-node

Le lab entier tourne sur **une seule VM Compute Engine** (e2-standard-2,
Ubuntu 24.04) : cluster k3s single-node, SPIRE, et les trois conteneurs.

```
+------------------------------------------------------------------------------+
| GCP Compute Engine (Ubuntu 24.04 / e2-standard-2)                            |
|                                                                              |
|  +------------------------------------------------------------------------+  |
|  | Cluster k3s (single-node)                                              |  |
|  |                                                                        |  |
|  |  Namespace: spire                                                      |  |
|  |  ├── spire-server   (CA racine — trust domain mcp.gcp.lab)             |  |
|  |  └── spire-agent    (DaemonSet, attestation k8s_psat + kubelet)        |  |
|  |                                                                        |  |
|  |  Namespace: mcp-lab                                                    |  |
|  |  ├── agent          (Job à la demande, SA sa-agent)     → SVID délivré |  |
|  |  ├── network-config (Deployment,       SA sa-legit)     → SVID délivré |  |
|  |  ├── rogue          (Deployment,       SA sa-rogue)     → AUCUN SVID   |  |
|  |  ├── mcp-obs-bridge (Deployment,       SA sa-mcp-obs)   → SVID délivré |  |
|  |  └── agent-sre      (Job à la demande, SA sa-sre-agent) → SVID délivré |  |
|  |                                                                        |  |
|  |  Namespace: monitoring                                                 |  |
|  |  ├── prometheus + alertmanager   (métriques et alertes)                |  |
|  |  ├── grafana                     (dashboards + annotations)            |  |
|  |  └── checkout-api                (le service qu'on casse à la demande) |  |
|  +------------------------------------------------------------------------+  |
+------------------------------------------------------------------------------+
```

Deux moitiés sur le même cluster : le **lab synthétique** (agent /
network-config / rogue) qui prouve la thèse d'identité, et le **service SRE**
(agent-sre / mcp-obs-bridge / monitoring) qui porte les mêmes verrous sur un
cas de production. Voir la section « Du lab au service » du README racine.

## Ce qui change par rapport au lab docker-compose

| | docker-compose | k3s / GCP |
|---|---|---|
| Trust domain | `mcp.lab` | `mcp.gcp.lab` |
| Attestation du nœud | join token généré à la main | `k8s_psat` — token de ServiceAccount projeté, vérifié par l'API k8s |
| Attestation des workloads | label Docker (`docker:label:...`) | ServiceAccount k8s (`k8s:ns:mcp-lab` + `k8s:sa:...`) |
| Socket Workload API | volume Docker partagé | hostPath `/run/spire/sockets` monté en lecture seule |

L'invariant, lui, ne change pas : **le rogue a un ServiceAccount (`sa-rogue`)
mais aucune entrée SPIRE ne le référence** — il ne peut donc jamais obtenir de
SVID, et le mode zero-trust le rejette au handshake.

## Déployer

Prérequis : `gcloud` authentifié, un projet avec Compute Engine activé.

```bash
cd deploy/gcp
./provision.sh          # crée la VM, copie le repo, installe k3s+SPIRE+lab
```

Puis les trois scénarios (via SSH sur la VM) :

```bash
gcloud compute ssh mcp-rogue-lab --zone europe-west1-b
bash ~/mcp_rogue/deploy/gcp/run-scenario.sh naive-rogue      # agent naïf -> rogue : dévalisé
bash ~/mcp_rogue/deploy/gcp/run-scenario.sh zerotrust-rogue  # zero-trust -> rogue : rejeté au handshake
bash ~/mcp_rogue/deploy/gcp/run-scenario.sh zerotrust-legit  # zero-trust -> légitime : vrai fichier
```

### Le service SRE / Observabilité

Après `provision.sh`, sur la VM :

```bash
bash ~/mcp_rogue/deploy/gcp/setup-observability.sh   # monitoring + bridge + policies

bash ~/mcp_rogue/deploy/gcp/run-sre.sh break         # "déploiement v2.1.0" : les 5xx montent
# attendre ~2 min que la règle HighErrorRate passe firing
bash ~/mcp_rogue/deploy/gcp/run-sre.sh incident      # l'agent enquête et annote (approuvé)
bash ~/mcp_rogue/deploy/gcp/run-sre.sh unapproved    # sans approbation : lectures OK, écriture refusée
bash ~/mcp_rogue/deploy/gcp/run-sre.sh compromised   # l'agent obéit à l'injection plantée dans l'alerte
bash ~/mcp_rogue/deploy/gcp/run-sre.sh status        # alertes, ratio, journal d'audit du bridge
bash ~/mcp_rogue/deploy/gcp/run-sre.sh heal
```

Voir les dashboards et les annotations posées par l'agent :

```bash
kubectl -n monitoring port-forward svc/grafana 3000:3000
# http://localhost:3000 — user « admin », dashboard « API Gateway »
# mot de passe (généré au premier déploiement) :
#   kubectl -n monitoring get secret grafana-admin \
#     -o jsonpath='{.data.admin-password}' | base64 -d
```

Détruire la VM (et arrêter la facturation) :

```bash
./provision.sh destroy
```

## Fichiers

- `provision.sh` — crée/détruit la VM, copie le repo, lance le setup.
- `setup-vm.sh` — sur la VM : k3s, build de l'image, SPIRE, workloads (idempotent).
- `register-entries.sh` — enregistre `network-config` et `agent` dans SPIRE ;
  n'enregistre **jamais** le rogue (c'est toute la démonstration).
- `run-scenario.sh` — lance l'agent comme Job k8s et affiche le verdict.
- `setup-observability.sh` — sur la VM, après `setup-vm.sh` : déploie la stack
  Prometheus/Alertmanager/Grafana + `checkout-api`, demande à Grafana un token
  de service-account (le bridge n'obtient jamais le mot de passe admin), crée
  les entrées SPIRE `obs-bridge` / `agent-sre`, déploie le bridge et applique
  les NetworkPolicies. Idempotent (le token est rotationné à chaque exécution).
- `run-sre.sh` — pilote l'incident : `break`, `incident`, `unapproved`,
  `compromised`, `status`, `heal`.
- `k8s/` — manifests : namespaces, SPIRE server (StatefulSet), SPIRE agent
  (DaemonSet), workloads mcp-lab (Deployments + Services + ServiceAccounts),
  NetworkPolicies default-deny (confinement du rayon d'action), stack de
  monitoring (`50-`), bridge d'observabilité (`60-`) et son confinement
  réseau (`70-`).

## Notes de sécurité (périmètre du lab)

- Aucun port du lab n'est exposé publiquement : tout le trafic MCP/mTLS reste
  interne au cluster ; seul SSH (port 22, règle par défaut du réseau) entre.
- **Egress confiné par NetworkPolicy** (`k8s/40-network-policy.yaml`) :
  default-deny sur tout `mcp-lab` ; l'agent ne joint que kube-dns et les deux
  serveurs MCP:8443, le rogue n'a aucune sortie. k3s enforce ces policies
  nativement (kube-router). Vérification une fois le lab levé (l'image du lab
  est distroless, donc on sonde avec un pod jetable portant le même label —
  il hérite des mêmes policies) :
  `kubectl -n mcp-lab run probe --rm -it --restart=Never --image=busybox:1.36
  --labels=app=rogue -- wget -T3 -qO- http://example.com` doit échouer
  (résolution ou connexion coupée par la policy).
- `insecure_bootstrap = true` côté SPIRE agent : même note de périmètre que le
  lab compose — on modélise un serveur MCP rogue, pas une compromission du
  plan de contrôle SPIRE.
- L'image applicative est buildée localement sur la VM et importée dans
  containerd (`imagePullPolicy: Never`) — pas de registry à sécuriser.
