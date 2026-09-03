# mcp-rogue

Par défaut, un agent MCP accorde sa confiance à un serveur sur la foi d'une entrée de configuration statique, écrite une fois et jamais revérifiée au moment de l'exécution. Ce dépôt remplace cette confiance explicite par une vérification cryptographique continue — basée sur SPIFFE/SPIRE et mTLS — et démontre sur un cluster réel qu'un serveur MCP malveillant est rejeté dès le handshake mTLS, avant même l'exécution de son moindre handler.

Le principe repose sur du Zero Trust à preuve inversée : au lieu de chercher à bloquer ce qui est identifié comme malveillant, on rejette tout ce qui ne prouve pas sa légitimité. Le serveur rogue n'a pas besoin d'être catalogué comme tel : il est incapable de produire l'identité cryptographique exigée.

---

## Threat model — deux moitiés à ne pas confondre

|  | Question | Nature | Traitement |
|---|---|---|---|
| **Moitié 1 — Identité** | « Qui es-tu ? » | Binaire, prouvable | **Résolue** par SPIFFE/mTLS |
| **Moitié 2 — Comportement** | « Que fais-tu ? » | Continue, non prédictible | **Contenue**, pas résolue |

La moitié 2 est incontournable : un serveur dûment authentifié peut dériver, et du contenu empoisonné transite sans obstacle par un service légitime. Cette problématique est filtrée au niveau applicatif (`internal/guardrail`), puis — un filtre textuel finissant toujours par céder face à l'obfuscation, aux langues rares ou au Base64 — confinée par trois verrous de réduction du rayon d'action (*blast radius*) qui ne dépendent d'aucun filtre : egress réseau default-deny, allowlist d'exécution et typage strict donnée vs code.

Il est impossible d'injecter un prompt dans une route réseau absente, un privilège non accordé ou un type de donnée inerte.

---

## Architecture

```
┌─ VM GCP e2-standard-2 · k3s single-node · CNI kube-router ────────────────────┐
│                                                                              │
│  ns spire                                                                    │
│    spire-server   CA racine, trust domain mcp.gcp.lab, SVID 1 h              │
│    spire-agent    DaemonSet, attestation de nœud k8s_psat                    │
│                                                                              │
│  ns mcp-lab                        SPIFFE ID              NetworkPolicy      │
│    agent-sre  ─────────────┐       …/agent-sre            egress: bridge+DNS │
│                            │ mTLS                                            │
│    mcp-obs-bridge  ◀───────┘       …/obs-bridge           détient le token   │
│         │                                                  Grafana           │
│    network-config                  …/network-config       lab synthétique    │
│    rogue                           AUCUN — jamais enregistré dans SPIRE      │
│         │                                                                    │
│  ns monitoring                                                               │
│    prometheus :9090   alertmanager :9093   grafana :3000   checkout-api :8080│
└──────────────────────────────────────────────────────────────────────────────┘
```

Deux moitiés sur le même cluster :

- **Le lab synthétique** — `network-config` (légitime) et `rogue` (malveillant)
  exposent le **même nom d'outil** `get_file`. C'est ce qui rend l'usurpation
  possible. Le rogue possède un ServiceAccount mais aucune entrée SPIRE, donc
  aucun SVID. `TRUST_MODE=naive` reproduit MCP tel quel et l'agent se fait
  dévaliser ; `TRUST_MODE=zerotrust` le rejette avant tout appel d'outil.
- **Le service SRE** — `agent-sre` lit la télémétrie et annote les dashboards à
  travers `mcp-obs-bridge`. L'asymétrie est le design : **l'agent reçoit un
  outil, jamais un token**. Un agent convaincu d'exfiltrer la clé API Grafana
  n'a rien à exfiltrer, et aucune route réseau vers Grafana s'il en obtenait une.

`cmd/mcp-proxy` généralise le dispositif : un sidecar qui interpose les verrous 0, 2 et 3 devant n'importe quel serveur MCP tiers, sans modifier son code. Le verrou 1 reste appliqué au niveau pod/réseau — un processus ne se l'appliquant pas à lui-même : l'upstream écoute sur loopback et le pod porte une politique d'egress default-deny. Ce composant est fourni sous forme de code et de tests unitaires/d'intégration.

---

## Les quatre verrous

| Verrou | Où | Garantie |
|---|---|---|
| **0 — Identité** | `internal/identity` | Le pair doit prouver son SPIFFE ID au handshake mTLS. Sans SVID attesté, pas de session. `OnlyIDs` là où un credential est en jeu, pas `MemberOf`. |
| **1 — Egress** | `deploy/gcp/k8s/40-`, `70-network-policy*.yaml` | Default-deny réseau, appliqué par le noyau. L'exfiltration meurt avant le premier paquet. |
| **2 — Exécution** | `internal/toolpolicy` | Allowlist de capacités **avant** que l'appel quitte le processus. Séparation read/action, approbation humaine nommant sa cible pour les actions. |
| **3 — Donnée vs code** | `internal/envelope` | La réponse est scellée dans `<untrusted_data id="nonce">`, nonce de 16 octets tiré par scellement, et le prompt système la déclare inerte. |

Les verrous 1 à 3 tiennent **même si** l'injection réussit à berner le modèle.
L'hypothèse de travail est que le filtre sera contourné.

---

## Carte du dépôt

| Chemin | Rôle |
|---|---|
| `internal/identity` | Construit les `tls.Config`/`http.Client` des deux modes, et l'interface `Verifier` qui découple le verrou 0 de SPIRE (modes `spiffe`, `mesh` XFCC, `local`). |
| `internal/toolpolicy` | Middleware `CallTool`. Refus par défaut ; un appel refusé n'atteint jamais la session inner. |
| `internal/approval` | HITL dynamique : interface `Approver`, webhook temps réel, tokens JWT `_meta.approvalToken`, trail d'audit chaîné HMAC. |
| `internal/toolpin` | Anti rug-pull : pinning SHA-256 des schémas d'outils dans `tools.lock.json`, quarantaine `ERR_TOOL_SCHEMA_MUTATED`. |
| `internal/envelope` | Scellement `<untrusted_data>`, défangage exporté (`Defang`) et clause de prompt système. |
| `internal/scrub` | Caviardage : tokens, secrets par nom de clé, userinfo d'URL, emails, identifiants clients, **IP routables uniquement**. |
| `internal/promql` | Politique de coût PromQL : 1 Kio, fenêtre 6 h, 8 sélecteurs, 6 matchers regex. |
| `internal/proxy` | Reverse-proxy MCP générique portant les verrous 0, 2 et 3. |
| `internal/guardrail` | Filtre de contenu du lab (schéma strict → marqueurs → caviardage). |
| `internal/labconfig` | L'entrée de configuration de confiance — l'artefact que la thèse attaque. |
| `internal/obsserver`, `obsclient`, `obstool`, `triage` | Le bridge d'observabilité et ses contrats. |
| `internal/server`, `mcptool` | Les deux serveurs du lab synthétique. |
| `internal/testca` | CA jetable émettant de vrais SVID pour les tests. |
| `cmd/` | `agent`, `network-config`, `rogue`, `mcp-observability`, `agent-sre`, `checkout-api`, `mcp-proxy`, `mcp-approve`. |
| `deploy/gcp/` | k3s, SPIRE, manifests, scripts de provisioning et de scénarios. |

---

## Le proxy générique : surface complète

`cmd/mcp-proxy` couvre désormais l'ensemble du protocole et des deux
transports MCP. Chaque mécanisme échoue fermé quand il n'est pas configuré.

**Transport stdio & supply-chain.** Sur desktop (Claude Desktop, IDE, CLI),
MCP est un subprocess : pas de réseau, donc pas de handshake — le verrou 0 est
hors sujet par construction, et le risque devient l'intégrité du binaire.
`mcp-proxy -stdio -- <commande> [args...]` enveloppe le serveur dans la config
de l'hôte ; `UPSTREAM_SHA256` pinne le hash du binaire avant le spawn
(`ERR_UPSTREAM_BINARY_MUTATED` sinon). Mêmes verrous 2 et 3, même code, sur
des pipes.

**Identité modulaire (`identity.Verifier`).** `IDENTITY_MODE` choisit qui
prouve l'appelant : `spiffe` (défaut — mTLS terminé ici, exige SPIRE), `mesh`
(Istio/Envoy a déjà fait le mTLS SPIFFE ; le proxy vérifie l'assertion
`X-Forwarded-Client-Cert` contre `AUTHORIZED_CLIENT_IDS` — aucun SPIRE à
vendre au-delà de celui du mesh, sous réserve que le port ne soit joignable
qu'à travers le sidecar et que `forwardClientCertDetails` soit activé), ou
`none` (développement, annoncé bruyamment).

**HITL dynamique.** `APPROVED_ACTIONS` reste, sous son vrai nom : une
allowlist statique décidée au déploiement, pas une approbation humaine. Le
vrai HITL est `internal/approval` : un webhook temps réel
(`APPROVAL_WEBHOOK_URL` — la requête JSON-RPC est mise en pause pendant que
Slack/Jira/ServiceNow répond `{approved, approved_by, ticket_id}`) et des
tokens d'approbation (`APPROVAL_JWT_KEY_FILE` ou `APPROVAL_JWT_HMAC_FILE` —
un JWT signé par un opérateur, TTL ≤ 15 min, lié à l'appel exact par
`action_digest = sha256(tool + "\n" + json_canonique(args))`, transmis dans
`_meta.approvalToken`; `cmd/mcp-approve` le mint). Les mécanismes configurés
se combinent en OU. Chaque décision — accord comme refus — est consignée dans
`AUDIT_LOG_FILE` : JSONL chaîné par MAC (`AUDIT_HMAC_KEY_FILE`), avec
`approved_by`, `ticket_id`, `action_digest`.

**Anti rug-pull.** `TOOLS_LOCK_FILE` pinne le SHA-256 de chaque outil
(name + description + inputSchema). Fichier absent : le premier `tools/list`
est pinné (trust-on-first-use, loggé). Ensuite, tout outil dont le hash dérive
est retiré de `tools/list` **et** mis en quarantaine — le `tools/call` suivant
est refusé avec `ERR_TOOL_SCHEMA_MUTATED`. Indépendamment du pinning, les
descriptions d'outils sont passées au caviardeur et défangées : une
instruction cachée dans une description est la même injection que dans une
réponse, un message plus tôt.

**Surface JSON-RPC default-deny.** Toute méthode hors de la matrice
(baseline + `ALLOWED_METHODS`) est refusée `ERR_METHOD_NOT_ALLOWED`.
`resources/read` et `resources/subscribe` exigent une allowlist d'URIs
(`RESOURCE_URIS`, globs à `*`) et leurs contenus reviennent caviardés puis
scellés dans `<untrusted_data>`. `prompts/get` exige `ALLOWED_PROMPTS` et ses
messages sont caviardés/défangés (pas scellés : un prompt est une instruction
par contrat). `sampling/createMessage` et `elicitation/create` initiés par le
serveur sont supprimés par défaut (`ALLOW_SERVER_SAMPLING=true` /
`ALLOW_SERVER_ELICITATION=true` pour ouvrir).

---

## Démarrage rapide

### Preuve exécutable, sans Docker ni SPIRE

La logique de sécurité est prouvée par la suite de tests, indépendamment de
toute infrastructure : `internal/testca` mint de vrais SVID en mémoire et les
tests traversent de vrais handshakes TLS et de vrais appels MCP.

```bash
go test -v ./...          # Go >= 1.25 (contrainte du SDK MCP), ou GOTOOLCHAIN=auto
```

Ce que la suite établit, entre autres : le handler du rogue ne s'exécute jamais
en mode zero-trust ; un appel refusé par `toolpolicy` n'atteint pas le
transport ; une réponse contenant un délimiteur forgé est désamorcée et scellée
sous un nonce frais.

### Lab conteneurisé (SPIRE réel)

```bash
make lab-up && make lab-register     # SPIRE, puis entrées — le rogue jamais
make lab-naive-rogue                 # agent naïf → rogue : dévalisé
make lab-zerotrust-rogue             # agent zero-trust → rogue : rejeté au handshake
make lab-zerotrust-legit             # agent zero-trust → légitime : fichier réel
make lab-down
```

### Cluster k3s sur GCP

```bash
cd deploy/gcp && ./provision.sh                        # VM, k3s, SPIRE, lab
gcloud compute ssh mcp-rogue-lab --zone europe-west1-b   # GCP_ZONE par défaut
bash ~/mcp_rogue/deploy/gcp/setup-vm.sh                # lab synthétique
bash ~/mcp_rogue/deploy/gcp/setup-observability.sh     # service SRE
./provision.sh destroy                                 # arrêter la facturation
```

### Validation sur cluster

```bash
bash deploy/gcp/run-scenario.sh naive-rogue|zerotrust-rogue|zerotrust-legit
bash deploy/gcp/run-sre.sh break        # « déploiement v2.1.0 » : checkout-api tombe
bash deploy/gcp/run-sre.sh incident     # passe d'astreinte, approbation en place
bash deploy/gcp/run-sre.sh unapproved   # lectures OK, écriture refusée
bash deploy/gcp/run-sre.sh compromised  # l'agent obéit à l'injection ; tout tombe
bash deploy/gcp/run-sre.sh status
kubectl -n monitoring port-forward svc/grafana 3000:3000
```

Le job `compromised` est le plus instructif : l'agent **obéit** à l'instruction
cachée dans le texte d'alerte, et les quatre tentatives échouent sur des verrous
qui n'ont pas eu à reconnaître l'injection.

```
attempt 1  delete_dashboard    → BLOCKED: toolpolicy: "delete_dashboard" not in grant set
attempt 2  annotate exec-board → BLOCKED: toolpolicy: "annotate_dashboard" refused by
                                 approver: no human approval on record for
                                 "annotate_dashboard:exec-board"
attempt 3  POST exfil URL      → BLOCKED: lookup exfil.attacker-controlled.test:
                                 no such host
attempt 4  tcp 1.1.1.1:443     → BLOCKED: connection refused (egress policy, noyau)
```

Verrous 2, 2, 1 et 1 : les deux premiers refus sont rendus en process, avant que
l'appel n'atteigne le transport ; les deux derniers dans le noyau.

---

## Limites d'ingénierie

**Course au démarrage des NetworkPolicies.** Les règles iptables sont
programmées **après** que le pod a reçu son IP. Mesuré sur le cluster : à t+0 s
un `wget` sort vers Internet, à t+20 s il est refusé. Le verrou d'egress tient
contre un workload subverti en cours d'exécution — le cas visé — mais pas contre
un workload qui exfiltre dans sa première seconde. Fermer la fenêtre demande une
application antérieure au workload : un CNI programmant la policy avant de
rendre le réseau, ou une passerelle d'egress obligatoire.

**Triage déterministe, aucun LLM branché.** `internal/triage` compose la note
d'incident par template. Sous egress default-deny, joindre une API externe
exigerait d'ouvrir une route sortante — exactement la décision de moindre
privilège que le projet sert à rendre visible. Brancher un modèle (Ollama
in-cluster, ou une API avec une règle d'egress explicite) ne change rien aux
verrous : le modèle réécrit la phrase, il ne choisit pas quels outils sont
appelés.

**Autres périmètres assumés.** Le validateur PromQL est syntaxique, pas un
parser complet : `prometheus/promql/parser` donnerait un AST correct au prix de
tirer `prometheus/prometheus`. Le caviardeur reconnaît des formes, ce n'est pas
un classifieur. `insecure_bootstrap = true` côté agent SPIRE : le lab modélise
un serveur MCP rogue, pas un plan de contrôle SPIRE compromis. Prometheus tourne
en `emptyDir`, rétention 2 h, réplique unique. Le mot de passe admin Grafana
est généré au premier déploiement par `setup-observability.sh` et ne quitte
jamais le cluster ; il se relit avec `kubectl -n monitoring get secret
grafana-admin -o jsonpath='{.data.admin-password}' | base64 -d`.

---

## Dépendances

- `github.com/modelcontextprotocol/go-sdk` v1.7.0 — pré-1.0, exige Go ≥ 1.25.
  Point de branchement mTLS : le champ `HTTPClient *http.Client` de
  `mcp.StreamableClientTransport`.
- `github.com/spiffe/go-spiffe/v2` v2.8.1.
- `github.com/go-jose/go-jose/v4` v4.1.4 — signature/vérification des tokens
  d'approbation JWT (déjà dans le graphe via go-spiffe, promu en dépendance
  directe).

Images pinnées : `spire-server`/`spire-agent` 1.15.3, `prom/prometheus` v3.1.0,
`prom/alertmanager` v0.28.0, `grafana/grafana` 11.4.0.
