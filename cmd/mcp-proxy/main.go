// Command mcp-proxy fronts a third-party MCP server with the locks this
// repository builds, without touching that server's source. It is the generic
// form of what cmd/mcp-observability does for a bridge we wrote ourselves.
//
// # Two transports
//
// Network sidecar (the default): the deployment shape it assumes:
//
//	┌── pod ───────────────────────────────────────────────┐
//	│  mcp-proxy   :8443  identity per IDENTITY_MODE       │
//	│      │                                               │
//	│      ▼                                               │
//	│  upstream    127.0.0.1:8080  vendor MCP server,      │
//	│                              bound to loopback       │
//	└──────────────────────────────────────────────────────┘
//
// Two placement rules decide whether this is a control or a decoration, and
// neither is enforceable from inside the process:
//
//	the upstream binds loopback only, or a caller reaches it directly;
//	the pod carries a default-deny egress policy, or the upstream exfiltrates
//	on its own and never needs a caller.
//
// Stdio wrapper (-stdio): the desktop shape — Claude Desktop, an IDE, a local
// CLI — where the MCP server is a subprocess and there is no network to put a
// handshake on. In the host's config, wrap the server:
//
//	mcp-proxy -stdio -- npx some-vendor-mcp-server --flag
//
// Lock 0 has no meaning across an OS pipe; what replaces it is supply-chain
// integrity: UPSTREAM_SHA256 pins the binary's hash before it is spawned.
//
// # Identity modes (network transport)
//
//	IDENTITY_MODE=spiffe  (default) this process terminates mTLS against a
//	                      SPIRE-issued SVID — the original design;
//	IDENTITY_MODE=mesh    an Istio/Envoy sidecar already ran SPIFFE mTLS and
//	                      asserts the peer in X-Forwarded-Client-Cert; the
//	                      proxy verifies the assertion against the same
//	                      AUTHORIZED_CLIENT_IDS allowlist. No SPIRE needed
//	                      beyond the one the mesh already runs;
//	IDENTITY_MODE=none    plain listener, identity explicitly waived. For
//	                      development only; the log says so on every start.
//
// Configuration is by environment and fails closed when unset: no identity,
// no listener; no ALLOWED_TOOLS, no tool call; no approver, no write; no
// RESOURCE_URIS, no resources/read; no ALLOWED_PROMPTS, no prompts/get.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"mcprogue/internal/approval"
	"mcprogue/internal/identity"
	"mcprogue/internal/labconfig"
	"mcprogue/internal/proxy"
	"mcprogue/internal/toolpin"
	"mcprogue/internal/toolpolicy"
)

func main() {
	stdio := flag.Bool("stdio", false, "wrap a stdio MCP server subprocess: mcp-proxy -stdio -- command [args...]")
	flag.Parse()

	ctx := context.Background()
	logf := log.Printf

	cfg := proxy.Config{
		Grants:                 mustGrants(),
		HideUngrantedTools:     true,
		AllowedMethods:         proxy.SplitList(labconfig.Env("ALLOWED_METHODS", "")),
		ResourceURIs:           proxy.SplitList(labconfig.Env("RESOURCE_URIS", "")),
		AllowedPrompts:         proxy.SplitList(labconfig.Env("ALLOWED_PROMPTS", "")),
		AllowServerSampling:    labconfig.Env("ALLOW_SERVER_SAMPLING", "") == "true",
		AllowServerElicitation: labconfig.Env("ALLOW_SERVER_ELICITATION", "") == "true",
	}

	// Rug-pull lock: pin the upstream's tool schemas.
	if path := labconfig.Env("TOOLS_LOCK_FILE", ""); path != "" {
		lock, err := toolpin.Open(path)
		if err != nil {
			log.Fatalf("mcp-proxy: %v", err)
		}
		cfg.ToolLock = lock
		if !lock.TrustOnFirstUse() {
			logf("mcp-proxy: tool schemas pinned from %s: %v", path, lock.Names())
		}
	} else {
		logf("mcp-proxy: WARNING — TOOLS_LOCK_FILE not set; tool schema drift (rug-pull) is not detected")
	}

	// Human-in-the-loop: build the approver chain and its audit trail.
	audit := buildAudit(logf)
	if approver := buildApprovers(logf); approver != nil {
		cfg.Approver = approval.ToToolPolicy(approver, audit, logf)
	}

	if *stdio {
		runStdio(ctx, cfg, flag.Args(), logf)
		return
	}
	runHTTP(ctx, cfg, logf)
}

// ---------------------------------------------------------------------------
// Transports
// ---------------------------------------------------------------------------

func runStdio(ctx context.Context, cfg proxy.Config, argv []string, logf func(string, ...any)) {
	// The audit and diagnostics must not pollute the protocol channel:
	// stdout carries JSON-RPC, everything else goes to stderr (log's default).
	log.SetOutput(os.Stderr)
	logf("mcp-proxy: stdio transport — lock 0 (network identity) does not apply; the OS process boundary is the identity and UPSTREAM_SHA256 pins the binary")

	p, err := proxy.NewStdio(cfg)
	if err != nil {
		log.Fatalf("mcp-proxy: %v", err)
	}
	if err := p.ServeStdio(ctx, argv, labconfig.Env("UPSTREAM_SHA256", "")); err != nil {
		log.Fatalf("mcp-proxy: %v", err)
	}
}

func runHTTP(ctx context.Context, cfg proxy.Config, logf func(string, ...any)) {
	cfg.Upstream = labconfig.Env("UPSTREAM_URL", "")
	p, err := proxy.New(cfg)
	if err != nil {
		log.Fatalf("mcp-proxy: %v", err)
	}

	// Lock 0, behind the Verifier seam: who proves the caller's identity
	// depends on the deployment, that somebody must is not negotiable.
	verifier := buildVerifier(ctx)
	defer verifier.Close()

	handler := withIdentity(verifier, p, logf)

	addr := labconfig.Env("LISTEN_ADDR", ":8443")
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	logf("mcp-proxy: fronting %s on %s (identity mode %q)", cfg.Upstream, addr, verifier.Name())
	logf("mcp-proxy: granted tools: %v", cfg.Grants)

	if tlsCfg := verifier.ServerTLS(); tlsCfg != nil {
		srv.TLSConfig = tlsCfg
		// Empty certificate paths: the certificate comes from the SVID, which
		// SPIRE rotates hourly. Nothing on disk, nothing to expire.
		err = srv.ListenAndServeTLS("", "")
	} else {
		err = srv.ListenAndServe()
	}
	if err != nil {
		log.Fatalf("mcp-proxy: %v", err)
	}
}

// withIdentity refuses any request the verifier cannot attribute. In SPIFFE
// mode the handshake already authorized the peer and this only names it for
// the audit line; in mesh mode this IS the authorization.
func withIdentity(v identity.Verifier, next http.Handler, logf func(string, ...any)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, err := v.Peer(r)
		if err != nil {
			logf("mcp-proxy: caller REFUSED by %s identity verifier: %v", v.Name(), err)
			http.Error(w, "mcp-proxy: caller identity not verified", http.StatusForbidden)
			return
		}
		r.Header.Set("X-MCP-Proxy-Peer", peer)
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// Identity wiring
// ---------------------------------------------------------------------------

func buildVerifier(ctx context.Context) identity.Verifier {
	clientIDs := proxy.SplitList(labconfig.Env("AUTHORIZED_CLIENT_IDS", ""))
	mode := labconfig.Env("IDENTITY_MODE", "spiffe")
	switch mode {
	case "spiffe":
		src, err := identity.NewSource(ctx, workloadSocket())
		if err != nil {
			log.Fatalf("mcp-proxy: no workload identity (is the SPIRE agent up and this workload registered?): %v", err)
		}
		// OnlyIDs, not MemberOf: "attested by our SPIRE" is a property every
		// workload has, including a compromised one.
		v, err := identity.NewSPIFFEVerifier(src, clientIDs...)
		if err != nil {
			log.Fatalf("mcp-proxy: %v", err)
		}
		log.Printf("mcp-proxy: authorized callers: %s", strings.Join(clientIDs, ", "))
		return v
	case "mesh":
		v, err := identity.NewMeshVerifier(clientIDs...)
		if err != nil {
			log.Fatalf("mcp-proxy: %v", err)
		}
		log.Printf("mcp-proxy: trusting the service mesh for mTLS; enforcing XFCC peer against: %s", strings.Join(clientIDs, ", "))
		log.Printf("mcp-proxy: mesh mode is sound ONLY if this port is reachable through the sidecar alone (mesh AuthorizationPolicy) and the mesh sets forwardClientCertDetails")
		return v
	case "none":
		log.Printf("mcp-proxy: WARNING — IDENTITY_MODE=none: any caller that can reach this port is accepted. Development only.")
		return identity.LocalVerifier{}
	default:
		log.Fatalf("mcp-proxy: unknown IDENTITY_MODE %q (want spiffe, mesh or none)", mode)
		return nil
	}
}

// workloadSocket resolves the SPIRE agent socket. SPIRE_AGENT_SOCKET is this
// component's documented name; SPIFFE_ENDPOINT_SOCKET is the standard
// go-spiffe variable the rest of the repository sets, honoured as a fallback.
//
// A bare path becomes a unix:// URI, which is what the Workload API expects.
func workloadSocket() string {
	s := os.Getenv("SPIRE_AGENT_SOCKET")
	if s == "" {
		s = os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	}
	if s == "" {
		s = "/run/spire/sockets/agent.sock"
	}
	if strings.Contains(s, "://") {
		return s
	}
	return "unix://" + s
}

// ---------------------------------------------------------------------------
// Approval wiring
// ---------------------------------------------------------------------------

func mustGrants() toolpolicy.Grants {
	g, err := proxy.ParseGrants(labconfig.Env("ALLOWED_TOOLS", ""))
	if err != nil {
		log.Fatalf("mcp-proxy: %v", err)
	}
	return g
}

// buildApprovers assembles the human-in-the-loop chain from the environment.
// Nil (nothing configured) leaves the proxy read-only by construction.
func buildApprovers(logf func(string, ...any)) approval.Approver {
	var chain []approval.Approver

	if spec := labconfig.Env("APPROVED_ACTIONS", ""); spec != "" {
		fn, err := proxy.ApproverFromSpec(spec)
		if err != nil {
			log.Fatalf("mcp-proxy: %v", err)
		}
		logf("mcp-proxy: static allowlist armed from APPROVED_ACTIONS: %s — note this is a deploy-time allowlist, not a live human approval; add APPROVAL_WEBHOOK_URL or an approval token key for real HITL", spec)
		chain = append(chain, approval.FromToolPolicy("static-allowlist", "APPROVED_ACTIONS@deploy", fn))
	}
	if url := labconfig.Env("APPROVAL_WEBHOOK_URL", ""); url != "" {
		timeout, err := time.ParseDuration(labconfig.Env("APPROVAL_WEBHOOK_TIMEOUT", "120s"))
		if err != nil {
			log.Fatalf("mcp-proxy: APPROVAL_WEBHOOK_TIMEOUT: %v", err)
		}
		logf("mcp-proxy: webhook approver armed: %s (timeout %s)", url, timeout)
		chain = append(chain, &approval.Webhook{URL: url, Timeout: timeout})
	}
	if key := loadTokenKey(); key != nil {
		maxTTL, err := time.ParseDuration(labconfig.Env("APPROVAL_JWT_MAX_TTL", approval.DefaultMaxTTL.String()))
		if err != nil {
			log.Fatalf("mcp-proxy: APPROVAL_JWT_MAX_TTL: %v", err)
		}
		logf("mcp-proxy: approval token verifier armed (max TTL %s): actions may carry an operator JWT in _meta.approvalToken", maxTTL)
		chain = append(chain, &approval.Token{
			Key:    key,
			MaxTTL: maxTTL,
			Issuer: labconfig.Env("APPROVAL_JWT_ISSUER", ""),
		})
	}

	if len(chain) == 0 {
		return nil
	}
	approver, err := approval.AnyOf(chain...)
	if err != nil {
		log.Fatalf("mcp-proxy: %v", err)
	}
	return approver
}

// loadTokenKey reads the approval-token verification key:
// APPROVAL_JWT_KEY_FILE (a PEM public key, from the operators' SSO/OIDC
// signer) or APPROVAL_JWT_HMAC_FILE (a shared secret, the lab shape).
func loadTokenKey() any {
	if path := labconfig.Env("APPROVAL_JWT_KEY_FILE", ""); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("mcp-proxy: read APPROVAL_JWT_KEY_FILE: %v", err)
		}
		block, _ := pem.Decode(b)
		if block == nil {
			log.Fatalf("mcp-proxy: APPROVAL_JWT_KEY_FILE %s holds no PEM block", path)
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			log.Fatalf("mcp-proxy: parse APPROVAL_JWT_KEY_FILE: %v", err)
		}
		switch pub.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
			return pub
		default:
			log.Fatalf("mcp-proxy: APPROVAL_JWT_KEY_FILE holds an unsupported key type %T", pub)
		}
	}
	if path := labconfig.Env("APPROVAL_JWT_HMAC_FILE", ""); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("mcp-proxy: read APPROVAL_JWT_HMAC_FILE: %v", err)
		}
		if len(b) < 32 {
			log.Fatalf("mcp-proxy: APPROVAL_JWT_HMAC_FILE holds %d bytes; an HMAC key shorter than 32 bytes is guessable", len(b))
		}
		return []byte(strings.TrimSpace(string(b)))
	}
	return nil
}

// buildAudit opens the signed approval trail. Unset means decisions appear
// only in the process log — allowed, but the operator is told.
func buildAudit(logf func(string, ...any)) *approval.Audit {
	path := labconfig.Env("AUDIT_LOG_FILE", "")
	if path == "" {
		logf("mcp-proxy: AUDIT_LOG_FILE not set; approval decisions are not persisted to a tamper-evident trail")
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		log.Fatalf("mcp-proxy: open AUDIT_LOG_FILE: %v", err)
	}
	var key []byte
	if keyPath := labconfig.Env("AUDIT_HMAC_KEY_FILE", ""); keyPath != "" {
		key, err = os.ReadFile(keyPath)
		if err != nil {
			log.Fatalf("mcp-proxy: read AUDIT_HMAC_KEY_FILE: %v", err)
		}
	} else {
		logf("mcp-proxy: AUDIT_HMAC_KEY_FILE not set; the audit chain is integrity-only (tamper-evident, not tamper-proof)")
	}
	logf("mcp-proxy: approval audit trail: %s", path)
	return approval.NewAudit(f, key)
}
