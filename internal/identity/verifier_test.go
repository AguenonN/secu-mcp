package identity_test

import (
	"net/http/httptest"
	"strings"
	"testing"

	"mcprogue/internal/identity"
)

const meshAgentID = "spiffe://cluster.local/ns/mcp-lab/sa/agent-sre"

// Envoy's real header shape: multiple hops, quoted subjects containing the
// separators, the peer's URI in the last element.
const xfcc = `By=spiffe://cluster.local/ns/mcp-lab/sa/gateway;Hash=aaa;Subject="CN=front,O=Acme, Inc.";URI=spiffe://cluster.local/ns/edge/sa/ingress,` +
	`By=spiffe://cluster.local/ns/mcp-lab/sa/mcp-proxy;Hash=bbb;Subject="O=weird;chars";URI=` + meshAgentID

func TestPeerFromXFCC(t *testing.T) {
	got, err := identity.PeerFromXFCC(xfcc)
	if err != nil {
		t.Fatal(err)
	}
	if got != meshAgentID {
		t.Fatalf("peer = %q, want the last element's URI %q", got, meshAgentID)
	}

	if _, err := identity.PeerFromXFCC(`By=x;Hash=y`); err == nil {
		t.Fatal("an element without a URI SAN produced a peer")
	}
	if _, err := identity.PeerFromXFCC(`URI=https://not-spiffe.example`); err == nil {
		t.Fatal("a non-SPIFFE URI passed as a peer identity")
	}
}

func TestMeshVerifier_EnforcesAllowlist(t *testing.T) {
	v, err := identity.NewMeshVerifier(meshAgentID)
	if err != nil {
		t.Fatal(err)
	}

	r := httptest.NewRequest("POST", "/mcp", nil)
	r.Header.Set("X-Forwarded-Client-Cert", xfcc)
	peer, err := v.Peer(r)
	if err != nil {
		t.Fatalf("the authorized mesh peer was refused: %v", err)
	}
	if peer != meshAgentID {
		t.Fatalf("peer = %q", peer)
	}

	// No header: the sidecar is not in front, refuse.
	bare := httptest.NewRequest("POST", "/mcp", nil)
	if _, err := v.Peer(bare); err == nil {
		t.Fatal("a request without XFCC was accepted")
	}

	// A verified but unlisted workload: mesh membership is not authorization.
	other := httptest.NewRequest("POST", "/mcp", nil)
	other.Header.Set("X-Forwarded-Client-Cert", "URI=spiffe://cluster.local/ns/mcp-lab/sa/stranger")
	if _, err := v.Peer(other); err == nil {
		t.Fatal("an unlisted mesh identity was accepted")
	}

	// An empty allowlist is a configuration error, not open season.
	if _, err := identity.NewMeshVerifier(); err == nil {
		t.Fatal("a mesh verifier with no allowlist was built")
	}
	if _, err := identity.NewMeshVerifier("not-a-spiffe-id"); err == nil ||
		!strings.Contains(err.Error(), "SPIFFE") {
		t.Fatalf("a non-SPIFFE allowlist entry was accepted (err=%v)", err)
	}
}
