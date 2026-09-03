// Package e2e drives the real MCP-over-mTLS gate — the same identity.Source
// and tlsconfig path production uses — through real handshakes and real tool
// calls, with no SPIRE and no Docker. A local CA (internal/testca) mints SVIDs
// for the legitimate workloads and none for the rogue.
//
// The claim under test: in zero-trust mode the rogue's handler never runs, so
// there is no exfiltration and no poisoned payload, because it cannot present
// the required identity. In naive mode the same rogue robs the agent.
package e2e

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"mcprogue/internal/identity"
	"mcprogue/internal/mcptool"
	"mcprogue/internal/server"
	"mcprogue/internal/testca"
)

const (
	trustDomain    = "mcp.lab"
	networkID      = "spiffe://mcp.lab/network-config"
	agentID        = "spiffe://mcp.lab/agent"
	routerMarker   = "ntp 10.0.0.53" // a line only the real router.conf carries
	poisonMarker   = "evil.example"  // a fragment only the poison payload carries
	handshakeGrace = 15 * time.Second
)

// serveMTLS runs an MCP server behind a real TLS listener and returns its URL.
func serveMTLS(t *testing.T, srv *mcp.Server, cfg *tls.Config) string {
	t.Helper()
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	httpSrv := &http.Server{Handler: handler}
	go func() { _ = httpSrv.Serve(tls.NewListener(ln, cfg)) }()
	t.Cleanup(func() { _ = httpSrv.Close() })
	return "https://" + ln.Addr().String()
}

// callGetFile connects an agent with the given HTTP client to endpoint and
// invokes get_file. It returns the marshalled result, or an error if the
// connection or the call was refused.
func callGetFile(t *testing.T, endpoint string, httpClient *http.Client) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), handshakeGrace)
	defer cancel()

	transport := &mcp.StreamableClientTransport{Endpoint: endpoint, HTTPClient: httpClient}
	client := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "0.1.0"}, nil)

	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		return "", err
	}
	defer session.Close()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      mcptool.ToolName,
		Arguments: mcptool.GetFileInput{Path: "router.conf"},
	})
	if err != nil {
		return "", err
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}

// fixtures builds a CA and the two workload SVIDs. The rogue gets nothing.
func fixtures(t *testing.T) (ca *testca.CA, serverSrc, agentSrc *identity.Source) {
	t.Helper()
	ca, err := testca.New(trustDomain)
	if err != nil {
		t.Fatalf("new CA: %v", err)
	}
	serverSVID, err := ca.Issue(networkID)
	if err != nil {
		t.Fatalf("issue network-config SVID: %v", err)
	}
	agentSVID, err := ca.Issue(agentID)
	if err != nil {
		t.Fatalf("issue agent SVID: %v", err)
	}
	return ca, identity.New(serverSVID, ca.Bundle()), identity.New(agentSVID, ca.Bundle())
}

// legitConfDir writes a real router.conf into a temp dir and returns its path.
func legitConfDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "router.conf")
	if err := os.WriteFile(path, []byte("hostname edge-router-01\n"+routerMarker+"\n"), 0o600); err != nil {
		t.Fatalf("write router.conf: %v", err)
	}
	return path
}

// Scenario A — zero-trust agent, legitimate server: identity proven, real file.
func TestZeroTrust_LegitServer_Succeeds(t *testing.T) {
	ca, serverSrc, agentSrc := fixtures(t)
	_ = ca

	authorizer, err := identity.MemberOf(trustDomain)
	if err != nil {
		t.Fatalf("authorizer: %v", err)
	}
	endpoint := serveMTLS(t, server.Legit(legitConfDir(t)), serverSrc.ServerTLS(authorizer))

	got, err := callGetFile(t, endpoint, agentSrc.ClientHTTP(spiffeid.RequireFromString(networkID)))
	if err != nil {
		t.Fatalf("zero-trust agent should reach the legitimate server, got: %v", err)
	}
	if !strings.Contains(got, routerMarker) {
		t.Fatalf("expected real router.conf (%q) in result, got:\n%s", routerMarker, got)
	}
	if strings.Contains(got, poisonMarker) {
		t.Fatalf("legitimate server must not return the poison payload:\n%s", got)
	}
}

// Scenario B — zero-trust agent, ROGUE server: refused at the handshake. The
// rogue's handler must never run: no exfiltration, no poison. This is the whole
// point of the lab.
func TestZeroTrust_RogueServer_IsRejected(t *testing.T) {
	_, _, agentSrc := fixtures(t)

	stolen := filepath.Join(t.TempDir(), "stolen.log")
	captured := false
	rogueTLS, err := identity.SelfSignedTLS()
	if err != nil {
		t.Fatalf("rogue tls: %v", err)
	}
	endpoint := serveMTLS(t, server.Rogue(stolen, func(string) { captured = true }), rogueTLS)

	got, err := callGetFile(t, endpoint, agentSrc.ClientHTTP(spiffeid.RequireFromString(networkID)))
	if err == nil {
		t.Fatalf("zero-trust agent MUST reject the rogue, but it got a response:\n%s", got)
	}
	t.Logf("rogue correctly refused by the identity gate: %v", err)

	if captured {
		t.Fatalf("SECURITY FAILURE: the rogue's handler ran despite being rejected")
	}
	if _, statErr := os.Stat(stolen); statErr == nil {
		t.Fatalf("SECURITY FAILURE: stolen.log was written; the rogue exfiltrated data")
	}
}

// Scenario C — naive agent, ROGUE server: this is MCP as it ships. The agent is
// robbed: the rogue captures the request and returns poisoned content.
func TestNaive_RogueServer_RobsTheAgent(t *testing.T) {
	stolen := filepath.Join(t.TempDir(), "stolen.log")
	captured := false
	rogueTLS, err := identity.SelfSignedTLS()
	if err != nil {
		t.Fatalf("rogue tls: %v", err)
	}
	endpoint := serveMTLS(t, server.Rogue(stolen, func(string) { captured = true }), rogueTLS)

	got, err := callGetFile(t, endpoint, identity.NaiveHTTP())
	if err != nil {
		t.Fatalf("naive agent connects to anything; unexpected error: %v", err)
	}
	if !strings.Contains(got, poisonMarker) {
		t.Fatalf("expected poisoned payload (%q) in result, got:\n%s", poisonMarker, got)
	}
	if !captured {
		t.Fatalf("expected the rogue to capture the request")
	}
	data, readErr := os.ReadFile(stolen)
	if readErr != nil {
		t.Fatalf("expected stolen.log to exist: %v", readErr)
	}
	if !strings.Contains(string(data), "get_file") {
		t.Fatalf("stolen.log should record the exfiltrated request, got:\n%s", data)
	}
}
